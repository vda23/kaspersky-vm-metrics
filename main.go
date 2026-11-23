package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func notify(value string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	conn, e := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if e == nil {
		conn.Write([]byte(value))
		conn.Close()
	}
}

// This loopback probe reports readiness only. It transmits no credentials or application data.
func probe(ctx context.Context, addr string, secure bool) (string, error) {
	scheme := "http"
	transport := &http.Transport{DisableKeepAlives: true}
	if secure {
		scheme = "https"
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	client := http.Client{
		Transport:     transport,
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, e := http.NewRequestWithContext(ctx, "GET", scheme+"://"+addr+"/healthz", nil)
	if e != nil {
		return "", e
	}
	res, e := client.Do(req)
	if e != nil {
		return "", e
	}
	defer res.Body.Close()
	var data struct {
		OK      bool
		Version string
	}
	e = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&data)
	if e != nil || res.StatusCode != 200 || !data.OK || data.Version == "" {
		return "", fmt.Errorf("invalid health response")
	}
	return data.Version, nil
}
func watchdog(ctx context.Context, addr string, secure bool, send func(string)) {
	usec := number(os.Getenv("WATCHDOG_USEC"))
	pid := number(os.Getenv("WATCHDOG_PID"))
	if usec == 0 || pid != 0 && pid != int64(os.Getpid()) {
		return
	}
	interval := max(time.Millisecond, time.Duration(usec)*time.Microsecond/3)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, e := probe(ctx, addr, secure); e == nil {
				send("WATCHDOG=1")
			}
		}
	}
}
func selfCheck(a *app, out io.Writer) {
	for _, tool := range []string{"systemctl", "ss", "journalctl", "tail"} {
		if _, e := exec.LookPath(tool); e != nil {
			fmt.Fprintln(out, "WARN command not found:", tool)
		}
	}
	if !a.cryptOK() {
		fmt.Fprintln(out, "WARN system libcrypt unavailable")
	} else if os.Geteuid() == 0 && a.authStatus() == "locked" {
		fmt.Fprintln(out, "WARN root account is locked; dashboard administration unavailable")
	}
	d := a.snapshot(context.Background(), true)
	for _, s := range d["services"].([]fields) {
		fmt.Fprintf(out, "INFO unit %s: %s\n", s["unit"], s["state"])
		if s["state"] == "not-found" || s["state"] == "unknown" {
			fmt.Fprintf(out, "WARN unit %s: %s\n", s["unit"], s["state"])
		}
	}
	for _, l := range a.logs {
		fmt.Fprintf(out, "INFO log %s: %s (exists=%t)\n", l.Key, l.Path, fileExists(resolved(l.Path)))
	}
	fmt.Fprintln(out, "OK", version)
}
func serve(ctx context.Context, a *app, bind string, port int, disableTLS bool) error {
	l, e := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
	if e != nil {
		return e
	}
	defer l.Close()
	secure := !disableTLS
	if secure {
		if e := a.setupTLS(); e != nil {
			log.Printf("HTTPS unavailable, read-only HTTP: %v", e)
			secure = false
		}
	}
	addr := l.Addr().(*net.TCPAddr)
	host := addr.IP.String()
	if addr.IP.IsUnspecified() {
		host = "127.0.0.1"
		if bind == "::" {
			host = "::1"
		}
	}
	local := net.JoinHostPort(host, strconv.Itoa(addr.Port))
	base, stop := context.WithCancel(ctx)
	defer stop()
	server := &http.Server{
		Handler:           a,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 << 10,
		BaseContext:       func(net.Listener) context.Context { return base },
	}
	if secure {
		l = tls.NewListener(l, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: a.certs.current})
	}
	delivery, stopDelivery := context.WithCancel(context.Background())
	defer stopDelivery()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); a.events.worker(delivery) }()
	done := make(chan error, 1)
	go func() { done <- server.Serve(l) }()
	scheme := "http"
	if secure {
		scheme = "https"
	}
	log.Printf("Kaspersky VM Metrics %s listening on %s://%s", version, scheme, addr)
	a.events.emit("monitor_started", "Kaspersky VM Metrics "+version+" started", nil)
	a.notify("READY=1")
	monitorDone := make(chan struct{})
	go func() { defer close(monitorDone); a.monitor(base, secure) }()
	go watchdog(base, local, secure, a.notify)
	select {
	case e = <-done:
	case <-ctx.Done():
		e = nil
	}
	a.notify("STOPPING=1")
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		server.Close()
	}
	<-monitorDone
	a.events.emit("monitor_stopped", "Kaspersky VM Metrics stopped", nil)
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		a.events.mu.Lock()
		n := len(a.events.pending)
		a.events.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stopDelivery()
	<-workerDone
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
func cli(args []string) error {
	if len(args) > 0 && args[0] == "--installer" {
		return installerCLI(args[1:])
	}
	flags := flag.NewFlagSet("kaspersky-vm-metrics", flag.ContinueOnError)
	bind := flags.String("bind", "0.0.0.0", "listen address")
	port := flags.Int("port", 8999, "listen port")
	noTLS := flags.Bool("no-tls", false, "read-only HTTP")
	check := flags.Bool("check", false, "check runtime prerequisites and exit")
	show := flags.Bool("version", false, "print version")
	health := flags.Bool("probe", false, "print local HTTPS health version")
	dir := flags.String("data-dir", "", "state directory (default: executable directory)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *show {
		fmt.Println(version)
		return nil
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("port must be 1..65535")
	}
	if *health {
		v, e := probe(context.Background(), net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)), !*noTLS)
		if e == nil {
			fmt.Println(v)
		}
		return e
	}
	if *dir == "" {
		p, e := os.Executable()
		if e != nil {
			return e
		}
		*dir = filepath.Dir(p)
	}
	a := newApp(*dir)
	if *check {
		selfCheck(a, os.Stdout)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return serve(ctx, a, *bind, *port, *noTLS)
}
func main() {
	if err := cli(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		log.Print(err)
		os.Exit(1)
	}
}

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

func TestDestinationAndCEF(t *testing.T) {
	for _, x := range []struct {
		raw fields
		err string
	}{
		{fields{}, "host_required"},
		{fields{"host": "n", "port": "0"}, "bad_port"},
		{fields{"host": "n", "port": 65536}, "bad_port"},
		{fields{"host": "n", "protocol": "http"}, "bad_protocol"},
		{fields{"host": "bad host"}, "bad_host"},
		{fields{"host": "[::1]", "protocol": "udp"}, ""},
		{fields{"enabled": false}, ""},
	} {
		if _, code := destinationFrom(x.raw); code != x.err {
			t.Fatal(x, code)
		}
	}
	b := newBus("test", time.Now)
	e := b.emit("restart_failed", "x=y\nnext", fields{"client": "127.0.0.1", "unit": "worker", "user": "root"})
	line := syslogLine(e, b.host)
	for _, s := range []string{"CEF:0|Kaspersky|Kaspersky VM Metrics|", "|212|", "msg=x\\=y next", "src=127.0.0.1", "cs1Label=unit cs1=worker"} {
		if !strings.Contains(line, s) {
			t.Errorf("missing %s in %s", s, line)
		}
	}
	for _, proto := range []string{"tcp", "udp"} {
		data := wire(strings.Repeat("я", 10000), proto)
		if !utf8.ValidString(data) || proto == "udp" && len(data) > 2048 ||
			proto == "tcp" && (!strings.HasSuffix(data, "\n") || len(data) > 16385) {
			t.Fatal(proto, len(data))
		}
	}
}
func TestSIEMWireAndHistory(t *testing.T) {
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			a := fixture(t)
			messages := make(chan string, 1)
			var addr net.Addr
			if proto == "udp" {
				c, e := net.ListenPacket("udp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				addr = c.LocalAddr()
				go func() { p := make([]byte, 4096); n, _, _ := c.ReadFrom(p); messages <- string(p[:n]) }()
			} else {
				l, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				addr = l.Addr()
				go func() {
					c, e := l.Accept()
					if e != nil {
						return
					}
					defer c.Close()
					s, _ := bufio.NewReader(c).ReadString('\n')
					messages <- s
				}()
			}
			_, port, _ := net.SplitHostPort(addr.String())
			req := fmt.Sprintf(`{"host":"127.0.0.1","port":%s,"protocol":%q,"password":"fixture"}`, port, proto)
			w := request(
				a,
				"POST",
				"/api/siem/test",
				req,
				true,
				map[string]string{"X-Requested-With": "kvm-metrics"},
			)
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			select {
			case m := <-messages:
				if !strings.Contains(m, "|900|") || !strings.Contains(m, "Kaspersky VM Metrics test event") {
					t.Fatal(m)
				}
			case <-time.After(time.Second):
				t.Fatal("no event")
			}
			recent, n := a.events.recent(10, time.Time{}, true)
			if n != 1 || recent[0]["siem"] != "sent" || len(a.events.pending) != 0 {
				t.Fatal(recent)
			}
		})
	}
}
func TestQueueRetry(t *testing.T) {
	b := newBus("vm.test", time.Now)
	b.configure(destination{Enabled: true, Protocol: "tcp", Port: 5144, Host: "localhost"})
	rx, tx := net.Pipe()
	defer rx.Close()
	tries := 0
	b.dial = func(context.Context, string, string) (net.Conn, error) {
		tries++
		if tries == 1 {
			return nil, fmt.Errorf("fixture refused")
		}
		return tx, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.worker(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	b.emit("monitor_started", "demo", nil)
	rx.SetReadDeadline(time.Now().Add(4 * time.Second))
	msg, e := bufio.NewReader(rx).ReadString('\n')
	if e != nil || !strings.Contains(msg, "|100|") {
		t.Fatal(msg, e)
	}
	deadline := time.Now().Add(time.Second)
	for b.status()["state"] != "ok" && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stats := b.status()["stats"].(fields)
	if stats["failed"] != 1 || stats["sent"] != 1 || stats["queued"] != 0 {
		t.Fatal(stats)
	}
}
func TestBoundedQueue(t *testing.T) {
	b := newBus("vm", time.Now)
	d := destination{Enabled: true, Host: "example.test", Port: 5144, Protocol: "tcp"}
	b.configure(d)
	for i := 0; i < 2002; i++ {
		b.emit("monitor_started", "fixture", nil)
	}
	stats := b.status()["stats"].(fields)
	if stats["queued"] != 2000 || stats["dropped"] != 2 {
		t.Fatal(stats)
	}
	_, total := b.recent(1, time.Time{}, false)
	if total != 500 {
		t.Fatal(total)
	}
	d.Enabled = false
	b.configure(d)
	if b.status()["stats"].(fields)["queued"] != 0 {
		t.Fatal("queue retained")
	}
}
func TestServeAndSystemd(t *testing.T) {
	a := fixture(t)
	notifications := make(chan string, 16)
	a.notify = func(s string) { notifications <- s }
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("WATCHDOG_USEC", "600000")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- serve(ctx, a, "127.0.0.1", 0, false) }()
	want := func(expected string) {
		t.Helper()
		timeout := time.After(4 * time.Second)
		for {
			select {
			case got := <-notifications:
				if got == expected {
					return
				}
			case <-timeout:
				t.Fatalf("timeout waiting for %s", expected)
			}
		}
	}
	want("READY=1")
	want("WATCHDOG=1")
	cancel()
	want("STOPPING=1")
	if e := <-result; e != nil {
		t.Fatal(e)
	}
}
func TestCapsAndBrandOverrides(t *testing.T) {
	a := fixture(t)
	put(t, filepath.Join(a.dir, "assets/logo-dark.svg"), "<svg/>")
	a.static = loadAssets(a.dir)
	w := request(a, "GET", "/?theme=dark", "", true, nil)
	if !strings.Contains(w.Body.String(), "/brand/logo-dark") {
		t.Fatal("brand override")
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("theme cookie")
	}
	for i := 0; i < cap(a.slots); i++ {
		a.slots <- struct{}{}
	}
	w = request(a, http.MethodGet, "/healthz", "", false, nil)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	for len(a.slots) > 0 {
		<-a.slots
	}
	for i := 0; i < cap(a.live); i++ {
		a.live <- struct{}{}
	}
	w = httptest.NewRecorder()
	a.stream(w, httptest.NewRequest("GET", "/", nil), logSource{})
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
}

func TestSystemdUnixgram(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notify")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: p, Net: "unixgram"})
	if (errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)) &&
		os.Getenv("KVM_REQUIRE_UNIXGRAM") != "1" {
		t.Skipf("test environment denies AF_UNIX datagram sockets: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	t.Setenv("NOTIFY_SOCKET", p)
	notify("READY=1")
	l.SetReadDeadline(time.Now().Add(time.Second))
	var b [32]byte
	n, _, err := l.ReadFromUnix(b[:])
	if err != nil || string(b[:n]) != "READY=1" {
		t.Fatal(n, err)
	}
}

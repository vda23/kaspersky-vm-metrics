package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLiveUpgradeFromV1(t *testing.T) {
	testLiveUpgrade(t, "1.0.0", "")
}

func TestLiveUpgradeFromPreview(t *testing.T) {
	preview := os.Getenv("KVM_PREVIEW_DIR")
	if preview == "" {
		t.Skip("run make test-upgrade to build the 1.2.0-dev baseline")
	}
	testLiveUpgrade(t, "1.2.0-dev", preview)
}

// Exercise the installer and real TLS endpoints before migration and after rollback.
// Only unit management and the host's monitoring command output are simulated.
func testLiveUpgrade(t *testing.T, previousVersion, preview string) {
	t.Helper()
	binary := os.Getenv("KVM_UPGRADE_BINARY")
	if binary == "" {
		t.Skip("run make test-upgrade to build the candidate")
	}
	root := t.TempDir()
	i := newInstaller(filepath.Join(root, "package"))
	i.dir, i.units = filepath.Join(root, "installed"), filepath.Join(root, "units")
	i.backups = filepath.Join(i.dir, "backup")
	i.timeout = 8 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	for _, dir := range []string{i.src, i.dir, i.units} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	unitCommand := filepath.Join(i.dir, programName)
	if preview == "" {
		const baseline = "f410f5001a7de56ba08503fb80dd6afd3de486a6"
		for _, name := range []string{legacyName, "install.sh", "KasperskySans-Regular.ttf"} {
			b, err := exec.Command("git", "show", baseline+":"+name).Output()
			if err != nil {
				t.Fatalf("read %s from 1.0.0: %v", name, err)
			}
			if err := os.WriteFile(filepath.Join(i.dir, name), b, 0755); err != nil {
				t.Fatal(err)
			}
		}
		unitCommand = "/usr/bin/python3 " + filepath.Join(i.dir, legacyName)
	} else {
		for _, name := range []string{programName, "install.sh", "KasperskySans-Regular.ttf"} {
			if err := copyFile(filepath.Join(preview, name), filepath.Join(i.dir, name), 0755); err != nil {
				t.Fatal(err)
			}
		}
	}
	var sums strings.Builder
	for _, name := range []string{programName, "install.sh", "KasperskySans-Regular.ttf"} {
		src := name
		if name == programName {
			src = binary
		}
		dst := filepath.Join(i.src, name)
		if err := copyFile(src, dst, 0755); err != nil {
			t.Fatal(err)
		}
		sum, err := digest(dst)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&sums, "%s  %s\n", sum, name)
	}
	put(t, filepath.Join(i.src, "SHA256SUMS"), sums.String())

	commands := filepath.Join(root, "commands")
	for name, script := range map[string]string{
		"systemctl": `case "$1" in
list-units) echo 'postgresql@15-main.service loaded active running Cluster';;
list-unit-files) echo 'postgresql.service enabled';;
show)
  shift
  for unit in "$@"; do
    case "$unit" in
      *.service)
        sub=running; pid=101
        if [ "$unit" = postgresql.service ]; then sub=exited; pid=0; fi
        printf 'Id=%s\nLoadState=loaded\nActiveState=active\nSubState=%s\nMainPID=%s\nMemoryCurrent=2048\nTasksCurrent=4\nNRestarts=0\nActiveEnterTimestampMonotonic=0\nResult=success\n\n' "$unit" "$sub" "$pid"
        ;;
    esac
  done;;
esac`,
		"ss": `case "$1" in
-tulnp) echo 'tcp LISTEN 0 10 [::]:5432 [::]:* users:(("postgres",pid=101,fd=8))';;
-tan) echo 'ESTAB 0 0 127.0.0.1:5432 127.0.0.1:40000';;
esac`,
	} {
		path := filepath.Join(commands, name)
		put(t, path, "#!/bin/sh\n"+script+"\n")
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", commands+":"+os.Getenv("PATH"))
	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("WATCHDOG_USEC", "")
	i.exists = func(name string) bool {
		return name == "systemctl" || name == "ss" || name == "tail" || name == "journalctl"
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	put(t, i.unit(), fmt.Sprintf("ExecStart=%s --port %d\n", unitCommand, port))
	certPath := filepath.Join(i.dir, "cert.pem")
	if err := generatePair(certPath, filepath.Join(i.dir, "key.pem"), "localhost", time.Now()); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(i.dir, "cert.org"), "installed=legacy\n")
	put(t, filepath.Join(i.dir, "settings.json"), `{"siem":{"enabled":false,"host":"collector.local","port":5144,"protocol":"tcp"},"previous":true}`)
	// Use yesterday so the daily writer cannot claim this filename during the test.
	report := reportPrefix + time.Now().AddDate(0, 0, -1).Format(reportLayout) + ".json"
	put(t, filepath.Join(i.dir, report), `{"schema":1,"kind":"daily"}`)
	dataSums := map[string]string{}
	for _, name := range []string{"cert.pem", "key.pem", "cert.org", "settings.json", report} {
		dataSums[name], err = digest(filepath.Join(i.dir, name))
		if err != nil {
			t.Fatal(err)
		}
	}

	var child *exec.Cmd
	stop := func() {
		if child == nil {
			return
		}
		child.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func(cmd *exec.Cmd) { done <- cmd.Wait() }(child)
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			child.Process.Kill()
			<-done
		}
		child = nil
	}
	defer stop()
	start := func() error {
		stop()
		args := []string{"--bind", "127.0.0.1", "--port", strconv.Itoa(i.installedPort())}
		program := filepath.Join(i.dir, programName)
		if strings.Contains(read(i.unit()), legacyName) {
			args = append([]string{filepath.Join(i.dir, legacyName)}, args...)
			program = "python3"
		}
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Dir = i.dir
		if err := cmd.Start(); err != nil {
			return err
		}
		child = cmd
		return nil
	}
	i.run = func(c context.Context, args ...string) (string, error) {
		if args[0] == "systemctl" {
			if args[1] == "restart" {
				return "", start()
			}
			return "", nil
		}
		return runCommand(c, args...)
	}

	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM([]byte(read(certPath))) {
		t.Fatal("failed to trust the original certificate")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trust}}, Timeout: 8 * time.Second}
	defer client.CloseIdleConnections()
	get := func(path string) []byte {
		t.Helper()
		url := fmt.Sprintf("https://127.0.0.1:%d%s", port, path)
		res, err := client.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
		if err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("%s: HTTP %d, %v", path, res.StatusCode, err)
		}
		return data
	}
	snapshot := func() fields {
		t.Helper()
		var status fields
		if err := json.Unmarshal(get("/api/status"), &status); err != nil {
			t.Fatal(err)
		}
		return fields{"services": status["services"], "ports": status["ports"], "summary": status["summary"]}
	}
	if err := start(); err != nil {
		t.Fatal(err)
	}
	if err := i.wait(ctx, port, previousVersion); err != nil {
		t.Fatal(err)
	}
	originalStatus := snapshot()
	originalUI := map[string][]byte{}
	for _, path := range []string{"/static/app.js", "/static/app.css", "/brand/logo", "/brand/favicon", "/font"} {
		originalUI[path] = get(path)
	}
	force := older(version, previousVersion)
	if force {
		if err := i.execute(ctx, installOptions{}); err == nil || !strings.Contains(err.Error(), "--force") {
			t.Fatalf("downgrade without confirmation returned %v", err)
		}
		if err := i.wait(ctx, port, previousVersion); err != nil || len(i.copies()) != 0 {
			t.Fatalf("declined downgrade changed the installation: %v", err)
		}
	}
	for _, step := range []struct{ action, want string }{{"", version}, {"rollback", previousVersion}} {
		if err := i.execute(ctx, installOptions{action: step.action, force: step.action == "" && force}); err != nil {
			t.Fatal(err)
		}
		if err := i.wait(ctx, port, step.want); err != nil {
			t.Fatal(err)
		}
		if got := snapshot(); !reflect.DeepEqual(got, originalStatus) {
			t.Fatalf("%s changed service or port metrics:\n%v\nwant %v", step.want, got, originalStatus)
		}
		for path, want := range originalUI {
			if !bytes.Equal(get(path), want) {
				t.Errorf("%s changed %s", step.want, path)
			}
		}
		if data := get("/log?file=" + report); string(data) != read(filepath.Join(i.dir, report)) {
			t.Errorf("%s cannot download the existing report", step.want)
		}
		for name, want := range dataSums {
			if got, err := digest(filepath.Join(i.dir, name)); err != nil || got != want {
				t.Errorf("%s changed %s: %v", step.want, name, err)
			}
		}
	}
}

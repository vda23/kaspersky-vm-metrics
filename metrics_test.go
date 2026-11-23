package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func put(t *testing.T, p, s string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte(s), 0600); e != nil {
		t.Fatal(e)
	}
}
func fixture(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	a := newApp(dir)
	a.host = "vm.test"
	a.now = func() time.Time { return time.Date(2026, 11, 20, 19, 1, 0, 0, time.UTC) }
	a.events = newBus(a.host, a.now)
	a.proc = filepath.Join(dir, "proc")
	a.shadow = []string{filepath.Join(dir, "shadow")}
	a.disks = []string{dir}
	a.groups = []string{filepath.Join(dir, "cgroup")}
	a.failDelay = 0
	a.cryptOK = func() bool { return true }
	a.verify = func(p, h string) bool { return p == "fixture" && h == "$test$hash" }
	put(t, a.shadow[0], "root:$test$hash:1::::::\n")
	put(t, filepath.Join(a.proc, "meminfo"), "MemTotal: 100 kB\nMemFree: 10 kB\nCached: 30 kB\nBuffers: 5 kB\n")
	put(t, filepath.Join(a.proc, "uptime"), "1000.75 400\n")
	put(t, filepath.Join(a.proc, "loadavg"), "1.23 2.34 3.45 1/20 5")
	for i := range a.logs {
		a.logs[i].Path = filepath.Join(dir, a.logs[i].Key+".log")
	}
	a.run = func(ctx context.Context, args ...string) (string, error) {
		switch args[0] {
		case "systemctl":
			switch args[1] {
			case "list-units":
				return "postgresql@15-main.service loaded active running DB\n", nil
			case "list-unit-files":
				return "postgresql.service enabled\n", nil
			case "restart":
				return "", nil
			case "show":
				var b strings.Builder
				for _, u := range args[2:] {
					if strings.HasPrefix(u, "--") {
						continue
					}
					sub, pid := "running", len(u)
					if u == "postgresql.service" {
						sub, pid = "exited", 0
					}
					fmt.Fprintf(
						&b,
						"Id=%s\nLoadState=loaded\nActiveState=active\nSubState=%s\nMainPID=%d\nMemoryCurrent=1024\nTasksCurrent=4\nNRestarts=0\nActiveEnterTimestampMonotonic=1000000\n\n",
						u,
						sub, pid,
					)
				}
				return b.String(), nil
			}
		case "ss":
			if args[1] == "-tan" {
				return "ESTAB 0 0 127.0.0.1:5432 127.0.0.1:10000\nESTAB 0 0 127.0.0.1:10000 127.0.0.1:5432\n", nil
			}
			return "tcp LISTEN 0 5 [::]:5432 [::]:* users:((\"postgres\",pid=26,fd=1))\n", nil
		case "journalctl":
			return "-- header\nentry\n", nil
		case "tail":
			return runCommand(ctx, args...)
		}
		return "", fmt.Errorf("unexpected command %v", args)
	}
	return a
}
func TestMetricsAndCache(t *testing.T) {
	a := fixture(t)
	ctx := context.Background()
	d := a.snapshot(ctx, false)
	if d["summary"].(fields)["running"] != 6 {
		t.Fatal(d)
	}
	pg := a.service(ctx, "postgresql", false)
	if pg["db_connections"] != 1 || pg["unit"] != "postgresql@15-main.service" ||
		pg["uptime_sec"] != int64(999) {
		t.Fatal(pg)
	}
	if n := d["system"].(fields)["memory"].(map[string]int64); n["processes"] != 55*1024 ||
		n["available"] != 45*1024 {
		t.Fatal(n)
	}
	if d["ports"].([]fields)[0]["port"] != 5432 {
		t.Fatal(d["ports"])
	}
	calls := 0
	a.run = func(context.Context, ...string) (string, error) { calls++; return "", nil }
	a.snapshot(ctx, false)
	if calls != 0 {
		t.Fatal("cache miss")
	}
	a.invalidate()
	a.snapshot(ctx, false)
	if calls == 0 {
		t.Fatal("stale cache")
	}
}
func TestMetricParsers(t *testing.T) {
	for _, x := range []struct {
		raw  string
		want cpuTimes
	}{{"cpu 2 3 4 10 5 6 7 8", cpuTimes{30, 45}}, {"cpu 1 2", cpuTimes{}}, {"cpu 1 bad 2 3", cpuTimes{}}} {
		if got := parseCPU(x.raw); got != x.want {
			t.Errorf("%s: %v", x.raw, got)
		}
	}
	for _, x := range []struct {
		p props
		s string
	}{{nil, "unknown"}, {props{"LoadState": "masked"}, "masked"}, {props{"LoadState": "not-found", "ActiveState": "active"}, "active"}} {
		if unitState(x.p) != x.s {
			t.Error(x)
		}
	}
	p := parsePorts(
		"udp UNCONN 0 0 *:53 *:*\ntcp LISTEN 0 0 [::]:22 [::]:* users:((\"sshd\",pid=88,fd=5),(\"sshd\",pid=8,fd=6))",
		map[int64]string{8: "one"},
	)
	if len(p) != 2 || p[0]["service"] != "one" || p[0]["process"] != "sshd" ||
		!reflect.DeepEqual(p[0]["pids"], []int64{8, 88}) {
		t.Fatal(p)
	}
	a := fixture(t)
	put(t, filepath.Join(a.groups[0], "kvm", "cgroup.procs"), "13\n12")
	put(t, filepath.Join(a.proc, "13/status"), "VmRSS: 2 kB")
	if n, ok := a.rss("/kvm"); !ok || n != 2048 {
		t.Fatal(n, ok)
	}
}
func TestAuthAndRestartLifecycle(t *testing.T) {
	a := fixture(t)
	ip := "127.0.0.1"
	now := a.now()
	for i := 4; i >= 0; i-- {
		if n := a.auth.fail(ip, now); n != i {
			t.Fatal(n)
		}
	}
	if a.auth.retry(ip, now) == 0 || a.auth.retry(ip, now.Add(301*time.Second)) != 0 {
		t.Fatal("lock period")
	}
	a.auth.reset(ip)
	s := a.service(context.Background(), "worker", true)
	if status, _, _ := a.startRestart(context.Background(), s, ip); status != 202 {
		t.Fatal(status)
	}
	if status, _, _ := a.startRestart(context.Background(), s, ip); status != 409 {
		t.Fatal(status)
	}
	if r := a.restartStatus("worker", s["unit"].(string), "active", 2000000, now.Add(3*time.Second)).(fields); r["result"] != "ok" {
		t.Fatal(r)
	}
	for _, x := range []struct {
		state string
		after time.Duration
		want  string
	}{{"failed", 3 * time.Second, "failed"}, {"activating", 181 * time.Second, "timeout"}} {
		a.startRestart(context.Background(), s, ip)
		r := a.restartStatus("worker", "worker.service", x.state, 0, now.Add(x.after)).(fields)
		if r["result"] != x.want {
			t.Fatal(r)
		}
	}
	a.run = func(context.Context, ...string) (string, error) { return "", fmt.Errorf("systemd rejected job") }
	if status, code, _ := a.startRestart(
		context.Background(),
		s,
		ip,
	); status != 500 ||
		code != "systemctl_failed" {
		t.Fatal(status, code)
	}
	for _, hash := range []string{"!", "*", "", "x"} {
		put(t, a.shadow[0], "root:"+hash+":")
		if a.authStatus() != "locked" {
			t.Fatal(hash)
		}
	}
	os.Remove(a.shadow[0])
	if a.authStatus() != "unavailable" {
		t.Fatal(a.authStatus())
	}
}
func TestLocalCrypt(t *testing.T) {
	if !cryptAvailable() {
		t.Skip("system libcrypt missing")
	}
	const h = "$6$metricsfixture$wcO/xvYCXMPwYoldPrdZA/tvW1Ht1MyGSu824EXic36dS6xeJyc39v/XxkKCmdYugn02FlM7XDIzlQFwC/syk."
	if !verifyHash("demo-fixture", h) || verifyHash("incorrect", h) || verifyHash("a\x00b", h) {
		t.Fatal("system crypt mismatch")
	}
}
func TestStateTransitions(t *testing.T) {
	a := fixture(t)
	m := newMonitor()
	svc := func(state string, n int64) []fields {
		return []fields{{"key": "worker", "unit": "worker.service", "state": state, "restarts": n}}
	}
	m.serviceChanges(a, svc("active", 0))
	m.serviceChanges(a, svc("activating", 0))
	m.serviceChanges(a, svc("failed", 0))
	m.serviceChanges(a, svc("active", 1))
	for _, v := range []float64{90, 91, 85, 84} {
		m.threshold(a, "memory", "memory", v, fields{})
	}
	recent, _ := a.events.recent(10, time.Time{}, false)
	var names []string
	for _, e := range recent {
		names = append(names, e["name"].(string))
	}
	if !reflect.DeepEqual(
		names,
		[]string{"service_failed", "service_up", "service_auto_restart", "memory_high", "memory_ok"},
	) {
		t.Fatal(names)
	}
}
func TestNotificationSocketAndCLI(t *testing.T) {
	if err := cli([]string{"--port", "0"}); err == nil {
		t.Fatal("port")
	}
	if err := cli([]string{"--version"}); err != nil {
		t.Fatal(err)
	}
	a := fixture(t)
	var b strings.Builder
	selfCheck(a, &b)
	if !strings.Contains(b.String(), "OK "+version) {
		t.Fatal(b.String())
	}
	srv := httptest.NewTLSServer(a)
	defer srv.Close()
	v, e := probe(context.Background(), srv.Listener.Addr().String(), true)
	if e != nil || v != version {
		t.Fatal(v, e)
	}
}

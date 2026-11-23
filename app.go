package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed VERSION config/*.json web/*
var assets embed.FS

type fields = map[string]any
type serviceDef struct {
	Key, Unit string
	Detect    []string
	DescRU    string `json:"desc_ru"`
	DescEN    string `json:"desc_en"`
	WarnRU    string `json:"warn_ru"`
	WarnEN    string `json:"warn_en"`
	DBPort    int    `json:"db_port"`
}
type logDef struct {
	Key, Path, Service string
	TitleRU            string `json:"title_ru"`
	TitleEN            string `json:"title_en"`
}

func embedded(name string) []byte {
	b, e := assets.ReadFile(name)
	if e != nil {
		panic(e)
	}
	return b
}
func definitions[T any](name string) T {
	var result T
	if err := json.Unmarshal(embedded("config/"+name+".json"), &result); err != nil {
		panic(err)
	}
	return result
}

var version = strings.TrimSpace(string(embedded("VERSION")))

type runner func(context.Context, ...string) (string, error)
type cappedBuffer struct {
	data  bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if left := b.limit - b.data.Len(); left > 0 {
		b.data.Write(p[:min(n, left)])
	}
	return n, nil
}
func runCommand(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "SYSTEMD_PAGER=cat", "SYSTEMD_COLORS=0")
	if args[0] != "journalctl" {
		cmd.Env = append(cmd.Env, "LC_ALL=C")
	}
	stdout, stderr := &cappedBuffer{limit: 32 << 20}, &cappedBuffer{limit: 4096}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		return stdout.data.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.data.String()))
	}
	return stdout.data.String(), nil
}
func command(ctx context.Context, run runner, timeout time.Duration, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return run(c, args...)
}
func read(path string) string     { b, _ := os.ReadFile(path); return string(b) }
func iso(t time.Time) string      { return t.Format(time.RFC3339) }
func epoch(t time.Time) float64   { return float64(t.UnixMilli()) / 1000 }
func fileExists(path string) bool { s, e := os.Stat(path); return e == nil && s.Mode().IsRegular() }
func atomicFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".kvm-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	return err
}
func writeJSONFile(path string, data any, mode os.FileMode) error {
	b, e := json.MarshalIndent(data, "", "  ")
	if e != nil {
		return e
	}
	return atomicFile(path, append(b, '\n'), mode)
}
func short(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func fqdn() string {
	h, _ := os.Hostname()
	if h == "" {
		return "localhost"
	}
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if n, e := net.DefaultResolver.LookupCNAME(c, h); e == nil && n != "" {
		return strings.TrimSuffix(n, ".")
	}
	return h
}

type app struct {
	dir, host, proc                 string
	groups, disks, shadow           []string
	defs                            []serviceDef
	logs                            []logDef
	run                             runner
	now                             func() time.Time
	verify                          func(string, string) bool
	cryptOK                         func() bool
	notify                          func(string)
	failDelay                       time.Duration
	collectMu                       sync.Mutex
	cached                          fields
	cachedAt, detectedAt            time.Time
	databaseUnit                    string
	cpu                             cpuTimes
	restarts                        restartBook
	auth                            throttle
	events                          *eventBus
	certs                           tlsState
	static                          map[string]asset
	reportMu, archiveMu, settingsMu sync.Mutex
	slots, live                     chan struct{}
}

func newApp(dir string) *app {
	a := &app{
		dir:    dir,
		host:   fqdn(),
		proc:   "/proc",
		groups: []string{"/sys/fs/cgroup", "/sys/fs/cgroup/systemd", "/sys/fs/cgroup/unified"},
		disks: []string{
			"/",
			"/var",
			"/var/log",
			"/var/log/kaspersky",
			"/var/lib/pgsql",
			"/var/lib/postgresql",
			"/opt",
			dir,
		},
		shadow:    []string{"/etc/tcb/root/shadow", "/etc/shadow"},
		defs:      definitions[[]serviceDef]("services"),
		logs:      definitions[[]logDef]("logs"),
		run:       runCommand,
		now:       time.Now,
		verify:    verifyHash,
		cryptOK:   cryptAvailable,
		failDelay: time.Second,
		notify:    notify,
		slots:     make(chan struct{}, 64),
		live:      make(chan struct{}, 8),
	}
	a.restarts.jobs = map[string]restartJob{}
	a.restarts.last = map[string]fields{}
	a.auth.attempts = map[string]attempt{}
	a.events = newBus(a.host, a.now)
	a.readSettings()
	a.static = loadAssets(dir)
	return a
}
func (a *app) def(key string) (serviceDef, bool) {
	for _, s := range a.defs {
		if s.Key == key {
			return s, true
		}
	}
	return serviceDef{}, false
}
func (a *app) logDef(key string) (logDef, bool) {
	for _, l := range a.logs {
		if l.Key == key {
			return l, true
		}
	}
	return logDef{}, false
}
func (a *app) invalidate() { a.collectMu.Lock(); defer a.collectMu.Unlock(); a.cached = nil }
func (a *app) status(ctx context.Context, tlsOn bool) fields {
	d := maps.Clone(a.snapshot(ctx, false))
	state := "insecure"
	if tlsOn {
		state = a.authStatus()
	}
	d["auth"] = fields{"restart": state}
	siem := a.events.status()
	d["siem"] = fields{"state": siem["state"], "enabled": siem["enabled"]}
	d["tls"] = a.certs.status(a.now())
	return d
}
func copyWithContext(ctx context.Context, w io.Writer, r io.Reader) (int64, error) {
	return io.Copy(w, contextReader{ctx, r})
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func entries(t *testing.T, data []byte) map[string]string {
	t.Helper()
	r, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	out := map[string]string{}
	for _, f := range r.File {
		h, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(h)
		h.Close()
		if e != nil {
			t.Fatal(e)
		}
		out[f.Name] = string(b)
	}
	return out
}
func TestArchiveByDayAndRotation(t *testing.T) {
	a := fixture(t)
	d := a.now()
	p := a.logs[0].Path
	prev := strings.Repeat("2026-11-19 23:59:00 INFO old\n", 10000)
	selected := "2026-11-20 01:00:00 WARN message\n  stack frame\n"
	other := "2026-11-21 01:00:00 INFO new\n"
	put(t, p, prev+selected+other)
	os.Chtimes(p, d.AddDate(0, 0, 1), d.AddDate(0, 0, 1))
	f, e := os.Create(p + ".1.gz")
	if e != nil {
		t.Fatal(e)
	}
	gz := gzip.NewWriter(f)
	fmt.Fprint(gz, prev, selected, other)
	gz.Close()
	f.Close()
	os.Chtimes(p+".1.gz", d, d)
	p2 := a.logs[1].Path
	put(t, p2, "undated\n")
	os.Chtimes(p2, d, d)
	var buf bytes.Buffer
	if e := a.dayZip(context.Background(), &buf, d); e != nil {
		t.Fatal(e)
	}
	got := entries(t, buf.Bytes())
	if got["worker/worker.log"] != selected || got["worker/worker.log.1"] != selected ||
		got["scanner/scanner.log"] != "undated\n" ||
		!strings.Contains(got["README.txt"], "vm.test") {
		t.Fatalf("incorrect archive: %v", got)
	}
}
func TestDatesLevelsAndOffsets(t *testing.T) {
	for _, s := range []string{"[20.11.2026 01:00]", "2026/11/20 02:00", `{"@timestamp":"2026-11-20T16:00:00Z"}`} {
		if logDate(s) != "2026-11-20" {
			t.Fatal(s)
		}
	}
	if logDate("2026-13-01 X") != "" {
		t.Fatal("invalid date")
	}
	a := fixture(t)
	p := a.logs[0].Path
	put(
		t,
		p,
		"INFO first\n"+`{"level":"error","timestamp":"2026-11-20T10:00:00Z","message":"broken","error":"detail","logger":"a"}`+"\nWARN delayed\nERROR partial",
	)
	h, _ := os.Open(p)
	defer h.Close()
	st, _ := h.Stat()
	scan, e := scanLevels(context.Background(), h, 0, st.Size(), 32<<20, 5)
	if e != nil || scan.Warnings != 1 || scan.Errors != 1 || scan.Lines != 3 ||
		scan.Last[0]["message"] != "broken: detail" ||
		scan.next != st.Size()-13 {
		t.Fatal(scan, e)
	}
	m := newMonitor()
	m.scanLogs(context.Background(), a)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	fmt.Fprint(f, "\nERROR brand-new\n")
	f.Close()
	m.scanLogs(context.Background(), a)
	events, _ := a.events.recent(3, time.Time{}, false)
	if len(events) != 1 || events[0]["fields"].(fields)["count"] != 1 {
		t.Fatal(events)
	}
	if e = os.Rename(p, p+".1"); e != nil {
		t.Fatal(e)
	}
	put(t, p, "ERROR rotated\n")
	m.scanLogs(context.Background(), a)
	events, _ = a.events.recent(3, time.Time{}, false)
	if len(events) != 2 {
		t.Fatal(events)
	}
}
func TestBoundedLogScanAtRecordBoundary(t *testing.T) {
	p := filepath.Join(t.TempDir(), "worker.log")
	const prefix = "INFO previous\n"
	const suffix = "ERROR retained\nWARN more\n"
	put(t, p, prefix+suffix)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, extra := range []int64{0, 3} {
		s, err := scanLevels(context.Background(), f, 0, int64(len(prefix+suffix)), int64(len(suffix))+extra, 1)
		if err != nil || !s.Truncated || s.Errors != 1 || s.Warnings != 1 || s.Scanned != int64(len(suffix))+extra {
			t.Fatalf("window overlap %d: %+v, %v", extra, s, err)
		}
	}
}

func TestReportsAndRetention(t *testing.T) {
	a := fixture(t)
	ctx := context.Background()
	now := a.now()
	p := a.logs[0].Path
	put(t, p, "2026-11-20 12:00 ERROR disk\n")
	os.Chtimes(p, now, now)
	old := reportPrefix + "01_11_2026.json"
	put(t, filepath.Join(a.dir, old), "{}\n")
	os.Chtimes(filepath.Join(a.dir, old), now.AddDate(0, 0, -8), now.AddDate(0, 0, -8))
	if e := a.daily(ctx, now.Add(-time.Hour)); e != nil || len(a.listReports()) != 1 {
		t.Fatal(e)
	}
	if e := a.daily(ctx, now); e != nil {
		t.Fatal(e)
	}
	reports := a.listReports()
	if len(reports) != 1 {
		t.Fatal(reports)
	}
	name := reports[0]["name"].(string)
	if name != reportPrefix+"20_11_2026.json" {
		t.Fatal(name)
	}
	var report fields
	if e := json.Unmarshal([]byte(read(a.reportPath(name))), &report); e != nil {
		t.Fatal(e)
	}
	if report["kind"] != "daily" || report["summary"].(map[string]any)["log_errors_today"] != float64(1) {
		t.Fatal(report["summary"])
	}
	if e := a.daily(ctx, now); e != nil {
		t.Fatal(e)
	}
	ev, _ := a.events.recent(10, time.Time{}, false)
	if len(ev) != 1 {
		t.Fatal(ev)
	}
	var b bytes.Buffer
	n, e := a.reportsZip(ctx, &b, []string{"../shadow", name, "BAD"})
	if n != 1 || e != nil || len(entries(t, b.Bytes())) != 1 {
		t.Fatal(n, e)
	}
	symlink := reportPrefix + "19_11_2026.json"
	if e = os.Symlink(p, filepath.Join(a.dir, symlink)); e != nil {
		t.Fatal(e)
	}
	if a.reportPath(symlink) != "" {
		t.Fatal("symlink accepted")
	}
}
func TestLiveStreamDisconnect(t *testing.T) {
	a := fixture(t)
	put(t, a.logs[0].Path, "first\nsecond\n")
	srv := httptest.NewServer(a)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/logs/live/file/worker?lines=2", nil)
	res, e := srv.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	br := bufio.NewReader(res.Body)
	var got strings.Builder
	for !strings.Contains(got.String(), `["first","second"]`) {
		line, e := br.ReadString('\n')
		if e != nil {
			res.Body.Close()
			t.Fatal(e, got.String())
		}
		got.WriteString(line)
	}
	res.Body.Close()
	cancel()
	if !strings.Contains(got.String(), "event: meta") {
		t.Fatal(got.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(a.live) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(a.live) != 0 {
		t.Fatal("tail did not stop")
	}
}

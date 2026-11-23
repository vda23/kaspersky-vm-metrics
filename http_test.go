package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func request(
	a *app,
	method, path, payload string,
	secure bool,
	headers map[string]string,
) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(payload))
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func TestHTTPContract(t *testing.T) {
	a := fixture(t)
	put(t, a.logs[0].Path, "one\n\x1b[31mtwo\x1b[0m\n")
	for _, x := range []struct {
		path     string
		status   int
		contains string
	}{
		{"/healthz", 200, version},
		{"/api/status", 200, "db_connections"},
		{"/api/logs", 200, "journals"},
		{"/api/logs/file/worker?lines=1", 200, `"lines":["two"]`},
		{"/api/logs/file/unknown", 404, "unknown_log"},
		{"/api/logs/file/scanner", 404, "file_not_found"},
		{"/api/logs/journal/vms", 200, `"lines":["entry"]`},
		{"/api/logs/journal/no", 404, "unknown_service"},
		{"/api/siem", 200, `"recommended"`},
		{"/api/siem/events", 200, `"lines":[]`},
		{"/api/reports", 200, `"reports":[]`},
		{"/api/report-now", 200, "on-demand"},
		{"/logs-day?date=2099-01-01", 400, "bad_date"},
		{"/logs-day?date=2026-11-99", 400, "bad_date"},
		{"/logs-today", 200, "PK"},
		{"/logs-archive?files=invalid", 404, ""},
		{"/log?file=../shadow", 404, ""},
		{"/api/no", 404, "not_found"},
		{"/?lang=en&theme=light", 200, "Kaspersky VM | Monitoring"},
		{"/brand/logo", 200, "PNG"},
		{"/brand/favicon", 200, "PNG"},
		{"/static/app.js", 200, "EventSource"},
		{"/static/app.css", 200, "font-face"},
	} {
		w := request(a, "GET", x.path, "", false, nil)
		if w.Code != x.status || !strings.Contains(w.Body.String(), x.contains) {
			t.Errorf("%s: HTTP %d, %.110s", x.path, w.Code, w.Body.String())
		}
	}
	w := request(a, "GET", "/static/app.js", "", false, nil)
	w = request(
		a,
		"GET",
		"/static/app.js",
		"",
		false,
		map[string]string{"If-None-Match": w.Header().Get("ETag")},
	)
	if w.Code != 304 || w.Body.Len() != 0 {
		t.Fatal(w.Code)
	}
	w = request(a, "DELETE", "/", "", false, nil)
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
func TestProtectedRoutes(t *testing.T) {
	a := fixture(t)
	h := map[string]string{"X-Requested-With": "kvm-metrics", "Origin": "https://example.com"}
	path := "/api/services/worker/restart"
	for _, x := range []struct {
		secure  bool
		headers map[string]string
		payload string
		code    int
		want    string
	}{
		{true, nil, "{}", 403, "csrf"},
		{true, map[string]string{"X-Requested-With": "kvm-metrics", "Origin": "https://foreign.test"}, "{}", 403, "csrf"},
		{false, map[string]string{"X-Requested-With": "kvm-metrics"}, "{}", 403, "insecure_transport"},
		{true, h, "[", 400, "bad_request"},
		{true, h, strings.Repeat("0", 4097), 400, "bad_request"},
	} {
		w := request(a, "POST", path, x.payload, x.secure, x.headers)
		if w.Code != x.code || !strings.Contains(w.Body.String(), x.want) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for i := 1; i <= 5; i++ {
		w := request(a, "POST", path, `{"password":"incorrect"}`, true, h)
		if i < 5 && w.Code != 401 || i == 5 && w.Code != 429 {
			t.Fatal(w.Code)
		}
	}
	w := request(a, "POST", path, `{"password":"fixture"}`, true, h)
	if w.Code != 429 {
		t.Fatal("locked")
	}
	a.auth.reset("192.0.2.1")
	var wg sync.WaitGroup
	statuses := make(chan int, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); statuses <- request(a, "POST", path, `{"password":"fixture"}`, true, h).Code }()
	}
	wg.Wait()
	close(statuses)
	accepted := 0
	for code := range statuses {
		if code == 202 {
			accepted++
		} else if code != 409 {
			t.Fatal(code)
		}
	}
	if accepted != 1 {
		t.Fatalf("queued %d times", accepted)
	}
	put(t, filepath.Join(a.dir, "settings.json"), `{"custom":42}`)
	w = request(
		a,
		"POST",
		"/api/siem",
		`{"enabled":false,"password":"fixture","port":"5144","protocol":"udp"}`,
		true,
		h,
	)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	stored := read(filepath.Join(a.dir, "settings.json"))
	if !strings.Contains(stored, "custom") || strings.Contains(stored, "fixture") {
		t.Fatal(stored)
	}
	fresh := newApp(a.dir)
	if fresh.events.status()["protocol"] != "udp" {
		t.Fatal("lost settings")
	}
	info, _ := os.Stat(filepath.Join(a.dir, "settings.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
}
func TestCertificates(t *testing.T) {
	a := fixture(t)
	if err := a.setupTLS(); err != nil {
		t.Fatal(err)
	}
	if a.certs.status(a.now())["mode"] != "self-signed" {
		t.Fatal("wrong certificate mode")
	}
	pair, _ := a.certs.current(nil)
	if len(pair.Certificate) == 0 {
		t.Fatal("empty chain")
	}
	if e := a.certs.leaf.VerifyHostname(a.host); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(a.dir, "key.pem")
	s, _ := os.Stat(key)
	if s.Mode().Perm() != 0600 {
		t.Fatal(s.Mode())
	}
	put(t, filepath.Join(a.dir, "cert.org"), "installed")
	if e := a.setupTLS(); e != nil || a.certs.status(a.now())["mode"] != "organization" {
		t.Fatal(e)
	}
	put(t, key, "invalid organization key")
	if e := a.setupTLS(); e != nil || a.certs.status(a.now())["mode"] != "fallback" {
		t.Fatal(e)
	}
	if read(key) != "invalid organization key" {
		t.Fatal("organization key overwritten")
	}
}
func TestTLSNetworkAndReports(t *testing.T) {
	a := fixture(t)
	server := httptest.NewTLSServer(a)
	defer server.Close()
	cl := server.Client()
	cl.Timeout = 3 * time.Second
	req, _ := http.NewRequest("HEAD", server.URL+"/static/app.js", nil)
	res, e := cl.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if len(b) != 0 || res.ContentLength <= 0 {
		t.Fatal("HEAD body or length")
	}
	a.daily(context.Background(), a.now())
	name := a.listReports()[0]["name"].(string)
	for _, p := range []string{"/log?file=" + name, "/logs-archive?files=" + name} {
		res, e := cl.Get(server.URL + p)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Disposition"), "attachment") {
			t.Fatal(res.Status)
		}
	}
	var d fields
	w := request(a, "GET", "/api/status", "", false, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(d["auth"]) != "map[restart:insecure]" {
		t.Fatal(d["auth"])
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

func respond(w http.ResponseWriter, status int, d any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(d)
}
func fail(w http.ResponseWriter, status int, code string, extra fields) {
	data := fields{"ok": false, "error": code}
	maps.Copy(data, extra)
	respond(w, status, data)
}
func body(w http.ResponseWriter, r *http.Request) fields {
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if e == nil && len(b) == 0 {
		return fields{}
	}
	var d fields
	if e != nil || json.Unmarshal(b, &d) != nil {
		return nil
	}
	return d
}
func attachment(w http.ResponseWriter, name, mime string) {
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	w.Header().Set("Content-Type", mime)
}
func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	const policy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; " +
		"form-action 'self'; frame-ancestors 'none'"
	w.Header().Set("Content-Security-Policy", policy)
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		fail(w, 503, "busy", nil)
		return
	}
	switch r.Method {
	case "POST":
		a.post(w, r)
	case "GET", "HEAD":
		a.get(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		fail(w, 405, "method_not_allowed", nil)
	}
}
func (a *app) post(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	restart := len(parts) == 4 && parts[0] == "api" && parts[1] == "services" && parts[3] == "restart"
	if !restart && path != "/api/siem" && path != "/api/siem/test" {
		fail(w, 404, "not_found", nil)
		return
	}
	action := "siem_settings"
	if path == "/api/siem/test" {
		action = "siem_test"
	}
	if restart {
		action = "restart"
		if _, ok := a.def(parts[2]); !ok {
			fail(w, 404, "unknown_service", nil)
			return
		}
	}
	d := body(w, r)
	var destination destination
	if !restart && d != nil && sameOrigin(r) {
		if action == "siem_test" {
			d["enabled"] = true
		}
		var code string
		destination, code = destinationFrom(d)
		if code != "" {
			fail(w, 400, code, nil)
			return
		}
	}
	if !a.authorize(w, r, d, action) {
		return
	}
	ip := clientIP(r)
	switch action {
	case "restart":
		s := a.service(r.Context(), parts[2], true)
		status, code, msg := a.startRestart(r.Context(), s, ip)
		if code != "" {
			fail(w, status, code, fields{"message": msg})
			return
		}
		respond(w, 202, fields{"ok": true, "unit": s["unit"], "key": s["key"]})
	case "siem_test":
		if e := a.events.test(r.Context(), destination, ip); e != nil {
			fail(
				w,
				502,
				"send_failed",
				fields{"message": short(e.Error(), 300), "protocol": destination.Protocol},
			)
			return
		}
		respond(w, 200, fields{"ok": true, "target": destination.address(), "protocol": destination.Protocol})
	case "siem_settings":
		if e := a.saveSettings(destination); e != nil {
			fail(w, 500, "save_failed", fields{"message": short(e.Error(), 300)})
			return
		}
		a.events.emit(
			"settings_changed",
			"SIEM forwarding settings saved",
			fields{
				"client":  ip,
				"user":    "root",
				"action":  action,
				"target":  destination.address(),
				"outcome": "success",
			},
		)
		respond(w, 200, a.events.payload())
	}
}
func (a *app) logsIndex(r *http.Request) fields {
	files, journals := []fields{}, []fields{}
	for _, l := range a.logs {
		p := resolved(l.Path)
		meta := fileMeta(p)
		var path any
		if p != "" {
			path = p
		}
		maps.Copy(
			meta,
			fields{
				"key":      l.Key,
				"title_ru": l.TitleRU,
				"title_en": l.TitleEN,
				"path":     l.Path,
				"resolved": path,
				"service":  l.Service,
			},
		)
		files = append(files, meta)
	}
	for _, s := range a.snapshot(r.Context(), false)["services"].([]fields) {
		journals = append(journals, fields{"key": s["key"], "unit": s["unit"]})
	}
	return fields{"files": files, "journals": journals, "reports": a.listReports()}
}
func requestedReports(values []string) []string {
	out := []string{}
	for _, v := range values {
		var items []string
		if json.Unmarshal([]byte(v), &items) != nil {
			var one string
			if json.Unmarshal([]byte(v), &one) == nil {
				items = []string{one}
			} else {
				items = strings.Split(v, ",")
			}
		}
		for _, n := range items {
			if !slices.Contains(out, n) {
				out = append(out, n)
				if len(out) == 100 {
					return out
				}
			}
		}
	}
	return out
}

var safeHost = regexp.MustCompile(`[^A-Za-z0-9.-]`)

func (a *app) get(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if x, ok := a.static[path]; ok {
		sendAsset(w, r, x)
		return
	}
	now := a.now()
	q := r.URL.Query()
	switch path {
	case "/", "/index.html":
		a.index(w, r)
	case "/healthz":
		respond(w, 200, fields{"ok": true, "version": version})
	case "/api/status":
		respond(w, 200, a.status(r.Context(), r.TLS != nil))
	case "/api/siem":
		respond(w, 200, a.events.payload())
	case "/api/siem/events":
		count := lineCount(r, 1)
		events, total := a.events.recent(count, time.Time{}, true)
		lines := []string{}
		for _, e := range events {
			lines = append(lines, e["raw"].(string))
		}
		respond(
			w,
			200,
			fields{
				"ok":        true,
				"kind":      "siem",
				"lines":     lines,
				"requested": count,
				"total":     total,
				"has_more":  total > len(lines),
				"time":      iso(now),
			},
		)
	case "/api/logs":
		respond(w, 200, a.logsIndex(r))
	case "/api/reports":
		respond(w, 200, fields{"reports": a.listReports()})
	case "/api/report-now":
		a.reportMu.Lock()
		defer a.reportMu.Unlock()
		attachment(w, reportPrefix+now.Format("02_01_2006_150405")+".json", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(a.report(r.Context(), "on-demand", now))
	case "/log":
		name := q.Get("file")
		p := a.reportPath(name)
		if p == "" {
			http.NotFound(w, r)
			return
		}
		attachment(w, name, "application/json; charset=utf-8")
		http.ServeFile(w, r, p)
	case "/logs-archive":
		names := requestedReports(q["files"])
		var buf bytes.Buffer
		n, e := a.reportsZip(r.Context(), &buf, names)
		if e != nil {
			fail(w, 500, "archive_error", nil)
			return
		}
		if n == 0 {
			http.NotFound(w, r)
			return
		}
		name := "kaspersky-vm-services-state-archive_" + now.Format(reportLayout) + ".zip"
		attachment(w, name, "application/zip")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(buf.Bytes()))
	case "/logs-day", "/logs-today":
		day := now
		if path == "/logs-day" {
			d, e := time.ParseInLocation(time.DateOnly, q.Get("date"), now.Location())
			if e != nil || d.Format(time.DateOnly) < "1970-01-02" || d.After(now) {
				fail(w, 400, "bad_date", nil)
				return
			}
			day = d
		}
		a.logDownload(w, r, day)
	default:
		if strings.HasPrefix(path, "/api/logs/") {
			parts := strings.Split(strings.TrimPrefix(path, "/api/logs/"), "/")
			live := len(parts) == 3 && parts[0] == "live"
			if live {
				parts = parts[1:]
			}
			if len(parts) == 2 && (parts[0] == "file" || parts[0] == "journal") {
				s, code := a.source(r.Context(), parts[0], parts[1])
				if code != "" {
					fail(w, 404, code, fields{"path": s.path})
					return
				}
				if live {
					a.stream(w, r, s)
				} else {
					a.tail(w, r, s)
				}
				return
			}
		}
		if strings.HasPrefix(path, "/api/") {
			fail(w, 404, "not_found", nil)
		} else {
			http.NotFound(w, r)
		}
	}
}
func (a *app) logDownload(w http.ResponseWriter, r *http.Request, day time.Time) {
	a.archiveMu.Lock()
	defer a.archiveMu.Unlock()
	tmp, e := os.CreateTemp("", "kvm-archive-*")
	if e != nil {
		fail(w, 500, "archive_error", nil)
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if e = a.dayZip(r.Context(), tmp, day); e != nil {
		fail(w, 500, "archive_error", nil)
		return
	}
	name := "kaspersky-vm-logs_" + safeHost.ReplaceAllString(
		a.host,
		"_",
	) + "_" + day.Format(
		reportLayout,
	) + ".zip"
	attachment(w, name, "application/zip")
	if s, e := tmp.Stat(); e == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(s.Size(), 10))
	}
	http.ServeContent(w, r, name, time.Time{}, tmp)
}

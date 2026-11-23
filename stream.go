package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type logSource struct{ kind, key, path, pattern, unit string }

func (a *app) source(ctx context.Context, kind, key string) (logSource, string) {
	s := logSource{kind: kind, key: key}
	if kind == "file" {
		l, ok := a.logDef(key)
		if !ok {
			return s, "unknown_log"
		}
		s.pattern = l.Path
		s.path = resolved(s.pattern)
		if !fileExists(s.path) {
			s.path = l.Path
			return s, "file_not_found"
		}
		return s, ""
	}
	if _, ok := a.def(key); !ok {
		return s, "unknown_service"
	}
	svc := a.service(ctx, key, false)
	s.unit = svc["unit"].(string)
	s.path = "journalctl -u " + s.unit
	return s, ""
}
func (s logSource) command(n int, follow bool) []string {
	count := strconv.Itoa(n)
	if s.kind == "file" {
		args := []string{"tail", "-n", count}
		if follow {
			args = append(args, "-F")
		}
		args = append(args, "--", s.path)
		if os.Geteuid() != 0 {
			f, e := os.Open(s.path)
			if e != nil && os.IsPermission(e) {
				args = append([]string{"sudo", "-n"}, args...)
			} else if e == nil {
				f.Close()
			}
		}
		return args
	}
	args := []string{"journalctl", "-u", s.unit, "-n", count, "--no-pager", "-o", "short-iso", "-q"}
	if follow {
		args = append(args, "-f")
	}
	return args
}
func lineCount(r *http.Request, minCount int) int {
	n, e := strconv.Atoi(r.URL.Query().Get("lines"))
	if e != nil {
		return 50
	}
	return max(minCount, min(1000, n))
}
func cleanLine(s string) string {
	return short(ansi.ReplaceAllString(strings.TrimRight(s, "\r\n"), ""), 8000)
}
func (a *app) tail(w http.ResponseWriter, r *http.Request, s logSource) {
	n := lineCount(r, 1)
	args := s.command(n, false)
	text, err := command(r.Context(), a.run, 15*time.Second, args...)
	if err != nil {
		code, status := "read_error", 500
		msg := strings.ToLower(err.Error())
		switch {
		case s.kind == "journal":
			code = "journal_error"
		case strings.Contains(msg, "no such file"):
			code, status = "file_not_found", 404
		case strings.Contains(msg, "permission") || strings.Contains(msg, "sudo:"):
			code, status = "permission_denied", 403
		case strings.Contains(msg, "deadline") || strings.Contains(msg, "signal: killed"):
			code, status = "timeout", 504
		}
		fail(
			w,
			status,
			code,
			fields{"command": strings.Join(args, " "), "message": short(err.Error(), 300), "path": s.path},
		)
		return
	}
	lines := []string{}
	if text != "" {
		for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			if s.kind == "journal" && strings.HasPrefix(l, "-- ") {
				continue
			}
			lines = append(lines, cleanLine(l))
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	d := fields{
		"ok":        true,
		"kind":      s.kind,
		"key":       s.key,
		"path":      s.path,
		"command":   strings.Join(args, " "),
		"lines":     lines,
		"requested": n,
		"has_more":  len(lines) >= n,
		"time":      iso(a.now()),
	}
	if s.kind == "file" {
		meta := fileMeta(s.path)
		d["size"], d["mtime"] = meta["size"], meta["mtime"]
	}
	respond(w, 200, d)
}

type follower struct {
	cancel context.CancelFunc
	lines  chan string
	done   chan struct{}
	err    error
}

func follow(ctx context.Context, s logSource, n int) (*follower, error) {
	sub, cancel := context.WithCancel(ctx)
	args := s.command(n, true)
	cmd := exec.CommandContext(sub, args[0], args[1:]...)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		cancel()
		return nil, e
	}
	if e = cmd.Start(); e != nil {
		cancel()
		return nil, e
	}
	f := &follower{cancel: cancel, lines: make(chan string, 16), done: make(chan struct{})}
	go func() {
		defer close(f.done)
		defer close(f.lines)
		defer cancel()
		br := bufio.NewReaderSize(pipe, 32768)
		for {
			line, n, _, er := record(br)
			if n > 0 && !(s.kind == "journal" && strings.HasPrefix(line, "-- ")) {
				select {
				case f.lines <- cleanLine(line):
				case <-sub.Done():
					pipe.Close()
				}
			}
			if er != nil || sub.Err() != nil {
				break
			}
		}
		f.err = cmd.Wait()
	}()
	return f, nil
}
func (f *follower) stop() { f.cancel(); <-f.done }
func (a *app) stream(w http.ResponseWriter, r *http.Request, s logSource) {
	select {
	case a.live <- struct{}{}:
		defer func() { <-a.live }()
	default:
		fail(w, 429, "too_many_streams", fields{"limit": cap(a.live)})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	if r.Method == "HEAD" {
		return
	}
	ctrl := http.NewResponseController(w)
	ctx, cancel := context.WithTimeout(r.Context(), time.Hour)
	defer cancel()
	f, e := follow(ctx, s, lineCount(r, 0))
	if e != nil {
		fail(w, 500, "read_error", fields{"message": short(e.Error(), 300)})
		return
	}
	defer func() { f.stop() }()
	write := func(data string) bool {
		ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, e := io.WriteString(w, data)
		return e == nil && ctrl.Flush() == nil
	}
	event := func(name string, data any) bool {
		b, _ := json.Marshal(data)
		return write("event: " + name + "\ndata: " + string(b) + "\n\n")
	}
	if !event("meta", fields{"kind": s.kind, "key": s.key, "path": s.path, "max_seconds": 3600}) ||
		!write("retry: 3000\n\n") {
		return
	}
	flush := time.NewTicker(250 * time.Millisecond)
	heartbeat := time.NewTicker(10 * time.Second)
	rotate := time.NewTicker(5 * time.Second)
	defer flush.Stop()
	defer heartbeat.Stop()
	defer rotate.Stop()
	lines := []string{}
	send := func() bool {
		if len(lines) == 0 {
			return true
		}
		ok := event("lines", lines)
		lines = lines[:0]
		return ok
	}
	for {
		select {
		case <-ctx.Done():
			if r.Context().Err() == nil {
				send()
				event("end", fields{"reason": "time_limit", "rc": nil})
			}
			return
		case l, ok := <-f.lines:
			if !ok {
				send()
				code := 0
				if f.err != nil {
					code = 1
				}
				event("end", fields{"reason": "exited", "rc": code})
				return
			}
			lines = append(lines, l)
			if len(lines) >= 500 && !send() {
				return
			}
		case <-flush.C:
			if !send() {
				return
			}
		case <-heartbeat.C:
			if !write(": ping\n\n") {
				return
			}
		case <-rotate.C:
			if s.pattern != "" {
				p := resolved(s.pattern)
				if p != "" && p != s.path && fileExists(p) {
					if !send() {
						return
					}
					s.path = p
					next, e := follow(ctx, s, 50)
					if e != nil {
						event("end", fields{"reason": "exited", "message": fmt.Sprint(e)})
						return
					}
					f.stop()
					f = next
					if !event("switch", fields{"path": p}) {
						return
					}
				}
			}
		}
	}
}

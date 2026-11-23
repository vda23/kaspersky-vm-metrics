package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type attempt struct {
	times []time.Time
	until time.Time
}
type throttle struct {
	mu        sync.Mutex
	attempts  map[string]attempt
	lastSweep time.Time
}

func (t *throttle) retry(ip string, now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.lastSweep) >= time.Minute {
		for k, x := range t.attempts {
			if !x.until.After(now) &&
				(len(x.times) == 0 || now.Sub(x.times[len(x.times)-1]) >= 10*time.Minute || !x.until.IsZero()) {
				delete(t.attempts, k)
			}
		}
		t.lastSweep = now
	}
	v := t.attempts[ip]
	if v.until.After(now) {
		return int(v.until.Sub(now).Seconds()) + 1
	}
	if !v.until.IsZero() {
		delete(t.attempts, ip)
	}
	return 0
}
func (t *throttle) fail(ip string, now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.attempts[ip]
	filtered := []time.Time{}
	for _, x := range v.times {
		if now.Sub(x) < 10*time.Minute {
			filtered = append(filtered, x)
		}
	}
	v.times = append(filtered, now)
	left := max(0, 5-len(v.times))
	if left == 0 {
		v.until = now.Add(5 * time.Minute)
	}
	t.attempts[ip] = v
	return left
}
func (t *throttle) reset(ip string) { t.mu.Lock(); defer t.mu.Unlock(); delete(t.attempts, ip) }
func (a *app) rootHash() (string, string) {
	for _, p := range a.shadow {
		data, e := os.ReadFile(p)
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			s := strings.SplitN(line, ":", 3)
			if len(s) >= 2 && s[0] == "root" {
				h := s[1]
				if h == "" || strings.ContainsAny(h[:1], "!*") || (!strings.HasPrefix(h, "$") && len(h) != 13) {
					return "", "locked"
				}
				if !a.cryptOK() {
					return "", "unavailable"
				}
				return h, "ok"
			}
		}
	}
	return "", "unavailable"
}
func (a *app) authStatus() string { _, s := a.rootHash(); return s }
func clientIP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return h
	}
	return r.RemoteAddr
}
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "kvm-metrics" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, e := url.Parse(origin)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return e == nil && u.User == nil && u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}
func (a *app) authorize(w http.ResponseWriter, r *http.Request, body fields, action string) bool {
	if !sameOrigin(r) {
		a.events.emit(
			"csrf_rejected",
			"Request from foreign origin rejected",
			fields{"client": clientIP(r), "action": action, "outcome": "failure"},
		)
		fail(w, 403, "csrf", nil)
		return false
	}
	if body == nil {
		fail(w, 400, "bad_request", nil)
		return false
	}
	if r.TLS == nil {
		fail(w, 403, "insecure_transport", nil)
		return false
	}
	ip := clientIP(r)
	if n := a.auth.retry(ip, a.now()); n > 0 {
		fail(w, 429, "locked", fields{"retry_after": n})
		return false
	}
	hash, state := a.rootHash()
	switch state {
	case "unavailable":
		fail(w, 503, "auth_unavailable", nil)
		return false
	case "locked":
		fail(w, 403, "root_locked", nil)
		return false
	}
	password, _ := body["password"].(string)
	delete(body, "password")
	if !a.verify(password, hash) {
		left := a.auth.fail(ip, a.now())
		name := "auth_failed"
		if left == 0 {
			name = "auth_locked"
		}
		a.events.emit(
			name,
			"Root authentication failed",
			fields{"client": ip, "user": "root", "action": action, "outcome": "failure"},
		)
		select {
		case <-r.Context().Done():
			return false
		case <-time.After(a.failDelay):
		}
		if left == 0 {
			fail(w, 429, "locked", fields{"retry_after": a.auth.retry(ip, a.now())})
		} else {
			fail(w, 401, "bad_password", fields{"attempts_left": left})
		}
		return false
	}
	a.auth.reset(ip)
	return true
}

type restartJob struct {
	start    time.Time
	since    int64
	client   string
	accepted bool
}
type restartBook struct {
	mu   sync.Mutex
	jobs map[string]restartJob
	last map[string]fields
}

func (a *app) startRestart(ctx context.Context, s fields, client string) (int, string, string) {
	key, unit := s["key"].(string), s["unit"].(string)
	b := &a.restarts
	b.mu.Lock()
	if _, busy := b.jobs[key]; busy {
		b.mu.Unlock()
		return 409, "in_progress", ""
	}
	job := restartJob{start: a.now(), since: s["since_mono"].(int64), client: client}
	b.jobs[key] = job
	delete(b.last, key)
	b.mu.Unlock()
	_, e := command(ctx, a.run, 15*time.Second, "systemctl", "restart", "--no-block", unit)
	b.mu.Lock()
	if e == nil {
		job.accepted = true
		b.jobs[key] = job
	} else {
		delete(b.jobs, key)
	}
	b.mu.Unlock()
	f := fields{
		"key":     key,
		"unit":    unit,
		"client":  client,
		"user":    "root",
		"action":  "restart",
		"outcome": "success",
	}
	if e != nil {
		f["outcome"] = "failure"
		a.events.emit("restart_failed", "Restart failed: "+unit, f)
		return 500, "systemctl_failed", short(e.Error(), 500)
	}
	a.events.emit("restart_requested", "Restart requested: "+unit, f)
	a.invalidate()
	return 202, "", ""
}
func (a *app) restartStatus(key, unit, state string, since int64, now time.Time) any {
	b := &a.restarts
	b.mu.Lock()
	defer b.mu.Unlock()
	if j, ok := b.jobs[key]; ok {
		elapsed := now.Sub(j.start)
		result := ""
		if j.accepted {
			switch {
			case elapsed >= 180*time.Second:
				result = "timeout"
			case elapsed < 2*time.Second:
			case state == "active" && since != j.since:
				result = "ok"
			case state == "failed" || state == "inactive" || state == "not-found" || state == "masked":
				result = "failed"
			}
		}
		if result == "" {
			return fields{
				"in_progress": true,
				"started":     epoch(j.start),
				"elapsed":     float64(elapsed.Milliseconds()) / 1000,
			}
		}
		delete(b.jobs, key)
		b.last[key] = fields{
			"in_progress": false,
			"started":     epoch(j.start),
			"finished":    epoch(now),
			"result":      result,
		}
		outcome := "success"
		if result != "ok" {
			outcome = "failure"
		}
		a.events.emit(
			"restart_"+result,
			fmt.Sprintf("Restart of %s: %s", unit, result),
			fields{
				"key":     key,
				"unit":    unit,
				"state":   state,
				"client":  j.client,
				"user":    "root",
				"action":  "restart",
				"outcome": outcome,
			},
		)
	}
	if last, ok := b.last[key]; ok {
		return last
	}
	return nil
}

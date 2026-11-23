package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
)

type logCursor struct {
	info   os.FileInfo
	offset int64
	path   string
}
type monitor struct {
	services           map[string]fields
	high               map[string]bool
	cursors            map[string]logCursor
	baselined          bool
	lastScan, lastCert time.Time
}

func newMonitor() *monitor {
	return &monitor{services: map[string]fields{}, high: map[string]bool{}, cursors: map[string]logCursor{}}
}
func (m *monitor) serviceChanges(a *app, services []fields) {
	for _, s := range services {
		key := s["key"].(string)
		state := s["state"].(string)
		switch state {
		case "active", "failed", "inactive", "not-found", "masked":
		default:
			continue
		}
		old := m.services[key]
		m.services[key] = s
		if old == nil {
			continue
		}
		if job, ok := s["restart"].(fields); ok && job["in_progress"] == true {
			continue
		}
		f := fields{"key": key, "unit": s["unit"], "state": state}
		if state != old["state"] {
			name := ""
			switch {
			case state == "active":
				name = "service_up"
			case state == "failed":
				name = "service_failed"
			case old["state"] == "active":
				name = "service_down"
			}
			if name != "" {
				a.events.emit(name, fmt.Sprintf("Service %s: %s → %s", s["unit"], old["state"], state), f)
			}
		}
		n, ok := s["restarts"].(int64)
		prev, had := old["restarts"].(int64)
		if state == "active" && ok && had && n > prev {
			f["count"] = n - prev
			a.events.emit("service_auto_restart", "Service restarted by systemd: "+key, f)
		}
	}
}
func (m *monitor) threshold(a *app, key, kind string, pct float64, f fields) {
	high := m.high[key]
	name := ""
	if !high && pct >= 90 {
		m.high[key] = true
		name = kind + "_high"
	} else if high && pct < 85 {
		m.high[key] = false
		name = kind + "_ok"
	}
	if name != "" {
		f["percent"] = pct
		a.events.emit(name, fmt.Sprintf("%s usage %.1f%%", key, pct), f)
	}
}
func (m *monitor) scanLogs(ctx context.Context, a *app) {
	for _, l := range a.logs {
		p := resolved(l.Path)
		f, e := os.Open(p)
		if e != nil {
			continue
		}
		s, e := f.Stat()
		if e != nil {
			f.Close()
			continue
		}
		prev, ok := m.cursors[l.Key]
		start := int64(0)
		if !m.baselined {
			start = s.Size()
		} else if ok && p == prev.path && os.SameFile(s, prev.info) && prev.offset <= s.Size() {
			start = prev.offset
		}
		scan, e := scanLevels(ctx, f, start, s.Size(), 4<<20, 1)
		f.Close()
		if e != nil {
			continue
		}
		m.cursors[l.Key] = logCursor{s, scan.next, p}
		if scan.Errors > 0 {
			a.events.emit(
				"log_errors",
				fmt.Sprintf(
					"%s: %d new error record(s). Last: %s",
					l.TitleEN,
					scan.Errors,
					scan.Last[0]["message"],
				),
				fields{"key": l.Key, "file": p, "count": scan.Errors},
			)
		}
	}
	m.baselined = true
}
func (m *monitor) tick(ctx context.Context, a *app, tlsOn bool) {
	d := a.snapshot(ctx, false)
	if ctx.Err() != nil {
		return
	}
	m.serviceChanges(a, d["services"].([]fields))
	mem := d["system"].(fields)["memory"].(map[string]int64)
	if mem["total"] > 0 {
		m.threshold(a, "memory", "memory", percent(mem["total"]-mem["available"], mem["total"]), fields{})
	}
	for _, v := range diskUsage(a.disks) {
		m.threshold(a, v["path"].(string), "disk", v["percent"].(float64), fields{"path": v["path"]})
	}
	now := a.now()
	if m.lastScan.IsZero() || now.Sub(m.lastScan) >= time.Minute {
		m.scanLogs(ctx, a)
		m.lastScan = now
	}
	if e := a.daily(ctx, now); e != nil && ctx.Err() == nil {
		log.Print(e)
	}
	if tlsOn && now.Sub(m.lastCert) >= 24*time.Hour {
		if !m.lastCert.IsZero() {
			if e := a.setupTLS(); e != nil {
				log.Printf("TLS renewal: %v", e)
			}
		}
		m.lastCert = now
	}
}
func (a *app) monitor(ctx context.Context, tlsOn bool) {
	m := newMonitor()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		m.tick(ctx, a, tlsOn)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

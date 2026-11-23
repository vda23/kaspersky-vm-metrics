package main

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const reportPrefix = "kaspersky-vm-services-state_"
const reportLayout = "02_01_2006"

var reportRE = regexp.MustCompile(`^kaspersky-vm-services-state_\d{2}_\d{2}_\d{4}\.json$`)

func reportDay(name string) time.Time {
	if !reportRE.MatchString(name) {
		return time.Time{}
	}
	t, _ := time.Parse(reportLayout, strings.TrimSuffix(strings.TrimPrefix(name, reportPrefix), ".json"))
	return t
}
func (a *app) reportPath(name string) string {
	if reportDay(name).IsZero() {
		return ""
	}
	p := filepath.Join(a.dir, name)
	if s, e := os.Lstat(p); e == nil && s.Mode().IsRegular() {
		return p
	}
	return ""
}
func (a *app) listReports() []fields {
	out := []fields{}
	entries, _ := os.ReadDir(a.dir)
	for _, entry := range entries {
		name := entry.Name()
		if reportDay(name).IsZero() || !entry.Type().IsRegular() {
			continue
		}
		if s, e := entry.Info(); e == nil {
			out = append(out, fields{"name": name, "size": s.Size(), "mtime": s.ModTime().Unix()})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return reportDay(out[i]["name"].(string)).After(reportDay(out[j]["name"].(string)))
	})
	return out
}
func (a *app) reportsZip(ctx context.Context, w io.Writer, names []string) (int, error) {
	z := zip.NewWriter(w)
	n := 0
	for _, name := range names {
		path := a.reportPath(name)
		if path == "" {
			continue
		}
		f, e := os.Open(path)
		if e != nil {
			continue
		}
		dst, e := z.Create(name)
		if e == nil {
			_, e = copyWithContext(ctx, dst, f)
		}
		f.Close()
		if e != nil {
			return 0, e
		}
		n++
	}
	return n, z.Close()
}
func diskUsage(paths []string) []fields {
	result := []fields{}
	seen := map[uint64]bool{}
	for _, p := range paths {
		var s syscall.Statfs_t
		var st syscall.Stat_t
		if syscall.Stat(p, &st) != nil || seen[uint64(st.Dev)] || syscall.Statfs(p, &s) != nil {
			continue
		}
		seen[uint64(st.Dev)] = true
		unit := int64(s.Bsize)
		total := int64(s.Blocks) * unit
		used := total - int64(s.Bfree)*unit
		free := int64(s.Bavail) * unit
		result = append(
			result,
			fields{
				"path":        p,
				"total_bytes": total,
				"used_bytes":  used,
				"free_bytes":  free,
				"percent":     percent(used, used+free),
			},
		)
	}
	return result
}
func (a *app) report(ctx context.Context, kind string, now time.Time) fields {
	d := a.snapshot(ctx, true)
	sys := maps.Clone(d["system"].(fields))
	issues := []fields{}
	status := "ok"
	problem := func(severity, code, message string, more fields) {
		v := fields{"severity": severity, "code": code, "message": message}
		maps.Copy(v, more)
		issues = append(issues, v)
		if severity == "critical" || status == "ok" {
			status = severity
		}
	}
	services := []fields{}
	down := []string{}
	for _, s := range d["services"].([]fields) {
		v := fields{"description": s["desc_ru"], "active_since": nil}
		for _, key := range []string{"key", "unit", "state", "sub_state", "result", "pid", "memory_bytes", "memory_source", "tasks", "restarts", "uptime_sec", "db_connections"} {
			if value, ok := s[key]; ok {
				v[key] = value
			}
		}
		if n, ok := s["uptime_sec"].(int64); ok {
			v["active_since"] = iso(now.Add(-time.Duration(n) * time.Second))
		}
		if r, ok := s["restart"].(fields); ok && r["in_progress"] == false {
			when := func(k string) string { return iso(time.UnixMilli(int64(r[k].(float64) * 1000))) }
			v["last_restart_from_dashboard"] = fields{
				"result":   r["result"],
				"started":  when("started"),
				"finished": when("finished"),
			}
		}
		services = append(services, v)
		if v["state"] != "active" {
			down = append(down, v["key"].(string))
			problem(
				"critical",
				"service_not_running",
				fmt.Sprintf("Служба %s в состоянии %s", v["unit"], v["state"]),
				fields{"key": v["key"]},
			)
		}
	}
	sys["kernel"] = strings.TrimSpace(read(filepath.Join(a.proc, "sys/kernel/osrelease")))
	averages := []float64{}
	for _, v := range strings.Fields(read(filepath.Join(a.proc, "loadavg"))) {
		if len(averages) == 3 {
			break
		}
		if x, e := strconv.ParseFloat(v, 64); e == nil {
			averages = append(averages, x)
		}
	}
	sys["load_average"] = averages
	mem := sys["memory"].(map[string]int64)
	if mem["total"] > 0 {
		m := fields{}
		for k, v := range mem {
			m[k] = v
		}
		pct := percent(mem["total"]-mem["available"], mem["total"])
		m["used_percent"] = pct
		sys["memory"] = m
		if pct >= 90 {
			problem("warning", "memory_high", fmt.Sprintf("Занято %.1f%% оперативной памяти", pct), nil)
		}
	}
	disks := diskUsage(a.disks)
	sys["disks"] = disks
	for _, disk := range disks {
		if disk["percent"].(float64) >= 90 {
			problem(
				"warning",
				"disk_high",
				fmt.Sprintf("Файловая система %s заполнена на %.1f%%", disk["path"], disk["percent"]),
				fields{"path": disk["path"]},
			)
		}
	}
	logs := []fields{}
	errors, warnings := 0, 0
	for _, l := range a.logs {
		entry := a.logSummary(ctx, l, now)
		logs = append(logs, entry)
		if t, ok := entry["today"].(scanResult); ok {
			errors += t.Errors
			warnings += t.Warnings
			if t.Errors > 0 {
				problem(
					"warning",
					"log_errors",
					fmt.Sprintf("%s: ошибок за сегодня — %d", l.TitleRU, t.Errors),
					fields{"key": l.Key},
				)
			}
		}
	}
	tlsInfo := a.certs.status(now)
	cert := tlsInfo["certificate"]
	if c, ok := cert.(fields); ok {
		c["mode"] = tlsInfo["mode"]
		if c["days_left"].(int) < 30 {
			problem(
				"warning",
				"certificate_expiring",
				fmt.Sprintf("Сертификат истекает через %d дн.", c["days_left"]),
				nil,
			)
		}
	}
	if tlsInfo["mode"] == "fallback" {
		problem("warning", "certificate_fallback", "Используется запасной самоподписанный сертификат", nil)
	}
	events, _ := a.events.recent(200, now.Add(-24*time.Hour), false)
	return fields{
		"report":          "kaspersky-vm-services-state",
		"schema":          1,
		"kind":            kind,
		"generated":       iso(now),
		"host":            a.host,
		"monitor_version": version,
		"summary": fields{
			"status":                status,
			"services_total":        len(services),
			"services_running":      len(services) - len(down),
			"services_not_running":  down,
			"services_memory_bytes": d["summary"].(fields)["services_memory_bytes"],
			"log_errors_today":      errors,
			"log_warnings_today":    warnings,
			"events_24h":            len(events),
			"problems":              issues,
		},
		"system":      sys,
		"services":    services,
		"logs":        logs,
		"ports":       d["ports"],
		"events_24h":  events,
		"siem":        a.events.status(),
		"certificate": cert,
	}
}
func (a *app) daily(ctx context.Context, now time.Time) error {
	if now.Hour() < 19 {
		return nil
	}
	a.reportMu.Lock()
	defer a.reportMu.Unlock()
	name := reportPrefix + now.Format(reportLayout) + ".json"
	p := filepath.Join(a.dir, name)
	if fileExists(p) {
		return nil
	}
	r := a.report(ctx, "daily", now)
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := writeJSONFile(p, r, 0644); e != nil {
		return e
	}
	for _, v := range a.listReports() {
		if time.Unix(v["mtime"].(int64), 0).Before(now.AddDate(0, 0, -7)) {
			old := v["name"].(string)
			if old != name {
				os.Remove(filepath.Join(a.dir, old))
			}
		}
	}
	a.events.emit(
		"report_created",
		"Daily state report: "+name,
		fields{"file": p, "outcome": r["summary"].(fields)["status"]},
	)
	return nil
}

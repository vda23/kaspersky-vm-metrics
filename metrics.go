package main

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

func num(s string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
func number(s string) int64 { n, _ := num(s); return n }
func optionalNum(s string) any {
	if n, ok := num(s); ok {
		return n
	}
	return nil
}
func percent(v, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return math.Round(1000*float64(v)/float64(total)) / 10
}
func memory(text string) map[string]int64 {
	raw := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		p := strings.Fields(line)
		if len(p) >= 2 {
			value, ok := num(p[1])
			if !ok {
				continue
			}
			if len(p) > 2 && strings.EqualFold(p[2], "kB") {
				value *= 1024
			}
			raw[strings.TrimSuffix(p[0], ":")] = value
		}
	}
	total := raw["MemTotal"]
	free := min(raw["MemFree"], total)
	used := total - free
	cache := min(used, raw["Cached"]+raw["Buffers"]+raw["SReclaimable"])
	available, ok := raw["MemAvailable"]
	if !ok {
		available = free + cache
	}
	return map[string]int64{
		"total":     total,
		"free":      free,
		"used":      used,
		"cache":     cache,
		"processes": used - cache,
		"available": min(available, total),
	}
}

type cpuTimes struct{ busy, total int64 }

func parseCPU(s string) cpuTimes {
	p := strings.Fields(strings.SplitN(s, "\n", 2)[0])
	if len(p) < 5 || p[0] != "cpu" {
		return cpuTimes{}
	}
	var total, idle int64
	for i, v := range p[1:min(len(p), 9)] {
		n, ok := num(v)
		if !ok {
			return cpuTimes{}
		}
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return cpuTimes{total - idle, total}
}
func (a *app) system(ctx context.Context) fields {
	sample := func() cpuTimes { return parseCPU(read(filepath.Join(a.proc, "stat"))) }
	cur := sample()
	prev := a.cpu
	if prev.total == 0 && cur.total > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
		prev = cur
		cur = sample()
	}
	a.cpu = cur
	var cpu any
	if prev.total > 0 && cur.total > prev.total {
		cpu = max(0., min(100., percent(cur.busy-prev.busy, cur.total-prev.total)))
	}
	osr := read("/etc/os-release")
	if osr == "" {
		osr = read("/usr/lib/os-release")
	}
	name := "Linux"
	for _, l := range strings.Split(osr, "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			name = strings.Trim(v, "\"'")
			break
		}
	}
	var uptime any
	if p := strings.Fields(read(filepath.Join(a.proc, "uptime"))); len(p) > 0 {
		if f, e := strconv.ParseFloat(p[0], 64); e == nil {
			uptime = int64(f)
		}
	}
	return fields{
		"os_name":     name,
		"cpu_threads": runtime.NumCPU(),
		"cpu_percent": cpu,
		"memory":      memory(read(filepath.Join(a.proc, "meminfo"))),
		"uptime_sec":  uptime,
	}
}

type props map[string]string

const showProps = "Id,LoadState,ActiveState,SubState,MemoryCurrent,TasksCurrent,MainPID,ActiveEnterTimestampMonotonic,NRestarts,ControlGroup,Result"

func (a *app) show(ctx context.Context, units []string) map[string]props {
	result := map[string]props{}
	if len(units) == 0 {
		return result
	}
	args := append([]string{"systemctl", "show"}, units...)
	s, _ := command(ctx, a.run, 5*time.Second, append(args, "--property="+showProps)...)
	for i, b := range strings.Split(strings.TrimSpace(s), "\n\n") {
		if i >= len(units) {
			break
		}
		p := props{}
		for _, l := range strings.Split(b, "\n") {
			k, v, ok := strings.Cut(l, "=")
			if ok {
				p[k] = v
			}
		}
		result[units[i]] = p
	}
	return result
}
func unitState(p props) string {
	if p["ActiveState"] != "active" && (p["LoadState"] == "not-found" || p["LoadState"] == "masked") {
		return p["LoadState"]
	}
	if p["ActiveState"] != "" {
		return p["ActiveState"]
	}
	return "unknown"
}
func (a *app) detect(ctx context.Context, d serviceDef) string {
	var units []string
	for _, options := range [][]string{
		{"systemctl", "list-units", "--all", "--type=service", "--plain", "--no-legend", "--no-pager"},
		{"systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"},
	} {
		args := append(options, d.Detect...)
		out, _ := command(ctx, a.run, 5*time.Second, args...)
		for _, l := range strings.Split(out, "\n") {
			p := strings.Fields(strings.TrimLeft(l, " ●"))
			if len(p) == 0 || strings.HasSuffix(p[0], "@.service") {
				continue
			}
			for _, pattern := range d.Detect {
				if ok, _ := filepath.Match(pattern, p[0]); ok && !slices.Contains(units, p[0]) {
					units = append(units, p[0])
				}
			}
		}
	}
	candidate := d.Unit
	best := -1
	ps := a.show(ctx, units)
	for _, u := range units {
		p := ps[u]
		if len(p) == 0 || p["LoadState"] == "not-found" {
			continue
		}
		rank := 0
		if p["LoadState"] == "loaded" {
			rank += 2
		}
		if p["SubState"] == "running" && number(p["MainPID"]) > 0 {
			rank += 4
		}
		if p["ActiveState"] == "active" {
			rank += 8
		}
		if u == d.Unit {
			rank++
		}
		if rank > best {
			candidate, best = u, rank
		}
	}
	return candidate
}
func (a *app) rss(group string) (int64, bool) {
	if group == "" {
		return 0, false
	}
	for _, root := range a.groups {
		p, e := os.ReadFile(filepath.Join(root, filepath.Clean("/"+group), "cgroup.procs"))
		if e != nil {
			continue
		}
		var total int64
		for _, id := range strings.Fields(string(p)) {
			if _, ok := num(id); !ok {
				continue
			}
			s := read(filepath.Join(a.proc, id, "status"))
			for _, l := range strings.Split(s, "\n") {
				v := strings.Fields(l)
				if len(v) >= 2 && v[0] == "VmRSS:" {
					total += number(v[1]) * 1024
					break
				}
			}
		}
		return total, true
	}
	return 0, false
}

var ssUser = regexp.MustCompile(`\("([^"]*)",pid=(\d+)`)

func port(s string) int {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return -1
	}
	n, e := strconv.Atoi(s[i+1:])
	if e != nil {
		return -1
	}
	return n
}
func parsePorts(text string, pids map[int64]string) []fields {
	out := []fields{}
	for _, line := range strings.Split(text, "\n") {
		p := strings.Fields(line)
		if len(p) < 6 || p[0] == "Netid" {
			continue
		}
		raw := strings.Join(p[6:], " ")
		ids := []int64{}
		names := []string{}
		var svc any
		for _, m := range ssUser.FindAllStringSubmatch(raw, -1) {
			id := number(m[2])
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
			if !slices.Contains(names, m[1]) {
				names = append(names, m[1])
			}
		}
		slices.Sort(names)
		slices.Sort(ids)
		for _, id := range ids {
			if key, ok := pids[id]; ok {
				svc = key
				break
			}
		}
		if len(names) > 0 {
			raw = strings.Join(names, ", ")
		}
		var n any
		if v := port(p[4]); v >= 0 {
			n = v
		}
		out = append(
			out,
			fields{
				"netid":   p[0],
				"state":   p[1],
				"local":   p[4],
				"port":    n,
				"process": raw,
				"pids":    ids,
				"service": svc,
			},
		)
	}
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i], out[j]
		tcp := func(p fields) bool { return strings.HasPrefix(p["netid"].(string), "tcp") }
		if tcp(x) != tcp(y) {
			return tcp(x)
		}
		rank := func(p fields) int {
			switch p["state"] {
			case "LISTEN":
				return 0
			case "UNCONN":
				return 1
			}
			return 2
		}
		if rank(x) != rank(y) {
			return rank(x) < rank(y)
		}
		a, b := port(x["local"].(string)), port(y["local"].(string))
		if a < 0 {
			a = 65536
		}
		if b < 0 {
			b = 65536
		}
		if a != b {
			return a < b
		}
		return x["local"].(string) < y["local"].(string)
	})
	return out
}
func connections(text string, dbPort int) int {
	n := 0
	for _, l := range strings.Split(text, "\n") {
		p := strings.Fields(l)
		if len(p) >= 5 && strings.HasPrefix(p[0], "ESTAB") && port(p[3]) == dbPort {
			n++
		}
	}
	return n
}
func (a *app) snapshot(ctx context.Context, force bool) fields {
	a.collectMu.Lock()
	defer a.collectMu.Unlock()
	now := a.now()
	if !force && a.cached != nil && now.Sub(a.cachedAt) < time.Second {
		return a.cached
	}
	units := make([]string, len(a.defs))
	for i, d := range a.defs {
		units[i] = d.Unit
		if len(d.Detect) > 0 {
			if a.databaseUnit == "" || now.Sub(a.detectedAt) >= 5*time.Minute {
				candidate := a.detect(ctx, d)
				if ctx.Err() == nil {
					a.databaseUnit = candidate
					a.detectedAt = now
				}
			}
			if a.databaseUnit != "" {
				units[i] = a.databaseUnit
			}
		}
	}
	ps := a.show(ctx, units)
	sys := a.system(ctx)
	uptime, _ := sys["uptime_sec"].(int64)
	db, _ := command(ctx, a.run, 5*time.Second, "ss", "-tan")
	pids := map[int64]string{}
	services := []fields{}
	running := 0
	var memoryTotal int64
	for i, d := range a.defs {
		u := units[i]
		p := ps[u]
		state := unitState(p)
		pid := number(p["MainPID"])
		since := number(p["ActiveEnterTimestampMonotonic"])
		mem, ok := num(p["MemoryCurrent"])
		var source, age any
		if ok {
			source = "cgroup"
		} else if state == "active" {
			if m, found := a.rss(p["ControlGroup"]); found {
				source = "rss"
				mem = m
			}
		}
		if pid > 0 {
			pids[pid] = d.Key
		}
		if state == "active" {
			running++
			if since > 0 {
				age = max(int64(0), uptime-since/1000000)
			}
		}
		memoryTotal += mem
		s := fields{
			"key":           d.Key,
			"unit":          u,
			"desc_ru":       d.DescRU,
			"desc_en":       d.DescEN,
			"warn_ru":       d.WarnRU,
			"warn_en":       d.WarnEN,
			"state":         state,
			"sub_state":     p["SubState"],
			"result":        p["Result"],
			"pid":           pid,
			"memory_bytes":  mem,
			"memory_source": source,
			"tasks":         optionalNum(p["TasksCurrent"]),
			"restarts":      optionalNum(p["NRestarts"]),
			"uptime_sec":    age,
			"since_mono":    since,
			"restart":       a.restartStatus(d.Key, u, state, since, now),
		}
		if d.DBPort > 0 {
			s["db_connections"] = connections(db, d.DBPort)
		}
		services = append(services, s)
	}
	listeners, _ := command(ctx, a.run, 5*time.Second, "ss", "-tulnp")
	data := fields{
		"version":  version,
		"host":     a.host,
		"time":     iso(now),
		"system":   sys,
		"services": services,
		"ports":    parsePorts(listeners, pids),
		"summary": fields{
			"running":               running,
			"total":                 len(services),
			"all_up":                running == len(services),
			"services_memory_bytes": memoryTotal,
		},
	}
	if ctx.Err() == nil {
		a.cached = data
		a.cachedAt = a.now()
	}
	return data
}
func (a *app) service(ctx context.Context, key string, force bool) fields {
	for _, s := range a.snapshot(ctx, force)["services"].([]fields) {
		if s["key"] == key {
			return s
		}
	}
	return nil
}

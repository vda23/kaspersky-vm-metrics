package main

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
var jsonDate = regexp.MustCompile(`"(?:timestamp|@timestamp|time|ts|date)"\s*:\s*"(\d{4}-\d{2}-\d{2})`)
var textDate = regexp.MustCompile(`^\[?(\d{4}[-/]\d{2}[-/]\d{2}|\d{2}\.\d{2}\.\d{4})[ T,]`)
var jsonLevel = regexp.MustCompile(`"(?i:level|lvl|severity)"\s*:\s*"([A-Za-z]+)"`)

var textLevel = regexp.MustCompile(
	`\b(ERROR|ERR|FATAL|CRITICAL|CRIT|PANIC|EMERG|ALERT|SEVERE|WARNING|WARN)\b|\blevel=([A-Za-z]+)`,
)

func logDate(s string) string {
	var m []string
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		m = jsonDate.FindStringSubmatch(s[:min(len(s), 4096)])
	} else {
		m = textDate.FindStringSubmatch(s)
	}
	if len(m) < 2 {
		return ""
	}
	day := strings.ReplaceAll(m[1], "/", "-")
	if day[2] == '.' {
		day = day[6:] + "-" + day[3:5] + "-" + day[:2]
	}
	if _, e := time.Parse(time.DateOnly, day); e != nil {
		return ""
	}
	return day
}
func level(s string) string {
	var m []string
	if strings.HasPrefix(strings.TrimSpace(s), "{") {
		m = jsonLevel.FindStringSubmatch(s[:min(len(s), 4096)])
	} else {
		m = textLevel.FindStringSubmatch(s[:min(len(s), 400)])
	}
	if len(m) < 2 {
		return ""
	}
	v := m[1]
	if v == "" && len(m) > 2 {
		v = m[2]
	}
	switch strings.ToLower(v) {
	case "error", "err", "fatal", "critical", "crit", "panic", "emerg", "alert", "severe":
		return "error"
	case "warning", "warn":
		return "warn"
	}
	return ""
}
func describeLine(s string) fields {
	out := fields{"time": "", "source": "", "message": short(strings.TrimSpace(s), 500)}
	var obj fields
	if json.Unmarshal([]byte(s), &obj) != nil {
		return out
	}
	first := func(keys ...string) string {
		for _, k := range keys {
			if v := obj[k]; v != nil && fmt.Sprint(v) != "" {
				return fmt.Sprint(v)
			}
		}
		return ""
	}
	msg := first("message", "msg")
	if err := first("error", "err"); err != "" && !strings.Contains(msg, err) {
		if msg != "" {
			msg += ": "
		}
		msg += err
	}
	if msg != "" {
		out["message"] = short(msg, 500)
	}
	out["source"] = short(first("logger", "component"), 120)
	out["time"] = first("timestamp", "time", "ts")
	return out
}
func resolved(pattern string) string {
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern
	}
	paths, _ := filepath.Glob(pattern)
	latest := ""
	var t time.Time
	for _, p := range paths {
		if s, e := os.Stat(p); e == nil && s.Mode().IsRegular() && !s.ModTime().Before(t) {
			latest, t = p, s.ModTime()
		}
	}
	return latest
}
func fileMeta(p string) fields {
	s, e := os.Stat(p)
	if e != nil || !s.Mode().IsRegular() {
		return fields{"exists": false, "size": nil, "mtime": nil, "readable": false}
	}
	return fields{"exists": true, "size": s.Size(), "mtime": s.ModTime().Unix(), "readable": true}
}
func candidates(pattern string) []string {
	result := []string{}
	for _, pat := range []string{pattern, pattern + ".*", pattern + "-*"} {
		paths, _ := filepath.Glob(pat)
		for _, p := range paths {
			if fileExists(p) && !slices.Contains(result, p) {
				result = append(result, p)
			}
		}
	}
	slices.Sort(result)
	return result
}

// Return the first fragment and the length of a complete record, without retaining very long lines.
func record(r *bufio.Reader) (string, int64, bool, error) {
	var first string
	var size int64
	for {
		part, e := r.ReadSlice('\n')
		if size == 0 {
			first = string(part)
		}
		size += int64(len(part))
		if e == bufio.ErrBufferFull {
			continue
		}
		return first, size, e == nil, e
	}
}
func nextDated(ctx context.Context, f *os.File, offset, end int64) (int64, string, error) {
	if offset >= end {
		return end, "", nil
	}
	start := offset
	if start > 0 {
		start--
	}
	r := bufio.NewReaderSize(io.NewSectionReader(f, start, end-start), 8192)
	if offset > 0 {
		_, n, _, _ := record(r)
		start += n
	}
	for start < end {
		if e := ctx.Err(); e != nil {
			return 0, "", e
		}
		s, n, _, e := record(r)
		if day := logDate(s); day != "" {
			return start, day, nil
		}
		start += n
		if e != nil {
			if errors.Is(e, io.EOF) {
				break
			}
			return 0, "", e
		}
	}
	return end, "", nil
}

// Search chronologically ordered uncompressed logs by byte offset. Continuation lines stay with their record.
func dayOffset(ctx context.Context, f *os.File, size int64, target string) (int64, bool, error) {
	_, first, e := nextDated(ctx, f, 0, min(size, 1<<20))
	if e != nil || first == "" {
		return 0, false, e
	}
	if first >= target {
		return 0, true, nil
	}
	lo, hi := int64(0), size
	for hi-lo > 32768 {
		mid := (lo + hi) / 2
		pos, day, e := nextDated(ctx, f, mid, size)
		if e != nil {
			return 0, false, e
		}
		if day == "" || day >= target {
			hi = mid
		} else {
			lo = pos
		}
	}
	for lo < size {
		pos, day, e := nextDated(ctx, f, lo, size)
		if e != nil {
			return 0, false, e
		}
		if day == "" || day >= target {
			return pos, true, nil
		}
		lo = pos + 1
	}
	return size, true, nil
}

type scanResult struct {
	Errors    int      `json:"errors"`
	Warnings  int      `json:"warnings"`
	Lines     int      `json:"lines"`
	Scanned   int64    `json:"scanned_bytes"`
	Truncated bool     `json:"truncated"`
	Last      []fields `json:"last_errors"`
	Format    string   `json:"date_format,omitempty"`
	next      int64
}

func scanLevels(ctx context.Context, f *os.File, start, end, limit int64, keep int) (scanResult, error) {
	s := scanResult{Last: []fields{}, next: start}
	if end-start > limit {
		start = end - limit
		s.Truncated = true
	}
	begin := start
	r := bufio.NewReaderSize(io.NewSectionReader(f, start, max(0, end-start)), 8192)
	if s.Truncated {
		var preceding [1]byte
		if _, err := f.ReadAt(preceding[:], start-1); err != nil {
			return s, err
		}
		if preceding[0] != '\n' {
			_, n, _, _ := record(r)
			start += n
		}
	}
	s.next = start
	for s.next < end {
		if e := ctx.Err(); e != nil {
			return s, e
		}
		text, n, complete, e := record(r)
		if complete {
			s.next += n
			s.Lines++
			switch level(text) {
			case "error":
				s.Errors++
				if keep > 0 {
					s.Last = append(s.Last, describeLine(text))
					if len(s.Last) > keep {
						s.Last = s.Last[1:]
					}
				}
			case "warn":
				s.Warnings++
			}
		}
		if e != nil {
			if errors.Is(e, io.EOF) {
				break
			}
			return s, e
		}
	}
	s.Scanned = s.next - begin
	return s, nil
}
func (a *app) logSummary(ctx context.Context, l logDef, day time.Time) fields {
	p := resolved(l.Path)
	result := fields{
		"key":        l.Key,
		"title":      l.TitleRU,
		"path":       l.Path,
		"file":       p,
		"exists":     false,
		"size_bytes": nil,
		"modified":   nil,
		"today":      nil,
	}
	f, e := os.Open(p)
	if e != nil {
		return result
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil {
		return result
	}
	result["exists"], result["size_bytes"], result["modified"] = true, s.Size(), iso(s.ModTime())
	if s.ModTime().In(day.Location()).Format(time.DateOnly) < day.Format(time.DateOnly) {
		result["today"] = scanResult{Last: []fields{}, Format: "n/a"}
		return result
	}
	start, dated, e := dayOffset(ctx, f, s.Size(), day.Format(time.DateOnly))
	if e != nil {
		return result
	}
	r, e := scanLevels(ctx, f, start, s.Size(), 32<<20, 5)
	if e != nil {
		result["error"] = e.Error()
		return result
	}
	r.Format = "unknown (whole file)"
	if dated {
		r.Format = "detected"
	}
	result["today"] = r
	return result
}
func gzipDay(ctx context.Context, r io.Reader, day string, w io.Writer) (int64, error) {
	gz, e := gzip.NewReader(r)
	if e != nil {
		return 0, e
	}
	defer gz.Close()
	br := bufio.NewReaderSize(gz, 65536)
	var size int64
	keep, first := false, true
	for {
		if e = ctx.Err(); e != nil {
			return size, e
		}
		p, err := br.ReadSlice('\n')
		if first {
			if date := logDate(string(p)); date != "" {
				keep = date == day
			}
		}
		if keep && len(p) > 0 {
			n, e := w.Write(p)
			size += int64(n)
			if e != nil {
				return size, e
			}
		}
		first = err != bufio.ErrBufferFull
		if err == nil || err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			return size, nil
		}
		return size, err
	}
}
func logMember(ctx context.Context, z *zip.Writer, path, key string, day time.Time) (int64, string, error) {
	f, e := os.Open(path)
	if e != nil {
		return 0, "", e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil {
		return 0, "", e
	}
	ds := day.Format(time.DateOnly)
	mtime := s.ModTime().In(day.Location()).Format(time.DateOnly)
	if mtime < ds {
		return 0, "", nil
	}
	name := key + "/" + filepath.Base(path)
	if strings.HasSuffix(name, ".gz") {
		tmp, e := os.CreateTemp("", "kvm-log-*")
		if e != nil {
			return 0, "", e
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		n, e := gzipDay(ctx, f, ds, tmp)
		if e != nil || n == 0 {
			return n, "", e
		}
		out, e := z.Create(strings.TrimSuffix(name, ".gz"))
		if e != nil {
			return 0, "", e
		}
		n, e = copyWithContext(ctx, out, io.NewSectionReader(tmp, 0, n))
		return n, "day", e
	}
	start, dated, e := dayOffset(ctx, f, s.Size(), ds)
	if e != nil {
		return 0, "", e
	}
	end := s.Size()
	mode := "day"
	if !dated {
		if mtime != ds {
			return 0, "", nil
		}
		mode = "whole-file"
	} else if mtime > ds {
		end, _, e = dayOffset(ctx, f, s.Size(), day.AddDate(0, 0, 1).Format(time.DateOnly))
		if e != nil {
			return 0, "", e
		}
	}
	if start >= end {
		return 0, "", nil
	}
	out, e := z.Create(name)
	if e != nil {
		return 0, "", e
	}
	n, e := copyWithContext(ctx, out, io.NewSectionReader(f, start, end-start))
	return n, mode, e
}
func (a *app) dayZip(ctx context.Context, dst io.Writer, day time.Time) error {
	z := zip.NewWriter(dst)
	var manifest strings.Builder
	fmt.Fprintf(
		&manifest,
		"Kaspersky VM Metrics %s\nHost: %s\nLogs for: %s\n\n",
		version,
		a.host,
		day.Format("02.01.2006"),
	)
	count := 0
	for _, l := range a.logs {
		for _, p := range candidates(l.Path) {
			n, mode, e := logMember(ctx, z, p, l.Key, day)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if e != nil {
				fmt.Fprintf(&manifest, "%s %s: %v\n", l.Key, p, e)
				continue
			}
			if n > 0 {
				count++
				fmt.Fprintf(&manifest, "%s %s %d bytes (%s)\n", l.Key, p, n, mode)
			}
		}
	}
	if count == 0 {
		manifest.WriteString("No component log entries for this day.\n")
	}
	m, e := z.Create("README.txt")
	if e != nil {
		return e
	}
	if _, e = io.WriteString(m, manifest.String()); e != nil {
		return e
	}
	return z.Close()
}

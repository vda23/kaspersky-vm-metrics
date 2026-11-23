package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type eventType struct {
	Name      string `json:"name"`
	Signature int    `json:"signature"`
	Severity  int    `json:"severity"`
	Category  string `json:"category"`
	Title     string `json:"title"`
}

var eventTypes = definitions[[]eventType]("events")
var cefFields = definitions[[][3]string]("cef")

type event struct {
	eventType
	id       int64
	stamp    time.Time
	message  string
	attrs    fields
	delivery string
	sent     time.Time
}
type destination struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (d destination) address() string { return net.JoinHostPort(d.Host, strconv.Itoa(d.Port)) }

var hostRE = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,253}$`)

func destinationFrom(raw fields) (destination, string) {
	d := destination{Enabled: true, Port: 5144, Protocol: "tcp"}
	if v, ok := raw["enabled"]; ok {
		val, ok := v.(bool)
		if !ok {
			return d, "bad_request"
		}
		d.Enabled = val
	}
	h, _ := raw["host"].(string)
	d.Host = strings.Trim(strings.TrimSpace(h), "[]")
	if p, ok := raw["protocol"]; ok && p != "" {
		s, _ := p.(string)
		if s != "tcp" && s != "udp" {
			return d, "bad_protocol"
		}
		d.Protocol = s
	}
	if p := raw["port"]; p != nil && p != "" {
		v, e := strconv.Atoi(fmt.Sprint(p))
		if e != nil || v < 1 || v > 65535 {
			return d, "bad_port"
		}
		d.Port = v
	}
	if d.Host != "" && !hostRE.MatchString(d.Host) {
		return d, "bad_host"
	}
	if d.Enabled && d.Host == "" {
		return d, "host_required"
	}
	return d, ""
}
func oneSpace(v any) string { return strings.Join(strings.Fields(fmt.Sprint(v)), " ") }
func cefValue(v any) string {
	return strings.NewReplacer("\\", "\\\\", "=", "\\=").Replace(oneSpace(v))
}
func syslogLine(e *event, host string) string {
	hdr := strings.NewReplacer("\\", "\\\\", "|", "\\|")
	var b strings.Builder
	fmt.Fprintf(
		&b,
		"<%d>%s %s CEF:0|Kaspersky|Kaspersky VM Metrics|%s|%d|%s|%d|rt=%d dvchost=%s cat=%s msg=%s",
		128+7-e.Severity,
		e.stamp.Format("Jan 2 15:04:05"),
		strings.Join(strings.Fields(host), ""),
		hdr.Replace(version),
		e.Signature,
		hdr.Replace(e.Title),
		e.Severity,
		e.stamp.UnixMilli(),
		cefValue(host),
		cefValue(e.Category),
		cefValue(e.message),
	)
	for _, f := range cefFields {
		v := e.attrs[f[0]]
		if v == nil || v == "" || f[1] == "src" && net.ParseIP(fmt.Sprint(v)) == nil {
			continue
		}
		if f[2] != "" {
			fmt.Fprintf(&b, " %sLabel=%s", f[1], f[2])
		}
		fmt.Fprintf(&b, " %s=%s", f[1], cefValue(v))
	}
	return b.String()
}
func wire(line, proto string) string {
	maxSize := 16384
	if proto == "udp" {
		maxSize = 2048
	}
	if len(line) > maxSize {
		line = line[:maxSize-3]
		for !utf8.ValidString(line) {
			line = line[:len(line)-1]
		}
		line += "..."
	}
	if proto == "tcp" {
		return line + "\n"
	}
	return line
}

type eventBus struct {
	mu                    sync.Mutex
	host                  string
	now                   func() time.Time
	seq                   int64
	history, pending      []*event
	cfg                   destination
	generation            uint64
	wake                  chan struct{}
	sent, failed, dropped int
	lastError             string
	lastFailure, lastSent time.Time
	connected             bool
	dial                  func(context.Context, string, string) (net.Conn, error)
}

func newBus(host string, now func() time.Time) *eventBus {
	return &eventBus{
		host: host,
		now:  now,
		cfg:  destination{Port: 5144, Protocol: "tcp"},
		wake: make(chan struct{}, 1),
		dial: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
}
func (b *eventBus) signal() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}
func (b *eventBus) configure(d destination) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cfg != d {
		b.generation++
		b.connected = false
		b.lastFailure = time.Time{}
		b.lastError = ""
	}
	b.cfg = d
	if !d.Enabled {
		for _, e := range b.pending {
			e.delivery = "dropped"
			b.dropped++
		}
		b.pending = nil
	}
	b.signal()
}
func (b *eventBus) emit(name, msg string, attrs fields) *event {
	var spec eventType
	for _, s := range eventTypes {
		if s.Name == name {
			spec = s
			break
		}
	}
	if spec.Name == "" {
		panic("missing event definition: " + name)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	if attrs == nil {
		attrs = fields{}
	}
	e := &event{eventType: spec, id: b.seq, stamp: b.now(), message: oneSpace(msg), attrs: maps.Clone(attrs)}
	b.history = append(b.history, e)
	if len(b.history) > 500 {
		b.history = b.history[1:]
	}
	if b.cfg.Enabled && name != "siem_test" {
		if len(b.pending) >= 2000 {
			b.pending[0].delivery = "dropped"
			b.pending = b.pending[1:]
			b.dropped++
		}
		e.delivery = "queued"
		b.pending = append(b.pending, e)
		b.signal()
	}
	if name == "auth_failed" || name == "auth_locked" || name == "csrf_rejected" ||
		strings.HasPrefix(name, "restart_") || name == "settings_changed" {
		details, _ := json.Marshal(e.attrs)
		log.Printf("AUDIT %s %s", name, details)
	}
	return e
}
func stamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return iso(t)
}
func (b *eventBus) status() fields {
	b.mu.Lock()
	defer b.mu.Unlock()
	state := "waiting"
	switch {
	case !b.cfg.Enabled:
		state = "off"
	case !b.lastFailure.IsZero() && !b.lastFailure.Before(b.lastSent):
		state = "error"
	case !b.lastSent.IsZero():
		state = "ok"
	}
	return fields{
		"enabled":  b.cfg.Enabled,
		"host":     b.cfg.Host,
		"port":     b.cfg.Port,
		"protocol": b.cfg.Protocol,
		"state":    state,
		"stats": fields{
			"queued":          len(b.pending),
			"sent":            b.sent,
			"failed":          b.failed,
			"dropped":         b.dropped,
			"connected":       b.connected,
			"last_error":      b.lastError,
			"last_error_time": stamp(b.lastFailure),
			"last_sent_time":  stamp(b.lastSent),
		},
	}
}
func (b *eventBus) recent(count int, since time.Time, raw bool) ([]fields, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []fields{}
	for _, e := range b.history[max(0, len(b.history)-count):] {
		if e.stamp.Before(since) {
			continue
		}
		v := fields{
			"id":        e.id,
			"time":      iso(e.stamp),
			"name":      e.Name,
			"title":     e.Title,
			"signature": e.Signature,
			"severity":  e.Severity,
			"category":  e.Category,
			"message":   e.message,
			"fields":    e.attrs,
		}
		if e.delivery != "" {
			v["siem"] = e.delivery
		}
		if !e.sent.IsZero() {
			v["siem_time"] = iso(e.sent)
		}
		if raw {
			v["raw"] = syslogLine(e, b.host)
		}
		out = append(out, v)
	}
	return out, len(b.history)
}
func (b *eventBus) payload() fields {
	recent, total := b.recent(5, time.Time{}, true)
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	return fields{
		"ok":          true,
		"config":      b.status(),
		"events":      eventTypes,
		"recent":      recent,
		"total":       total,
		"format":      "syslog RFC 3164 + CEF:0, facility local0",
		"recommended": fields{"protocol": "tcp", "port": 5144, "standard_port": 514},
	}
}
func (b *eventBus) transmit(ctx context.Context, d destination, e *event, conn *net.Conn) error {
	if *conn == nil {
		c, err := b.dial(ctx, d.Protocol, d.address())
		if err != nil {
			return err
		}
		*conn = c
	}
	(*conn).SetWriteDeadline(time.Now().Add(5 * time.Second))
	data := wire(syslogLine(e, b.host), d.Protocol)
	n, err := (*conn).Write([]byte(data))
	if err == nil && n != len(data) {
		return fmt.Errorf("short syslog write")
	}
	return err
}
func (b *eventBus) test(ctx context.Context, d destination, ip string) error {
	e := b.emit(
		"siem_test",
		"Kaspersky VM Metrics test event",
		fields{"client": ip, "target": d.address() + "/" + d.Protocol},
	)
	var c net.Conn
	err := b.transmit(ctx, d, e, &c)
	if c != nil {
		c.Close()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		e.delivery = "sent"
		e.sent = b.now()
	} else {
		e.delivery = "dropped"
	}
	log.Printf("AUDIT siem_test client=%q target=%q result=%s", ip, d.address(), e.delivery)
	return err
}
func (b *eventBus) worker(ctx context.Context) {
	var conn net.Conn
	closeConn := func() {
		if conn != nil {
			conn.Close()
			conn = nil
		}
	}
	defer closeConn()
	var generation uint64
	backoff := time.Second
	for ctx.Err() == nil {
		b.mu.Lock()
		cfg, gen := b.cfg, b.generation
		var e *event
		if cfg.Enabled && len(b.pending) > 0 {
			e = b.pending[0]
		}
		b.mu.Unlock()
		if gen != generation {
			closeConn()
			generation = gen
			backoff = time.Second
		}
		if e == nil {
			select {
			case <-ctx.Done():
				return
			case <-b.wake:
			}
			continue
		}
		err := b.transmit(ctx, cfg, e, &conn)
		b.mu.Lock()
		if err != nil {
			closeConn()
			b.connected = false
			b.failed++
			b.lastError = short(err.Error(), 300)
			b.lastFailure = b.now()
		} else {
			if len(b.pending) > 0 && b.pending[0] == e {
				b.pending = b.pending[1:]
			}
			e.delivery = "sent"
			e.sent = b.now()
			b.lastSent = e.sent
			b.sent++
			b.connected = cfg.Protocol == "tcp" && gen == b.generation
			b.lastError = ""
			backoff = time.Second
		}
		b.mu.Unlock()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(time.Minute, backoff*2)
		}
	}
}
func (a *app) readSettings() {
	var data struct {
		SIEM fields `json:"siem"`
	}
	if err := json.Unmarshal(
		[]byte(read(filepath.Join(a.dir, "settings.json"))),
		&data,
	); err == nil &&
		data.SIEM != nil {
		if d, code := destinationFrom(data.SIEM); code == "" {
			a.events.configure(d)
		}
	}
}
func (a *app) saveSettings(d destination) error {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	p := filepath.Join(a.dir, "settings.json")
	old := map[string]json.RawMessage{}
	b, e := os.ReadFile(p)
	if e == nil {
		if e = json.Unmarshal(b, &old); e != nil {
			return e
		}
		if old == nil {
			old = map[string]json.RawMessage{}
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	value, _ := json.Marshal(d)
	old["siem"] = value
	if e = writeJSONFile(p, old, 0600); e != nil {
		return e
	}
	a.events.configure(d)
	return nil
}

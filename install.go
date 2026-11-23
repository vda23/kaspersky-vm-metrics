package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const programName = "kaspersky-vm-metrics"
const legacyName = programName + ".py"
const unitName = programName + ".service"

var branding = []string{
	"KasperskySans-Regular.ttf",
	"logo.svg",
	"logo.png",
	"logo-dark.svg",
	"logo-dark.png",
	"logo-light.svg",
	"logo-light.png",
	"favicon.svg",
	"favicon.png",
}

type installOptions struct {
	port                     int
	force, purge, self       bool
	cert, key, chain, action string
}
type installer struct {
	src, dir, units, backups string
	out                      io.Writer
	run                      runner
	exists                   func(string) bool
	health                   func(context.Context, int) (string, error)
	fingerprint              func(int) (string, error)
	timeout                  time.Duration
	keep                     int
}

func envOr(name, value string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return value
}
func newInstaller(src string) *installer {
	dir := envOr("INSTALL_DIR", "/opt/"+programName)
	wait, _ := strconv.Atoi(envOr("HEALTH_TIMEOUT", "30"))
	keep, _ := strconv.Atoi(envOr("KEEP_BACKUPS", "3"))
	return &installer{
		src:     src,
		dir:     dir,
		units:   envOr("SYSTEMD_DIR", "/etc/systemd/system"),
		backups: envOr("BACKUP_DIR", filepath.Join(dir, "backup")),
		out:     os.Stdout,
		run:     runCommand,
		keep:    max(1, keep),
		timeout: time.Duration(max(1, wait)) * time.Second,
		exists:  func(s string) bool { _, e := exec.LookPath(s); return e == nil },
		health: func(ctx context.Context, port int) (string, error) {
			return probe(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), true)
		},
		fingerprint: servedFingerprint,
	}
}
func (i *installer) say(format string, args ...any) { fmt.Fprintf(i.out, format+"\n", args...) }
func installFlags(args []string) (installOptions, error) {
	var o installOptions
	f := flag.NewFlagSet("install.sh", flag.ContinueOnError)
	f.IntVar(&o.port, "port", 0, "TCP-порт (по умолчанию установленный или 8999)")
	f.BoolVar(&o.force, "force", false, "переустановить или понизить версию")
	f.BoolVar(&o.purge, "purge", false, "удалить также настройки и отчёты при --uninstall")
	f.BoolVar(&o.self, "self-signed", false, "вернуть самоподписанный сертификат")
	f.StringVar(&o.cert, "cert", "", "сертификат организации PEM")
	f.StringVar(&o.key, "key", "", "закрытый ключ PEM")
	f.StringVar(&o.chain, "chain", "", "промежуточные сертификаты PEM")
	actions := map[string]string{
		"status":    "состояние установки",
		"version":   "установленная и работающая версии",
		"rollback":  "восстановить последнюю резервную копию",
		"preflight": "проверить готовность",
		"diag":      "собрать диагностику",
		"uninstall": "удалить службу",
	}
	for name, usage := range actions {
		f.Bool(name, false, usage)
	}
	if e := f.Parse(args); e != nil {
		return o, e
	}
	if f.NArg() != 0 {
		return o, fmt.Errorf("лишние аргументы: %v", f.Args())
	}
	var err error
	f.Visit(func(x *flag.Flag) {
		if _, ok := actions[x.Name]; ok && x.Value.String() == "true" {
			if o.action != "" {
				err = fmt.Errorf("выберите одно действие")
			}
			o.action = x.Name
		}
		if x.Name == "port" && (o.port < 1 || o.port > 65535) {
			err = fmt.Errorf("порт должен быть в диапазоне 1–65535")
		}
	})
	if err != nil {
		return o, err
	}
	if o.action == "version" {
		o.action = "status"
	}
	if (o.cert == "") != (o.key == "") || o.chain != "" && o.cert == "" || o.self && o.cert != "" {
		return o, fmt.Errorf("проверьте сочетание --cert, --key, --chain и --self-signed")
	}
	if (o.cert != "" || o.self) && o.action != "" || o.purge && o.action != "uninstall" {
		return o, fmt.Errorf("параметры несовместимы с выбранным действием")
	}
	return o, nil
}
func (i *installer) unit() string { return filepath.Join(i.units, unitName) }

var portFlag = regexp.MustCompile(`(?m)^ExecStart=[^\n]* --port[= ]([0-9]+)`)
var legacyVersion = regexp.MustCompile(`(?m)^__version__\s*=\s*["']([^"']+)["']`)

func currentProgram(dir string) string {
	for _, n := range []string{programName, legacyName} {
		p := filepath.Join(dir, n)
		if fileExists(p) {
			return p
		}
	}
	return ""
}
func (i *installer) installed() bool { return currentProgram(i.dir) != "" && fileExists(i.unit()) }
func (i *installer) installedPort() int {
	m := portFlag.FindStringSubmatch(read(i.unit()))
	if len(m) > 1 {
		n, _ := strconv.Atoi(m[1])
		if n > 0 && n <= 65535 {
			return n
		}
	}
	return 8999
}
func (i *installer) versionAt(ctx context.Context, dir string) string {
	p := currentProgram(dir)
	if p == "" {
		return ""
	}
	if filepath.Base(p) == legacyName {
		if m := legacyVersion.FindStringSubmatch(read(p)); len(m) > 1 {
			return m[1]
		}
		return ""
	}
	s, e := command(ctx, i.run, 5*time.Second, p, "--version")
	if e != nil {
		return ""
	}
	return strings.TrimSpace(s)
}
func older(a, b string) bool {
	left, lpre, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	right, rpre, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	x, y := strings.Split(left, "."), strings.Split(right, ".")
	for k := 0; k < max(len(x), len(y)); k++ {
		var p, q int64
		if k < len(x) {
			p = number(x[k])
		}
		if k < len(y) {
			q = number(y[k])
		}
		if p != q {
			return p < q
		}
	}
	if lpre == rpre || lpre == "" {
		return false
	}
	return rpre == "" || lpre < rpre
}
func copyFile(src, dst string, mode os.FileMode) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	tmp, e := os.CreateTemp(filepath.Dir(dst), ".install-*")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	_, e = io.Copy(tmp, in)
	if e == nil {
		e = tmp.Chmod(mode)
	}
	if e == nil {
		e = tmp.Sync()
	}
	if er := tmp.Close(); e == nil {
		e = er
	}
	if e == nil {
		e = os.Rename(tmp.Name(), dst)
	}
	return e
}
func digest(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	return fmt.Sprintf("%x", h.Sum(nil)), e
}
func (i *installer) checkPackage() error {
	manifest := filepath.Join(i.src, "SHA256SUMS")
	b, e := os.ReadFile(manifest)
	if os.IsNotExist(e) && i.src == i.dir {
		return nil
	}
	if e != nil {
		return e
	}
	found := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		p := strings.Fields(l)
		if len(p) != 2 {
			return fmt.Errorf("повреждён SHA256SUMS")
		}
		name := strings.TrimPrefix(p[1], "*")
		if name == "." || name == ".." || filepath.Base(name) != name {
			return fmt.Errorf("недопустимый путь в SHA256SUMS")
		}
		v, e := digest(filepath.Join(i.src, name))
		if e != nil || v != p[0] {
			return fmt.Errorf("неверная контрольная сумма %s", name)
		}
		found[name] = true
	}
	if !found[programName] || !found["install.sh"] {
		return fmt.Errorf("неполный SHA256SUMS")
	}
	return nil
}
func (i *installer) asset(name string) string {
	for _, dir := range []string{i.src, filepath.Join(i.src, "assets")} {
		p := filepath.Join(dir, name)
		if fileExists(p) {
			return p
		}
	}
	return ""
}
func (i *installer) changed() bool {
	for _, name := range append([]string{programName, "install.sh"}, branding...) {
		src := i.asset(name)
		if src == "" {
			continue
		}
		a, e := digest(src)
		b, other := digest(filepath.Join(i.dir, name))
		if e != nil || other != nil || a != b {
			return true
		}
	}
	return false
}
func (i *installer) writeProgram(port int) error {
	if e := os.MkdirAll(i.dir, 0755); e != nil {
		return e
	}
	for _, name := range append([]string{programName, "install.sh"}, branding...) {
		src := i.asset(name)
		if src == "" {
			if name == programName || name == "install.sh" {
				return fmt.Errorf("нет %s в пакете", name)
			}
			continue
		}
		dst := filepath.Join(i.dir, name)
		if src == dst {
			continue
		}
		mode := os.FileMode(0644)
		if name == programName || name == "install.sh" {
			mode = 0755
		}
		if e := copyFile(src, dst, mode); e != nil {
			return e
		}
	}
	data := fmt.Sprintf(unitTemplate, filepath.Join(i.dir, programName), port, i.dir)
	return atomicFile(i.unit(), []byte(data), 0644)
}

const unitTemplate = `[Unit]
Description=Kaspersky VM Metrics Service
After=network.target

[Service]
Type=notify
ExecStart="%s" --port %d
WorkingDirectory=%s
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
TimeoutStartSec=30
TimeoutStopSec=15
WatchdogSec=60
NotifyAccess=main

[Install]
WantedBy=multi-user.target
`

func (i *installer) copies() []string {
	items, _ := os.ReadDir(i.backups)
	dirs := []string{}
	for _, ent := range items {
		p := filepath.Join(i.backups, ent.Name())
		if ent.IsDir() && !strings.HasPrefix(ent.Name(), ".") && currentProgram(p) != "" &&
			fileExists(filepath.Join(p, unitName)) {
			dirs = append(dirs, p)
		}
	}
	slices.SortFunc(dirs, func(a, b string) int {
		x, _ := os.Stat(a)
		y, _ := os.Stat(b)
		if x == nil || y == nil {
			return strings.Compare(b, a)
		}
		if c := y.ModTime().Compare(x.ModTime()); c != 0 {
			return c
		}
		return strings.Compare(b, a)
	})
	return dirs
}

// Keep settings, certificates, logs and reports outside program rollback.
func (i *installer) managedPaths() []string {
	paths := []string{i.unit()}
	for _, name := range append([]string{programName, legacyName, "install.sh"}, branding...) {
		paths = append(paths, filepath.Join(i.dir, name))
	}
	return paths
}

func (i *installer) saveFiles(backup string) error {
	for _, src := range i.managedPaths() {
		st, err := os.Stat(src)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err := copyFile(src, filepath.Join(backup, filepath.Base(src)), st.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func (i *installer) restoreFiles(backup string) error {
	for _, dst := range i.managedPaths() {
		src := filepath.Join(backup, filepath.Base(dst))
		st, err := os.Stat(src)
		if os.IsNotExist(err) {
			if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if err := copyFile(src, dst, st.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func (i *installer) backup(v string) (string, error) {
	if e := os.MkdirAll(i.backups, 0700); e != nil {
		return "", e
	}
	tmp, e := os.MkdirTemp(i.backups, ".pending-*")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(tmp)
	if currentProgram(i.dir) == "" {
		return "", fmt.Errorf("нет установленной версии")
	}
	if err := i.saveFiles(tmp); err != nil {
		return "", err
	}
	name := safeHost.ReplaceAllString(v, "_") + "_" + time.Now().Format("20060102-150405.000000000")
	dst := filepath.Join(i.backups, name)
	return dst, os.Rename(tmp, dst)
}
func (i *installer) restore(ctx context.Context, backup string) error {
	program := currentProgram(backup)
	if program == "" || !fileExists(filepath.Join(backup, unitName)) {
		return fmt.Errorf("неполная резервная копия %s", backup)
	}
	if err := i.restoreFiles(backup); err != nil {
		return err
	}
	i.labels(ctx, i.installedPort())
	return i.restart(ctx)
}
func (i *installer) restart(ctx context.Context) error {
	if _, e := command(ctx, i.run, 30*time.Second, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	_, e := command(ctx, i.run, time.Minute, "systemctl", "restart", unitName)
	return e
}
func (i *installer) wait(ctx context.Context, port int, version string) error {
	c, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()
	for {
		got, e := i.health(c, port)
		if e == nil && got != "" && (version == "" || got == version) {
			return nil
		}
		select {
		case <-c.Done():
			return fmt.Errorf("порт %d: не получена ожидаемая версия %s: %w", port, version, c.Err())
		case <-time.After(150 * time.Millisecond):
		}
	}
}
func (i *installer) update(ctx context.Context, o installOptions, port int) error {
	installed := i.installed()
	oldPort := i.installedPort()
	old := i.versionAt(ctx, i.dir)
	if e := i.checkPackage(); e != nil {
		return e
	}
	if e := i.preflight(ctx, port); e != nil {
		return e
	}
	if installed && old == version && oldPort == port && !o.force && !i.changed() {
		i.say("Уже установлена версия %s", version)
		if running, err := i.health(ctx, port); err != nil || running != version {
			if err := i.restart(ctx); err != nil {
				return err
			}
			return i.wait(ctx, port, version)
		}
		return nil
	}
	if installed && older(version, old) && !o.force {
		return fmt.Errorf("для понижения с %s до %s укажите --force", old, version)
	}
	if !i.exists("ss") {
		i.installSS(ctx)
	}
	var backup string
	var e error
	if installed {
		backup, e = i.backup(old)
		if e != nil {
			return e
		}
		i.say("Резервная копия %s", backup)
	} else {
		backup, e = os.MkdirTemp("", "kvm-first-install-*")
		if e != nil {
			return e
		}
		defer os.RemoveAll(backup)
		if e = i.saveFiles(backup); e != nil {
			return e
		}
	}
	apply := func() error {
		if e := i.writeProgram(port); e != nil {
			return e
		}
		i.labels(ctx, port)
		if e := i.restart(ctx); e != nil {
			return e
		}
		return i.wait(ctx, port, version)
	}
	if e = apply(); e != nil {
		if !installed {
			// Enabling the unit and opening the firewall happen only after a healthy start.
			if fileExists(i.unit()) {
				command(ctx, i.run, 30*time.Second, "systemctl", "stop", unitName)
			}
			restoreErr := i.restoreFiles(backup)
			_, reloadErr := command(ctx, i.run, 30*time.Second, "systemctl", "daemon-reload")
			return errors.Join(e, restoreErr, reloadErr)
		}
		restoreErr := i.restore(ctx, backup)
		if restoreErr == nil {
			restoreErr = i.wait(ctx, oldPort, old)
		}
		if restoreErr != nil {
			return fmt.Errorf("ошибка обновления (%v) и отката (%v), копия %s", e, restoreErr, backup)
		}
		return fmt.Errorf("восстановлена версия %s после ошибки обновления: %w", old, e)
	}
	if _, err := command(ctx, i.run, 30*time.Second, "systemctl", "enable", unitName); err != nil {
		i.say("Автозапуск: %v", err)
	}
	if !installed || port != oldPort {
		i.firewall(ctx, port, true)
	}
	os.Remove(filepath.Join(i.dir, legacyName))
	if installed && port != oldPort {
		i.firewall(ctx, oldPort, false)
	}
	copies := i.copies()
	for _, p := range copies[min(i.keep, len(copies)):] {
		os.RemoveAll(p)
	}
	i.say("Установлена версия %s, адрес https://%s:%d/", version, fqdn(), port)
	return nil
}
func (i *installer) rollback(ctx context.Context) error {
	copies := i.copies()
	if len(copies) == 0 {
		return fmt.Errorf("резервных копий нет")
	}
	p := copies[0]
	v := i.versionAt(ctx, p)
	old := i.installedPort()
	priorVersion := i.versionAt(ctx, i.dir)
	var recovery string
	if i.installed() {
		var err error
		recovery, err = i.backup(priorVersion)
		if err != nil {
			return err
		}
	}
	err := i.restore(ctx, p)
	port := i.installedPort()
	if err == nil {
		err = i.wait(ctx, port, v)
	}
	if err != nil {
		if recovery != "" {
			restoreErr := i.restore(ctx, recovery)
			if restoreErr == nil {
				restoreErr = i.wait(ctx, old, priorVersion)
			}
			if restoreErr != nil {
				return fmt.Errorf("откат: %v, восстановление из %s: %w", err, recovery, restoreErr)
			}
			os.RemoveAll(recovery)
		}
		return fmt.Errorf("откат не подтверждён, копия %s: %w", p, err)
	}
	if old != port {
		i.firewall(ctx, port, true)
		i.firewall(ctx, old, false)
	}
	if recovery != "" {
		if err := os.RemoveAll(recovery); err != nil {
			return err
		}
	}
	i.say("Восстановлена версия %s", v)
	return os.RemoveAll(p)
}
func (i *installer) execute(ctx context.Context, o installOptions) error {
	port := o.port
	if port == 0 {
		port = i.installedPort()
	}
	switch o.action {
	case "status":
		i.status(ctx)
		return nil
	case "diag":
		return i.diagnostics(ctx)
	case "preflight":
		return i.preflight(ctx, port)
	}
	for _, p := range []string{i.dir, i.units, i.backups} {
		if !filepath.IsAbs(p) || filepath.Clean(p) == "/" || strings.ContainsAny(p, "\n\r\"%") {
			return fmt.Errorf("недопустимый каталог %q", p)
		}
	}
	if filepath.Clean(i.backups) == filepath.Clean(i.dir) || filepath.Clean(i.units) == filepath.Clean(i.dir) {
		return fmt.Errorf("каталоги службы, unit-файла и копий должны различаться")
	}
	lock, e := os.Open(i.units)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return fmt.Errorf("другой установщик уже работает: %w", e)
	}
	switch o.action {
	case "uninstall":
		return i.uninstall(ctx, o.purge)
	case "rollback":
		return i.rollback(ctx)
	}
	var pair certFiles
	if o.cert != "" {
		pair, e = i.validatePair(o)
		if e != nil {
			return e
		}
	}
	onlyCert := (o.self || o.cert != "") && i.installed() && i.src == i.dir && o.port == 0
	if !onlyCert {
		if e = i.update(ctx, o, port); e != nil {
			return e
		}
	}
	if o.self || o.cert != "" {
		return i.changeCert(ctx, port, o.self, pair)
	}
	return nil
}
func installerCLI(args []string) error {
	o, e := installFlags(args)
	if e != nil {
		return e
	}
	if os.Geteuid() != 0 {
		return errors.New("запустите установщик от root")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	return newInstaller(filepath.Dir(exe)).execute(context.Background(), o)
}

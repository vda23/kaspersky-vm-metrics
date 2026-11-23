package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func (i *installer) preflight(ctx context.Context, port int) error {
	if !i.exists("systemctl") {
		return fmt.Errorf("systemctl не найден")
	}
	for _, name := range []string{"ss", "journalctl", "tail"} {
		if !i.exists(name) {
			i.say("WARN не найдена команда %s", name)
		}
	}
	if i.exists("astra-digsig-control") {
		s, _ := command(ctx, i.run, 5*time.Second, "astra-digsig-control", "is-enabled")
		if strings.TrimSpace(s) == "ACTIVE" {
			i.say("Для запуска в активной ЗПС подпись ELF должна соответствовать политике площадки.")
		}
	}
	binary := filepath.Join(i.src, programName)
	out, e := command(ctx, i.run, 45*time.Second, binary, "--check")
	if e != nil {
		return fmt.Errorf("самопроверка бинарника: %w", e)
	}
	i.say("%s", strings.TrimSpace(out))
	if !i.installed() || port != i.installedPort() {
		l, e := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
		if e != nil {
			return fmt.Errorf("порт %d недоступен: %w", port, e)
		}
		l.Close()
	}
	return nil
}
func (i *installer) installSS(ctx context.Context) {
	var e error
	switch {
	case i.exists("apt-get"):
		_, e = command(ctx, i.run, 3*time.Minute, "apt-get", "update", "-y")
		if e == nil {
			_, e = command(ctx, i.run, 3*time.Minute, "apt-get", "install", "-y", "iproute2")
		}
	case i.exists("dnf"):
		_, e = command(ctx, i.run, 3*time.Minute, "dnf", "install", "-y", "iproute")
	case i.exists("yum"):
		_, e = command(ctx, i.run, 3*time.Minute, "yum", "install", "-y", "iproute")
	default:
		e = fmt.Errorf("нет пакетного менеджера")
	}
	if e != nil {
		i.say("WARN iproute2: %v. Сетевые показатели будут неполными.", e)
	}
}
func (i *installer) firewall(ctx context.Context, port int, open bool) {
	portStr := strconv.Itoa(port)
	rule := portStr + "/tcp"
	run := func(args ...string) bool {
		_, e := command(ctx, i.run, 20*time.Second, args...)
		if e != nil {
			i.say("Настройка межсетевого экрана %s: %v", args[0], e)
		}
		return e == nil
	}
	if i.exists("firewall-cmd") {
		if _, e := command(ctx, i.run, 5*time.Second, "firewall-cmd", "--state"); e == nil {
			act := "--add-port="
			if !open {
				act = "--remove-port="
			}
			if run("firewall-cmd", act+rule, "--permanent") {
				run("firewall-cmd", "--reload")
			}
			return
		}
	}
	if i.exists("ufw") {
		if open {
			run("ufw", "allow", rule)
		} else {
			run("ufw", "delete", "allow", rule)
		}
		return
	}
	if i.exists("iptables") {
		args := []string{"INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT"}
		op := "-D"
		if open {
			if _, e := command(
				ctx,
				i.run,
				5*time.Second,
				append([]string{"iptables", "-C"}, args...)...); e == nil {
				return
			}
			op = "-I"
		}
		run(append([]string{"iptables", op}, args...)...)
		return
	}
	if open && i.exists("nft") {
		i.say("nftables: проверьте входящий порт %d/tcp по правилам вашей площадки.", port)
	}
}
func (i *installer) labels(ctx context.Context, port int) {
	if !i.exists("getenforce") {
		return
	}
	mode, e := command(ctx, i.run, 5*time.Second, "getenforce")
	if e != nil || strings.TrimSpace(mode) == "Disabled" {
		return
	}
	if p := currentProgram(i.dir); p != "" {
		if _, e = command(ctx, i.run, 5*time.Second, "chcon", "-t", "bin_t", p); e != nil {
			i.say("SELinux: %v", e)
		}
	}
	if i.exists("semanage") {
		args := []string{"-t", "http_port_t", "-p", "tcp", strconv.Itoa(port)}
		if _, e = command(
			ctx,
			i.run,
			30*time.Second,
			append([]string{"semanage", "port", "-a"}, args...)...); e != nil {
			if _, e = command(
				ctx,
				i.run,
				30*time.Second,
				append([]string{"semanage", "port", "-m"}, args...)...); e != nil {
				i.say("SELinux, порт: %v", e)
			}
		}
	}
}
func (i *installer) status(ctx context.Context) {
	p := i.installedPort()
	installed := i.versionAt(ctx, i.dir)
	running, e := i.health(ctx, p)
	if e != nil {
		running = "не отвечает"
	}
	if installed == "" {
		installed = "нет"
	}
	state, _ := command(ctx, i.run, 5*time.Second, "systemctl", "is-active", unitName)
	i.say(
		"Установлена: %s\nРаботает: %s\nСлужба: %s\nПорт: %d",
		installed,
		running,
		strings.TrimSpace(state),
		p,
	)
	if leaf, e := readLeaf(filepath.Join(i.dir, "cert.pem")); e == nil {
		mode := "самоподписанный"
		if fileExists(filepath.Join(i.dir, "cert.org")) {
			mode = "организации"
		}
		i.say("Сертификат %s, %s, до %s", mode, leaf.Subject, iso(leaf.NotAfter))
	}
	for _, p := range i.copies() {
		i.say("Резервная копия: %s", p)
	}
}
func (i *installer) uninstall(ctx context.Context, purge bool) error {
	wasInstalled := i.installed()
	if !wasInstalled && filepath.Base(i.dir) != programName {
		return fmt.Errorf("каталог %s не содержит установленной службы", i.dir)
	}
	p := i.installedPort()
	for _, op := range []string{"stop", "disable"} {
		_, e := command(ctx, i.run, 30*time.Second, "systemctl", op, unitName)
		if e != nil && wasInstalled {
			return e
		}
	}
	if e := os.Remove(i.unit()); e != nil && !os.IsNotExist(e) {
		return e
	}
	if _, e := command(ctx, i.run, 30*time.Second, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	if wasInstalled {
		i.firewall(ctx, p, false)
	}
	for _, b := range i.copies() {
		if e := os.RemoveAll(b); e != nil {
			return e
		}
	}
	if purge {
		return os.RemoveAll(i.dir)
	}
	for _, n := range append([]string{programName, legacyName, "install.sh", "config.example.json"}, branding...) {
		if e := os.Remove(filepath.Join(i.dir, n)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	i.say("Служба удалена. Данные сохранены в %s", i.dir)
	return nil
}
func (i *installer) diagnostics(ctx context.Context) error {
	dest := envOr("DIAG_DIR", os.TempDir())
	f, e := os.CreateTemp(dest, "kvm-metrics-diag-*.tar.gz")
	if e != nil {
		return e
	}
	path := f.Name()
	success := false
	defer func() {
		f.Close()
		if !success {
			os.Remove(path)
		}
	}()
	gzipper := gzip.NewWriter(f)
	archive := tar.NewWriter(gzipper)
	add := func(name, s string) error {
		if e := archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(s))}); e != nil {
			return e
		}
		_, e := archive.Write([]byte(s))
		return e
	}
	var notes strings.Builder
	copyInstaller := *i
	copyInstaller.out = &notes
	copyInstaller.status(ctx)
	fmt.Fprintf(&notes, "Дата: %s\nУзел: %s\nАрхитектура: %s\n", iso(time.Now()), fqdn(), runtime.GOARCH)
	if release := read("/etc/os-release"); release != "" {
		notes.WriteString(release)
	}
	if e = add("status.txt", notes.String()); e != nil {
		return e
	}
	commands := map[string][]string{
		"journal.txt":          {"journalctl", "-u", unitName, "-n", "1000", "--no-pager"},
		"systemctl-status.txt": {"systemctl", "status", unitName, "--no-pager"},
		"units-list.txt": {
			"systemctl",
			"list-units",
			"--all",
			"--type=service",
			"--no-pager",
			"postgres*",
			"kaspersky*",
		},
	}
	if p := currentProgram(i.dir); filepath.Base(p) == programName {
		commands["self-check.txt"] = []string{p, "--check"}
	}
	args := []string{"systemctl", "show"}
	for _, d := range definitions[[]serviceDef]("services") {
		args = append(args, d.Unit)
	}
	commands["kvm-units.txt"] = append(args, "--property="+showProps)
	for name, args := range commands {
		out, err := command(ctx, i.run, 30*time.Second, args...)
		if err != nil {
			out += "\n" + err.Error()
		}
		if e = add(name, out); e != nil {
			return e
		}
	}
	var logs strings.Builder
	for _, l := range definitions[[]logDef]("logs") {
		for _, path := range candidates(l.Path) {
			if st, err := os.Stat(path); err == nil {
				fmt.Fprintf(&logs, "%s %d %s\n", path, st.Size(), iso(st.ModTime()))
			}
		}
	}
	if e = add("kvm-log-files.txt", logs.String()); e != nil {
		return e
	}
	if fileExists(i.unit()) {
		if e = add(unitName, read(i.unit())); e != nil {
			return e
		}
	}
	if e = archive.Close(); e != nil {
		return e
	}
	if e = gzipper.Close(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	success = true
	i.say("Архив диагностики: %s", path)
	return nil
}

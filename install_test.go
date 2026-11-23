package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type installFixture struct {
	*installer
	legacy, newProgram string
	log                []string
	rejectNew          bool
	out                strings.Builder
}

func makeInstall(t *testing.T) *installFixture {
	t.Helper()
	base := t.TempDir()
	i := newInstaller(filepath.Join(base, "pkg"))
	i.dir = filepath.Join(base, "service")
	i.units = filepath.Join(base, "units")
	i.backups = filepath.Join(i.dir, "backup")
	i.timeout = 20 * time.Millisecond
	os.MkdirAll(i.units, 0700)
	f := &installFixture{installer: i, legacy: "__version__ = \"1.0.0\"\n", newProgram: "binary fixture"}
	i.out = &f.out
	i.exists = func(n string) bool { return n == "systemctl" || n == "ss" || n == "tail" || n == "journalctl" }
	for name, data := range map[string]string{programName: f.newProgram, "install.sh": "#!/bin/sh\n", "KasperskySans-Regular.ttf": "font fixture"} {
		put(t, filepath.Join(i.src, name), data)
	}
	var sums strings.Builder
	for _, n := range []string{programName, "install.sh", "KasperskySans-Regular.ttf"} {
		v, _ := digest(filepath.Join(i.src, n))
		fmt.Fprintf(&sums, "%s  %s\n", v, n)
	}
	put(t, filepath.Join(i.src, "SHA256SUMS"), sums.String())
	i.run = func(ctx context.Context, args ...string) (string, error) {
		f.log = append(f.log, strings.Join(args, " "))
		switch args[len(args)-1] {
		case "--version":
			return version, nil
		case "--check":
			return "OK " + version, nil
		}
		return "active", nil
	}
	i.health = func(ctx context.Context, p int) (string, error) {
		if strings.Contains(read(i.unit()), "python3") {
			return "1.0.0", nil
		}
		if f.rejectNew {
			return "", fmt.Errorf("simulated failure")
		}
		return version, nil
	}
	return f
}
func (f *installFixture) old(t *testing.T) {
	put(t, filepath.Join(f.dir, legacyName), f.legacy)
	put(t, filepath.Join(f.dir, "install.sh"), "legacy installer")
	put(t, f.unit(), "ExecStart=/usr/bin/python3 "+filepath.Join(f.dir, legacyName)+" --port 29443\n")
	for _, n := range []string{"settings.json", "cert.pem", "key.pem", reportPrefix + "10_11_2026.json"} {
		put(t, filepath.Join(f.dir, n), "fixture "+n)
	}
}
func (f *installFixture) dataOK(t *testing.T) {
	t.Helper()
	for _, n := range []string{"settings.json", "cert.pem", "key.pem", reportPrefix + "10_11_2026.json"} {
		if read(filepath.Join(f.dir, n)) != "fixture "+n {
			t.Fatal(n)
		}
	}
}
func TestUpgradeRollback(t *testing.T) {
	f := makeInstall(t)
	f.old(t)
	ctx := context.Background()
	if !f.installed() || f.installedPort() != 29443 {
		t.Fatal("old installation not detected")
	}
	if e := f.execute(ctx, installOptions{}); e != nil {
		t.Fatal(e)
	}
	if fileExists(filepath.Join(f.dir, legacyName)) || !strings.Contains(read(f.unit()), "Type=notify") ||
		f.installedPort() != 29443 ||
		len(f.copies()) != 1 {
		t.Fatal("migration failed")
	}
	f.dataOK(t)
	if e := f.execute(ctx, installOptions{}); e != nil || len(f.copies()) != 1 {
		t.Fatal("repeat update", e)
	}
	if e := f.execute(ctx, installOptions{action: "rollback"}); e != nil {
		t.Fatal(e)
	}
	if f.versionAt(ctx, f.dir) != "1.0.0" || !strings.Contains(read(f.unit()), "python3") ||
		read(filepath.Join(f.dir, "install.sh")) != "legacy installer" {
		t.Fatal("old service not restored")
	}
	f.dataOK(t)
	f.rejectNew = true
	if e := f.execute(
		ctx,
		installOptions{},
	); e == nil ||
		!strings.Contains(e.Error(), "восстановлена версия 1.0.0") {
		t.Fatal(e)
	}
	if f.versionAt(ctx, f.dir) != "1.0.0" {
		t.Fatal("failed health rollback")
	}
	f.dataOK(t)
}
func TestInstallerFirstInstallAndRemoval(t *testing.T) {
	f := makeInstall(t)
	ctx := context.Background()
	o := installOptions{port: 29444}
	if e := f.execute(ctx, o); e != nil {
		t.Fatal(e)
	}
	if f.installedPort() != 29444 || !f.installed() {
		t.Fatal("first install")
	}
	put(t, filepath.Join(f.dir, "settings.json"), "keep")
	f.status(ctx)
	if !strings.Contains(f.out.String(), version) {
		t.Fatal("status")
	}
	if e := f.execute(ctx, installOptions{action: "uninstall"}); e != nil {
		t.Fatal(e)
	}
	if read(filepath.Join(f.dir, "settings.json")) != "keep" || fileExists(f.unit()) ||
		fileExists(filepath.Join(f.dir, programName)) {
		t.Fatal("uninstall")
	}
}
func TestFailedInstallCanBeRetried(t *testing.T) {
	f := makeInstall(t)
	ctx := context.Background()
	font := filepath.Join(f.dir, "KasperskySans-Regular.ttf")
	put(t, font, "existing font")
	put(t, filepath.Join(f.dir, "settings.json"), "keep")
	reject := func(context.Context, int) (string, error) { return "unexpected-version", nil }
	healthy := f.health
	f.health = reject
	if err := f.execute(ctx, installOptions{}); err == nil {
		t.Fatal("accepted a different service version")
	}
	if fileExists(f.unit()) || fileExists(filepath.Join(f.dir, programName)) || read(font) != "existing font" ||
		read(filepath.Join(f.dir, "settings.json")) != "keep" || strings.Contains(strings.Join(f.log, "\n"), "systemctl enable") {
		t.Fatal("failed first install left an enabled service or changed existing files")
	}
	f.health = healthy
	if err := f.execute(ctx, installOptions{}); err != nil {
		t.Fatal(err)
	}
	f.health = reject
	if err := f.execute(ctx, installOptions{}); err == nil {
		t.Fatal("repeat install reported success for an unhealthy service")
	}
}

func TestUnhealthyRollbackRestoresCurrentVersion(t *testing.T) {
	f := makeInstall(t)
	f.old(t)
	ctx := context.Background()
	if err := f.execute(ctx, installOptions{}); err != nil {
		t.Fatal(err)
	}
	f.health = func(ctx context.Context, port int) (string, error) {
		if strings.Contains(read(f.unit()), "python3") {
			return "", fmt.Errorf("older service failed to start")
		}
		return version, nil
	}
	if err := f.execute(ctx, installOptions{action: "rollback"}); err == nil {
		t.Fatal("rollback unexpectedly succeeded")
	}
	if f.versionAt(ctx, f.dir) != version || len(f.copies()) != 1 {
		t.Fatal("lost the current version or the original backup")
	}
	f.dataOK(t)
}

func TestInstallerIntegrityAndOptions(t *testing.T) {
	f := makeInstall(t)
	f.old(t)
	put(t, filepath.Join(f.src, programName), "corrupted")
	if e := f.execute(context.Background(), installOptions{}); e == nil {
		t.Fatal("accepted damaged package")
	}
	if len(f.copies()) != 0 || !strings.Contains(read(f.unit()), "python3") {
		t.Fatal("mutated installed service")
	}
	for _, args := range [][]string{
		{"--port", "0"},
		{"--port", "70000"},
		{"--purge"},
		{"--cert", "one"},
		{"--chain", "one"},
		{"--diag", "--rollback"},
		{"--cert", "one", "--key", "two", "--self-signed"},
	} {
		if _, e := installFlags(args); e == nil {
			t.Fatal(args)
		}
	}
	if o, e := installFlags([]string{"--uninstall", "--purge"}); e != nil || !o.purge {
		t.Fatal(e)
	}
	if !older("1.1.0", "1.2.0-dev") || !older("1.2.0-dev", "1.2.0") || older("1.2.0-dev", "1.0.0") || older("1.2.10", "1.2.9") {
		t.Fatal("version comparison")
	}
}
func TestInstallerCertRollback(t *testing.T) {
	f := makeInstall(t)
	f.old(t)
	ctx := context.Background()
	p, k := filepath.Join(f.src, "new.crt"), filepath.Join(f.src, "new.key")
	if e := generatePair(p, k, "vm.test", time.Now()); e != nil {
		t.Fatal(e)
	}
	c, e := f.validatePair(installOptions{cert: p, key: k})
	if e != nil {
		t.Fatal(e)
	}
	f.fingerprint = func(int) (string, error) { return "wrong", nil }
	if e = f.changeCert(ctx, 29443, false, c); e == nil {
		t.Fatal("wrong fingerprint")
	}
	f.dataOK(t)
	f.fingerprint = func(int) (string, error) { return c.fingerprint, nil }
	if e = f.changeCert(ctx, 29443, false, c); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(read(filepath.Join(f.dir, "cert.org")), c.fingerprint) {
		t.Fatal("marker")
	}
	if e = f.changeCert(ctx, 29443, true, certFiles{}); e != nil {
		t.Fatal(e)
	}
	if !fileExists(filepath.Join(f.dir, "key.pem.prev")) || fileExists(filepath.Join(f.dir, "cert.org")) {
		t.Fatal("self signed reset")
	}
	put(t, k, "broken")
	if _, e = f.validatePair(installOptions{cert: p, key: k}); e == nil {
		t.Fatal("bad key")
	}
}
func TestInstallerDiagnostics(t *testing.T) {
	f := makeInstall(t)
	f.old(t)
	dest := t.TempDir()
	t.Setenv("DIAG_DIR", dest)
	if e := f.diagnostics(context.Background()); e != nil {
		t.Fatal(e)
	}
	matches, _ := filepath.Glob(filepath.Join(dest, "*.tar.gz"))
	if len(matches) != 1 {
		t.Fatal(matches)
	}
	file, _ := os.Open(matches[0])
	defer file.Close()
	gz, e := gzip.NewReader(file)
	if e != nil {
		t.Fatal(e)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		names = append(names, h.Name)
	}
	if !slices.Contains(names, "kvm-units.txt") || slices.Contains(names, "key.pem") ||
		slices.Contains(names, "settings.json") {
		t.Fatal(names)
	}
}
func TestInstallerFirewallAndLabels(t *testing.T) {
	f := makeInstall(t)
	ctx := context.Background()
	for _, tool := range []string{"firewall-cmd", "ufw", "iptables", "nft"} {
		f.exists = func(n string) bool { return n == tool }
		f.firewall(ctx, 9443, true)
		f.firewall(ctx, 9443, false)
	}
	f.exists = func(s string) bool { return s == "getenforce" || s == "semanage" }
	f.labels(ctx, 9443)
	if !strings.Contains(strings.Join(f.log, "\n"), "semanage port -a -t http_port_t -p tcp 9443") {
		t.Fatal(f.log)
	}
}

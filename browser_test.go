package main

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Set KVM_BROWSER to an installed Chromium executable to exercise the shipped JavaScript.
func TestDashboardBrowser(t *testing.T) {
	browser := os.Getenv("KVM_BROWSER")
	if browser == "" {
		t.Skip("KVM_BROWSER not configured")
	}
	a := fixture(t)
	server := httptest.NewServer(a)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(
		ctx,
		browser,
		"--headless",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--no-first-run",
		"--user-data-dir="+t.TempDir(),
		"--virtual-time-budget=5000",
		"--dump-dom",
		server.URL+"/?lang=en&theme=light",
	)
	b, e := cmd.Output()
	if e != nil {
		if exit, ok := e.(*exec.ExitError); ok {
			t.Fatalf("%v: %s", e, short(string(exit.Stderr), 1200))
		}
		t.Fatal(e)
	}
	page := string(b)
	for _, want := range []string{`lang="en"`, `data-theme="light"`, `data-state="ok"`, `data-key="postgresql"`, "postgresql@15-main", `src="/brand/logo"`} {
		if !strings.Contains(page, want) {
			t.Errorf("rendered DOM lacks %q", want)
		}
	}
}

package main

import (
	"context"
	"encoding/json"
	"maps"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"testing"
)

// Keys are captured from the original 1.0.0 handlers at f410f50 using empty systemctl/ss replies.
func TestV1ResponseKeys(t *testing.T) {
	a := fixture(t)
	ctx := context.Background()
	status := a.status(ctx, true)
	sys := status["system"].(fields)
	services := status["services"].([]fields)
	siem := a.events.payload()
	config := siem["config"].(fields)
	report := a.report(ctx, "on-demand", a.now())
	logs := a.logsIndex(httptest.NewRequest("GET", "/api/logs", nil))
	objects := map[string]any{
		"status":         status,
		"system":         sys,
		"memory":         sys["memory"],
		"service":        services[0],
		"database":       services[len(services)-1],
		"summary":        status["summary"],
		"tls":            status["tls"],
		"siem":           siem,
		"config":         config,
		"stats":          config["stats"],
		"report":         report,
		"report_summary": report["summary"],
		"logs":           logs,
		"log_file":       logs["files"].([]fields)[0],
		"journal":        logs["journals"].([]fields)[0],
	}
	b, e := os.ReadFile("testdata/v1-contract.json")
	if e != nil {
		t.Fatal(e)
	}
	var want map[string][]string
	if e = json.Unmarshal(b, &want); e != nil {
		t.Fatal(e)
	}
	for name, keys := range want {
		data, e := json.Marshal(objects[name])
		if e != nil {
			t.Fatal(e)
		}
		var obj fields
		if e = json.Unmarshal(data, &obj); e != nil {
			t.Fatal(e)
		}
		got := slices.Sorted(maps.Keys(obj))
		if !reflect.DeepEqual(got, keys) {
			t.Errorf("%s: got %v, v1 has %v", name, got, keys)
		}
	}
}

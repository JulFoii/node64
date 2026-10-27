package healthchecks

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestNetworkMapPage(t *testing.T) {
	srv, _ := newDockerModule(t)
	if got := dockerGetPage(t, srv, networkMapPath); !strings.Contains(got, "data-network-canvas") {
		t.Fatalf("network map canvas missing: %s", got)
	}
}

func TestNetworkMapAPIUsesConfiguredSources(t *testing.T) {
	_, srv := newTestModule(t)
	code, body := call(t, srv, http.MethodPost, "/api/checks", map[string]any{
		"name": "Public site", "type": "http", "target": "https://status.example.test/health",
		"interval_seconds": 20, "retry_interval_seconds": 5, "stabilize": 1,
	})
	if code != http.StatusCreated {
		t.Fatalf("create check: %d %s", code, body)
	}
	code, body = call(t, srv, http.MethodGet, "/api/healthchecks/network-map", nil)
	if code != http.StatusOK {
		t.Fatalf("map: %d %s", code, body)
	}
	var got NetworkMap
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.RefreshSeconds < 10 || got.GeneratedAt.IsZero() {
		t.Fatalf("metadata: %+v", got)
	}
	var check, host bool
	for _, n := range got.Nodes {
		check = check || n.Kind == "check" && n.Name == "Public site" && n.URL != ""
		host = host || n.Kind == "host" && n.Host == "status.example.test" && n.State == "unknown"
	}
	if !check || !host {
		t.Fatalf("configured objects missing: %+v", got.Nodes)
	}
	for _, e := range got.Edges {
		if e.Kind == "monitors" && len(e.From) > 6 && e.From[:6] == "check:" && len(e.To) > 5 && e.To[:5] == "host:" {
			return
		}
	}
	t.Fatalf("check-to-host link missing: %+v", got.Edges)
}

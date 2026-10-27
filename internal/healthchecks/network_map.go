package healthchecks

// Die Netzwerkansicht bildet ausschliesslich Daten ab, die Node64 bereits
// verlaesslich kennt. Sie versucht bewusst nicht, das lokale Netz zu scannen:
// ohne Agent, SNMP-Zugang oder ARP-Tabelle waere das unvollstaendig und die
// Anzeige koennte falsche Topologien suggerieren.

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/proxmox"
)

const networkMapPath = "/healthchecks/network-map"

// NetworkMap ist die schreibgeschuetzte Momentaufnahme fuer die Karte und
// ihre API. IDs sind nur innerhalb einer Momentaufnahme stabil.
type NetworkMap struct {
	GeneratedAt    time.Time         `json:"generated_at"`
	RefreshSeconds int               `json:"refresh_seconds"`
	Nodes          []NetworkMapNode  `json:"nodes"`
	Edges          []NetworkMapEdge  `json:"edges"`
	Events         []NetworkMapEvent `json:"events"`
	Warnings       []string          `json:"warnings"`
}

type NetworkMapNode struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"` // node64, node, check, host, pve, vm, container, cloud
	Name      string         `json:"name"`
	State     string         `json:"state"`
	Host      string         `json:"host,omitempty"`
	Target    string         `json:"target,omitempty"`
	Addresses []string       `json:"addresses,omitempty"`
	Detail    string         `json:"detail,omitempty"`
	Message   string         `json:"message,omitempty"`
	LastSeen  *time.Time     `json:"last_seen,omitempty"`
	Stale     bool           `json:"stale,omitempty"`
	URL       string         `json:"url,omitempty"`
	Metrics   map[string]any `json:"metrics,omitempty"`
}

type NetworkMapEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // monitors, runs, contains, dependency
}

type NetworkMapEvent struct {
	Token   string    `json:"token"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Time    time.Time `json:"time"`
	Reason  string    `json:"reason,omitempty"`
	Message string    `json:"message,omitempty"`
}

func (m *Module) networkMapRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler, api func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET "+networkMapPath, page(m.pageNetworkMap))
	mux.Handle("GET /api/healthchecks/network-map", api(m.apiNetworkMap))
}

func (m *Module) pageNetworkMap(w http.ResponseWriter, r *http.Request) {
	m.g.Render(w, r, http.StatusOK, Name+"/network_map", "nav.network_map", nil)
}

func (m *Module) apiNetworkMap(w http.ResponseWriter, r *http.Request) {
	d, err := m.NetworkMap(r.Context())
	if err != nil {
		m.log.Error("network map", "err", err)
		writeErr(w, http.StatusInternalServerError, "network map unavailable")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// NetworkMap baut die Karte aus der Check-Konfiguration, den letzten
// Gesundheitswerten und den eingerichteten Proxmox-/Docker-Quellen. Ein
// Zielhost ist dabei ein konfiguriertes Ziel, keine behauptete Entdeckung.
func (m *Module) NetworkMap(ctx context.Context) (*NetworkMap, error) {
	now := time.Now().UTC()
	d := &NetworkMap{GeneratedAt: now, RefreshSeconds: 15, Nodes: []NetworkMapNode{}, Edges: []NetworkMapEdge{}, Events: []NetworkMapEvent{}, Warnings: []string{}}
	addNode := func(n NetworkMapNode) {
		if n.Metrics != nil && len(n.Metrics) == 0 {
			n.Metrics = nil
		}
		d.Nodes = append(d.Nodes, n)
	}
	edgeSet := map[string]bool{}
	addEdge := func(from, to, kind string) {
		key := from + "\x00" + to + "\x00" + kind
		if edgeSet[key] {
			return
		}
		edgeSet[key] = true
		d.Edges = append(d.Edges, NetworkMapEdge{From: from, To: to, Kind: kind})
	}

	selfID := "node64:self"
	selfName := strings.TrimSpace(m.core.SettingOr(ctx, "node.name", ""))
	if selfName == "" {
		selfName = strings.TrimSpace(m.core.SettingOr(ctx, "sync.node_name", ""))
	}
	if selfName == "" {
		selfName = "Node64"
	}
	addNode(NetworkMapNode{ID: selfID, Kind: "node64", Name: selfName, State: "up", LastSeen: &now})

	peerIDs := map[string]string{}
	for _, p := range m.peers(ctx) {
		id := "node:" + p.ID
		if p.Self {
			peerIDs[p.ID] = selfID
			continue
		}
		state := "unchecked"
		if p.Online {
			state = "up"
		}
		addNode(NetworkMapNode{ID: id, Kind: "node", Name: nonEmpty(p.Name, "Node"), State: state, Detail: p.Location, Stale: !p.Online})
		addEdge(selfID, id, "runs")
		peerIDs[p.ID] = id
	}

	list, err := m.st.Checks(ctx)
	if err != nil {
		return nil, err
	}
	checkIDs := map[string]string{}
	hostIDs := map[string]string{}
	dockerChecks := map[string][]string{}
	cloudID := "service:ipv64"
	cloudAdded := false
	for _, c := range list {
		rt := m.liveRuntime(c)
		state := string(rt.State)
		if state == "" {
			state = "pending"
		}
		isStale := stale(c, rt.LastCheck, state)
		if isStale {
			state = "unchecked"
		}
		if c.Paused {
			state, isStale = "paused", false
		}
		id := "check:" + c.Token
		checkIDs[c.Token] = id
		if c.Type == checks.TypeDocker && !c.Foreign() {
			key := dockerCheckHost(c) + "\x00" + dockerTarget(c)
			dockerChecks[key] = append(dockerChecks[key], id)
		}
		addNode(NetworkMapNode{ID: id, Kind: "check", Name: c.Name, State: state, Target: c.Target, Detail: string(c.Type), Message: rt.LastMessage,
			LastSeen: timeRef(rt.LastCheck), Stale: isStale, URL: "/healthchecks/" + url.PathEscape(c.Token), Metrics: map[string]any{"latency_ms": msf(rt.LastLatency), "interval_seconds": int(c.Interval.Seconds()), "consecutive_failures": rt.ConsecutiveFail}})

		if c.Execution == "online" || c.Execution == "both" || c.Owner == "online" {
			if !cloudAdded {
				addNode(NetworkMapNode{ID: cloudID, Kind: "cloud", Name: "ipv64", State: "unknown"})
				cloudAdded = true
			}
			addEdge(cloudID, id, "monitors")
		}
		if len(c.Nodes) == 0 && c.Execution != "online" && c.Owner != "online" {
			addEdge(selfID, id, "monitors")
		}
		for _, nodeID := range c.Nodes {
			from := peerIDs[nodeID]
			if from == "" {
				from = "node:" + nodeID
				peerIDs[nodeID] = from
				addNode(NetworkMapNode{ID: from, Kind: "node", Name: nodeID, State: "unknown", Stale: true})
			}
			addEdge(from, id, "monitors")
		}
		if host := mapTargetHost(c); host != "" {
			hostID := hostIDs[host]
			if hostID == "" {
				hostID = "host:" + host
				hostIDs[host] = hostID
				addresses := []string(nil)
				if net.ParseIP(host) != nil {
					addresses = []string{host}
				}
				addNode(NetworkMapNode{ID: hostID, Kind: "host", Name: host, State: "unknown", Host: host, Addresses: addresses})
			}
			addEdge(id, hostID, "monitors")
		}
	}
	for _, c := range list {
		if c.Parent != "" && checkIDs[c.Parent] != "" {
			addEdge(checkIDs[c.Parent], checkIDs[c.Token], "dependency")
		}
	}
	m.addMapVirtualization(ctx, d, addNode, addEdge, selfID, checkIDs, dockerChecks)
	if evs, err := m.st.Events(ctx, "", 30, 0); err == nil {
		for _, e := range evs {
			name := e.Token
			for _, c := range list {
				if c.Token == e.Token {
					name = c.Name
					break
				}
			}
			d.Events = append(d.Events, NetworkMapEvent{Token: e.Token, Name: name, Kind: e.Kind, Time: e.Time, Reason: e.Reason, Message: e.Message})
		}
	} else {
		d.Warnings = append(d.Warnings, "events_unavailable")
	}
	sort.Slice(d.Nodes, func(i, j int) bool { return d.Nodes[i].ID < d.Nodes[j].ID })
	sort.Slice(d.Edges, func(i, j int) bool {
		return d.Edges[i].From+d.Edges[i].To+d.Edges[i].Kind < d.Edges[j].From+d.Edges[j].To+d.Edges[j].Kind
	})
	return d, nil
}

func (m *Module) addMapVirtualization(ctx context.Context, d *NetworkMap, addNode func(NetworkMapNode), addEdge func(string, string, string), selfID string, checkIDs map[string]string, dockerChecks map[string][]string) {
	systems, err := m.pve.st.Systems(ctx)
	if err != nil {
		d.Warnings = append(d.Warnings, "virtualization_unavailable")
		return
	}
	for _, sys := range systems {
		view := m.pveSysView(ctx, sys)
		kind, url := "pve", pveResPath(sys.ID, "")
		if sys.IsDocker() {
			kind, url = "docker-host", dockerSysPath(sys.ID)
		}
		state := view.State
		if state == "" {
			state = "unknown"
		}
		systemID := "system:" + strconv.FormatInt(sys.ID, 10)
		addNode(NetworkMapNode{ID: systemID, Kind: kind, Name: sys.Name, State: state, Target: strings.Join(sys.Addresses, ", "), Message: view.Error, LastSeen: timeRef(snapshotTime(view.Snap)), Stale: view.Snap == nil, URL: url})
		addEdge(selfID, systemID, "runs")
		if view.Snap == nil {
			continue
		}
		for _, res := range view.Snap.Resources {
			if res.Excluded() {
				continue
			}
			resKind := mapResourceKind(sys, res)
			resID := systemID + ":" + res.Key()
			state := string(res.State)
			if state == "" {
				state = "unknown"
			}
			name := res.Name
			if name == "" {
				name = res.Key()
			}
			metrics := map[string]any{"cpu_percent": res.CPU * 100, "memory_bytes": res.Mem, "memory_limit_bytes": res.MaxMem, "uptime_seconds": res.Uptime}
			if res.Type == proxmox.TypeDocker {
				metrics["image"], metrics["health"], metrics["restarts"] = res.Image, res.Health, res.Restarts
			}
			addNode(NetworkMapNode{ID: resID, Kind: resKind, Name: name, State: state, Host: res.Node, Detail: res.Status, URL: pveKeyPath(sys.Kind, sys.ID, res.Key()), Metrics: metrics})
			addEdge(systemID, resID, "contains")
			if set := view.Settings; set != nil {
				if st := set.Item(res.Key()); st != nil && st.CheckToken != "" && checkIDs[st.CheckToken] != "" {
					addEdge(checkIDs[st.CheckToken], resID, "monitors")
				}
			}
			if sys.IsDocker() && res.Type == proxmox.TypeDocker {
				key := dockerSysHost(sys) + "\x00" + res.Name
				for _, checkID := range dockerChecks[key] {
					addEdge(checkID, resID, "monitors")
				}
			}
		}
	}
}

func mapTargetHost(c *Check) string {
	switch c.Type {
	case checks.TypeDocker, checks.TypeProxmox, checks.TypeDNS, checks.TypeWhois, checks.TypePush:
		return ""
	}
	return strings.ToLower(strings.TrimSpace(checks.TargetHost(c.Definition())))
}

func mapResourceKind(sys *proxmox.System, r proxmox.Resource) string {
	if sys.IsDocker() || r.Type == proxmox.TypeDocker {
		return "container"
	}
	if r.Type == proxmox.TypeNode {
		return "pve-node"
	}
	return "vm"
}

func snapshotTime(s *proxmox.Snapshot) time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.Time
}

func timeRef(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) != "" {
		return s
	}
	return fallback
}

package service

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

type deskManager struct {
	*fakeManager
	proxyCalls     atomic.Int32
	objectReads    atomic.Int32
	interfaceReads atomic.Int32
	statusCalls    atomic.Int32
}

func (m *deskManager) ListInterfaces(ctx context.Context, adom, device string) ([]fortinet.Interface, error) {
	m.interfaceReads.Add(1)
	return m.fakeManager.ListInterfaces(ctx, adom, device)
}

func (m *deskManager) ListRoutesBatch(context.Context, string, []fortinet.RouteTarget) (map[string]fortinet.RouteBatchResult, error) {
	return nil, errors.New("routes unavailable")
}

func (m *deskManager) PackageStatusBatch(_ context.Context, _ string, members []fortinet.PackageMember) (map[string]fortinet.PackageStatus, error) {
	m.statusCalls.Add(1)
	out := make(map[string]fortinet.PackageStatus, len(members))
	for _, member := range members {
		out[member.Device+"/"+member.VDOM] = fortinet.PackageStatus{Device: member.Device, VDOM: member.VDOM, Package: "pkg", Status: "installed"}
	}
	return out, nil
}

func (m *deskManager) ProxyGet(_ context.Context, adom, device, vdom, resource string) (fortinet.ProxyResult, error) {
	m.proxyCalls.Add(1)
	result := fortinet.ProxyResult{ADOM: adom, Device: device, VDOM: vdom, Resource: resource}
	switch {
	case strings.Contains(resource, "/firewall/session"):
		result.Data = []any{
			map[string]any{"src": "10.1.1.1", "dst": "8.8.8.8", "sport": 51515, "dport": 443, "proto": 6, "policyid": 4, "snat": "198.51.100.10", "duration": 12, "bytes": 1000},
			map[string]any{"src": "10.9.9.9", "dst": "1.1.1.1", "sport": 1, "dport": 53, "proto": 17, "policyid": 1},
		}
	case strings.Contains(resource, "/system/dhcp"):
		return fortinet.ProxyResult{}, errors.New("dhcp unavailable")
	case strings.Contains(resource, "/network/arp"):
		result.Data = []any{map[string]any{"ip": "10.1.1.1", "mac": "aa:bb:cc:dd:ee:ff"}}
	case strings.Contains(resource, "/vpn/ipsec"):
		result.Data = []any{map[string]any{"name": "hub", "rgwy": "203.0.113.1", "status": "up", "incoming_bytes": 10}}
	case strings.Contains(resource, "/vpn/ssl"):
		result.Data = []any{map[string]any{"user": "alice", "remote_host": "198.51.100.20", "duration": 30}}
	case strings.Contains(resource, "ha-peer"):
		result.Data = []any{
			map[string]any{"serial_no": "FGT123", "hostname": "fgt", "role": "primary"},
			map[string]any{"serial_no": "FGT124", "hostname": "fgt-2", "role": "secondary"},
		}
	case strings.Contains(resource, "ha-checksums"):
		result.Data = []any{map[string]any{"checksum": "abc"}, map[string]any{"checksum": "abc"}}
	case strings.Contains(resource, "/cmdb/system/ha"):
		result.Data = map[string]any{"mode": "a-p"}
	case strings.Contains(resource, "bgp/neighbors"):
		result.Data = []any{map[string]any{"neighbor_ip": "192.0.2.1", "state": "Established"}}
	case strings.Contains(resource, "ospf/neighbors"):
		result.Data = []any{}
	case strings.Contains(resource, "sla-log"):
		result.Data = []any{map[string]any{"interface": "wan1", "latency": 12, "jitter": 1, "packetloss": 0, "state": "up"}}
	case strings.Contains(resource, "/firewall/policy"):
		result.Data = []any{map[string]any{"policyid": 4, "name": "lan", "hit_count": 10, "bytes": 20, "last_used": 1}}
	case strings.Contains(resource, "/router/ipv4"):
		result.Data = []any{map[string]any{"ip_mask": "0.0.0.0/0", "gateway": "192.0.2.1"}}
	default:
		result.Data = []any{}
	}
	return result, nil
}

func (m *deskManager) Read(_ context.Context, resource string, _ map[string]any) (any, error) {
	m.objectReads.Add(1)
	switch {
	case strings.Contains(resource, "ssl-ssh-profile"):
		return map[string]any{"name": "deep", "inspection-mode": "deep-inspection", "https": map[string]any{"status": "deep-inspection", "ports": []any{443}}, "untrusted-cert": "block"}, nil
	case strings.Contains(resource, "/revision"):
		return nil, errors.New("code -3: Object does not exist")
	case strings.Contains(resource, "/device/"):
		return map[string]any{"name": "fgt", "conf_status": "insync", "sn": "FGT123"}, nil
	case strings.Contains(resource, "central-snat"):
		return []any{map[string]any{"name": "snat1", "srcaddr": "10.1.1.1"}}, nil
	case strings.Contains(resource, "ippool"):
		return []any{map[string]any{"name": "pool", "startip": "198.51.100.10"}}, nil
	case strings.Contains(resource, "firewall/vip"):
		return []any{map[string]any{"name": "web", "extip": "203.0.113.10", "extport": "443"}}, nil
	default:
		return []any{}, nil
	}
}

func deskFixture(t *testing.T) (*Service, *deskManager, *focusAnalyzer) {
	t.Helper()
	base := &fakeManager{
		name:  "fmg",
		adoms: []fortinet.ADOM{{Name: "test-adom-branch"}},
		devices: map[string][]fortinet.Device{
			"test-adom-branch": {{Name: "fgt", ADOM: "test-adom-branch", Profile: "fmg", Serial: "FGT123", Hostname: "edge", VDOMs: []string{"root"}}},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-branch": {{Name: "pkg", OID: 42, Members: []fortinet.PackageMember{{Device: "fgt", VDOM: "root"}}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-branch/fgt": {{Name: "lan", IP: "10.1.1.1/24", VDOM: "root"}},
		},
		policies: map[string][]fortinet.FirewallPolicy{
			"test-adom-branch/pkg": {{PolicyID: 4, Name: "lan", Status: "enable", Action: "accept", SourceAddresses: []string{"LAN-users"}, Services: []string{"HTTPS"}, SSLSSHProfile: "deep"}},
		},
	}
	manager := &deskManager{fakeManager: base}
	analyzer := &focusAnalyzer{}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{
		{Name: "fmg", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p", Default: true},
		{Name: "faz", Product: config.ProductFortiAnalyzer, URL: "https://faz.invalid", Username: "u", Password: "p", Default: true, ADOMs: []string{"test-adom-analyzer"}},
	}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	store.Refresh(context.Background())
	manager.interfaceReads.Store(0)
	manager.proxyCalls.Store(0)
	manager.objectReads.Store(0)
	return New(cfg, store, map[string]fortinet.Manager{"fmg": manager}, map[string]fortinet.Analyzer{"faz": analyzer}), manager, analyzer
}

func TestRouteFailureDoesNotRereadInterfaces(t *testing.T) {
	app, manager, _ := deskFixture(t)
	value, err := app.GetInterfaces(context.Background(), "", "", "fgt", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	if result["source"] != "inventory_snapshot" || !strings.Contains(result["data_error"].(string), "list_routes") || manager.interfaceReads.Load() != 0 {
		t.Fatalf("result = %#v reads = %d", result, manager.interfaceReads.Load())
	}
}

func TestMonitorReadsAreReusedAndSessionsAreNot(t *testing.T) {
	app, manager, _ := deskFixture(t)
	if _, err := app.GetFortiManagerSettings(context.Background(), "", "", "fgt", "root", "routing-table"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.GetFortiManagerSettings(context.Background(), "", "", "fgt", "root", "routing-table"); err != nil {
		t.Fatal(err)
	}
	if manager.proxyCalls.Load() != 1 {
		t.Fatalf("routing proxy calls = %d, want 1", manager.proxyCalls.Load())
	}
	before := manager.proxyCalls.Load()
	for range 2 {
		value, err := app.GetFirewallSessions(context.Background(), SessionQuery{DeviceScope: DeviceScope{Device: "fgt"}, SourceIP: "10.1.1.1", Protocol: "tcp"})
		if err != nil {
			t.Fatal(err)
		}
		result := value.(map[string]any)
		sessions := result["sessions"].([]map[string]any)
		if result["filtered_locally"] != true || result["profile"] != "fmg" || len(sessions) != 1 || sessions[0]["policy_id"] != 4 || sessions[0]["snat"] != "198.51.100.10" {
			t.Fatalf("sessions = %#v", result)
		}
		if !strings.Contains(result["sessions"].([]map[string]any)[0]["dst"].(string), "8.8.8.8") {
			t.Fatalf("session = %#v", sessions[0])
		}
	}
	if manager.proxyCalls.Load()-before != 2 {
		t.Fatalf("session proxy calls = %d, want 2", manager.proxyCalls.Load()-before)
	}
}

func TestDeskToolsFilterIdentityVPNHAAndNeighbors(t *testing.T) {
	app, manager, _ := deskFixture(t)
	identity, err := app.ResolveAddressIdentity(context.Background(), AddressIdentityQuery{DeviceScope: DeviceScope{Device: "fgt"}, IP: "10.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	found := identity.(map[string]any)["matches"].(map[string][]map[string]any)
	errors := identity.(map[string]any)["errors"].([]any)
	if len(found["arp"]) != 1 || len(found["dhcp"]) != 0 || len(errors) != 1 {
		t.Fatalf("identity = %#v", identity)
	}
	vpn, err := app.GetVPNStatus(context.Background(), DeviceScope{Device: "fgt"})
	if err != nil {
		t.Fatal(err)
	}
	tunnels := vpn.(map[string]any)["ipsec_tunnels"].([]map[string]any)
	if len(tunnels) != 1 || tunnels[0]["name"] != "hub" || tunnels[0]["status"] != "up" {
		t.Fatalf("vpn = %#v", vpn)
	}
	ha, err := app.GetHAStatus(context.Background(), DeviceScope{Device: "fgt"})
	if err != nil {
		t.Fatal(err)
	}
	if ha.(map[string]any)["checksum_sync"] != true || len(ha.(map[string]any)["peers"].([]map[string]any)) != 2 {
		t.Fatalf("ha = %#v", ha)
	}
	neighbors, err := app.GetRoutingNeighbors(context.Background(), DeviceScope{Device: "fgt"})
	if err != nil {
		t.Fatal(err)
	}
	bgp := neighbors.(map[string]any)["bgp_neighbors"].([]map[string]any)
	sla := neighbors.(map[string]any)["sdwan_sla"].([]map[string]any)
	if len(bgp) != 1 || bgp[0]["state"] != "Established" || len(sla) != 1 || sla[0]["interface"] != "wan1" {
		t.Fatalf("neighbors = %#v", neighbors)
	}
	if _, err := app.GetPackageInstallStatus(context.Background(), DeviceScope{Device: "fgt", VDOM: "root"}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.GetPackageInstallStatus(context.Background(), DeviceScope{Device: "fgt", VDOM: "root"}); err != nil {
		t.Fatal(err)
	}
	if manager.statusCalls.Load() != 1 {
		t.Fatalf("package status reads = %d, want the shared cache", manager.statusCalls.Load())
	}
}

func TestNATPolicyHistoryAndSSLUseCachedReads(t *testing.T) {
	app, manager, _ := deskFixture(t)
	nat, err := app.GetNATMapping(context.Background(), NATQuery{DeviceScope: DeviceScope{Device: "fgt"}, SourceIP: "10.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	snat := nat.(map[string]any)["central_snat"].([]map[string]any)
	pools := nat.(map[string]any)["ippool"].([]map[string]any)
	if len(snat) != 1 || snat[0]["name"] != "snat1" || len(pools) != 0 {
		t.Fatalf("nat = %#v", nat)
	}
	reads := manager.objectReads.Load()
	if _, err := app.GetNATMapping(context.Background(), NATQuery{DeviceScope: DeviceScope{Device: "fgt"}, SourceIP: "10.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if manager.objectReads.Load() != reads {
		t.Fatalf("object reads = %d, want %d from the object cache", manager.objectReads.Load(), reads)
	}
	usage, err := app.GetPolicyUsage(context.Background(), PolicyUsageQuery{DeviceScope: DeviceScope{Device: "fgt"}, PolicyID: 4, Name: "LAN-users"})
	if err != nil {
		t.Fatal(err)
	}
	hits := usage.(map[string]any)["hit_counts"].([]map[string]any)
	used := usage.(map[string]any)["where_used"].([]map[string]any)
	if len(hits) != 1 || hits[0]["hit_count"] != 10 || len(used) == 0 || used[0]["policy_id"] != 4 {
		t.Fatalf("usage = %#v", usage)
	}
	history, err := app.GetPackageHistory(context.Background(), PackageHistoryQuery{DeviceScope: DeviceScope{Device: "fgt"}})
	if err != nil {
		t.Fatal(err)
	}
	record := history.(map[string]any)
	if record["device"] != "fgt" || record["device_record"].(map[string]any)["conf_status"] != "insync" {
		t.Fatalf("history = %#v", record)
	}
	packages := record["packages"].([]map[string]any)
	if len(packages) != 1 || packages[0]["oid"] != int64(42) {
		t.Fatalf("packages = %#v", packages)
	}
	if len(record["errors"].([]any)) == 0 {
		t.Fatal("revision failure should be reported")
	}
	profile, err := app.GetSSLSSHProfile(context.Background(), SSLProfileQuery{Device: "fgt", Name: "deep"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.(map[string]any)["inspection_mode"] != "deep-inspection" {
		t.Fatalf("profile = %#v", profile)
	}
	before := manager.objectReads.Load()
	if _, err := app.GetSSLSSHProfile(context.Background(), SSLProfileQuery{Device: "fgt", Name: "deep"}); err != nil {
		t.Fatal(err)
	}
	if manager.objectReads.Load() != before {
		t.Fatalf("ssl profile was read again (%d -> %d)", before, manager.objectReads.Load())
	}
}

type focusAnalyzer struct {
	reads []string
}

func (a *focusAnalyzer) Name() string { return "faz" }
func (a *focusAnalyzer) Status(context.Context) (any, error) {
	return map[string]any{"version": "7.6"}, nil
}
func (a *focusAnalyzer) SearchLogs(_ context.Context, request fortinet.LogSearchRequest) (fortinet.LogSearchResult, error) {
	return fortinet.LogSearchResult{
		Profile: "faz", ADOM: request.ADOM, Device: request.Device, LogType: request.LogType, Filter: request.Filter,
		TaskID: "9", Count: 2, TotalCount: 4, Limit: request.Limit, Complete: true,
		Records: []any{map[string]any{"srcip": "10.0.0.8"}},
	}, nil
}
func (a *focusAnalyzer) Read(_ context.Context, resource string, _ map[string]any) (any, error) {
	a.reads = append(a.reads, resource)
	if strings.Contains(resource, "/logsearch/count/") {
		return map[string]any{"matched": 4}, nil
	}
	return []any{map[string]any{"devname": "edge-log", "sn": "FGT123", "name": "edge-log"}}, nil
}
func (a *focusAnalyzer) Close() error { return nil }

func TestCountAndDeviceMapOmitRows(t *testing.T) {
	app, _, analyzer := deskFixture(t)
	counted, err := app.CountFortiAnalyzerLogs(context.Background(), LogFocusQuery{ADOM: "test-adom-analyzer", Focus: "deny", Filter: `srcip="10.1.1.1"`})
	if err != nil {
		t.Fatal(err)
	}
	result := counted.(map[string]any)
	if result["log_type"] != "traffic" || !strings.Contains(result["filter"].(string), `action="deny"`) || result["count"].(map[string]any)["matched"] != 4 {
		t.Fatalf("count = %#v", result)
	}
	if _, ok := result["records"]; ok {
		t.Fatalf("count returned rows: %#v", result)
	}
	if len(analyzer.reads) != 1 || !strings.Contains(analyzer.reads[0], "/logsearch/count/9") {
		t.Fatalf("analyzer reads = %#v", analyzer.reads)
	}
	mapped, err := app.MapAnalyzerDevice(context.Background(), AnalyzerDeviceQuery{Device: "fgt"})
	if err != nil {
		t.Fatal(err)
	}
	matches := mapped.(map[string]any)["matches"].([]map[string]any)
	if mapped.(map[string]any)["analyzer_adom"] != "test-adom-analyzer" || mapped.(map[string]any)["analyzer_adom_source"] != "configured" || len(matches) != 1 {
		t.Fatalf("map = %#v", mapped)
	}
	receipt, err := app.GetLogReceipt(context.Background(), LogReceiptQuery{Device: "edge-log"})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.(map[string]any)["adom"] != "test-adom-analyzer" || len(receipt.(map[string]any)["devices"].([]map[string]any)) != 1 {
		t.Fatalf("receipt = %#v", receipt)
	}
}

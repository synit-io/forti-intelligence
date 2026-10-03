package inventory

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

func routeFixtureDevice() fortinet.Device {
	return fortinet.Device{
		Profile: "fmg", ADOM: "test-adom-primary", Name: "edge",
		Interfaces: []fortinet.Interface{
			{Name: "v_ad_clients", VDOM: "root", Zone: "z_ad_clients", Network: "10.49.0.0/22", Networks: []string{"10.49.0.0/22"}},
			{Name: "wan1", VDOM: "root", Zone: "z_wan", Network: "203.0.113.0/30", Networks: []string{"203.0.113.0/30"}},
			{Name: "wan2", VDOM: "root", Network: "198.51.100.0/30", Networks: []string{"198.51.100.0/30"}},
			{Name: "dmz-if", VDOM: "dmz", Network: "172.16.0.0/24", Networks: []string{"172.16.0.0/24"}},
		},
		Routes: []fortinet.Route{
			{Family: "ipv4", VDOM: "root", SeqNum: 1, Destination: "0.0.0.0/0", Gateway: "203.0.113.1", Interface: "wan1", Distance: 10, Priority: 1, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 2, Destination: "0.0.0.0/0", Gateway: "198.51.100.1", Interface: "wan2", Distance: 20, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 3, Destination: "10.0.0.0/8", Gateway: "203.0.113.2", Interface: "wan1", Distance: 10, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 4, Destination: "10.49.0.0/16", Gateway: "198.51.100.2", Interface: "wan2", Distance: 10, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 5, Destination: "192.168.0.0/16", Blackhole: true, Distance: 10, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 6, Destination: "172.20.0.0/16", Interface: "vpn", Distance: 10, Status: "disable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 7, Destination: "8.8.8.0/24", SDWANZone: "virtual-wan-link", Distance: 10, Priority: 5, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 8, Destination: "8.8.8.0/24", Gateway: "203.0.113.9", Interface: "wan1", Distance: 10, Priority: 3, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 9, DstAddrObject: "branch-nets", Interface: "vpn", Status: "enable"},
			{Family: "ipv6", VDOM: "root", SeqNum: 1, Destination: "::/0", Gateway: "2001:db8::1", Interface: "wan1", Distance: 10, Status: "enable"},
			{Family: "ipv4", VDOM: "dmz", SeqNum: 1, Destination: "0.0.0.0/0", Gateway: "172.16.0.1", Interface: "dmz-if", Distance: 10, Status: "enable"},
		},
	}
}

func TestBestRoutesPrefersConnectedThenLongestPrefixThenDistance(t *testing.T) {
	device := routeFixtureDevice()
	cases := []struct {
		ip             string
		vdom           string
		wantKinds      []string
		wantIface      string
		wantOther      int
		wantUnresolved int
	}{
		{"10.49.0.17", "root", []string{"connected"}, "v_ad_clients", 4, 1},
		{"10.7.0.1", "root", []string{"static"}, "wan1", 2, 1},
		{"1.1.1.1", "root", []string{"default"}, "wan1", 1, 1},
		{"192.168.1.1", "root", []string{"blackhole"}, "", 2, 1},
		{"172.20.1.1", "root", []string{"default"}, "wan1", 1, 1},
		{"2001:db8:1::5", "root", []string{"default"}, "wan1", 0, 1},
		{"172.16.0.9", "dmz", []string{"connected"}, "dmz-if", 1, 0},
	}
	for _, testCase := range cases {
		best, unresolved := BestRoutes(device, netip.MustParseAddr(testCase.ip), testCase.vdom)
		if len(best) != len(testCase.wantKinds) {
			t.Fatalf("%s: best = %#v", testCase.ip, best)
		}
		if best[0].Kind != testCase.wantKinds[0] || best[0].Interface != testCase.wantIface || best[0].OtherMatchingRoutes != testCase.wantOther || best[0].Rank != 1 {
			t.Errorf("%s: candidate = %#v", testCase.ip, best[0])
		}
		if unresolved != testCase.wantUnresolved {
			t.Errorf("%s: unresolved object routes = %d, want %d", testCase.ip, unresolved, testCase.wantUnresolved)
		}
	}
	equal, _ := BestRoutes(device, netip.MustParseAddr("8.8.8.8"), "root")
	if len(equal) != 1 || equal[0].EqualCost || equal[0].Priority != 3 || equal[0].OtherMatchingRoutes != 3 {
		t.Fatalf("preferred priority = %#v", equal)
	}
	device.Routes[6].Priority = 3
	equal, _ = BestRoutes(device, netip.MustParseAddr("8.8.8.8"), "root")
	if len(equal) != 2 || !equal[0].EqualCost || equal[0].Interface != "virtual-wan-link" || equal[0].Priority != 3 || equal[0].SDWANZone != "virtual-wan-link" || equal[1].Interface != "wan1" || equal[1].Zone != "z_wan" {
		t.Fatalf("equal-cost tier = %#v", equal)
	}
	all, _ := BestRoutes(device, netip.MustParseAddr("1.1.1.1"), "")
	if len(all) != 2 || all[0].VDOM != "dmz" || all[1].VDOM != "root" {
		t.Fatalf("all VDOMs = %#v", all)
	}
}

type routeRefreshManager struct {
	batchRefreshManager
	routes   map[string][]fortinet.Route
	routeErr error
	targets  []fortinet.RouteTarget
}

func (m *routeRefreshManager) ListRoutesBatch(_ context.Context, _ string, targets []fortinet.RouteTarget) (map[string]fortinet.RouteBatchResult, error) {
	m.targets = append(m.targets, targets...)
	results := make(map[string]fortinet.RouteBatchResult)
	for _, target := range targets {
		if m.routeErr != nil && target.Device == "edge-2" {
			results[target.Device] = fortinet.RouteBatchResult{Err: m.routeErr}
			continue
		}
		results[target.Device] = fortinet.RouteBatchResult{Routes: m.routes[target.Device]}
	}
	return results, nil
}

func TestRefreshCollectsRoutesAndResolvesThem(t *testing.T) {
	manager := &routeRefreshManager{
		batchRefreshManager: batchRefreshManager{devices: []fortinet.Device{{Name: "edge-1"}, {Name: "edge-2"}}},
		routes: map[string][]fortinet.Route{
			"edge-1": {{Family: "ipv4", VDOM: "root", SeqNum: 1, Destination: "0.0.0.0/0", Gateway: "10.0.0.254", Interface: "edge-1-wan", Distance: 10, Status: "enable"}},
			"edge-2": {{Family: "ipv4", VDOM: "root", SeqNum: 1, Destination: "0.0.0.0/0", Gateway: "10.0.0.253", Interface: "edge-2-wan", Distance: 10, Status: "enable"}},
		},
	}
	manager.refreshTestManager.adoms = []fortinet.ADOM{{Name: "test-adom-primary"}}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 2)
	store.Refresh(context.Background())
	if len(manager.targets) != 2 || manager.targets[0].VDOM != "root" || manager.targets[0].IPv6 {
		t.Fatalf("route targets = %#v", manager.targets)
	}
	result, err := store.ResolveRoute(RouteQuery{IP: "8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Ready || len(result.Candidates) != 2 || result.Candidates[0].Device != "edge-1" || result.Candidates[0].Interface != "edge-1-wan" || result.Candidates[0].Kind != "default" || !result.Ambiguous {
		t.Fatalf("route result = %#v", result)
	}
	if scoped, _ := store.ResolveRoute(RouteQuery{IP: "10.0.0.5", Device: "edge-2"}); len(scoped.Candidates) != 1 || scoped.Candidates[0].Kind != "connected" || scoped.Ambiguous {
		t.Fatalf("scoped result = %#v", scoped)
	}
	if _, err := store.ResolveRoute(RouteQuery{IP: "not-an-ip"}); err == nil {
		t.Fatal("invalid ip accepted")
	}

	manager.routeErr = errors.New("fmg API result: code -11: No permission for the resource")
	snapshot := store.Refresh(context.Background())
	var routeErrors []RefreshError
	for _, failure := range snapshot.Errors {
		if failure.Stage == "list_routes" {
			routeErrors = append(routeErrors, failure)
		}
	}
	if len(routeErrors) != 1 || routeErrors[0].Device != "edge-2" || routeErrors[0].Kind != fortinet.ErrorKindPermission {
		t.Fatalf("route errors = %#v", routeErrors)
	}
	for _, device := range snapshot.Devices {
		if device.Name == "edge-2" && len(device.Routes) != 1 {
			t.Fatalf("edge-2 must keep last-known-good routes: %#v", device.Routes)
		}
	}
	result, _ = store.ResolveRoute(RouteQuery{IP: "8.8.8.8", Device: "edge-2"})
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0].Message, "-11") {
		t.Fatalf("scoped errors = %#v", result.Errors)
	}
}

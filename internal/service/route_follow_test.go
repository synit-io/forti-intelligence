package service

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

// multiRouteManager serves the routing tables of several fixture devices.
type multiRouteManager struct {
	*fakeManager
	routed map[string]fortinet.Device
}

func (m *multiRouteManager) ListRoutesBatch(_ context.Context, _ string, targets []fortinet.RouteTarget) (map[string]fortinet.RouteBatchResult, error) {
	result := make(map[string]fortinet.RouteBatchResult)
	for _, target := range targets {
		if device, ok := m.routed[target.Device]; ok {
			result[target.Device] = fortinet.RouteBatchResult{Routes: device.Routes, StaticOK: true, PolicyOK: true, SDWANOK: true}
		}
	}
	return result, nil
}

// twoHopFixture: branch (lan 10.1.0.0/24) routes everything to the hub over
// a transit link; the hub routes to an ISP gateway that is not inventoried.
// The hub also has a lower-distance default over a disabled interface.
func twoHopFixture(t *testing.T) *Service {
	t.Helper()
	branch := fortinet.Device{
		Profile: "fmg", ADOM: "test-adom-primary", Name: "branch", VDOMs: []string{"root"},
		Interfaces: []fortinet.Interface{
			{Name: "lan", VDOM: "root", IP: "10.1.0.1", Network: "10.1.0.0/24", Networks: []string{"10.1.0.0/24"}},
			{Name: "transit", VDOM: "root", IP: "172.16.0.1", Network: "172.16.0.0/30", Networks: []string{"172.16.0.0/30"}},
		},
		Routes: []fortinet.Route{{Family: "ipv4", VDOM: "root", SeqNum: 1, Destination: "0.0.0.0/0", Gateway: "172.16.0.2", Interface: "transit", Distance: 10, Status: "enable"}},
	}
	hub := fortinet.Device{
		Profile: "fmg", ADOM: "test-adom-primary", Name: "hub", VDOMs: []string{"root"},
		Interfaces: []fortinet.Interface{
			{Name: "transit", VDOM: "root", IP: "172.16.0.2", Zone: "z_transit", Network: "172.16.0.0/30", Networks: []string{"172.16.0.0/30"}},
			{Name: "wan", VDOM: "root", IP: "198.51.100.2", Network: "198.51.100.0/24", Networks: []string{"198.51.100.0/24"}},
			{Name: "old-wan", VDOM: "root", IP: "203.0.113.2", Status: "down", Network: "203.0.113.0/24", Networks: []string{"203.0.113.0/24"}},
		},
		Routes: []fortinet.Route{
			{Family: "ipv4", VDOM: "root", SeqNum: 1, Destination: "0.0.0.0/0", Gateway: "198.51.100.1", Interface: "wan", Distance: 10, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 2, Destination: "0.0.0.0/0", Gateway: "203.0.113.1", Interface: "old-wan", Distance: 5, Status: "enable"},
		},
	}
	base := &fakeManager{
		name:       "fmg",
		adoms:      []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices:    map[string][]fortinet.Device{"test-adom-primary": {branch, hub}},
		interfaces: map[string][]fortinet.Interface{"test-adom-primary/branch": branch.Interfaces, "test-adom-primary/hub": hub.Interfaces},
		live:       map[string]fortinet.ProxyResult{},
	}
	manager := &multiRouteManager{fakeManager: base, routed: map[string]fortinet.Device{"branch": branch, "hub": hub}}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p", Default: true}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	store.Refresh(context.Background())
	return New(cfg, store, map[string]fortinet.Manager{"fmg": manager}, nil)
}

func TestResolveRouteFollowsManagedPathToTheInternetEdge(t *testing.T) {
	app := twoHopFixture(t)
	app.resolver = &fakeDNSResolver{ips: []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("2606:2800:220:1::1")}}}
	output, err := app.ResolveRoute(context.Background(), RouteLookupInput{IP: "www.example.com", SourceIP: "10.1.0.10", Protocol: "tcp", DestinationPort: 443, Follow: true})
	if err != nil {
		t.Fatalf("ResolveRoute() error = %v", err)
	}
	if output.DestinationResolution == nil || strings.Join(output.DestinationResolution.EvaluatedAddresses, ",") != "93.184.216.34" || len(output.OtherAddresses) != 0 {
		t.Fatalf("resolution = %#v, want only the IPv4 address evaluated for an IPv4 source", output.DestinationResolution)
	}
	path := output.Path
	if path == nil || len(path.Hops) != 2 || path.Hops[0].Device != "branch" || path.Hops[1].Device != "hub" {
		t.Fatalf("path = %#v, want branch then hub", path)
	}
	if path.End != "leaves_managed_network" || path.LastManagedDevice != "hub" || strings.Join(path.Hops[1].Ingress, ",") != "transit,z_transit" {
		t.Fatalf("path end = %q last = %q ingress = %v", path.End, path.LastManagedDevice, path.Hops[1].Ingress)
	}
	// The hub's lower-distance default uses a disabled interface.
	if strings.Join(path.Hops[1].Gateways, ",") != "198.51.100.1" || !strings.Contains(strings.Join(output.Warnings, " "), "administratively down") {
		t.Fatalf("hub gateways = %v warnings = %v", path.Hops[1].Gateways, output.Warnings)
	}
	// Without follow, the branch decision still names the next FortiGate.
	plain, err := app.ResolveRoute(context.Background(), RouteLookupInput{IP: "93.184.216.34", Device: "branch"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Decisions) != 1 || len(plain.Decisions[0].NextHops) != 1 || plain.Decisions[0].NextHops[0].Device != "hub" || plain.Decisions[0].NextHops[0].Interface != "transit" {
		t.Fatalf("decisions = %#v, want the hub's transit interface as next hop", plain.Decisions)
	}
	if plain.Path != nil {
		t.Fatal("path returned without follow")
	}
}

func TestResolveRouteFollowNeedsAStart(t *testing.T) {
	app := twoHopFixture(t)
	output, err := app.ResolveRoute(context.Background(), RouteLookupInput{IP: "93.184.216.34", Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if output.Path == nil || output.Path.End != "not_resolved" || len(output.Path.Hops) != 0 {
		t.Fatalf("path = %#v, want a clear not_resolved without device or source", output.Path)
	}
}

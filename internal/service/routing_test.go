package service

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

func sdwanDevice() fortinet.Device {
	return fortinet.Device{
		Profile: "fmg-a", ADOM: "test-adom-primary", Name: "branch", VDOMs: []string{"root"},
		Interfaces: []fortinet.Interface{
			{Name: "lan", VDOM: "root", Zone: "z_lan", Network: "10.49.0.0/22", Networks: []string{"10.49.0.0/22"}},
			{Name: "wan1", VDOM: "root", Network: "203.0.113.0/30", Networks: []string{"203.0.113.0/30"}},
			{Name: "wan2", VDOM: "root", Network: "198.51.100.0/30", Networks: []string{"198.51.100.0/30"}},
			{Name: "mpls", VDOM: "root", Zone: "z_mpls", Network: "172.31.0.0/30", Networks: []string{"172.31.0.0/30"}},
		},
		Routes: []fortinet.Route{
			{Family: "ipv4", VDOM: "root", SeqNum: 1, Destination: "0.0.0.0/0", SDWANZone: "underlay", Distance: 1, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 2, Destination: "10.0.0.0/8", Gateway: "172.31.0.1", Interface: "mpls", Distance: 10, Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 3, Destination: "192.0.2.0/24", Blackhole: true, Distance: 10, Status: "enable"},
		},
		PolicyRoutes: []fortinet.PolicyRoute{
			{Family: "ipv4", VDOM: "root", SeqNum: 1, InputDevices: []string{"lan"}, Src: []string{"10.49.1.0/24"}, Dst: []string{"8.8.4.0/24"}, Protocol: 17, StartPort: 53, EndPort: 53, Action: "permit", OutputDevice: "mpls", Gateway: "172.31.0.1", Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 2, Dst: []string{"9.9.9.0/24"}, Action: "deny", Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 3, DstAddr: []string{"partner-net"}, Action: "permit", OutputDevice: "mpls", Status: "enable"},
			{Family: "ipv4", VDOM: "root", SeqNum: 4, Dst: []string{"1.1.1.0/24"}, Action: "permit", OutputDevice: "wan2", Status: "disable"},
		},
		SDWAN: []fortinet.SDWANConfig{{
			VDOM: "root", Status: "enable", Zones: []string{"underlay"},
			Members: []fortinet.SDWANMember{
				{SeqNum: 1, Interface: "wan1", Zone: "underlay", Gateway: "203.0.113.1", Status: "enable"},
				{SeqNum: 2, Interface: "wan2", Zone: "underlay", Gateway: "198.51.100.1", Status: "enable"},
			},
			Rules: []fortinet.SDWANRule{
				{ID: 1, Name: "o365", Mode: "sla", Dst: []string{"o365-net"}, PriorityMembers: []int{2, 1}},
				{ID: 2, Name: "voice", Mode: "manual", Dst: []string{"all"}, Protocol: 17, StartPort: 5060, EndPort: 5061, PriorityMembers: []int{1}},
			},
		}},
	}
}

func TestEvaluateRoutingFollowsFortiOSPrecedence(t *testing.T) {
	device := sdwanDevice()
	resolver := newAddressResolver([]fortinet.AddressObject{
		{Name: "partner-net", Subnet: "100.64.0.0 255.255.0.0"},
		{Name: "o365-net", Subnet: "52.96.0.0 255.240.0.0"},
	})
	tuple := func(src, dst string, protocol, port int, ingress ...string) routeTuple {
		value := routeTuple{dst: netip.MustParseAddr(dst), protocol: protocol, dstPort: port, ingress: ingress}
		if src != "" {
			value.src = netip.MustParseAddr(src)
		}
		return value
	}

	decision := evaluateRouting(device, "root", tuple("10.49.1.5", "8.8.4.4", 17, 53, "lan", "z_lan"), resolver)
	if decision.Stage != "policy_route" || decision.PolicyRoute.SeqNum != 1 || strings.Join(decision.EgressInterfaces, ",") != "mpls" || strings.Join(decision.EgressZones, ",") != "z_mpls" || decision.Confidence != "configured" {
		t.Fatalf("policy route decision = %#v", decision)
	}
	// Same flow without protocol: the protocol condition is undecidable, so
	// the route is tentative and the SD-WAN implicit rule applies.
	decision = evaluateRouting(device, "root", tuple("10.49.1.5", "8.8.4.4", 0, 0, "lan"), resolver)
	if decision.Stage != "routing_table" || decision.Confidence != "tentative" || !strings.Contains(strings.Join(decision.Notes, " "), "Policy route 1 may match (protocol unknown)") {
		t.Fatalf("tentative decision = %#v", decision)
	}
	if strings.Join(decision.EgressInterfaces, ",") != "wan1,wan2" || strings.Join(decision.EgressZones, ",") != "underlay" || strings.Join(decision.Gateways, ",") != "198.51.100.1,203.0.113.1" {
		t.Fatalf("implicit SD-WAN egress = %#v", decision)
	}
	decision = evaluateRouting(device, "root", tuple("", "9.9.9.9", 6, 443), resolver)
	if decision.Stage != "routing_table" || !strings.Contains(strings.Join(decision.Notes, " "), "action deny") || decision.SDWANRule != nil {
		t.Fatalf("deny decision = %#v", decision)
	}
	decision = evaluateRouting(device, "root", tuple("", "100.64.3.3", 6, 443), resolver)
	if decision.Stage != "policy_route" || decision.PolicyRoute.SeqNum != 3 {
		t.Fatalf("object policy route = %#v", decision)
	}
	decision = evaluateRouting(device, "root", tuple("", "100.64.3.3", 6, 443), nil)
	if decision.Stage == "policy_route" || decision.Confidence != "tentative" || !strings.Contains(strings.Join(decision.Notes, " "), "address object not resolvable") {
		t.Fatalf("unresolvable object route = %#v", decision)
	}
	decision = evaluateRouting(device, "root", tuple("", "52.97.1.1", 6, 443), resolver)
	if decision.Stage != "sdwan_rule" || decision.SDWANRule.ID != 1 || decision.SDWANRule.Members[0].Interface != "wan2" || strings.Join(decision.EgressInterfaces, ",") != "wan1,wan2" || !strings.Contains(decision.SDWANRule.Selection, "SLA") {
		t.Fatalf("sla rule = %#v", decision)
	}
	decision = evaluateRouting(device, "root", tuple("", "1.1.1.1", 17, 5060), resolver)
	if decision.Stage != "sdwan_rule" || decision.SDWANRule.ID != 2 || strings.Join(decision.EgressInterfaces, ",") != "wan1" || !strings.Contains(decision.SDWANRule.Selection, "Manual") {
		t.Fatalf("manual rule = %#v", decision)
	}
	decision = evaluateRouting(device, "root", tuple("", "1.1.1.1", 0, 0), resolver)
	if decision.Stage != "routing_table" || decision.Confidence != "tentative" || !strings.Contains(strings.Join(decision.Notes, " "), "SD-WAN rule 2") {
		t.Fatalf("disabled policy route and tentative voice rule = %#v", decision)
	}
	decision = evaluateRouting(device, "root", tuple("", "10.20.0.1", 6, 443), resolver)
	if decision.Stage != "routing_table" || strings.Join(decision.EgressInterfaces, ",") != "mpls" || decision.SDWANRule != nil {
		t.Fatalf("non SD-WAN route must skip SD-WAN rules: %#v", decision)
	}
	decision = evaluateRouting(device, "root", tuple("", "192.0.2.9", 6, 443), resolver)
	if decision.Stage != "blackhole" {
		t.Fatalf("blackhole = %#v", decision)
	}
	decision = evaluateRouting(fortinet.Device{Name: "empty"}, "root", tuple("", "192.0.2.9", 6, 443), nil)
	if decision.Stage != "no_route" {
		t.Fatalf("no route = %#v", decision)
	}
}

func TestResolveRouteAndPolicyLookupUseSDWANZones(t *testing.T) {
	device := sdwanDevice()
	manager := &fakeManager{
		name:       "fmg-a",
		adoms:      []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices:    map[string][]fortinet.Device{"test-adom-primary": {device}},
		interfaces: map[string][]fortinet.Interface{"test-adom-primary/branch": device.Interfaces},
		packages:   map[string][]fortinet.PolicyPackage{"test-adom-primary": {{Name: "default", Members: []fortinet.PackageMember{{Device: "branch", VDOM: "root"}}}}},
		policies: map[string][]fortinet.FirewallPolicy{"test-adom-primary/default": {
			{PolicyID: 1, Status: "enable", Action: "accept", SourceInterfaces: []string{"z_lan"}, DestinationInterfaces: []string{"underlay"}, SourceAddresses: []string{"all"}, DestinationAddresses: []string{"all"}, Services: []string{"HTTPS"}},
			{PolicyID: 2, Status: "enable", Action: "accept", SourceInterfaces: []string{"z_lan"}, DestinationInterfaces: []string{"z_mpls"}, SourceAddresses: []string{"all"}, DestinationAddresses: []string{"all"}, Services: []string{"HTTPS"}},
		}},
		addresses: map[string][]fortinet.AddressObject{"test-adom-primary": {{Name: "o365-net", Subnet: "52.96.0.0 255.240.0.0"}, {Name: "partner-net", Subnet: "100.64.0.0 255.255.0.0"}}},
		live:      map[string]fortinet.ProxyResult{},
	}
	routes := &routeInventoryManager{fakeManager: manager, device: device}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p", Default: true}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": routes}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-a": routes}, nil)

	route, err := app.ResolveRoute(context.Background(), RouteLookupInput{IP: "52.97.1.1", SourceIP: "10.49.1.5", Protocol: "tcp", DestinationPort: 443})
	if err != nil {
		t.Fatalf("ResolveRoute() error = %v", err)
	}
	if len(route.Decisions) != 1 || route.Decisions[0].Stage != "sdwan_rule" || route.Decisions[0].SDWANRule.Name != "o365" || !strings.Contains(strings.Join(route.Decisions[0].Notes, " "), "ADOM values") {
		t.Fatalf("decisions = %#v", route.Decisions)
	}
	if _, err := app.ResolveRoute(context.Background(), RouteLookupInput{IP: "52.97.1.1", SourceIP: "2001:db8::1"}); err == nil {
		t.Fatal("mixed families accepted")
	}
	if _, err := app.ResolveRoute(context.Background(), RouteLookupInput{IP: "52.97.1.1", Protocol: "bogus"}); err == nil {
		t.Fatal("invalid protocol accepted")
	}

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{SourceIP: "10.49.1.5", DestinationIP: "52.97.1.1", DestinationPort: 443, Protocol: "tcp"})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	candidate := output.CandidateDevices[0]
	if strings.Join(candidate.DestinationZones, ",") != "underlay" || len(candidate.Routing) != 1 || candidate.Routing[0].Stage != "sdwan_rule" {
		t.Fatalf("candidate = %#v", candidate)
	}
	if len(output.Matches) != 1 || output.Matches[0].Policy.PolicyID != 1 {
		t.Fatalf("matches = %#v, want the SD-WAN zone policy only", output.Matches)
	}
	partner, err := app.LookupPolicies(context.Background(), PolicyLookupInput{SourceIP: "10.49.1.5", DestinationIP: "100.64.3.3", DestinationPort: 443, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(partner.Matches) != 1 || partner.Matches[0].Policy.PolicyID != 2 || partner.CandidateDevices[0].Routing[0].Stage != "policy_route" {
		t.Fatalf("partner matches = %#v routing=%#v", partner.Matches, partner.CandidateDevices[0].Routing)
	}
}

// routeInventoryManager serves the fixture's routing tables to inventory.
type routeInventoryManager struct {
	*fakeManager
	device fortinet.Device
}

func (m *routeInventoryManager) ListRoutesBatch(_ context.Context, _ string, targets []fortinet.RouteTarget) (map[string]fortinet.RouteBatchResult, error) {
	result := make(map[string]fortinet.RouteBatchResult)
	for _, target := range targets {
		if target.Device == m.device.Name {
			result[target.Device] = fortinet.RouteBatchResult{Routes: m.device.Routes, PolicyRoutes: m.device.PolicyRoutes, SDWAN: m.device.SDWAN}
		}
	}
	return result, nil
}

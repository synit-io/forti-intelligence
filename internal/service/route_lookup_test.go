package service

import (
	"context"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

func TestLookupPoliciesDerivesDestinationInterfaceFromConfiguredRoutes(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-a",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary"}},
		interfaces: map[string][]fortinet.Interface{"test-adom-primary/edge-1": {
			{Name: "lan", VDOM: "root", Zone: "z_lan", IP: "10.49.0.1", Netmask: "255.255.252.0", Network: "10.49.0.0/22", Networks: []string{"10.49.0.0/22"}},
			{Name: "wan1", VDOM: "root", Zone: "z_wan", IP: "203.0.113.2", Netmask: "255.255.255.252", Network: "203.0.113.0/30", Networks: []string{"203.0.113.0/30"}},
			{Name: "wan2", VDOM: "root", IP: "198.51.100.2", Netmask: "255.255.255.252", Network: "198.51.100.0/30", Networks: []string{"198.51.100.0/30"}},
		}},
		devices: map[string][]fortinet.Device{"test-adom-primary": {{
			Name: "edge-1", ADOM: "test-adom-primary", Profile: "fmg-a", VDOMs: []string{"root"},
			Routes: []fortinet.Route{
				{Family: "ipv4", VDOM: "root", SeqNum: 1, Destination: "0.0.0.0/0", Gateway: "203.0.113.1", Interface: "wan1", Distance: 10, Status: "enable"},
				{Family: "ipv4", VDOM: "root", SeqNum: 2, Destination: "0.0.0.0/0", Gateway: "198.51.100.1", Interface: "wan2", Distance: 20, Status: "enable"},
			},
			Packages: []string{"default"}, PackageTargets: []fortinet.PackageTarget{{Package: "default", VDOM: "root"}},
		}}},
		packages: map[string][]fortinet.PolicyPackage{"test-adom-primary": {{Name: "default", Members: []fortinet.PackageMember{{Device: "edge-1", VDOM: "root"}}}}},
		policies: map[string][]fortinet.FirewallPolicy{"test-adom-primary/default": {
			{PolicyID: 1, Status: "enable", Action: "accept", SourceInterfaces: []string{"z_lan"}, DestinationInterfaces: []string{"z_wan"}, SourceAddresses: []string{"all"}, DestinationAddresses: []string{"all"}, Services: []string{"DNS"}},
			{PolicyID: 2, Status: "enable", Action: "accept", SourceInterfaces: []string{"z_lan"}, DestinationInterfaces: []string{"wan2"}, SourceAddresses: []string{"all"}, DestinationAddresses: []string{"all"}, Services: []string{"DNS"}},
		}},
		live: map[string]fortinet.ProxyResult{},
	}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p", Default: true}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-a": manager}, nil)

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{SourceIP: "10.49.0.17", DestinationIP: "8.8.8.8", DestinationPort: 53, Protocol: "udp"})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	if len(output.CandidateDevices) != 1 {
		t.Fatalf("candidates = %#v", output.CandidateDevices)
	}
	candidate := output.CandidateDevices[0]
	if strings.Join(candidate.DestinationInterfaces, ",") != "wan1" || strings.Join(candidate.DestinationZones, ",") != "z_wan" || len(candidate.Routing) != 1 || candidate.Routing[0].Stage != "routing_table" || strings.Join(candidate.Routing[0].Gateways, ",") != "203.0.113.1" || candidate.Routing[0].Routes[0].Kind != "default" {
		t.Fatalf("candidate = %#v", candidate)
	}
	if !strings.Contains(strings.Join(candidate.Warnings, " "), "derived from configured routing") {
		t.Fatalf("candidate warnings = %v", candidate.Warnings)
	}
	if len(output.Matches) != 1 || output.Matches[0].Policy.PolicyID != 1 {
		t.Fatalf("matches = %#v, want only the z_wan policy", output.Matches)
	}

	// A directly connected destination keeps the connected interface and adds no route evidence.
	connected, err := app.LookupPolicies(context.Background(), PolicyLookupInput{SourceIP: "10.49.0.17", DestinationIP: "198.51.100.1", DestinationPort: 53, Protocol: "udp"})
	if err != nil {
		t.Fatal(err)
	}
	if c := connected.CandidateDevices[0]; strings.Join(c.DestinationInterfaces, ",") != "wan2" || len(c.Routing) != 0 {
		t.Fatalf("connected candidate = %#v", c)
	}

	// Route evidence never creates a candidate on its own.
	fallback, err := app.LookupPolicies(context.Background(), PolicyLookupInput{SourceIP: "192.0.2.10", DestinationIP: "8.8.8.8", DestinationPort: 53, Protocol: "udp"})
	if err != nil {
		t.Fatal(err)
	}
	if c := fallback.CandidateDevices[0]; c.Resolution != "fallback-all-inventory-devices" || len(c.Routing) != 0 {
		t.Fatalf("fallback candidate = %#v", c)
	}

	route, err := app.ResolveRoute(context.Background(), RouteLookupInput{IP: "8.8.8.8", Device: "edge-1"})
	if err != nil || len(route.Candidates) != 1 || route.Candidates[0].Interface != "wan1" || route.Candidates[0].OtherMatchingRoutes != 1 || len(route.Decisions) != 1 || route.Decisions[0].Stage != "routing_table" {
		t.Fatalf("ResolveRoute() = %#v, %v", route, err)
	}
	status, err := app.ListFortiGates(context.Background(), "", "", false, false, false)
	if err != nil || status.Devices[0].Routes != nil {
		t.Fatalf("routes must be omitted by default: %#v %v", status.Devices[0].Routes, err)
	}
	status, _ = app.ListFortiGates(context.Background(), "", "", false, true, false)
	if len(status.Devices[0].Routes) != 2 {
		t.Fatalf("include_routes = %#v", status.Devices[0].Routes)
	}
}

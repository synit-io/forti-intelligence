package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

func TestSourcePortBoundsGroupsAndNegation(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp", "sctp"} {
		for _, test := range []struct {
			name       string
			port       int
			negate     bool
			policyID   int
			confidence string
		}{
			{"outside", 53, false, 2, "likely"},
			{"lower bound", 1024, false, 1, "likely"},
			{"upper bound", 65535, false, 1, "likely"},
			{"unknown", 0, false, 1, "tentative"},
			{"negated inside", 1024, true, 2, "likely"},
			{"negated outside", 53, true, 1, "likely"},
			{"negated unknown", 0, true, 1, "tentative"},
		} {
			t.Run(protocol+"/"+test.name, func(t *testing.T) {
				first := lanToWAN(1, "accept", "group")
				first.ServiceNegate = test.negate
				app, _ := lookupFixture(t, []fortinet.FirewallPolicy{first, lanToWAN(2, "deny", "ALL")}, nil, []fortinet.ServiceObject{
					{Name: "group", Members: []string{"restricted"}},
					{Name: "restricted", Protocol: "TCP/UDP/SCTP", TCPPortRange: "443:1024-65535", UDPPortRange: "443:1024-65535", SCTPPortRange: "443:1024-65535"},
				})
				out := lookup(t, app, PolicyLookupInput{Protocol: protocol, SourcePort: test.port})
				if len(out.Decisions) != 1 || out.Decisions[0].PolicyID != test.policyID || out.Decisions[0].Confidence != test.confidence {
					t.Fatalf("decisions=%+v", out.Decisions)
				}
			})
		}
	}
	app, _ := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(1, "accept", "paired")}, nil, []fortinet.ServiceObject{
		{Name: "paired", Protocol: "TCP", TCPPortRange: "443:1000-2000 443:3000-4000"},
	})
	out := lookup(t, app, PolicyLookupInput{SourcePort: 3500})
	if out.Decisions[0].PolicyID != 1 {
		t.Fatalf("second paired range ignored: %+v", out.Decisions)
	}
}

func TestDNSMixedConnectedAndRoutedDestinations(t *testing.T) {
	app, base := lookupFixture(t, nil, nil, nil)
	base.interfaces["test-adom-primary/fgt"] = append(base.interfaces["test-adom-primary/fgt"], fortinet.Interface{Name: "wan2", VDOM: "root", Networks: []string{"198.51.100.0/24"}})
	base.devices["test-adom-primary"][0].Routes = []fortinet.Route{
		{Family: "ipv4", VDOM: "root", Destination: "8.8.8.8/32", Interface: "wan2", Gateway: "198.51.100.1", Distance: 10},
	}
	deny := lanToWAN(2, "deny", "ALL")
	deny.DestinationInterfaces = []string{"wan2"}
	base.policies["test-adom-primary/pkg"] = []fortinet.FirewallPolicy{lanToWAN(1, "accept", "ALL"), deny}
	manager := &trafficRouteManager{fakeManager: base}
	app = trafficRoutingService(t, map[string]fortinet.Manager{"fmg": manager})
	app.resolver = &fakeDNSResolver{ips: []net.IPAddr{{IP: net.ParseIP("203.0.113.50")}, {IP: net.ParseIP("8.8.8.8")}}}
	out := lookup(t, app, PolicyLookupInput{DestinationIP: "mixed.example", SourceInterface: "lan"})
	if len(out.Decisions) != 2 {
		t.Fatalf("decisions=%+v", out.Decisions)
	}
	for _, decision := range out.Decisions {
		expected := 1
		if decision.DestinationIP == "8.8.8.8" {
			expected = 2
		}
		if decision.PolicyID != expected {
			t.Fatalf("destination borrowed another egress: %+v", out.Decisions)
		}
	}
}

func TestPolicyLookupSeparatesOverlappingVDOMs(t *testing.T) {
	app, manager := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(7, "accept", "ALL")}, nil, nil)
	manager.devices["test-adom-primary"][0].VDOMs = []string{"root", "blue"}
	manager.interfaces["test-adom-primary/fgt"] = append(manager.interfaces["test-adom-primary/fgt"],
		fortinet.Interface{Name: "blue-lan", IP: "10.0.0.1/24", VDOM: "blue"},
		fortinet.Interface{Name: "blue-wan", IP: "203.0.113.1/24", VDOM: "blue"},
	)
	manager.packages["test-adom-primary"] = append(manager.packages["test-adom-primary"], fortinet.PolicyPackage{Name: "blue-pkg", Members: []fortinet.PackageMember{{Device: "fgt", VDOM: "blue"}}})
	policy := lanToWAN(9, "deny", "ALL")
	policy.SourceInterfaces, policy.DestinationInterfaces = []string{"blue-lan"}, []string{"blue-wan"}
	manager.policies["test-adom-primary/blue-pkg"] = []fortinet.FirewallPolicy{policy}
	manager.live["test-adom-primary/fgt/root/lan/tcp"] = fortinet.ProxyResult{Data: map[string]any{"policyid": float64(7)}}
	manager.live["test-adom-primary/fgt/blue/blue-lan/tcp"] = fortinet.ProxyResult{Data: map[string]any{"policyid": float64(9)}}
	app.store.Refresh(context.Background())
	out := lookup(t, app, PolicyLookupInput{})
	if len(out.Decisions) != 2 || len(out.LiveLookups) != 2 {
		t.Fatalf("overlap collapsed: %+v", out)
	}
	for _, decision := range out.Decisions {
		if decision.VDOM == "blue" && decision.PolicyID != 9 || decision.VDOM == "root" && decision.PolicyID != 7 {
			t.Fatalf("decision crossed VDOMs: %+v", decision)
		}
	}
	for _, live := range out.LiveLookups {
		if live.Agreement != "agrees" {
			t.Fatalf("wrong scoped comparison: %+v", live)
		}
	}
	for _, candidate := range out.CandidateDevices {
		if len(candidate.VDOMs) != 1 || len(candidate.PackageTargets) != 1 || candidate.PackageTargets[0].VDOM != candidate.VDOMs[0] || len(candidate.Packages) != 1 {
			t.Fatalf("candidate package scope crossed VDOMs: %+v", candidate)
		}
	}
	scoped := lookup(t, app, PolicyLookupInput{VDOM: "blue"})
	if len(scoped.Decisions) != 1 || scoped.Decisions[0].VDOM != "blue" || scoped.Decisions[0].PolicyID != 9 {
		t.Fatalf("explicit VDOM ignored: %+v", scoped.Decisions)
	}
}

func TestRouteFollowRequiresUniqueVDOM(t *testing.T) {
	manager := trafficEdge("fmg")
	manager.devices["test-adom-primary"][0].VDOMs = []string{"root", "blue"}
	manager.interfaces["test-adom-primary/edge"] = append(manager.interfaces["test-adom-primary/edge"],
		fortinet.Interface{Name: "blue-lan", VDOM: "blue", Networks: []string{"10.0.0.0/24"}},
		fortinet.Interface{Name: "blue-wan", VDOM: "blue", Networks: []string{"198.51.100.0/24"}},
	)
	manager.devices["test-adom-primary"][0].Routes = append(manager.devices["test-adom-primary"][0].Routes,
		fortinet.Route{Family: "ipv4", VDOM: "blue", Destination: "0.0.0.0/0", Interface: "blue-wan", Gateway: "198.51.100.1", Distance: 10},
	)
	app := trafficRoutingService(t, map[string]fortinet.Manager{"fmg": manager})
	input := RouteLookupInput{IP: "8.8.8.8", SourceIP: "10.0.0.42", Device: "edge", Follow: true}
	out, err := app.ResolveRoute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if out.Path.End != "not_resolved" || len(out.Path.Hops) != 0 {
		t.Fatalf("VDOM silently selected: %+v", out.Path)
	}
	input.VDOM = "blue"
	out, err = app.ResolveRoute(context.Background(), input)
	if err != nil || len(out.Path.Hops) != 1 || out.Path.Hops[0].VDOM != "blue" {
		t.Fatalf("explicit VDOM=%+v %v", out.Path, err)
	}
	input.VDOM, input.SourceInterface = "", "blue-lan"
	out, err = app.ResolveRoute(context.Background(), input)
	if err != nil || len(out.Path.Hops) != 1 || out.Path.Hops[0].VDOM != "blue" {
		t.Fatalf("ingress VDOM=%+v %v", out.Path, err)
	}
	input.VDOM, input.SourceInterface = "blue", "lan"
	out, err = app.ResolveRoute(context.Background(), input)
	if err != nil || out.Path.End != "not_resolved" || len(out.Path.Hops) != 0 {
		t.Fatalf("ingress from another VDOM accepted: %+v %v", out.Path, err)
	}
}

func TestTentativeRoutingPrecedesEveryTerminalReason(t *testing.T) {
	for _, terminal := range []string{"external gateway", "connected", "blackhole", "no route"} {
		t.Run(terminal, func(t *testing.T) {
			manager := trafficEdge("fmg")
			destination := "8.8.8.8"
			switch terminal {
			case "connected":
				destination = "203.0.113.50"
			case "blackhole":
				manager.devices["test-adom-primary"][0].Routes = []fortinet.Route{{Family: "ipv4", VDOM: "root", Destination: "0.0.0.0/0", Blackhole: true, Distance: 10}}
			case "no route":
				manager.devices["test-adom-primary"][0].Routes = nil
			}
			manager.devices["test-adom-primary"][0].PolicyRoutes = []fortinet.PolicyRoute{{VDOM: "root", SeqNum: 1, Protocol: 6, StartSourcePort: 1024, EndSourcePort: 65535, OutputDevice: "wan", Gateway: "203.0.113.3"}}
			app := trafficRoutingService(t, map[string]fortinet.Manager{"fmg": manager})
			input := RouteLookupInput{IP: destination, SourceIP: "10.0.0.42", Protocol: "tcp", DestinationPort: 443, Follow: true}
			out, err := app.ResolveRoute(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if out.Path.End != "tentative_decision" || !strings.Contains(strings.Join(out.Path.Hops[0].Notes, " "), "source port range") {
				t.Fatalf("path=%+v", out.Path)
			}
			input.SourcePort = 1024
			out, err = app.ResolveRoute(context.Background(), input)
			if err != nil || out.Path.Hops[0].Stage != "policy_route" || out.Path.Hops[0].Confidence != "configured" {
				t.Fatalf("source-port condition not resolved: %+v %v", out.Path, err)
			}
		})
	}
}

func TestLiveLookupCacheBoundsActiveEntries(t *testing.T) {
	app, _ := lookupFixture(t, nil, nil, nil)
	created := time.Now().Add(-10 * time.Second)
	for i := range maxLiveLookupEntries {
		app.liveLookupCache[fmt.Sprint(i)] = liveLookupEntry{created: created.Add(time.Duration(i)), result: fortinet.ProxyResult{Data: "existing"}}
	}
	calls := 0
	read := func() (fortinet.ProxyResult, error) { calls++; return fortinet.ProxyResult{Data: "new"}, nil }
	for range 2 {
		if _, err := app.cachedPolicyLookup(context.Background(), "new", read); err != nil {
			t.Fatal(err)
		}
	}
	if len(app.liveLookupCache) != maxLiveLookupEntries || calls != 1 {
		t.Fatalf("cache size=%d reads=%d", len(app.liveLookupCache), calls)
	}
	if _, exists := app.liveLookupCache["0"]; exists {
		t.Fatal("oldest active entry was retained")
	}
}

func TestLiveComparisonRequiresUniquePackage(t *testing.T) {
	id := 7
	entry := LivePolicyLookup{Profile: "fmg", ADOM: "test-adom-primary", Device: "edge", VDOM: "root", DestinationIP: "8.8.8.8", PolicyID: &id}
	out := PolicyLookupOutput{Decisions: []PolicyDecision{
		{Profile: "fmg", ADOM: "test-adom-primary", Device: "edge", VDOM: "root", DestinationIP: "8.8.8.8", Package: "a", PolicyID: 7, Action: "accept"},
		{Profile: "fmg", ADOM: "test-adom-primary", Device: "edge", VDOM: "root", DestinationIP: "8.8.8.8", Package: "b", PolicyID: 8, Action: "deny"},
	}}
	reconcileLive(&entry, &out)
	if entry.Agreement != "ambiguous_configured_verdict" || entry.StaticFirstMatch != nil {
		t.Fatalf("package chosen silently: %+v", entry)
	}
	out.Decisions[1].Action = "unknown"
	reconcileLive(&entry, &out)
	if entry.Agreement != "ambiguous_configured_verdict" || entry.StaticFirstMatch != nil {
		t.Fatalf("unread package was discarded: %+v", entry)
	}
}

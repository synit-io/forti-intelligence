package service

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

func TestStaticServiceHonorsSourcePorts(t *testing.T) {
	app, _ := lookupFixture(t, []fortinet.FirewallPolicy{
		lanToWAN(1, "accept", "restricted-https"), lanToWAN(2, "deny", "ALL"),
	}, nil, []fortinet.ServiceObject{{Name: "restricted-https", Protocol: "TCP/UDP/SCTP", TCPPortRange: "443:1024-65535"}})
	out := lookup(t, app, PolicyLookupInput{SourcePort: 53})
	if len(out.Decisions) != 1 || out.Decisions[0].PolicyID != 2 {
		t.Fatalf("source port 53 outside 1024-65535: decisions=%+v; want deny policy 2", out.Decisions)
	}
}

func TestPolicyDNSAddressesHaveIndependentEgress(t *testing.T) {
	deny := lanToWAN(2, "deny", "ALL")
	deny.DestinationInterfaces = []string{"dmz"}
	app, _ := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(1, "accept", "ALL"), deny}, nil, nil)
	app.resolver = &fakeDNSResolver{ips: []net.IPAddr{{IP: net.ParseIP("203.0.113.50")}, {IP: net.ParseIP("10.0.5.50")}}}
	out := lookup(t, app, PolicyLookupInput{DestinationIP: "multi.example"})
	if len(out.Decisions) != 2 {
		t.Fatalf("decisions=%+v; want both DNS addresses", out.Decisions)
	}
	for _, decision := range out.Decisions {
		if decision.DestinationIP == "10.0.5.50" && decision.PolicyID != 2 {
			t.Fatalf("dmz destination selected WAN policy: decisions=%+v; want dmz deny policy 2", out.Decisions)
		}
	}
}

type trafficRouteManager struct {
	*fakeManager
}

func (m *trafficRouteManager) ListRoutesBatch(_ context.Context, adom string, targets []fortinet.RouteTarget) (map[string]fortinet.RouteBatchResult, error) {
	results := make(map[string]fortinet.RouteBatchResult)
	for _, target := range targets {
		for _, device := range m.devices[adom] {
			if device.Name == target.Device {
				results[target.Device] = fortinet.RouteBatchResult{Routes: device.Routes, PolicyRoutes: device.PolicyRoutes, StaticOK: true, PolicyOK: true, SDWANOK: true}
			}
		}
	}
	return results, nil
}

func trafficRoutingService(t *testing.T, managers map[string]fortinet.Manager) *Service {
	t.Helper()
	cfg := config.Default()
	for name := range managers {
		cfg.Profiles = append(cfg.Profiles, config.ProfileConfig{Name: name, Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"})
	}
	store := inventory.NewStore(managers, 0, 1)
	store.Refresh(context.Background())
	return New(cfg, store, managers, nil)
}

func trafficEdge(name string) *trafficRouteManager {
	ifaces := []fortinet.Interface{{Name: "lan", IP: "10.0.0.1/24", Networks: []string{"10.0.0.0/24"}, VDOM: "root"}, {Name: "wan", IP: "203.0.113.2/24", Networks: []string{"203.0.113.0/24"}, VDOM: "root"}}
	device := fortinet.Device{Name: "edge", Profile: name, ADOM: "test-adom-primary", VDOMs: []string{"root"}, Routes: []fortinet.Route{{Family: "ipv4", VDOM: "root", Destination: "0.0.0.0/0", Gateway: "203.0.113.1", Interface: "wan", Distance: 10, Status: "enable"}}}
	return &trafficRouteManager{fakeManager: &fakeManager{name: name, adoms: []fortinet.ADOM{{Name: "test-adom-primary"}}, devices: map[string][]fortinet.Device{"test-adom-primary": {device}}, interfaces: map[string][]fortinet.Interface{"test-adom-primary/edge": ifaces}}}
}

func TestRouteFollowRequiresUniqueDeviceScope(t *testing.T) {
	app := trafficRoutingService(t, map[string]fortinet.Manager{"fmg-a": trafficEdge("fmg-a"), "fmg-b": trafficEdge("fmg-b")})
	out, err := app.ResolveRoute(context.Background(), RouteLookupInput{IP: "8.8.8.8", Device: "edge", Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Path != nil && len(out.Path.Hops) > 0 {
		t.Fatalf("ambiguous=%v yet chose %+v; want unresolved starting scope", out.Ambiguous, out.Path.Hops[0])
	}
}

func TestRouteFollowStopsOnTentativeTerminal(t *testing.T) {
	manager := trafficEdge("fmg")
	manager.devices["test-adom-primary"][0].PolicyRoutes = []fortinet.PolicyRoute{{VDOM: "root", SeqNum: 1, Protocol: 6, StartSourcePort: 1024, EndSourcePort: 65535, Gateway: "203.0.113.3", OutputDevice: "wan", Status: "enable"}}
	app := trafficRoutingService(t, map[string]fortinet.Manager{"fmg": manager})
	out, err := app.ResolveRoute(context.Background(), RouteLookupInput{IP: "8.8.8.8", SourceIP: "10.0.0.42", Protocol: "tcp", DestinationPort: 443, Device: "edge", Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Path == nil || len(out.Path.Hops) != 1 || out.Path.Hops[0].Confidence != "tentative" {
		t.Fatalf("unexpected fixture result: %+v", out.Path)
	}
	if out.Path.End != "tentative_decision" {
		t.Fatalf("tentative hop ended as %q: %s", out.Path.End, out.Path.Note)
	}
}

func TestRefreshSeparatesLiveLookupFlights(t *testing.T) {
	app, _ := lookupFixture(t, nil, nil, nil)
	oldStarted, releaseOld := make(chan struct{}), make(chan struct{})
	oldDone := make(chan struct{})
	go func() {
		defer close(oldDone)
		_, _ = app.cachedPolicyLookup(context.Background(), "same-flow", func() (fortinet.ProxyResult, error) {
			close(oldStarted)
			<-releaseOld
			return fortinet.ProxyResult{Data: "old"}, nil
		})
	}()
	<-oldStarted
	if _, err := app.RefreshInventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	freshStarted := make(chan struct{})
	freshResult := make(chan fortinet.ProxyResult, 1)
	go func() {
		result, _ := app.cachedPolicyLookup(context.Background(), "same-flow", func() (fortinet.ProxyResult, error) {
			close(freshStarted)
			return fortinet.ProxyResult{Data: "fresh"}, nil
		})
		freshResult <- result
	}()
	select {
	case <-freshStarted:
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseOld)
	<-oldDone
	if result := <-freshResult; result.Data != "fresh" {
		t.Fatalf("post-refresh caller received %v from pre-refresh flight", result.Data)
	}
}

func TestInvestigateUsesResolvedWebsiteScope(t *testing.T) {
	app, manager := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(1, "accept", "ALL")}, nil, nil)
	manager.interfaces["test-adom-primary/fgt"][0].Networks = []string{"10.0.0.0/24"}
	manager.interfaces["test-adom-primary/fgt"][2].Networks = []string{"203.0.113.0/24"}
	app.store.Refresh(context.Background())
	out, err := app.Investigate(context.Background(), InvestigateInput{SourceIP: "10.0.0.42", DestinationIP: "203.0.113.50", DestinationPort: 443, Protocol: "tcp", URL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Route.Path == nil || out.Route.Path.LastManagedDevice != "fgt" || out.Policy == nil || len(out.Policy.Decisions) != 1 {
		t.Fatalf("unexpected fixture result: %+v", out)
	}
	for _, stepErr := range out.Errors {
		if strings.Contains(stepErr, "policy_id needs device") {
			t.Fatalf("route identified fgt and policy identified 1 but web-filter scope was lost: %v", out.Errors)
		}
	}
}

func TestPolicyUsageReportsTableErrors(t *testing.T) {
	app, manager := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(1, "accept", "ALL")}, nil, nil)
	app.managers["fmg"] = &failingPolicyListManager{fakeManager: manager}
	value, err := app.GetPolicyUsage(context.Background(), PolicyUsageQuery{DeviceScope: DeviceScope{Profile: "fmg", ADOM: "test-adom-primary", Device: "fgt"}, Name: "all"})
	if err != nil {
		t.Fatal(err)
	}
	out := value.(map[string]any)
	if out["where_used_complete"] != false || len(out["errors"].([]any)) != 1 {
		t.Fatalf("usage = %+v", out)
	}
	failure := out["errors"].([]any)[0].(map[string]any)
	if failure["profile"] != "fmg" || failure["adom"] != "test-adom-primary" || failure["package"] != "pkg" || failure["table"] != "policy" {
		t.Fatalf("table failure lost scope: %+v", failure)
	}
	if len(out["where_used"].([]map[string]any)) == 0 {
		t.Fatal("successful IPv6 references were lost with the failed IPv4 table")
	}
}

func TestLiveReconcilePreservesVDOM(t *testing.T) {
	policyID := 9
	entry := LivePolicyLookup{Profile: "fmg", ADOM: "test-adom-primary", Device: "edge", VDOM: "blue", DestinationIP: "8.8.8.8", Protocol: "tcp", PolicyID: &policyID}
	out := PolicyLookupOutput{Decisions: []PolicyDecision{
		{Profile: "fmg", ADOM: "test-adom-primary", Device: "edge", VDOM: "root", DestinationIP: "8.8.8.8", Package: "root-pkg", PolicyID: 7, Action: "accept"},
		{Profile: "fmg", ADOM: "test-adom-primary", Device: "edge", VDOM: "blue", DestinationIP: "8.8.8.8", Package: "blue-pkg", PolicyID: 9, Action: "accept"},
	}}
	reconcileLive(&entry, &out)
	if entry.Agreement != "agrees" {
		t.Fatalf("blue live result compared with wrong VDOM: agreement=%s static=%d warnings=%v", entry.Agreement, *entry.StaticFirstMatch, out.Warnings)
	}
}

func TestLiveLookupCacheEvictsExpiredEntries(t *testing.T) {
	app, _ := lookupFixture(t, nil, nil, nil)
	app.liveLookupCache["expired"] = liveLookupEntry{created: time.Now().Add(-2 * liveLookupTTL), result: fortinet.ProxyResult{Data: "old"}}
	_, err := app.cachedPolicyLookup(context.Background(), "new", func() (fortinet.ProxyResult, error) { return fortinet.ProxyResult{Data: "fresh"}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(app.liveLookupCache) != 1 {
		t.Fatalf("live cache retains expired entry after new insert: entries=%d", len(app.liveLookupCache))
	}
}

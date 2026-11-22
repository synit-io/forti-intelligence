package service

import (
	"context"
	"errors"
	"testing"
)

func TestLiveRoutePreservesConfiguredEvidenceAndInstalledNextHops(t *testing.T) {
	app, manager, _ := deskFixture(t)
	row := func(prefix string, vrf int, gateway string, priority int) map[string]any {
		return map[string]any{"ip_mask": prefix, "vrf": vrf, "gateway": gateway, "interface": "wan", "type": "static", "distance": 10, "metric": 0, "priority": priority}
	}
	manager.proxyOverride = func(resource string) (any, error) {
		if resource != "/api/v2/monitor/router/ipv4" {
			return nil, errors.New("unexpected monitor: " + resource)
		}
		return []any{map[string]any{"target": "fgt", "response": map[string]any{"vdom": "root", "results": []any{
			row("0.0.0.0/0", 0, "192.0.2.1", 0),
			row("10.1.1.0/24", 0, "192.0.2.2", 0),
			row("10.1.1.0/24", 0, "192.0.2.3", 0),
			row("10.1.1.0/24", 0, "192.0.2.4", 1),
			row("0.0.0.0/0", 1, "192.0.2.5", 0),
		}}}}, nil
	}
	input := RouteLookupInput{IP: "10.1.1.72", Device: "fgt", VDOM: "root"}
	configured, err := app.ResolveRoute(context.Background(), input)
	if err != nil || configured.LiveRoute != nil || manager.proxyCalls.Load() != 0 {
		t.Fatalf("configured = %#v, %v, %d monitor reads", configured, err, manager.proxyCalls.Load())
	}
	input.Live = true
	for range 2 {
		out, err := app.ResolveRoute(context.Background(), input)
		if err != nil || len(out.Decisions) != 1 || out.Decisions[0].Stage != "routing_table" {
			t.Fatalf("configured decisions = %#v, %v", out.Decisions, err)
		}
		evidence := out.LiveRoute
		if evidence == nil || evidence.Status != "available" || evidence.Profile != "fmg" || evidence.VDOM != "root" || len(evidence.Matches) != 2 {
			t.Fatalf("evidence = %#v", evidence)
		}
		match := evidence.Matches[0]
		if match.Prefix != "10.1.1.0/24" || *match.VRF != 0 || len(match.NextHops) != 3 || !match.NextHops[0].EqualCost || !match.NextHops[1].EqualCost || match.NextHops[2].EqualCost || evidence.Matches[1].Prefix != "0.0.0.0/0" {
			t.Fatalf("matches = %#v", evidence.Matches)
		}
	}
	if got := manager.proxyCalls.Load(); got != 1 {
		t.Fatalf("monitor reads = %d, want one shared read", got)
	}
}

func TestLiveRouteValidatesScopeAndHandlesPartialOrUnavailableIPv6(t *testing.T) {
	app, manager, _ := deskFixture(t)
	manager.proxyOverride = func(resource string) (any, error) {
		if resource != "/api/v2/monitor/router/ipv6" {
			return nil, errors.New("unexpected monitor: " + resource)
		}
		return []any{
			map[string]any{"ip_mask": "2001:db8::/32", "gateway": "fe80::1", "interface": "wan"},
			map[string]any{"ip_mask": "invalid"},
		}, nil
	}
	input := RouteLookupInput{IP: "2001:db8::a", Device: "fgt", Live: true}
	if _, err := app.ResolveRoute(context.Background(), input); err == nil {
		t.Fatal("missing VDOM accepted")
	}
	input.VDOM = "blue"
	unknown, err := app.ResolveRoute(context.Background(), input)
	if err != nil || unknown.LiveRoute == nil || unknown.LiveRoute.Status != "unavailable" || manager.proxyCalls.Load() != 0 {
		t.Fatalf("unknown VDOM = %#v, %v", unknown.LiveRoute, err)
	}
	input.VDOM = "root"
	out, err := app.ResolveRoute(context.Background(), input)
	if err != nil || out.LiveRoute == nil || out.LiveRoute.Status != "partial" || len(out.LiveRoute.Matches) != 1 || len(out.LiveRoute.Warnings) != 2 || out.LiveRoute.Matches[0].VRF != nil {
		t.Fatalf("partial IPv6 = %#v, %v", out.LiveRoute, err)
	}
	manager.proxyOverride = func(string) (any, error) { return nil, errors.New("monitor unavailable") }
	input.IP = "10.1.1.72"
	out, err = app.ResolveRoute(context.Background(), input)
	if err != nil || len(out.Decisions) != 1 || out.LiveRoute == nil || out.LiveRoute.Status != "unavailable" || out.LiveRoute.Error != "monitor unavailable" {
		t.Fatalf("failed monitor = %#v, %v", out, err)
	}
	input.IP = "www.example.com"
	if _, err := app.ResolveRoute(context.Background(), input); err == nil {
		t.Fatal("hostname accepted for live read")
	}
}

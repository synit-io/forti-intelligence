package service

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

type trafficWebManager struct {
	*webFilterManager
}

func (m *trafficWebManager) ListRoutesBatch(ctx context.Context, adom string, targets []fortinet.RouteTarget) (map[string]fortinet.RouteBatchResult, error) {
	return (&trafficRouteManager{fakeManager: m.fakeManager}).ListRoutesBatch(ctx, adom, targets)
}

func TestInvestigateChecksEveryWebsiteHopAndAddress(t *testing.T) {
	for _, hostname := range []bool{false, true} {
		name := "IP"
		if hostname {
			name = "hostname"
		}
		t.Run(name, func(t *testing.T) {
			original := twoHopFixture(t).managers["fmg"].(*multiRouteManager)
			managers := make(map[string]fortinet.Manager)
			readers := make(map[string]*trafficWebManager)
			for _, deviceName := range []string{"branch", "hub"} {
				device := original.routed[deviceName]
				profile, adom, ingress, egress, action := "fmg-branch", "test-adom-primary", "lan", "transit", "monitor"
				if deviceName == "hub" {
					profile, adom, ingress, egress, action = "fmg-core", "test-adom-core", "z_transit", "wan", "block"
				}
				device.Profile, device.ADOM = profile, adom
				filterName := deviceName + "-web"
				base := &fakeManager{
					name:       profile,
					adoms:      []fortinet.ADOM{{Name: adom}},
					devices:    map[string][]fortinet.Device{adom: {device}},
					interfaces: map[string][]fortinet.Interface{adom + "/" + deviceName: device.Interfaces},
					packages: map[string][]fortinet.PolicyPackage{adom: {
						{Name: "pkg", Members: []fortinet.PackageMember{{Device: deviceName, VDOM: "root"}}},
					}},
					policies: map[string][]fortinet.FirewallPolicy{adom + "/pkg": {{
						PolicyID: 5, Status: "enable", Action: "accept",
						SourceInterfaces: []string{ingress}, DestinationInterfaces: []string{egress},
						SourceAddresses: []string{"all"}, DestinationAddresses: []string{"all"}, Services: []string{"ALL"},
						UTMStatus: "enable", ProfileType: "single", WebFilterProfile: filterName,
					}}},
				}
				reader := &trafficWebManager{webFilterManager: &webFilterManager{
					fakeManager: base,
					profiles:    []fortinet.WebFilterProfile{{Name: filterName, Filters: []fortinet.CategoryFilter{{Category: "52", Action: action}}}},
					statuses: map[string]fortinet.PackageStatus{
						deviceName + "/root": {Device: deviceName, VDOM: "root", Package: "pkg", Status: "installed"},
					},
					rating: fortinet.URLRating{CategoryIDs: []int{52}},
				}}
				managers[profile], readers[deviceName] = reader, reader
			}
			app := trafficRoutingService(t, managers)
			t.Cleanup(app.WaitBackground)
			destination, addresses := "8.8.8.8", 1
			if hostname {
				destination, addresses = "site.example", 2
				app.resolver = &fakeDNSResolver{ips: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("1.1.1.1")}}}
			}
			out, err := app.Investigate(context.Background(), InvestigateInput{
				SourceIP: "10.1.0.10", DestinationIP: destination,
				Protocol: "tcp", SourcePort: 12000, DestinationPort: 443, URL: "https://site.example",
			})
			if err != nil || len(out.Errors) > 0 || len(out.Hops) != 2*addresses {
				t.Fatalf("investigation hops=%+v errors=%v err=%v", out.Hops, out.Errors, err)
			}
			for i, hop := range out.Hops {
				expectedDevice, expectedProfile, expectedADOM, expectedIngress, expectedDecision := "branch", "fmg-branch", "test-adom-primary", "lan", "monitored"
				if i%2 == 1 {
					expectedDevice, expectedProfile, expectedADOM, expectedIngress, expectedDecision = "hub", "fmg-core", "test-adom-core", "transit", "blocked"
					if !strings.Contains(strings.Join(hop.Warnings, " "), "original flow tuple") {
						t.Fatalf("downstream NAT uncertainty omitted: %+v", hop)
					}
				}
				if hop.Route.Device != expectedDevice || hop.Route.Profile != expectedProfile || hop.Route.ADOM != expectedADOM {
					t.Fatalf("scope crossed at hop %d: %+v", i, hop)
				}
				if hop.Policy == nil || len(hop.Policy.Decisions) != 1 || hop.Policy.Decisions[0].PolicyID != 5 ||
					hop.Policy.Query.DestinationIP != hop.DestinationIP || hop.Policy.Query.SourceInterface != expectedIngress {
					t.Fatalf("carrying policy/ingress lost at hop %d: %+v", i, hop.Policy)
				}
				if hop.WebFilter == nil || hop.WebFilter.Query.PolicyID != 5 || hop.WebFilter.Query.Profile != expectedProfile ||
					hop.WebFilter.Query.ADOM != expectedADOM || hop.WebFilter.Query.Device != expectedDevice || hop.WebFilter.Query.VDOM != "root" {
					t.Fatalf("web-filter scope lost at hop %d: %+v", i, hop.WebFilter)
				}
				result := profileResult(t, *hop.WebFilter, expectedDevice+"-web")
				if result.Decision != expectedDecision {
					t.Fatalf("hop %d decision=%s want=%s", i, result.Decision, expectedDecision)
				}
			}
			if out.Policy != out.Hops[0].Policy || out.WebFilter != out.Hops[0].WebFilter {
				t.Fatal("legacy fields must retain the first hop's evidence")
			}
			app.WaitBackground()
			if readers["branch"].ratingCalls != 1 || readers["hub"].ratingCalls != 0 {
				t.Fatalf("rating repeated: branch=%d hub=%d", readers["branch"].ratingCalls, readers["hub"].ratingCalls)
			}
		})
	}
}

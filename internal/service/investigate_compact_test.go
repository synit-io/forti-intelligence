package service

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

func TestCompactInvestigationPreservesDiagnosticEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, action                            string
		unknownPort, multipleAddresses, partial bool
	}{
		{"allow", "accept", false, false, false},
		{"deny", "deny", false, false, false},
		{"unknown_source_port", "accept", true, false, false},
		{"multiple_destinations", "accept", false, true, false},
		{"partial_reads", "accept", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := lanToWAN(1, tc.action, "ALL")
			var services []fortinet.ServiceObject
			if tc.unknownPort {
				policy.Services = []string{"restricted-https"}
				services = []fortinet.ServiceObject{{Name: "restricted-https", Protocol: "TCP/UDP/SCTP", TCPPortRange: "443:1024-65535"}}
			}
			app, manager := lookupFixture(t, []fortinet.FirewallPolicy{policy}, nil, services)
			manager.interfaces["test-adom-primary/fgt"][0].Networks = []string{"10.0.0.0/24"}
			manager.interfaces["test-adom-primary/fgt"][2].Networks = []string{"203.0.113.0/24"}
			app.store.Refresh(context.Background())
			input := InvestigateInput{SourceIP: "10.0.0.42", DestinationIP: "203.0.113.50", DestinationPort: 443, Protocol: "tcp", SourcePort: 54321, IncludeLogs: true}
			if tc.unknownPort {
				input.SourcePort = 0
			}
			if tc.multipleAddresses {
				input.DestinationIP = "multi.example"
				app.resolver = &fakeDNSResolver{ips: []net.IPAddr{{IP: net.ParseIP("203.0.113.50")}, {IP: net.ParseIP("203.0.113.51")}}}
			}
			full, err := app.Investigate(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if len(full.Hops) == 0 {
				t.Fatal("fixture has no traced hops")
			}
			if tc.partial && len(full.Hops) > 0 && full.Hops[0].Policy != nil {
				full.Hops[0].Policy.Complete = false
				full.Hops[0].Errors = append(full.Hops[0].Errors, "partial policy read")
			}
			before, _ := json.Marshal(full)
			compact := CompactInvestigate(input, full)
			if tc.unknownPort && (len(full.Hops[0].Policy.Decisions) == 0 || full.Hops[0].Policy.Decisions[0].Confidence != "tentative" || compact.Hops[0].Policy.Decisions[0].Confidence != "tentative") {
				t.Fatal("source-port uncertainty lost")
			}
			after, _ := json.Marshal(full)
			if string(before) != string(after) {
				t.Fatal("projection mutated full result")
			}
			if !reflect.DeepEqual(compact.Ownership, full.Ownership) || !reflect.DeepEqual(compact.Errors, full.Errors) || !reflect.DeepEqual(compact.Warnings, full.Warnings) || len(compact.Hops) != len(full.Hops) {
				t.Fatal("scope/errors/alternatives lost")
			}
			for i, hop := range full.Hops {
				got := compact.Hops[i]
				if !reflect.DeepEqual(got.Route, hop.Route) || !reflect.DeepEqual(got.Warnings, hop.Warnings) || !reflect.DeepEqual(got.Errors, hop.Errors) || got.DestinationIP != hop.DestinationIP {
					t.Fatal("hop evidence lost")
				}
				if hop.Policy != nil && (!reflect.DeepEqual(got.Policy.Decisions, hop.Policy.Decisions) || got.Policy.Complete != hop.Policy.Complete || !reflect.DeepEqual(got.Policy.Matches, hop.Policy.Matches)) {
					t.Fatal("verdict or matching uncertainty changed")
				}
			}
			if compact.Coverage.ReturnPath != "not checked" || !strings.Contains(compact.Coverage.NAT, "original tuple") || compact.Flow.DestinationPort != 443 || compact.Coverage.Logs == "not requested" {
				t.Fatal("coverage overstated or requested log stage hidden")
			}
			if len(full.Hops) > 0 && (compact.Policy != nil || compact.WebFilter != nil || len(compact.Route.Path.Hops) != 0) {
				t.Fatal("duplicate first-hop evidence retained")
			}
			if compact.Route.DestinationResolution != full.Route.DestinationResolution || len(compact.Route.OtherAddresses) != len(full.Route.OtherAddresses) || !reflect.DeepEqual(compact.Route.Decisions, full.Route.Decisions) {
				t.Fatal("destination branches or routing lost")
			}
			encoded := measuredFixture(t, "investigation-"+tc.name+"-compact", compact)
			measuredFull := measuredFixture(t, "investigation-"+tc.name+"-full", full)
			ownership := measuredFixture(t, "ownership-"+tc.name, full.Ownership)
			policyBytes := measuredFixture(t, "policy-"+tc.name, full.Policy)
			t.Logf("scenario=%s full_bytes=%d compact_bytes=%d ownership_bytes=%d policy_bytes=%d", tc.name, len(measuredFull), len(encoded), len(ownership), len(policyBytes))
			if len(full.Hops) > 0 && len(encoded) >= len(measuredFull) {
				t.Fatalf("compact fixture not smaller: %d >= %d", len(encoded), len(before))
			}
			if strings.Contains(string(before), `"detail"`) || strings.Contains(string(before), `"Input"`) {
				t.Fatal("legacy JSON shape changed")
			}
		})
	}
}

func TestCompactInvestigationKeepsUnscopedPolicyAndLogTask(t *testing.T) {
	input := InvestigateInput{SourceIP: "10.0.0.1", DestinationIP: "203.0.113.1", IncludeLogs: true}
	full := InvestigateOutput{Input: &input, Policy: &PolicyLookupOutput{Warnings: []string{"overlapping VDOMs"}}, Logs: &fortinet.LogSearchResult{TaskID: "42", TimedOut: true, NextAction: &fortinet.LogNextAction{Kind: "poll"}}, Warnings: []string{"NAT unresolved"}}
	compact := CompactInvestigate(input, full)
	if compact.Policy == nil || compact.Logs != full.Logs || compact.Logs.NextAction.Kind != "poll" || len(compact.Policy.Warnings) != 1 {
		t.Fatal("unscoped fallback/task lost")
	}
}

func TestCompactInvestigationPreservesPathAmbiguityAndDisagreement(t *testing.T) {
	t.Run("multiple_hops_and_upstream_nat", func(t *testing.T) {
		app := twoHopFixture(t)
		input := InvestigateInput{SourceIP: "10.1.0.10", DestinationIP: "8.8.8.8", DestinationPort: 443, Protocol: "tcp"}
		full, err := app.Investigate(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		compact := CompactInvestigate(input, full)
		if len(full.Hops) != 2 || len(compact.Hops) != 2 || compact.Route.Path.End != full.Route.Path.End || !reflect.DeepEqual(compact.Hops[1].Warnings, full.Hops[1].Warnings) || !strings.Contains(strings.Join(compact.Hops[1].Warnings, " "), "NAT") {
			t.Fatal("lost downstream path limits")
		}
		if !reflect.DeepEqual(compact.Hops[1].Route, full.Hops[1].Route) || len(compact.Route.Path.Hops) != 0 {
			t.Fatal("canonical hops changed")
		}
	})
	t.Run("overlapping_vdoms", func(t *testing.T) {
		app, manager := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(7, "accept", "ALL")}, nil, nil)
		manager.devices["test-adom-primary"][0].VDOMs = []string{"root", "blue"}
		manager.interfaces["test-adom-primary/fgt"] = append(manager.interfaces["test-adom-primary/fgt"], fortinet.Interface{Name: "blue-lan", VDOM: "blue", IP: "10.0.0.1/24", Networks: []string{"10.0.0.0/24"}}, fortinet.Interface{Name: "blue-wan", VDOM: "blue", IP: "203.0.113.2/24", Networks: []string{"203.0.113.0/24"}})
		manager.interfaces["test-adom-primary/fgt"][0].Networks = []string{"10.0.0.0/24"}
		manager.interfaces["test-adom-primary/fgt"][2].Networks = []string{"203.0.113.0/24"}
		manager.packages["test-adom-primary"] = append(manager.packages["test-adom-primary"], fortinet.PolicyPackage{Name: "blue-pkg", Members: []fortinet.PackageMember{{Device: "fgt", VDOM: "blue"}}})
		app.store.Refresh(context.Background())
		input := InvestigateInput{SourceIP: "10.0.0.42", DestinationIP: "203.0.113.50", DestinationPort: 443, Protocol: "tcp"}
		full, err := app.Investigate(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		compact := CompactInvestigate(input, full)
		if !full.Ownership.Ambiguous || !compact.Ownership.Ambiguous || !reflect.DeepEqual(full.Ownership.Candidates, compact.Ownership.Candidates) || !reflect.DeepEqual(full.Route.Decisions, compact.Route.Decisions) {
			t.Fatal("overlapping scopes collapsed")
		}
	})
	t.Run("configured_live_disagreement", func(t *testing.T) {
		app, manager := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(7, "accept", "ALL")}, nil, nil)
		manager.interfaces["test-adom-primary/fgt"][0].Networks = []string{"10.0.0.0/24"}
		manager.interfaces["test-adom-primary/fgt"][2].Networks = []string{"203.0.113.0/24"}
		manager.live["test-adom-primary/fgt/root/lan/tcp"] = fortinet.ProxyResult{Data: map[string]any{"policyid": float64(9)}}
		app.store.Refresh(context.Background())
		input := InvestigateInput{SourceIP: "10.0.0.42", DestinationIP: "203.0.113.50", DestinationPort: 443, Protocol: "tcp"}
		full, err := app.Investigate(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		compact := CompactInvestigate(input, full)
		if len(full.Hops) != 1 || len(full.Hops[0].Policy.LiveLookups) != 1 || full.Hops[0].Policy.LiveLookups[0].Agreement != "differs" {
			t.Fatal("fixture has no disagreement")
		}
		live := compact.Hops[0].Policy.LiveLookups[0]
		if live.Agreement != "differs" || *live.PolicyID != 9 || live.Result != nil || !reflect.DeepEqual(compact.Hops[0].Policy.Warnings, full.Hops[0].Policy.Warnings) {
			t.Fatal("disagreement or warning lost")
		}
	})
}

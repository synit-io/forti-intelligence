package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

// lookupFixture builds one FortiGate (fgt, VDOM root) with lan 10.0.0.0/24,
// dmz 10.0.5.0/24 and wan 203.0.113.0/24, and one package with policies.
func lookupFixture(t *testing.T, policies []fortinet.FirewallPolicy, addresses []fortinet.AddressObject, services []fortinet.ServiceObject) (*Service, *fakeManager) {
	t.Helper()
	manager := &fakeManager{
		name:  "fmg",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices: map[string][]fortinet.Device{
			"test-adom-primary": {{Name: "fgt", ADOM: "test-adom-primary", Profile: "fmg", VDOMs: []string{"root"}}},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-primary": {{Name: "pkg", Members: []fortinet.PackageMember{{Device: "fgt", VDOM: "root"}}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-primary/fgt": {
				{Name: "lan", IP: "10.0.0.1/24", VDOM: "root"},
				{Name: "dmz", IP: "10.0.5.1/24", VDOM: "root"},
				{Name: "wan", IP: "203.0.113.1/24", VDOM: "root"},
			},
		},
		policies:  map[string][]fortinet.FirewallPolicy{"test-adom-primary/pkg": policies},
		addresses: map[string][]fortinet.AddressObject{"test-adom-primary": addresses},
		services:  map[string][]fortinet.ServiceObject{"test-adom-primary": services},
		live:      map[string]fortinet.ProxyResult{},
	}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	store.Refresh(context.Background())
	return New(cfg, store, map[string]fortinet.Manager{"fmg": manager}, nil), manager
}

func lanToWAN(id int, action string, services ...string) fortinet.FirewallPolicy {
	return fortinet.FirewallPolicy{
		PolicyID: id, Status: "enable", Action: action,
		SourceInterfaces: []string{"lan"}, DestinationInterfaces: []string{"wan"},
		SourceAddresses: []string{"all"}, DestinationAddresses: []string{"all"}, Services: services,
	}
}

func lookup(t *testing.T, app *Service, input PolicyLookupInput) PolicyLookupOutput {
	t.Helper()
	if input.SourceIP == "" {
		input.SourceIP = "10.0.0.42"
	}
	if input.DestinationIP == "" {
		input.DestinationIP = "203.0.113.50"
	}
	if input.DestinationPort == 0 {
		input.DestinationPort = 443
	}
	if input.Protocol == "" {
		input.Protocol = "tcp"
	}
	output, err := app.LookupPolicies(context.Background(), input)
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	return output
}

func matchedIDs(output PolicyLookupOutput) []int {
	ids := make([]int, 0, len(output.Matches))
	for _, match := range output.Matches {
		ids = append(ids, match.Policy.PolicyID)
	}
	return ids
}

// FortiOS applies the first matching policy: a deny before an accept wins,
// whatever the accept's evidence score.
func TestLookupOrdersByPolicySequenceAndStatesFirstMatch(t *testing.T) {
	app, _ := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(5, "deny", "ALL"), lanToWAN(7, "accept", "HTTPS")}, nil, nil)
	output := lookup(t, app, PolicyLookupInput{})
	if fmt.Sprint(matchedIDs(output)) != "[5 7]" || !output.Matches[0].FirstMatch || output.Matches[1].FirstMatch {
		t.Fatalf("matches = %v first = %v, want deny 5 first", matchedIDs(output), output.Matches[0].FirstMatch)
	}
	if len(output.Decisions) != 1 || output.Decisions[0].PolicyID != 5 || output.Decisions[0].Action != "deny" || !output.Complete {
		t.Fatalf("decisions = %#v complete = %v", output.Decisions, output.Complete)
	}
}

func TestLookupStatesImplicitDenyOnlyWhenComplete(t *testing.T) {
	onlyDMZ := lanToWAN(9, "accept", "ALL")
	onlyDMZ.DestinationInterfaces = []string{"dmz"}
	app, manager := lookupFixture(t, []fortinet.FirewallPolicy{onlyDMZ}, nil, nil)
	output := lookup(t, app, PolicyLookupInput{})
	if len(output.Matches) != 0 || len(output.Decisions) != 1 || output.Decisions[0].Action != "implicit_deny" || !output.Complete {
		t.Fatalf("decisions = %#v matches = %v", output.Decisions, matchedIDs(output))
	}

	// A failed package read must not look like "no policy matches".
	failing := &failingPolicyListManager{fakeManager: manager}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg": failing}, 0, 1)
	store.Refresh(context.Background())
	failingApp := New(cfg, store, map[string]fortinet.Manager{"fmg": failing}, nil)
	output = lookup(t, failingApp, PolicyLookupInput{})
	if output.Complete || len(output.Decisions) != 1 || output.Decisions[0].Action != "unknown" {
		t.Fatalf("complete = %v decisions = %#v, want an undecided package", output.Complete, output.Decisions)
	}
}

// FortiOS 6.4+ policies carry IPv4 and IPv6 addresses in separate columns;
// an internet service replaces the address list. Neither may count as "all".
func TestLookupEvaluatesAddressesPerFamilyAndInternetServices(t *testing.T) {
	ipv6Only := lanToWAN(11, "accept", "ALL")
	ipv6Only.SourceAddresses, ipv6Only.DestinationAddresses = nil, nil
	ipv6Only.SourceAddresses6, ipv6Only.DestinationAddresses6 = []string{"all"}, []string{"all"}
	isdb := lanToWAN(12, "accept", "ALL")
	isdb.DestinationAddresses = nil
	isdb.DestinationInternetService = true
	isdb.InternetServices = []string{"Microsoft-Office365"}
	app, _ := lookupFixture(t, []fortinet.FirewallPolicy{ipv6Only, isdb}, nil, nil)
	output := lookup(t, app, PolicyLookupInput{})
	if fmt.Sprint(matchedIDs(output)) != "[12]" {
		t.Fatalf("matches = %v, want only the internet-service policy", matchedIDs(output))
	}
	match := output.Matches[0]
	if match.Confidence != "tentative" || !strings.Contains(strings.Join(match.Warnings, " "), "Internet Service") {
		t.Fatalf("internet-service match = %#v, want tentative with a warning", match)
	}
}

func TestLookupMatchesVIPPolicyOnMappedInterface(t *testing.T) {
	vipPolicy := fortinet.FirewallPolicy{
		PolicyID: 20, Status: "enable", Action: "accept",
		SourceInterfaces: []string{"wan"}, DestinationInterfaces: []string{"dmz"},
		SourceAddresses: []string{"all"}, DestinationAddresses: []string{"web-vip"}, Services: []string{"HTTPS"},
	}
	addresses := []fortinet.AddressObject{{Name: "web-vip", StartIP: "203.0.113.80", EndIP: "203.0.113.80", ExternalIP: "203.0.113.80", MappedIP: "10.0.5.80"}}
	app, _ := lookupFixture(t, []fortinet.FirewallPolicy{vipPolicy}, addresses, nil)
	output := lookup(t, app, PolicyLookupInput{SourceIP: "198.51.100.7", DestinationIP: "203.0.113.80", SourceInterface: "wan"})
	if fmt.Sprint(matchedIDs(output)) != "[20]" || len(output.Matches[0].TranslationEvidence) == 0 {
		t.Fatalf("matches = %#v, want the VIP policy with its translation", output.Matches)
	}
}

func TestLookupServiceGroupScopeAndIdentityDetails(t *testing.T) {
	services := []fortinet.ServiceObject{
		{Name: "HTTPS", TCPPortRange: "8443"},
		{Name: "WEB-ALT", TCPPortRange: "8080-8090:1024-65535"},
	}
	addresses := []fortinet.AddressObject{
		{Name: "lan-net", Subnet: "10.0.0.0 255.255.255.0"},
		{Name: "printer", Subnet: "10.0.0.9 255.255.255.255"},
		{Name: "clients", Members: []string{"lan-net"}, ExcludeMembers: []string{"printer"}},
	}
	grouped := lanToWAN(30, "accept", "WEB-ALT")
	grouped.SourceAddresses = []string{"clients"}
	app, _ := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(29, "accept", "HTTPS"), grouped}, addresses, services)

	// The ADOM's HTTPS object (8443) wins over the built-in definition (443).
	if output := lookup(t, app, PolicyLookupInput{}); len(output.Matches) != 0 {
		t.Fatalf("port 443 matches = %v, want none: the ADOM defines HTTPS as 8443", matchedIDs(output))
	}
	if output := lookup(t, app, PolicyLookupInput{DestinationPort: 8443}); fmt.Sprint(matchedIDs(output)) != "[29]" {
		t.Fatalf("port 8443 matches = %v, want 29", matchedIDs(output))
	}
	// dst:src port ranges match on their destination part.
	if output := lookup(t, app, PolicyLookupInput{DestinationPort: 8085}); fmt.Sprint(matchedIDs(output)) != "[30]" {
		t.Fatalf("port 8085 matches = %v, want 30", matchedIDs(output))
	}
	// The excluded printer does not match the group.
	if output := lookup(t, app, PolicyLookupInput{SourceIP: "10.0.0.9", DestinationPort: 8085}); len(output.Matches) != 0 {
		t.Fatalf("excluded member matches = %v, want none", matchedIDs(output))
	}

	identity := lanToWAN(31, "accept", "ALL")
	identity.Users = []string{"alice"}
	elsewhere := lanToWAN(32, "accept", "ALL")
	elsewhere.Scope = []fortinet.PackageMember{{Device: "other-fgt", VDOM: "root"}}
	app, _ = lookupFixture(t, []fortinet.FirewallPolicy{elsewhere, identity}, nil, nil)
	output := lookup(t, app, PolicyLookupInput{})
	if fmt.Sprint(matchedIDs(output)) != "[31]" || output.Matches[0].Confidence != "tentative" {
		t.Fatalf("matches = %#v, want only 31 (32 is installed elsewhere), tentative for its user condition", output.Matches)
	}
	if !builtinProtocolPort(builtinServices["dns"], "tcp", 53) {
		t.Fatal("built-in DNS must match TCP as well as UDP")
	}
}

type timeoutLookupManager struct {
	*fakeManager
}

func (m *timeoutLookupManager) PolicyLookup(ctx context.Context, adom, device, vdom string, request fortinet.PolicyLookupRequest) (fortinet.ProxyResult, error) {
	m.policyLookupCalls++
	return fortinet.ProxyResult{}, fmt.Errorf("proxy policy-lookup: %w", context.DeadlineExceeded)
}

func TestLookupRunsBoundedLiveLookupsAfterConfiguredVerdict(t *testing.T) {
	app, manager := lookupFixture(t, []fortinet.FirewallPolicy{lanToWAN(7, "accept", "ALL")}, nil, nil)
	manager.live["test-adom-primary/fgt/root/lan/tcp"] = fortinet.ProxyResult{Data: map[string]any{"results": map[string]any{"success": true, "policy_id": float64(7)}}}
	app.resolver = &fakeDNSResolver{ips: []net.IPAddr{{IP: net.ParseIP("203.0.113.50")}, {IP: net.ParseIP("203.0.113.51")}, {IP: net.ParseIP("203.0.113.52")}}}
	output := lookup(t, app, PolicyLookupInput{DestinationIP: "portal.example.com", Protocol: "any"})
	// tcp and udp for three addresses would be six lookups; four run.
	if manager.policyLookupCalls != maxLiveLookups || len(output.LiveLookups) != maxLiveLookups || !strings.Contains(strings.Join(output.Warnings, " "), "2 further live policy lookups") {
		t.Fatalf("live calls = %d lookups = %d warnings = %v", manager.policyLookupCalls, len(output.LiveLookups), output.Warnings)
	}
	first := output.LiveLookups[0]
	if first.PolicyID == nil || *first.PolicyID != 7 || first.Agreement != "agrees" || len(output.Decisions) != 3 {
		t.Fatalf("live = %#v decisions = %#v", first, output.Decisions)
	}

	slow := &timeoutLookupManager{fakeManager: manager}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg": slow}, 0, 1)
	store.Refresh(context.Background())
	slowApp := New(cfg, store, map[string]fortinet.Manager{"fmg": slow}, nil)
	manager.policyLookupCalls = 0
	output = lookup(t, slowApp, PolicyLookupInput{Protocol: "any"})
	if manager.policyLookupCalls != 1 || len(output.Decisions) != 1 || output.Decisions[0].PolicyID != 7 {
		t.Fatalf("live calls = %d decisions = %#v, want one timed-out lookup and the configured verdict", manager.policyLookupCalls, output.Decisions)
	}
}

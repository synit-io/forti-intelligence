package service

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

func TestLookupPoliciesResolvesCrossADOMDeviceInterfaceAndObjects(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-a",
		adoms: []fortinet.ADOM{{Name: "test-adom-customer-a"}, {Name: "test-adom-customer-b"}},
		devices: map[string][]fortinet.Device{
			"test-adom-customer-a": {{Name: "branch-1", ADOM: "test-adom-customer-a", Profile: "fmg-a", VDOMs: []string{"root"}}},
			"test-adom-customer-b": {{Name: "branch-2", ADOM: "test-adom-customer-b", Profile: "fmg-a", VDOMs: []string{"root"}}},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-customer-a": {{Name: "default", Members: []fortinet.PackageMember{{Device: "branches/east", VDOM: "root"}}}},
			"test-adom-customer-b": {{Name: "default", Members: []fortinet.PackageMember{{Device: "branch-2", VDOM: "root"}}}},
		},
		groups: map[string][]fortinet.DeviceGroup{
			"test-adom-customer-a": {{Name: "branches/east", Members: []fortinet.PackageMember{{Device: "branch-1", VDOM: "root"}}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-customer-a/branch-1": {
				{Name: "lan", IP: "10.10.0.1", Netmask: "255.255.255.0", VDOM: "root"},
				{Name: "wan", IP: "192.0.2.1", Netmask: "255.255.255.0", VDOM: "root"},
			},
			"test-adom-customer-b/branch-2": {{Name: "lan", IP: "10.20.0.1", Netmask: "255.255.255.0", VDOM: "root"}},
		},
		policies: map[string][]fortinet.FirewallPolicy{
			"test-adom-customer-a/default": {{
				PolicyID: 10, Name: "allow-web", Status: "enable", Action: "accept",
				SourceInterfaces: []string{"lan"}, DestinationInterfaces: []string{"wan"},
				SourceAddresses: []string{"lan-hosts"}, DestinationAddresses: []string{"web-server"}, Services: []string{"HTTPS"},
			}},
		},
		addresses: map[string][]fortinet.AddressObject{
			"test-adom-customer-a": {
				{Name: "lan-hosts", Subnet: "10.10.0.0 255.255.255.0"},
				{Name: "web-server", StartIP: "192.0.2.0", EndIP: "192.0.2.255", MappedIP: "10.30.0.10", MappedPort: "8443"},
			},
		},
		live: map[string]fortinet.ProxyResult{},
	}
	manager.live["test-adom-customer-a/branch-1/root/lan/tcp"] = fortinet.ProxyResult{Data: map[string]any{"policyid": 10}}

	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": manager}, 0, 2)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-a": manager}, nil)

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		SourceIP: "10.10.0.50", DestinationIP: "192.0.2.10", DestinationPort: 443,
	})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	if len(output.CandidateDevices) != 1 {
		t.Fatalf("candidate devices across ADOMs = %#v, want only matching ADOM/device", output.CandidateDevices)
	}
	candidate := output.CandidateDevices[0]
	if candidate.ADOM != "test-adom-customer-a" || candidate.Device != "branch-1" || len(candidate.SourceInterfaces) != 1 || candidate.SourceInterfaces[0] != "lan" {
		t.Fatalf("candidate = %#v", candidate)
	}
	if len(candidate.PackageTargets) != 1 || candidate.PackageTargets[0].Package != "default" || candidate.PackageTargets[0].VDOM != "root" {
		t.Fatalf("candidate package targets = %#v, want default/root", candidate.PackageTargets)
	}
	if len(output.Matches) != 1 || output.Matches[0].Policy.PolicyID != 10 {
		t.Fatalf("matches = %#v, want policy 10", output.Matches)
	}
	if output.Matches[0].VDOM != "root" {
		t.Fatalf("match VDOM = %q, want root", output.Matches[0].VDOM)
	}
	if len(output.Matches[0].TranslationEvidence) != 1 || output.Matches[0].TranslationEvidence[0] != "web-server -> 10.30.0.10:8443" {
		t.Fatalf("translation evidence = %#v, want VIP mapping", output.Matches[0].TranslationEvidence)
	}
	if len(output.LiveLookups) != 2 {
		t.Fatalf("live lookup attempts = %d, want TCP and UDP", len(output.LiveLookups))
	}
	if manager.policyLookupCalls != 2 {
		t.Fatalf("manager live calls = %d, want 2", manager.policyLookupCalls)
	}
}

func TestLookupPoliciesUsesInterfaceForLiveAndZoneForStaticPolicy(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-zone",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices: map[string][]fortinet.Device{
			"test-adom-primary": {{Name: "edge-1", ADOM: "test-adom-primary", Profile: "fmg-zone", VDOMs: []string{"root"}}},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-primary": {{Name: "default", Members: []fortinet.PackageMember{{Device: "edge-1", VDOM: "root"}}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-primary/edge-1": {
				{Name: "lan", IP: "10.0.0.1", Netmask: "255.255.255.0", Zone: "inside", VDOM: "root"},
				{Name: "wan", IP: "192.0.2.1", Netmask: "255.255.255.0", Zone: "outside", VDOM: "root"},
			},
		},
		policies: map[string][]fortinet.FirewallPolicy{
			"test-adom-primary/default": {{
				PolicyID: 10, Status: "enable", Action: "accept",
				SourceInterfaces: []string{"inside"}, DestinationInterfaces: []string{"outside"},
				SourceAddresses: []string{"all"}, DestinationAddresses: []string{"all"}, Services: []string{"HTTPS"},
			}},
		},
		services: map[string][]fortinet.ServiceObject{
			"test-adom-primary": {{Name: "HTTPS", TCPPortRange: "443"}},
		},
		live: map[string]fortinet.ProxyResult{
			"test-adom-primary/edge-1/root/lan/tcp": {Data: map[string]any{"policyid": 10}},
		},
	}

	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-zone", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-zone": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-zone": manager}, nil)

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		Profile: "fmg-zone", SourceIP: "10.0.0.50", DestinationIP: "192.0.2.10", DestinationPort: 443, Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	if len(output.CandidateDevices) != 1 {
		t.Fatalf("candidate devices = %#v, want one", output.CandidateDevices)
	}
	candidate := output.CandidateDevices[0]
	if len(candidate.SourceInterfaces) != 1 || candidate.SourceInterfaces[0] != "lan" || len(candidate.SourceZones) != 1 || candidate.SourceZones[0] != "inside" {
		t.Fatalf("candidate source selectors = %#v, want lan/inside", candidate)
	}
	if len(candidate.DestinationZones) != 1 || candidate.DestinationZones[0] != "outside" {
		t.Fatalf("candidate destination zones = %#v, want outside", candidate.DestinationZones)
	}
	// FortiOS rejects a zone as srcintf (HTTP 400); the live lookup must use
	// the ingress interface and report its zone separately.
	if len(output.LiveLookups) != 1 || output.LiveLookups[0].SourceInterface != "lan" || output.LiveLookups[0].SourceZone != "inside" || output.LiveLookups[0].Result == nil {
		t.Fatalf("live lookups = %#v, want interface lan with zone inside", output.LiveLookups)
	}

	// An explicit zone selects its member interface that holds the source.
	explicit, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		Profile: "fmg-zone", SourceIP: "10.0.0.50", DestinationIP: "192.0.2.10", DestinationPort: 443, Protocol: "tcp", SourceInterface: "inside",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(explicit.LiveLookups) != 1 || explicit.LiveLookups[0].SourceInterface != "lan" {
		t.Fatalf("explicit zone live lookups = %#v, want member interface lan", explicit.LiveLookups)
	}
	manager.policyLookupCalls = 1
	if manager.policyLookupCalls != 1 || len(output.Matches) != 1 || len(output.Matches[0].SourceZones) != 1 || output.Matches[0].SourceZones[0] != "inside" {
		t.Fatalf("zone policy lookup = calls %d matches %#v, want one zone-aware match", manager.policyLookupCalls, output.Matches)
	}
}

func TestLookupPoliciesResolvesFQDNAndEvaluatesEachAddress(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-dns",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices: map[string][]fortinet.Device{
			"test-adom-primary": {{Name: "edge-1", ADOM: "test-adom-primary", Profile: "fmg-dns", VDOMs: []string{"root"}}},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-primary": {{Name: "default", Members: []fortinet.PackageMember{{Device: "edge-1", VDOM: "root"}}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-primary/edge-1": {
				{Name: "lan", IP: "10.0.0.1", Netmask: "255.255.255.0", VDOM: "root"},
				{Name: "wan", IP: "192.0.2.1", Netmask: "255.255.255.0", VDOM: "root"},
			},
		},
		policies: map[string][]fortinet.FirewallPolicy{
			"test-adom-primary/default": {{
				PolicyID: 53, Status: "enable", Action: "accept",
				SourceInterfaces: []string{"lan"}, DestinationInterfaces: []string{"wan"},
				SourceAddresses: []string{"all"}, DestinationAddresses: []string{"web"}, Services: []string{"DNS"},
			}},
		},
		addresses: map[string][]fortinet.AddressObject{
			"test-adom-primary": {{Name: "web", Subnet: "192.0.2.0 255.255.255.0"}},
		},
		services: map[string][]fortinet.ServiceObject{
			"test-adom-primary": {{Name: "DNS", TCPPortRange: "53", UDPPortRange: "53"}},
		},
		live: map[string]fortinet.ProxyResult{},
	}

	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-dns", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-dns": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-dns": manager}, nil)
	resolver := &fakeDNSResolver{
		ips:   []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}, {IP: net.ParseIP("192.0.2.11")}},
		cname: "canonical.example.",
	}
	app.resolver = resolver

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		SourceIP: "10.0.0.1", DestinationIP: "dns.example.test", DestinationPort: 53, Protocol: "udp",
	})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	if resolver.host != "dns.example.test" {
		t.Fatalf("resolver host = %q, want dns.example.test", resolver.host)
	}
	if output.DestinationResolution.CanonicalName != "canonical.example" {
		t.Fatalf("canonical name = %q, want canonical.example", output.DestinationResolution.CanonicalName)
	}
	if got := output.DestinationResolution.Addresses; len(got) != 2 || got[0] != "192.0.2.10" || got[1] != "192.0.2.11" {
		t.Fatalf("resolved addresses = %#v, want both A records", got)
	}
	if len(output.CandidateDevices) != 1 {
		t.Fatalf("candidate devices = %#v, want one source-subnet match", output.CandidateDevices)
	}
	if candidate := output.CandidateDevices[0]; candidate.ADOM != "test-adom-primary" || candidate.Device != "edge-1" || len(candidate.SourceInterfaces) != 1 || candidate.SourceInterfaces[0] != "lan" {
		t.Fatalf("candidate = %#v", candidate)
	}
	if len(output.Matches) != 2 || output.Matches[0].DestinationIP == output.Matches[1].DestinationIP {
		t.Fatalf("matches = %#v, want one match per resolved address", output.Matches)
	}
	if manager.policyLookupCalls != 2 {
		t.Fatalf("manager live calls = %d, want one UDP lookup per resolved address", manager.policyLookupCalls)
	}
}

func TestLookupPoliciesRestrictsDeviceAndInfersInterface(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-device",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices: map[string][]fortinet.Device{
			"test-adom-primary": {
				{Name: "edge-1", ADOM: "test-adom-primary", Profile: "fmg-device", VDOMs: []string{"root"}},
				{Name: "edge-2", ADOM: "test-adom-primary", Profile: "fmg-device", VDOMs: []string{"root"}},
			},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-primary": {{Name: "default", Members: []fortinet.PackageMember{
				{Device: "edge-1", VDOM: "root"}, {Device: "edge-2", VDOM: "root"},
			}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-primary/edge-1": {{Name: "lan", IP: "10.0.0.1", Netmask: "255.255.255.0", VDOM: "root"}},
			"test-adom-primary/edge-2": {{Name: "lan", IP: "10.1.0.1", Netmask: "255.255.255.0", VDOM: "root"}},
		},
	}

	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-device", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-device": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-device": manager}, nil)

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		Profile: "fmg-device", ADOM: "test-adom-primary", Device: "edge-1",
		SourceIP: "10.0.0.1", DestinationIP: "8.8.8.8", DestinationPort: 53,
	})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	if len(output.CandidateDevices) != 1 {
		t.Fatalf("candidate devices = %#v, want explicit device only", output.CandidateDevices)
	}
	candidate := output.CandidateDevices[0]
	if candidate.Profile != "fmg-device" || candidate.ADOM != "test-adom-primary" || candidate.Device != "edge-1" || len(candidate.SourceInterfaces) != 1 || candidate.SourceInterfaces[0] != "lan" {
		t.Fatalf("candidate = %#v, want inferred lan interface", candidate)
	}
}

func TestLookupPoliciesReportsOfflineDeviceWithStructuredError(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-offline",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices: map[string][]fortinet.Device{
			"test-adom-primary": {{Name: "edge-offline", ADOM: "test-adom-primary", Profile: "fmg-offline", ConnectionStatus: "down", VDOMs: []string{"root"}}},
		},
	}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-offline", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-offline": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-offline": manager}, nil)

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		Profile: "fmg-offline", ADOM: "test-adom-primary", Device: "edge-offline",
		SourceIP: "10.0.0.1", DestinationIP: "192.0.2.1", DestinationPort: 443, Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v; an offline device must still be evaluated statically", err)
	}
	if len(output.CandidateDevices) != 1 || output.CandidateDevices[0].Device != "edge-offline" || len(output.LiveLookups) != 0 || manager.policyLookupCalls != 0 {
		t.Fatalf("candidates=%#v live=%#v calls=%d", output.CandidateDevices, output.LiveLookups, manager.policyLookupCalls)
	}
	found := false
	for _, refreshError := range output.Errors {
		if refreshError.Device == "edge-offline" && refreshError.Kind == fortinet.ErrorKindDeviceUnavailable && refreshError.Stage == "live_policy_lookup" && !strings.Contains(refreshError.Hint, "refresh_inventory") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("structured errors = %#v, want live lookup skip without refresh advice", output.Errors)
	}
	for _, warning := range output.Warnings {
		if strings.Contains(warning, "Inventory refresh") {
			t.Fatalf("offline device reported as inventory failure: %q", warning)
		}
	}
	if !strings.Contains(strings.Join(output.Warnings, " "), "live policy lookup was skipped") {
		t.Fatalf("warnings = %v", output.Warnings)
	}
}

func TestLookupPoliciesReportsLiveLookupErrorDetails(t *testing.T) {
	base := &fakeManager{
		name:  "fmg-live-error",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices: map[string][]fortinet.Device{
			"test-adom-primary": {{Name: "edge-1", ADOM: "test-adom-primary", Profile: "fmg-live-error", VDOMs: []string{"root"}}},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-primary": {{Name: "default", Members: []fortinet.PackageMember{{Device: "edge-1", VDOM: "root"}}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-primary/edge-1": {{Name: "lan", IP: "10.0.0.1", Netmask: "255.255.255.0", VDOM: "root"}},
		},
	}
	manager := &failingPolicyLookupManager{fakeManager: base}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-live-error", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-live-error": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-live-error": manager}, nil)

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		Profile: "fmg-live-error", SourceIP: "10.0.0.10", DestinationIP: "192.0.2.1", DestinationPort: 443, Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	if len(output.LiveLookups) != 1 || output.LiveLookups[0].ErrorDetails == nil || output.LiveLookups[0].ErrorDetails.Kind != fortinet.ErrorKindUnavailable {
		t.Fatalf("live lookups = %#v, want structured unavailable error", output.LiveLookups)
	}
	if len(output.Errors) == 0 || output.Errors[0].Stage != "policy_lookup" {
		t.Fatalf("errors = %#v, want policy_lookup error", output.Errors)
	}
}

func TestLookupPoliciesRejectsInvalidDestinationPort(t *testing.T) {
	app := New(config.Default(), inventory.NewStore(nil, 0, 1), nil, nil)
	_, err := app.LookupPolicies(context.Background(), PolicyLookupInput{SourceIP: "192.0.2.1", DestinationIP: "198.51.100.1", DestinationPort: 0})
	if err == nil {
		t.Fatal("LookupPolicies() error = nil, want invalid port error")
	}
}

func TestLookupPoliciesRejectsInvalidProtocol(t *testing.T) {
	app := New(config.Default(), inventory.NewStore(nil, 0, 1), nil, nil)
	_, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		SourceIP: "192.0.2.1", DestinationIP: "198.51.100.1", DestinationPort: 443, Protocol: "not-a-protocol",
	})
	if err == nil {
		t.Fatal("LookupPolicies() error = nil, want invalid protocol error")
	}
}

func TestLookupPoliciesRejectsMixedIPVersions(t *testing.T) {
	app := New(config.Default(), inventory.NewStore(nil, 0, 1), nil, nil)
	_, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		SourceIP: "192.0.2.1", DestinationIP: "2001:db8::1", DestinationPort: 443,
	})
	if err == nil {
		t.Fatal("LookupPolicies() error = nil, want mixed IP version error")
	}
}

func TestFortinetInterfaceContainsCIDRAndSecondaryAddress(t *testing.T) {
	if !fortinetInterfaceContains(fortinet.Interface{IP: "2001:db8:10::1/64"}, net.ParseIP("2001:db8:10::42")) {
		t.Fatal("CIDR interface did not contain IPv6 address")
	}
	if !fortinetInterfaceContains(fortinet.Interface{IPv6: []string{"2001:db8:11::1/64"}}, net.ParseIP("2001:db8:11::42")) {
		t.Fatal("IPv6-only interface did not contain IPv6 address")
	}
	if fortinetInterfaceContains(fortinet.Interface{IPv6: []string{"::/0"}}, net.ParseIP("2001:db8:99::42")) {
		t.Fatal("IPv6 placeholder ::/0 matched an address")
	}
	if !fortinetInterfaceContains(fortinet.Interface{
		IP: "10.0.0.1", Netmask: "255.255.255.0", Addresses: []string{"10.0.1.1 255.255.255.0"},
	}, net.ParseIP("10.0.1.42")) {
		t.Fatal("secondary interface address did not contain IPv4 address")
	}
}

func TestWithTimeoutCapsLongCallerDeadline(t *testing.T) {
	cfg := config.Default()
	cfg.Server.RequestTimeout = "10ms"
	app := New(cfg, inventory.NewStore(nil, 0, 1), nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	capped, release := app.withTimeout(ctx)
	defer release()
	deadline, ok := capped.Deadline()
	if !ok || time.Until(deadline) > 100*time.Millisecond {
		t.Fatalf("deadline = %v, want approximately 10ms", deadline)
	}
}

func TestValidateObjectTypeAllowsFutureFirewallObjectsButRejectsTraversal(t *testing.T) {
	if err := validateObjectType("firewall/new-object-family"); err != nil {
		t.Fatalf("future firewall object rejected: %v", err)
	}
	for _, objectType := range []string{"/sys/status", "firewall/../address", "firewall/address?x=1", "firewall//address"} {
		if err := validateObjectType(objectType); err == nil {
			t.Fatalf("validateObjectType(%q) = nil, want rejection", objectType)
		}
	}
}

func TestValidateFortiGateReadResourceRestrictsToMonitorAndCMDB(t *testing.T) {
	for _, resource := range []string{
		"/api/v2/monitor/system/status",
		"/api/v2/cmdb/system/interface?vdom=root",
	} {
		if err := validateFortiGateReadResource(resource); err != nil {
			t.Fatalf("validateFortiGateReadResource(%q) error = %v", resource, err)
		}
	}
	for _, resource := range []string{
		"/api/v2/execute/system/reboot",
		"/api/v2/monitor/../execute/system/reboot",
		"https://evil.example/api/v2/monitor/system/status",
	} {
		if err := validateFortiGateReadResource(resource); err == nil {
			t.Fatalf("validateFortiGateReadResource(%q) = nil, want rejection", resource)
		}
	}
}

func TestLookupPoliciesKeepsUnresolvedObjectsAsTentativeMatches(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-a",
		adoms: []fortinet.ADOM{{Name: "test-adom-customer-a"}},
		devices: map[string][]fortinet.Device{
			"test-adom-customer-a": {{Name: "branch-1", ADOM: "test-adom-customer-a", Profile: "fmg-a", VDOMs: []string{"root"}}},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-customer-a": {{Name: "default", Members: []fortinet.PackageMember{{Device: "branch-1", VDOM: "root"}}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-customer-a/branch-1": {{Name: "lan", IP: "10.10.0.1", Netmask: "255.255.255.0", VDOM: "root"}},
		},
		policies: map[string][]fortinet.FirewallPolicy{
			"test-adom-customer-a/default": {{
				PolicyID: 20, Status: "enable", Action: "accept",
				SourceInterfaces: []string{"lan"}, SourceAddresses: []string{"dynamic-source"},
				DestinationAddresses: []string{"missing-destination"}, Services: []string{"missing-service"},
			}},
		},
	}

	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-a": manager}, nil)

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		SourceIP: "10.10.0.50", DestinationIP: "192.0.2.10", DestinationPort: 443, Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	if len(output.Matches) != 1 || output.Matches[0].Policy.PolicyID != 20 {
		t.Fatalf("matches = %#v, want tentative policy 20", output.Matches)
	}
	if len(output.Matches[0].Warnings) < 3 {
		t.Fatalf("warnings = %#v, want interface and unresolved-object warnings", output.Matches[0].Warnings)
	}
}

func TestLookupPoliciesUsesIPv6PolicyFamily(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-v6",
		adoms: []fortinet.ADOM{{Name: "test-adom-ipv6"}},
		devices: map[string][]fortinet.Device{
			"test-adom-ipv6": {{Name: "v6-gate", ADOM: "test-adom-ipv6", Profile: "fmg-v6", VDOMs: []string{"root"}}},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-ipv6": {{Name: "v6-package", Members: []fortinet.PackageMember{{Device: "v6-gate", VDOM: "root"}}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-ipv6/v6-gate": {
				{Name: "lan6", IP: "2001:db8:1::1/64", VDOM: "root"},
				{Name: "wan6", IP: "2001:db8:2::1/64", VDOM: "root"},
			},
		},
		policies: map[string][]fortinet.FirewallPolicy{
			"test-adom-ipv6/v6-package": {{
				PolicyID: 60, Status: "enable", Action: "accept",
				SourceInterfaces: []string{"lan6"}, DestinationInterfaces: []string{"wan6"},
				SourceAddresses: []string{"src6"}, DestinationAddresses: []string{"dst6"}, Services: []string{"HTTPS"},
			}},
		},
		addresses: map[string][]fortinet.AddressObject{
			"test-adom-ipv6": {
				{Name: "src6", Subnet: "2001:db8:1::/64"},
				{Name: "dst6", Subnet: "2001:db8:2::/64"},
			},
		},
	}

	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-v6", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-v6": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-v6": manager}, nil)

	output, err := app.LookupPolicies(context.Background(), PolicyLookupInput{
		SourceIP: "2001:db8:1::42", DestinationIP: "2001:db8:2::42", DestinationPort: 443, Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("LookupPolicies() error = %v", err)
	}
	if len(output.Matches) != 1 || output.Matches[0].Policy.PolicyID != 60 || manager.ipv6PolicyCalls != 1 {
		t.Fatalf("matches = %#v, ipv6 policy calls = %d", output.Matches, manager.ipv6PolicyCalls)
	}
}

func TestDirectFortiManagerScopeInferenceAndInventoryFiltering(t *testing.T) {
	managerA := &fakeManager{
		name:       "fmg-a",
		adoms:      []fortinet.ADOM{{Name: "test-adom-customer-a"}},
		devices:    map[string][]fortinet.Device{"test-adom-customer-a": {{Name: "branch-a"}}},
		interfaces: map[string][]fortinet.Interface{"test-adom-customer-a/branch-a": {{Name: "lan", VDOM: "root"}}},
	}
	managerB := &fakeManager{
		name:    "fmg-b",
		adoms:   []fortinet.ADOM{{Name: "test-adom-customer-b"}},
		devices: map[string][]fortinet.Device{"test-adom-customer-b": {{Name: "branch-b"}}},
	}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{
		{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://a.invalid", Username: "u", Password: "p"},
		{Name: "fmg-b", Product: config.ProductFortiManager, URL: "https://b.invalid", Username: "u", Password: "p"},
	}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": managerA, "fmg-b": managerB}, 0, 2)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-a": managerA, "fmg-b": managerB}, nil)

	value, err := app.GetInterfaces(context.Background(), "", "test-adom-customer-a", "branch-a", "", false, false)
	if err != nil {
		t.Fatalf("GetInterfaces() error = %v", err)
	}
	if value.(map[string]any)["profile"] != "fmg-a" {
		t.Fatalf("inferred profile result = %#v, want fmg-a", value)
	}
	filtered, err := app.ListFortiGates(context.Background(), "", "test-adom-customer-a", false, false, false)
	if err != nil {
		t.Fatalf("ListFortiGates() error = %v", err)
	}
	if len(filtered.ADOMs) != 1 || filtered.ADOMs[0].Profile != "fmg-a" || len(filtered.Devices) != 1 || filtered.Devices[0].Name != "branch-a" || len(filtered.Profiles) != 1 || filtered.Profiles[0].Profile != "fmg-a" {
		t.Fatalf("filtered inventory = %#v, want only test-adom-customer-a/fmg-a", filtered)
	}
}

func TestConfiguredADOMBlocksDirectFortiManagerRead(t *testing.T) {
	manager := &fakeManager{name: "fmg-a", adoms: []fortinet.ADOM{{Name: "test-adom-primary"}}}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{
		Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://a.invalid", Username: "u", Password: "p",
		ADOMs: []string{"test-adom-primary"},
	}}
	app := New(cfg, inventory.NewStore(map[string]fortinet.Manager{"fmg-a": manager}, 0, 1), map[string]fortinet.Manager{"fmg-a": manager}, nil)

	_, err := app.GetFortiManagerRead(context.Background(), "fmg-a", "/pm/config/adom/test-adom-denied/obj/firewall/address", nil)
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("GetFortiManagerRead() error = %v, want configured-ADOM rejection", err)
	}
}

func TestListPoliciesDoesNotSynthesizeUnverifiedDeviceScope(t *testing.T) {
	manager := &fakeManager{
		name:     "fmg-a",
		adoms:    []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices:  map[string][]fortinet.Device{"test-adom-primary": {{Name: "edge-1"}}},
		packages: map[string][]fortinet.PolicyPackage{"test-adom-primary": {{Name: "default", Members: []fortinet.PackageMember{{Device: "edge-1", VDOM: "root"}}}}},
		policies: map[string][]fortinet.FirewallPolicy{"test-adom-primary/default": {{PolicyID: 9, Action: "accept"}}},
	}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://a.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-a": manager}, nil)

	value, err := app.ListPolicies(context.Background(), PolicyListInput{Profile: "fmg-a", ADOM: "test-adom-primary", Package: "default", Device: "edge-2", IPVersion: "ipv4"})
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}
	result := value.(map[string]any)
	if result["package_scope_verified"] != false {
		t.Fatalf("package_scope_verified = %#v, want false", result["package_scope_verified"])
	}
	if len(result["warnings"].([]string)) == 0 {
		t.Fatalf("warnings = %#v, want unverified scope warning", result["warnings"])
	}
	policies := result["packages"].(map[string]any)["default"].([]fortinet.FirewallPolicy)
	if len(policies) != 1 || policies[0].Device != "" {
		t.Fatalf("policies = %#v, want policy without synthesized device", policies)
	}
}

func TestListPoliciesReturnsStructuredPackageAccessError(t *testing.T) {
	base := &fakeManager{
		name:     "fmg-package-error",
		adoms:    []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices:  map[string][]fortinet.Device{"test-adom-primary": {{Name: "edge-1", ADOM: "test-adom-primary", Profile: "fmg-package-error", VDOMs: []string{"root"}}}},
		packages: map[string][]fortinet.PolicyPackage{"test-adom-primary": {{Name: "default", Members: []fortinet.PackageMember{{Device: "edge-1", VDOM: "root"}}}}},
	}
	manager := &failingPolicyListManager{fakeManager: base}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-package-error", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-package-error": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-package-error": manager}, nil)

	value, err := app.ListPolicies(context.Background(), PolicyListInput{Profile: "fmg-package-error", ADOM: "test-adom-primary", Package: "default", Device: "edge-1", IPVersion: "ipv4"})
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}
	result := value.(map[string]any)
	packageResult := result["packages"].(map[string]any)["default"].(map[string]any)
	details, ok := packageResult["error_details"].(fortinet.ErrorInfo)
	if !ok || details.Kind != fortinet.ErrorKindPermission {
		t.Fatalf("package result = %#v, want permission error_details", packageResult)
	}
	errors, ok := result["errors"].([]inventory.RefreshError)
	if !ok || len(errors) != 1 || errors[0].Stage != "list_policies" || errors[0].Package != "default" {
		t.Fatalf("errors = %#v, want structured list_policies/default error", result["errors"])
	}
}

type fakeManager struct {
	name              string
	adoms             []fortinet.ADOM
	devices           map[string][]fortinet.Device
	groups            map[string][]fortinet.DeviceGroup
	packages          map[string][]fortinet.PolicyPackage
	interfaces        map[string][]fortinet.Interface
	policies          map[string][]fortinet.FirewallPolicy
	addresses         map[string][]fortinet.AddressObject
	services          map[string][]fortinet.ServiceObject
	live              map[string]fortinet.ProxyResult
	policyLookupCalls int
	ipv6PolicyCalls   int
}

type failingPolicyLookupManager struct {
	*fakeManager
}

func (f *failingPolicyLookupManager) PolicyLookup(context.Context, string, string, string, fortinet.PolicyLookupRequest) (fortinet.ProxyResult, error) {
	return fortinet.ProxyResult{}, errors.New("connection refused by FortiGate")
}

type failingPolicyListManager struct {
	*fakeManager
}

func (f *failingPolicyListManager) ListPolicies(context.Context, string, string) ([]fortinet.FirewallPolicy, error) {
	return nil, errors.New("fmg API result: code -11: No permission for the resource")
}

func (f *fakeManager) Name() string                                       { return f.name }
func (f *fakeManager) ListADOMs(context.Context) ([]fortinet.ADOM, error) { return f.adoms, nil }
func (f *fakeManager) ListDevices(_ context.Context, adom string) ([]fortinet.Device, error) {
	return f.devices[adom], nil
}
func (f *fakeManager) ListDeviceGroups(_ context.Context, adom string) ([]fortinet.DeviceGroup, error) {
	return f.groups[adom], nil
}
func (f *fakeManager) ListPolicyPackages(_ context.Context, adom string) ([]fortinet.PolicyPackage, error) {
	return f.packages[adom], nil
}
func (f *fakeManager) ListPolicies(_ context.Context, adom, pkg string) ([]fortinet.FirewallPolicy, error) {
	return f.policies[adom+"/"+pkg], nil
}
func (f *fakeManager) ListIPv6Policies(_ context.Context, adom, pkg string) ([]fortinet.FirewallPolicy, error) {
	f.ipv6PolicyCalls++
	return f.policies[adom+"/"+pkg], nil
}
func (f *fakeManager) ListAddresses(_ context.Context, adom string) ([]fortinet.AddressObject, error) {
	return f.addresses[adom], nil
}
func (f *fakeManager) ListServices(_ context.Context, adom string) ([]fortinet.ServiceObject, error) {
	return f.services[adom], nil
}
func (f *fakeManager) ListInterfaces(_ context.Context, adom, device string) ([]fortinet.Interface, error) {
	return f.interfaces[adom+"/"+device], nil
}
func (f *fakeManager) ProxyGet(context.Context, string, string, string, string) (fortinet.ProxyResult, error) {
	return fortinet.ProxyResult{}, nil
}
func (f *fakeManager) PolicyLookup(_ context.Context, adom, device, vdom string, request fortinet.PolicyLookupRequest) (fortinet.ProxyResult, error) {
	f.policyLookupCalls++
	return f.live[adom+"/"+device+"/"+vdom+"/"+request.SourceInterface+"/"+request.Protocol], nil
}
func (f *fakeManager) Read(context.Context, string, map[string]any) (any, error) { return nil, nil }
func (f *fakeManager) Close() error                                              { return nil }

type fakeDNSResolver struct {
	ips   []net.IPAddr
	cname string
	host  string
}

func (r *fakeDNSResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.host = host
	return r.ips, nil
}

func (r *fakeDNSResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	r.host = host
	return r.cname, nil
}

func TestOfflineDeviceDoesNotMakePackageScopeTentative(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-a",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices: map[string][]fortinet.Device{"test-adom-primary": {
			{Name: "edge-1", ADOM: "test-adom-primary", Profile: "fmg-a", ConnectionStatus: "up", VDOMs: []string{"root"}},
			{Name: "edge-2", ADOM: "test-adom-primary", Profile: "fmg-a", ConnectionStatus: "down", VDOMs: []string{"root"}},
		}},
		packages: map[string][]fortinet.PolicyPackage{"test-adom-primary": {{Name: "default", Members: []fortinet.PackageMember{{Device: "edge-1", VDOM: "root"}}}}},
		policies: map[string][]fortinet.FirewallPolicy{"test-adom-primary/default": {{PolicyID: 1, Status: "enable"}}},
	}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": manager}, 0, 1)
	snapshot := store.Refresh(context.Background())
	if snapshot.Profiles[0].Stale || len(snapshot.UnavailableDevices) != 1 {
		t.Fatalf("snapshot = %#v", snapshot.Profiles)
	}
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-a": manager}, nil)
	value, err := app.ListPolicies(context.Background(), PolicyListInput{Profile: "fmg-a", ADOM: "test-adom-primary", Package: "default", Device: "edge-1", IPVersion: "ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	if result["package_scope_verified"] != true || result["warnings"] != nil {
		t.Fatalf("result = %#v, an offline peer must not make package scope tentative", result)
	}
	status, err := app.ListFortiGates(context.Background(), "", "test-adom-primary", false, false, false)
	if err != nil || len(status.UnavailableDevices) != 1 || status.UnavailableDevices[0].Device != "edge-2" || len(status.Errors) != 0 {
		t.Fatalf("inventory_status = %#v, %v", status, err)
	}
}

func TestLookupPoliciesExplainsLoadingInventory(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": &fakeManager{name: "fmg-a"}}, 0, 1)
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-a": &fakeManager{name: "fmg-a"}}, nil)
	_, err := app.LookupPolicies(context.Background(), PolicyLookupInput{SourceIP: "10.0.0.1", DestinationIP: "192.0.2.1", DestinationPort: 443})
	if err == nil || !strings.Contains(err.Error(), "No FortiGate inventory snapshot exists yet") {
		t.Fatalf("error = %v", err)
	}
}

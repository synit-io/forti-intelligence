package inventory

import (
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

func TestResolveIPOwnership(t *testing.T) {
	store := NewStore(nil, time.Hour, 1)
	query := OwnershipQuery{IP: "10.49.0.17"}
	before, err := store.ResolveIPOwnership(query)
	if err != nil || before.Ready || len(before.Candidates) != 0 {
		t.Fatalf("before=%+v err=%v", before, err)
	}
	snapshot := Snapshot{GeneratedAt: time.Now(), Profiles: []ProfileState{{Profile: "fmg", Stale: true}}, Errors: []RefreshError{{Profile: "fmg", ADOM: "test-adom-internal", Device: "edge", Stage: "list_interface_zones"}}, Devices: []fortinet.Device{
		{Profile: "fmg", ADOM: "test-adom-internal", Name: "edge", ConnectionStatus: "up", PackageTargets: []fortinet.PackageTarget{{Package: "correct", VDOM: "root"}, {Package: "other", VDOM: "tenant"}}, Interfaces: []fortinet.Interface{{Name: "v_ad_clients", VDOM: "root", Zone: "z_ad_clients", IP: "10.49.0.1", Network: "10.49.0.0/22", Networks: []string{"10.49.0.0/22", "2001:db8::/64"}}}},
		{Profile: "fmg", ADOM: "test-adom-other", Name: "edge", Interfaces: []fortinet.Interface{{Name: "v_ad_clients", VDOM: "root", Networks: []string{"10.0.0.0/8", "0.0.0.0/0", "::/0"}}}},
	}}
	store.setSnapshot(snapshot)
	result, err := store.ResolveIPOwnership(query)
	if err != nil || !result.Ready || !result.Ambiguous || len(result.Candidates) != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	first := result.Candidates[0]
	if first.ADOM != "test-adom-internal" || first.Network != "10.49.0.0/22" || first.Zone != "z_ad_clients" || len(first.Packages) != 1 || first.Packages[0] != "correct" {
		t.Fatalf("candidate=%+v", first)
	}
	if len(result.Errors) != 1 || !result.Profiles[0].Stale {
		t.Fatal("freshness evidence lost")
	}
	result.Candidates[0].Packages[0] = "mutated"
	query.ADOM = "test-adom-internal"
	scoped, _ := store.ResolveIPOwnership(query)
	if scoped.Ambiguous || len(scoped.Candidates) != 1 || scoped.Candidates[0].Packages[0] != "correct" {
		t.Fatalf("scoped=%+v", scoped)
	}
	ipv6, _ := store.ResolveIPOwnership(OwnershipQuery{IP: "2001:db8::17"})
	if len(ipv6.Candidates) != 1 {
		t.Fatalf("ipv6=%+v", ipv6)
	}
	for _, q := range []OwnershipQuery{{IP: "192.0.2.1"}, {IP: "10.49.0.17", VDOM: "tenant"}, {IP: "10.49.0.17", Profile: "absent"}, {IP: "10.49.0.17", Device: "absent"}} {
		got, err := store.ResolveIPOwnership(q)
		if err != nil || len(got.Candidates) != 0 {
			t.Fatalf("query=%+v result=%+v err=%v", q, got, err)
		}
	}
	for _, ip := range []string{"host.example", "10.0.0.0/8", "::", "fe80::1%eth0"} {
		if _, err := store.ResolveIPOwnership(OwnershipQuery{IP: ip}); err == nil {
			t.Fatalf("accepted %s", ip)
		}
	}
	store.setSnapshot(Snapshot{GeneratedAt: time.Now()})
	after, _ := store.ResolveIPOwnership(query)
	if len(after.Candidates) != 0 || len(after.Errors) != 0 {
		t.Fatal("old index survived replacement")
	}
}

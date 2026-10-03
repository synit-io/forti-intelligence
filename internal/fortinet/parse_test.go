package fortinet

import "slices"

import "testing"

func TestParseAddressesIncludesGroupsAndVIPRanges(t *testing.T) {
	result := []any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{
			map[string]any{"name": "lan-host", "subnet": []any{"10.0.0.0", "255.255.255.0"}},
			map[string]any{"name": "lan-group", "member": []any{map[string]any{"name": "lan-host"}}},
			map[string]any{"name": "published-web", "extip": "192.0.2.10-192.0.2.12", "mappedip": "10.0.0.10"},
			map[string]any{"name": "published-ssh", "extip": "192.0.2.22", "mappedip": "10.0.0.22"},
		},
	}}

	objects := parseAddresses(result)
	if len(objects) != 4 {
		t.Fatalf("parseAddresses() returned %d objects, want 4", len(objects))
	}
	if objects[1].Name != "lan-group" || len(objects[1].Members) != 1 || objects[1].Members[0] != "lan-host" {
		t.Fatalf("group object = %#v", objects[1])
	}
	if objects[2].StartIP != "192.0.2.10" || objects[2].EndIP != "192.0.2.12" {
		t.Fatalf("VIP range = %#v, want 192.0.2.10-192.0.2.12", objects[2])
	}
	if objects[2].ExternalIP != "192.0.2.10-192.0.2.12" || objects[2].MappedIP != "10.0.0.10" {
		t.Fatalf("VIP translation = %#v, want external and mapped addresses", objects[2])
	}
	if objects[3].StartIP != "192.0.2.22" || objects[3].EndIP != "192.0.2.22" {
		t.Fatalf("single VIP = %#v, want exact 192.0.2.22", objects[3])
	}
}

func TestParseAddressesReadsNestedIPv6Prefix(t *testing.T) {
	objects := parseAddresses([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{map[string]any{
			"name": "branch-v6",
			"ip6":  map[string]any{"ip6-address": "2001:db8:100::/64"},
		}},
	}})
	if len(objects) != 1 || objects[0].Subnet != "2001:db8:100::/64" {
		t.Fatalf("IPv6 objects = %#v, want nested prefix", objects)
	}
}

func TestParsePackageMembersAcceptsStringScopes(t *testing.T) {
	for _, value := range []any{"branch-1", []string{"branch-1", "branch-2"}, []any{"branch-3"}} {
		members := parsePackageMembers(value)
		if len(members) == 0 {
			t.Fatalf("parsePackageMembers(%#v) returned no members", value)
		}
	}
}

func TestParsePackagesPreservesNestedPackagePath(t *testing.T) {
	packages := parsePackages([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{
			map[string]any{"name": "ppkg", "folder": "emea/spain", "type": "pkg"},
			map[string]any{"name": "emea/global/ppkg", "type": "pkg"},
			map[string]any{"name": "emea", "type": "folder"},
		},
	}})
	if len(packages) != 2 {
		t.Fatalf("parsePackages() returned %d packages, want 2", len(packages))
	}
	if packages[0].Name != "emea/spain/ppkg" || packages[1].Name != "emea/global/ppkg" {
		t.Fatalf("package names = %#v, want nested paths", packages)
	}
	if packages[0].Type != "pkg" || packages[1].Type != "pkg" {
		t.Fatalf("package types = %#v, want pkg", packages)
	}
}

func TestParsePackagesFlattensFortiManagerFolderSubobjects(t *testing.T) {
	packages := parsePackages([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{
			map[string]any{
				"name": "TG", "type": "folder",
				"subobj": []any{map[string]any{
					"name": "fw_tg_new", "oid": 34781, "type": "pkg",
					"scope member": []any{map[string]any{"name": "test-device-02", "vdom": "root"}},
				}},
			},
			map[string]any{
				"name": "Hub", "type": "folder",
				"subobj": []any{map[string]any{
					"name": "test-device-04", "oid": 53249, "type": "pkg",
				}},
			},
			map[string]any{
				"name": "Messe", "type": "pkg",
				"scope member": []any{map[string]any{"name": "test-device-03", "vdom": "root"}},
			},
		},
	}})

	if len(packages) != 3 {
		t.Fatalf("parsePackages() returned %d packages, want 3: %#v", len(packages), packages)
	}
	want := []string{"TG/fw_tg_new", "Hub/test-device-04", "Messe"}
	for index, packageName := range want {
		if packages[index].Name != packageName || packages[index].Type != "pkg" {
			t.Fatalf("package[%d] = %#v, want name=%q type=pkg", index, packages[index], packageName)
		}
	}
	if len(packages[0].Members) != 1 || packages[0].Members[0].Device != "test-device-02" {
		t.Fatalf("nested package scope = %#v, want test-device-02/root", packages[0].Members)
	}
}

func TestParseDevicesPreservesCanonicalStatusFields(t *testing.T) {
	devices := parseDevices([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{map[string]any{
			"name": "fgt-1", "sn": "FGVM", "os_ver": "v7.6.1", "platform_str": "FortiGate-VM64",
			"conn_status": "up", "conf_status": "insync", "vdom": []any{"root"},
		}},
	}}, "test-adom-primary", "fmg")
	if len(devices) != 1 {
		t.Fatalf("devices = %#v, want one device", devices)
	}
	device := devices[0]
	if device.Serial != "FGVM" || device.Version != "v7.6.1" || device.Platform != "FortiGate-VM64" || device.ConnectionStatus != "up" || device.ConfigStatus != "insync" {
		t.Fatalf("device = %#v, want canonical device fields", device)
	}
}

func TestParseDeviceGroupsReadsObjectMembers(t *testing.T) {
	groups := parseDeviceGroups([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{map[string]any{
			"name":          "branches/east",
			"object member": []any{map[string]any{"name": "branch-1", "vdom": "root"}},
		}},
	}})
	if len(groups) != 1 || groups[0].Name != "branches/east" || len(groups[0].Members) != 1 || groups[0].Members[0].Device != "branch-1" {
		t.Fatalf("device groups = %#v, want one object member", groups)
	}
}

func TestParseDeviceGroupsReadsMapKeyedMembers(t *testing.T) {
	groups := parseDeviceGroups([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{map[string]any{
			"name":          "branches",
			"object member": map[string]any{"branch-1": map[string]any{"vdom": "root"}},
		}},
	}})
	if len(groups) != 1 || len(groups[0].Members) != 1 || groups[0].Members[0].Device != "branch-1" || groups[0].Members[0].VDOM != "root" {
		t.Fatalf("device groups = %#v, want map-keyed member", groups)
	}
}

func TestParseInterfacesReadsNestedIPv6Address(t *testing.T) {
	interfaces := parseInterfaces([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{map[string]any{
			"name": "port6", "ip": "10.0.0.1 255.255.255.0",
			"ipv6": map[string]any{"ip6-address": "2001:db8:6::1/64", "ip6-extra-addr": []any{"2001:db8:6::2/64"}},
		}},
	}})
	if len(interfaces) != 1 || len(interfaces[0].IPv6) != 2 {
		t.Fatalf("interfaces = %#v, want two nested IPv6 addresses", interfaces)
	}
}

func TestParseInterfacesComputesNetworksAndZone(t *testing.T) {
	interfaces := parseInterfaces([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{map[string]any{
			"name": "port1", "ip": []any{"10.0.0.1", "255.255.255.0"},
			"secondaryip": []any{map[string]any{"ip": "10.0.1.1", "netmask": "255.255.255.0"}},
			"ipv6":        []any{"2001:db8:1::1/64"}, "zone": "inside",
		}},
	}})
	if len(interfaces) != 1 {
		t.Fatalf("interfaces = %#v, want one interface", interfaces)
	}
	iface := interfaces[0]
	if iface.Network != "10.0.0.0/24" || iface.Zone != "inside" {
		t.Fatalf("interface = %#v, want primary network and zone", iface)
	}
	for _, want := range []string{"10.0.0.0/24", "10.0.1.0/24", "2001:db8:1::/64"} {
		if !containsString(iface.Networks, want) {
			t.Fatalf("interface networks = %#v, missing %q", iface.Networks, want)
		}
	}
}

func TestParseInterfacesHandlesFortiOSVDOMArraysAndUnconfiguredNetworks(t *testing.T) {
	interfaces := parseInterfaces([]any{
		map[string]any{
			"name":      "wan1",
			"ip":        []any{"192.0.2.1", "255.255.255.0"},
			"vdom":      []any{"root"},
			"interface": []any{"wan-parent"},
			"ipv6":      map[string]any{"ip6-address": "::/0"},
		},
		map[string]any{
			"name": "unused",
			"ip":   []any{"0.0.0.0", "0.0.0.0"},
			"vdom": []any{"root"},
		},
	})
	if len(interfaces) != 2 {
		t.Fatalf("interfaces = %#v, want two records", interfaces)
	}
	if got := interfaces[0].VDOM; got != "root" {
		t.Fatalf("vdom = %q, want root", got)
	}
	if got := interfaces[0].Parent; got != "wan-parent" {
		t.Fatalf("parent = %q, want wan-parent", got)
	}
	if got := interfaces[0].Network; got != "192.0.2.0/24" {
		t.Fatalf("network = %q, want 192.0.2.0/24", got)
	}
	if len(interfaces[0].Networks) != 1 || interfaces[0].Networks[0] != "192.0.2.0/24" {
		t.Fatalf("networks = %#v, want only connected IPv4 network", interfaces[0].Networks)
	}
	if got := interfaces[1].Network; got != "" {
		t.Fatalf("unconfigured network = %q, want empty", got)
	}
	if len(interfaces[1].Networks) != 0 {
		t.Fatalf("unconfigured networks = %#v, want empty", interfaces[1].Networks)
	}
}

func TestParseInterfaceZonesMapsMembers(t *testing.T) {
	interfaces := []Interface{{Name: "port1"}, {Name: "port2"}, {Name: "port3"}}
	memberships := parseInterfaceZones([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{map[string]any{
			"name": "inside", "interface": []any{"port1", "port2"},
		}},
	}})
	applyInterfaceZones(interfaces, memberships)
	if interfaces[0].Zone != "inside" || interfaces[1].Zone != "inside" || interfaces[2].Zone != "" {
		t.Fatalf("interfaces = %#v, want port1/port2 in inside zone", interfaces)
	}
}

func TestParseInterfaceZonesReadsMapKeyedMembers(t *testing.T) {
	interfaces := []Interface{{Name: "port1"}}
	memberships := parseInterfaceZones([]any{map[string]any{
		"data": []any{map[string]any{"name": "inside", "interface": map[string]any{"port1": map[string]any{}}}},
	}})
	applyInterfaceZones(interfaces, memberships)
	if interfaces[0].Zone != "inside" {
		t.Fatalf("interfaces = %#v, want port1 in inside zone", interfaces)
	}
}

func containsString(values []string, want string) bool {
	return slices.Contains(values, want)
}

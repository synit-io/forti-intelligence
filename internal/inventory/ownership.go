package inventory

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// OwnershipQuery selects connected-network evidence, not a forwarding decision.
type OwnershipQuery struct {
	IP      string `json:"ip" jsonschema:"IPv4 or IPv6 address to locate, for example 10.49.0.17"`
	Profile string `json:"profile,omitempty" jsonschema:"Limit to one FortiManager profile name"`
	ADOM    string `json:"adom,omitempty" jsonschema:"Limit to one ADOM name"`
	Device  string `json:"device,omitempty" jsonschema:"Limit to one managed FortiGate name"`
	VDOM    string `json:"vdom,omitempty" jsonschema:"Limit to one VDOM name"`
}

type OwnershipCandidate struct {
	Profile          string    `json:"profile"`
	ADOM             string    `json:"adom"`
	Device           string    `json:"device"`
	Serial           string    `json:"serial,omitempty"`
	VDOM             string    `json:"vdom"`
	Interface        string    `json:"interface"`
	Zone             string    `json:"zone,omitempty"`
	Network          string    `json:"network"`
	InterfaceIP      string    `json:"interface_ip,omitempty"`
	ConnectionStatus string    `json:"connection_status,omitempty"`
	InterfaceStatus  string    `json:"interface_status,omitempty"`
	DataAsOf         time.Time `json:"data_as_of"`
	Packages         []string  `json:"packages,omitempty"`
}

type OwnershipResult struct {
	IP          string         `json:"ip"`
	Scope       OwnershipQuery `json:"scope"`
	GeneratedAt time.Time      `json:"generated_at"`
	Ready       bool           `json:"ready"`
	// RefreshInProgress with ready=false means the first background refresh
	// is still loading; retry shortly instead of refreshing again.
	RefreshInProgress  bool                 `json:"refresh_in_progress,omitempty"`
	Ambiguous          bool                 `json:"ambiguous"`
	Candidates         []OwnershipCandidate `json:"candidates"`
	Profiles           []ProfileState       `json:"profiles,omitempty"`
	Errors             []RefreshError       `json:"errors,omitempty"`
	UnavailableDevices []DeviceNotice       `json:"unavailable_devices,omitempty"`
	Limitation         string               `json:"limitation"`
}

func buildOwnershipIndex(snapshot Snapshot) map[netip.Prefix][]OwnershipCandidate {
	index := make(map[netip.Prefix][]OwnershipCandidate)
	for _, device := range snapshot.Devices {
		for _, iface := range device.Interfaces {
			vdom := iface.VDOM
			if vdom == "" {
				vdom = "root"
			}
			candidate := OwnershipCandidate{Profile: device.Profile, ADOM: device.ADOM, Device: device.Name, Serial: device.Serial, VDOM: vdom, Interface: iface.Name, Zone: iface.Zone, InterfaceIP: iface.IP, ConnectionStatus: device.ConnectionStatus, InterfaceStatus: iface.Status, DataAsOf: device.DataAsOf}
			for _, target := range device.PackageTargets {
				if target.VDOM == "" || target.VDOM == vdom {
					candidate.Packages = append(candidate.Packages, target.Package)
				}
			}
			sort.Strings(candidate.Packages)
			seen := make(map[netip.Prefix]bool)
			for _, network := range append(append([]string(nil), iface.Networks...), iface.Network) {
				prefix, err := netip.ParsePrefix(network)
				if err != nil || prefix.Bits() == 0 || prefix.Addr().IsUnspecified() {
					continue
				}
				prefix = prefix.Masked()
				if seen[prefix] {
					continue
				}
				seen[prefix] = true
				entry := candidate
				entry.Network = prefix.String()
				index[prefix] = append(index[prefix], entry)
			}
		}
	}
	return index
}

// ResolveIPOwnership performs at most 129 prefix-map probes, plus matching
// results. The index and freshness metadata belong to the same snapshot.
// All overlaps are retained, ordered most-specific first; no network I/O occurs.
func (s *Store) ResolveIPOwnership(query OwnershipQuery) (OwnershipResult, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(query.IP))
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() {
		return OwnershipResult{}, fmt.Errorf("ip must be a concrete IPv4 or IPv6 address without a zone")
	}
	ip = ip.Unmap()
	query.IP = ip.String()
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := OwnershipResult{IP: ip.String(), Scope: query, GeneratedAt: s.snapshot.GeneratedAt, Ready: !s.snapshot.GeneratedAt.IsZero(), RefreshInProgress: !s.startedAt.IsZero(), Candidates: []OwnershipCandidate{}, Limitation: "Connected-network candidates only; not proof of route, endpoint ownership, live state, or policy permission. No match is not proof of absence. Inspect profiles and errors for retained or incomplete data; offline FortiGates keep their FortiManager database data and are listed under unavailable_devices."}
	for bits := ip.BitLen(); bits > 0; bits-- {
		for _, candidate := range s.ownership[netip.PrefixFrom(ip, bits).Masked()] {
			if query.Profile != "" && candidate.Profile != query.Profile || query.ADOM != "" && candidate.ADOM != query.ADOM || query.Device != "" && candidate.Device != query.Device || query.VDOM != "" && candidate.VDOM != query.VDOM {
				continue
			}
			candidate.Packages = append([]string(nil), candidate.Packages...)
			result.Candidates = append(result.Candidates, candidate)
		}
	}
	for _, profile := range s.snapshot.Profiles {
		if query.Profile == "" || profile.Profile == query.Profile {
			result.Profiles = append(result.Profiles, profile)
		}
	}
	for _, failure := range s.snapshot.Errors {
		if query.Profile != "" && failure.Profile != query.Profile || query.ADOM != "" && failure.ADOM != "" && failure.ADOM != query.ADOM || query.Device != "" && failure.Device != "" && failure.Device != query.Device {
			continue
		}
		result.Errors = append(result.Errors, failure)
	}
	result.UnavailableDevices = scopedNotices(s.snapshot.UnavailableDevices, query.Profile, query.ADOM, query.Device)
	owners := make(map[[5]string]bool)
	for _, candidate := range result.Candidates {
		owners[[5]string{candidate.Profile, candidate.ADOM, candidate.Device, candidate.VDOM, candidate.Interface}] = true
	}
	result.Ambiguous = len(owners) > 1
	return result, nil
}

func scopedNotices(notices []DeviceNotice, profile, adom, device string) []DeviceNotice {
	var result []DeviceNotice
	for _, notice := range notices {
		if profile != "" && notice.Profile != profile || adom != "" && notice.ADOM != adom || device != "" && notice.Device != device {
			continue
		}
		result = append(result, notice)
	}
	return result
}

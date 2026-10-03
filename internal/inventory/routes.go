package inventory

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

// RouteQuery selects configured-route evidence for one destination address.
type RouteQuery struct {
	IP      string `json:"ip" jsonschema:"Destination IPv4 or IPv6 address to route, for example 8.8.8.8"`
	Profile string `json:"profile,omitempty" jsonschema:"Limit to one FortiManager profile name"`
	ADOM    string `json:"adom,omitempty" jsonschema:"Limit to one ADOM name"`
	Device  string `json:"device,omitempty" jsonschema:"Limit to one managed FortiGate name; use the source-side FortiGate from resolve_ip_ownership"`
	VDOM    string `json:"vdom,omitempty" jsonschema:"Limit to one VDOM name"`
}

// RouteCandidate is the best configured route of one device VDOM for the
// queried address. Rank 1 is preferred; equal-cost entries share a tier.
type RouteCandidate struct {
	Profile             string                 `json:"profile"`
	ADOM                string                 `json:"adom"`
	Device              string                 `json:"device"`
	VDOM                string                 `json:"vdom"`
	Rank                int                    `json:"rank"`
	EqualCost           bool                   `json:"equal_cost,omitempty"`
	Kind                string                 `json:"kind"`
	Destination         string                 `json:"destination"`
	Gateway             string                 `json:"gateway,omitempty"`
	Interface           string                 `json:"interface,omitempty"`
	Zone                string                 `json:"zone,omitempty"`
	SDWANZone           string                 `json:"sdwan_zone,omitempty"`
	SDWANMembers        []fortinet.SDWANMember `json:"sdwan_members,omitempty"`
	Distance            int                    `json:"distance"`
	Priority            int                    `json:"priority,omitempty"`
	SeqNum              int                    `json:"seq_num,omitempty"`
	Comment             string                 `json:"comment,omitempty"`
	OtherMatchingRoutes int                    `json:"other_matching_routes,omitempty"`
	prefixBits          int
}

type RouteResult struct {
	IP                 string           `json:"ip"`
	Scope              RouteQuery       `json:"scope"`
	GeneratedAt        time.Time        `json:"generated_at"`
	Ready              bool             `json:"ready"`
	RefreshInProgress  bool             `json:"refresh_in_progress,omitempty"`
	Ambiguous          bool             `json:"ambiguous"`
	Candidates         []RouteCandidate `json:"candidates"`
	Profiles           []ProfileState   `json:"profiles,omitempty"`
	Errors             []RefreshError   `json:"errors,omitempty"`
	UnavailableDevices []DeviceNotice   `json:"unavailable_devices,omitempty"`
	Warnings           []string         `json:"warnings,omitempty"`
	Limitation         string           `json:"limitation"`
}

const routeLimitation = "Configured routing from the FortiManager device database: connected networks, static routes, policy routes and SD-WAN rules. Dynamic routes (BGP/OSPF), SD-WAN health/SLA state, VRFs and route health are not in the database; use get_fortigate_settings /api/v2/monitor/router/ipv4 on the FortiGate when they can change the decision. No candidate is not proof that the device lacks a route."

// ResolveRoute returns, for every device VDOM in scope that has a matching
// connected network or static route, the preferred route tier. It performs
// no network I/O.
func (s *Store) ResolveRoute(query RouteQuery) (RouteResult, error) {
	return ResolveRouteIn(s.Snapshot(), query)
}

// ResolveRouteIn evaluates query against the given snapshot, so a caller
// that reads further data from the same snapshot sees one consistent
// inventory even when a refresh publishes a new one meanwhile.
func ResolveRouteIn(snapshot Snapshot, query RouteQuery) (RouteResult, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(query.IP))
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() {
		return RouteResult{}, fmt.Errorf("ip must be a concrete IPv4 or IPv6 address without a zone")
	}
	ip = ip.Unmap()
	query.IP = ip.String()
	result := RouteResult{IP: ip.String(), Scope: query, GeneratedAt: snapshot.GeneratedAt, Ready: !snapshot.GeneratedAt.IsZero(), RefreshInProgress: snapshot.RefreshInProgress, Candidates: []RouteCandidate{}, Limitation: routeLimitation}
	if !result.Ready {
		result.Warnings = append(result.Warnings, notReadyMessage(snapshot))
	}
	result.UnavailableDevices = scopedNotices(snapshot.UnavailableDevices, query.Profile, query.ADOM, query.Device)
	groups := 0
	unresolvedObjects := 0
	downRoutes := 0
	for _, device := range snapshot.Devices {
		if query.Profile != "" && device.Profile != query.Profile || query.ADOM != "" && device.ADOM != query.ADOM || query.Device != "" && device.Name != query.Device {
			continue
		}
		candidates, objectRoutes := BestRoutes(device, ip, query.VDOM)
		unresolvedObjects += objectRoutes
		downRoutes += DownInterfaceRoutes(device, ip, query.VDOM)
		if len(candidates) == 0 {
			continue
		}
		seenVDOM := make(map[string]struct{})
		for _, candidate := range candidates {
			seenVDOM[candidate.VDOM] = struct{}{}
		}
		groups += len(seenVDOM)
		result.Candidates = append(result.Candidates, candidates...)
	}
	result.Ambiguous = groups > 1
	if unresolvedObjects > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%d static route(s) in scope use address objects or internet services as destination and were not evaluated.", unresolvedObjects))
	}
	if downRoutes > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%d configured route(s) to this address use an administratively down interface; FortiOS does not install them, so they were not considered.", downRoutes))
	}
	for _, profile := range snapshot.Profiles {
		if query.Profile == "" || profile.Profile == query.Profile {
			result.Profiles = append(result.Profiles, profile)
		}
	}
	for _, failure := range snapshot.Errors {
		if query.Profile != "" && failure.Profile != query.Profile || query.ADOM != "" && failure.ADOM != "" && failure.ADOM != query.ADOM || query.Device != "" && failure.Device != "" && failure.Device != query.Device {
			continue
		}
		if failure.Stage == "list_routes" || failure.Stage == "list_interfaces" || failure.Stage == "list_devices" || failure.Stage == "list_adoms" || failure.Stage == "refresh" {
			result.Errors = append(result.Errors, failure)
		}
	}
	return result, nil
}

// BestRoutes computes the preferred configured route tier for ip in each
// VDOM of device (or only vdom when given): longest prefix first, then
// lowest administrative distance and lowest priority. Equal-cost routes
// share all three criteria.
// The second value counts object-based routes that could not be evaluated.
func BestRoutes(device fortinet.Device, ip netip.Addr, vdom string) ([]RouteCandidate, int) {
	byVDOM := make(map[string][]RouteCandidate)
	unresolved := 0
	zoneOf := make(map[string]string, len(device.Interfaces))
	for _, iface := range device.Interfaces {
		if iface.Zone != "" {
			zoneOf[iface.Name] = iface.Zone
		}
	}
	down := downInterfaces(device)
	base := func(routeVDOM string) RouteCandidate {
		return RouteCandidate{Profile: device.Profile, ADOM: device.ADOM, Device: device.Name, VDOM: routeVDOM}
	}
	for _, iface := range device.Interfaces {
		if down[iface.Name] {
			// An administratively down interface has no connected route.
			continue
		}
		ifaceVDOM := iface.VDOM
		if ifaceVDOM == "" {
			ifaceVDOM = "root"
		}
		if vdom != "" && ifaceVDOM != vdom {
			continue
		}
		seen := make(map[string]struct{})
		for _, network := range append(append([]string(nil), iface.Networks...), iface.Network) {
			prefix, err := netip.ParsePrefix(network)
			if err != nil || prefix.Bits() == 0 || !prefix.Contains(ip) {
				continue
			}
			prefix = prefix.Masked()
			if _, duplicate := seen[prefix.String()]; duplicate {
				continue
			}
			seen[prefix.String()] = struct{}{}
			candidate := base(ifaceVDOM)
			candidate.Kind, candidate.Destination, candidate.Interface, candidate.Zone = "connected", prefix.String(), iface.Name, iface.Zone
			candidate.prefixBits = prefix.Bits()
			byVDOM[ifaceVDOM] = append(byVDOM[ifaceVDOM], candidate)
		}
	}
	wantFamily := "ipv4"
	if ip.Is6() {
		wantFamily = "ipv6"
	}
	for _, route := range device.Routes {
		routeVDOM := route.VDOM
		if routeVDOM == "" {
			routeVDOM = "root"
		}
		if vdom != "" && routeVDOM != vdom {
			continue
		}
		if route.Status == "disable" {
			continue
		}
		if route.Destination == "" {
			if route.DstAddrObject != "" {
				unresolved++
			}
			continue
		}
		if route.Family != "" && route.Family != wantFamily {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || !prefix.Contains(ip) {
			continue
		}
		if down[route.Interface] {
			// FortiOS does not install a route over a disabled interface.
			continue
		}
		candidate := base(routeVDOM)
		candidate.Kind = "static"
		if prefix.Bits() == 0 {
			candidate.Kind = "default"
		}
		if route.Blackhole {
			candidate.Kind = "blackhole"
		}
		candidate.Destination = prefix.Masked().String()
		candidate.Gateway, candidate.Interface, candidate.SDWANZone = route.Gateway, route.Interface, route.SDWANZone
		if candidate.Interface == "" && route.SDWANZone != "" {
			candidate.Interface = route.SDWANZone
		}
		candidate.Zone = zoneOf[candidate.Interface]
		if members := SDWANZoneMembers(device, routeVDOM, candidate.SDWANZone); len(members) > 0 {
			candidate.SDWANMembers = members
		} else if candidate.SDWANZone == "" {
			if members := SDWANZoneMembers(device, routeVDOM, candidate.Interface); len(members) > 0 {
				// Older configurations route to the zone name as the device.
				candidate.SDWANZone, candidate.SDWANMembers = candidate.Interface, members
			}
		}
		candidate.Distance, candidate.Priority, candidate.SeqNum, candidate.Comment = route.Distance, route.Priority, route.SeqNum, route.Comment
		candidate.prefixBits = prefix.Bits()
		byVDOM[routeVDOM] = append(byVDOM[routeVDOM], candidate)
	}

	vdoms := make([]string, 0, len(byVDOM))
	for name := range byVDOM {
		vdoms = append(vdoms, name)
	}
	sort.Strings(vdoms)
	result := make([]RouteCandidate, 0)
	for _, name := range vdoms {
		matches := byVDOM[name]
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].prefixBits != matches[j].prefixBits {
				return matches[i].prefixBits > matches[j].prefixBits
			}
			if matches[i].Distance != matches[j].Distance {
				return matches[i].Distance < matches[j].Distance
			}
			if matches[i].Priority != matches[j].Priority {
				return matches[i].Priority < matches[j].Priority
			}
			return matches[i].SeqNum < matches[j].SeqNum
		})
		tier := 0
		for tier < len(matches) && matches[tier].prefixBits == matches[0].prefixBits && matches[tier].Distance == matches[0].Distance && matches[tier].Priority == matches[0].Priority {
			tier++
		}
		for index := 0; index < tier; index++ {
			matches[index].Rank = index + 1
			matches[index].EqualCost = tier > 1
		}
		matches[0].OtherMatchingRoutes = len(matches) - tier
		result = append(result, matches[:tier]...)
	}
	return result, unresolved
}

func downInterfaces(device fortinet.Device) map[string]bool {
	down := make(map[string]bool)
	for _, iface := range device.Interfaces {
		if strings.EqualFold(strings.TrimSpace(iface.Status), "down") {
			down[iface.Name] = true
		}
	}
	return down
}

// DownInterfaceRoutes counts the connected networks and static routes to ip
// that BestRoutes left out because their interface is administratively down.
func DownInterfaceRoutes(device fortinet.Device, ip netip.Addr, vdom string) int {
	down := downInterfaces(device)
	if len(down) == 0 {
		return 0
	}
	count := 0
	for _, iface := range device.Interfaces {
		if !down[iface.Name] || vdom != "" && firstNonEmptyVDOM(iface.VDOM) != vdom {
			continue
		}
		for _, network := range append(append([]string(nil), iface.Networks...), iface.Network) {
			if prefix, err := netip.ParsePrefix(network); err == nil && prefix.Bits() > 0 && prefix.Contains(ip) {
				count++
				break
			}
		}
	}
	for _, route := range device.Routes {
		if !down[route.Interface] || route.Status == "disable" || vdom != "" && firstNonEmptyVDOM(route.VDOM) != vdom {
			continue
		}
		if prefix, err := netip.ParsePrefix(route.Destination); err == nil && prefix.Contains(ip) {
			count++
		}
	}
	return count
}

func firstNonEmptyVDOM(vdom string) string {
	if vdom == "" {
		return "root"
	}
	return vdom
}

// NextHopOwner is an inventoried FortiGate interface that holds a gateway
// address, and so is the next managed hop of a route.
type NextHopOwner struct {
	Gateway   string `json:"gateway"`
	Profile   string `json:"profile"`
	ADOM      string `json:"adom"`
	Device    string `json:"device"`
	VDOM      string `json:"vdom,omitempty"`
	Interface string `json:"interface"`
	Zone      string `json:"zone,omitempty"`
}

// NextHopOwners returns the inventoried interfaces whose own address is
// gateway. Only an exact interface address identifies the next FortiGate: a
// shared subnet alone does not prove which device the gateway is.
func NextHopOwners(snapshot Snapshot, gateway netip.Addr) []NextHopOwner {
	gateway = gateway.Unmap()
	var owners []NextHopOwner
	for _, device := range snapshot.Devices {
		for _, iface := range device.Interfaces {
			if !interfaceHasAddress(iface, gateway) {
				continue
			}
			owners = append(owners, NextHopOwner{
				Gateway: gateway.String(), Profile: device.Profile, ADOM: device.ADOM, Device: device.Name,
				VDOM: firstNonEmptyVDOM(iface.VDOM), Interface: iface.Name, Zone: iface.Zone,
			})
		}
	}
	return owners
}

func interfaceHasAddress(iface fortinet.Interface, address netip.Addr) bool {
	values := append(append([]string{iface.IP}, iface.Addresses...), iface.IPv6...)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if host, _, found := strings.Cut(value, "/"); found {
			value = host
		}
		if fields := strings.Fields(value); len(fields) > 0 {
			value = fields[0]
		}
		if parsed, err := netip.ParseAddr(value); err == nil && parsed.Unmap() == address {
			return true
		}
	}
	return false
}

// SDWANZoneMembers returns the enabled SD-WAN members of zone in vdom. The
// legacy default zone "virtual-wan-link" also matches every member when the
// configuration defines no explicit zones.
func SDWANZoneMembers(device fortinet.Device, vdom, zone string) []fortinet.SDWANMember {
	if strings.TrimSpace(zone) == "" {
		return nil
	}
	if vdom == "" {
		vdom = "root"
	}
	var members []fortinet.SDWANMember
	for _, config := range device.SDWAN {
		configVDOM := config.VDOM
		if configVDOM == "" {
			configVDOM = "root"
		}
		if configVDOM != vdom {
			continue
		}
		for _, member := range config.Members {
			if member.Status == "disable" {
				continue
			}
			if member.Zone == zone || (zone == "virtual-wan-link" && len(config.Zones) == 0) {
				members = append(members, member)
			}
		}
	}
	return members
}

// SDWANMemberZone returns the SD-WAN zone of an interface in vdom, or "".
func SDWANMemberZone(device fortinet.Device, vdom, iface string) string {
	if vdom == "" {
		vdom = "root"
	}
	for _, config := range device.SDWAN {
		configVDOM := config.VDOM
		if configVDOM == "" {
			configVDOM = "root"
		}
		if configVDOM != vdom {
			continue
		}
		for _, member := range config.Members {
			if member.Interface == iface && member.Status != "disable" {
				return member.Zone
			}
		}
	}
	return ""
}

// NotReadyMessage explains an empty inventory: still loading, or no
// snapshot at all.
func NotReadyMessage(snapshot Snapshot) string {
	return notReadyMessage(snapshot)
}

func notReadyMessage(snapshot Snapshot) string {
	if snapshot.RefreshInProgress {
		return fmt.Sprintf("FortiGate inventory is still loading: the background refresh started at %s is running. Retry in a few seconds; calling refresh_inventory would only wait for the same refresh.", snapshot.RefreshStartedAt.Format(time.RFC3339))
	}
	return "No FortiGate inventory snapshot exists yet; the background refresh runs at startup and on its interval, or call refresh_inventory."
}

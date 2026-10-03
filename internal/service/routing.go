package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

// RouteLookupInput asks which configured path a FortiGate would take to a
// destination. Source, ingress, protocol and port refine policy-route and
// SD-WAN rule matching; without them such rules are reported as tentative.
type RouteLookupInput struct {
	IP              string `json:"ip" jsonschema:"Destination IPv4 or IPv6 address, or a hostname resolved with the MCP host's DNS (up to 4 addresses of the source's family are evaluated), for example 8.8.8.8 or www.example.com"`
	SourceIP        string `json:"source_ip,omitempty" jsonschema:"Source address of the flow; needed to evaluate policy routes and SD-WAN rules with source conditions"`
	SourceInterface string `json:"source_interface,omitempty" jsonschema:"Ingress interface or zone; derived from source_ip ownership when omitted"`
	Protocol        string `json:"protocol,omitempty" jsonschema:"tcp, udp, sctp, icmp or an IP protocol number; rules with a protocol condition stay tentative when omitted"`
	DestinationPort int    `json:"destination_port,omitempty" jsonschema:"Destination port for rules with a port range"`
	SourcePort      int    `json:"source_port,omitempty" jsonschema:"Source port for policy-route source-port conditions; matching restricted rules remain tentative when omitted"`
	Profile         string `json:"profile,omitempty" jsonschema:"Limit to one FortiManager profile name"`
	ADOM            string `json:"adom,omitempty" jsonschema:"Limit to one ADOM name"`
	Device          string `json:"device,omitempty" jsonschema:"Limit to one managed FortiGate name; use the source-side FortiGate from resolve_ip_ownership"`
	VDOM            string `json:"vdom,omitempty" jsonschema:"Limit to one VDOM name"`
	Follow          bool   `json:"follow,omitempty" jsonschema:"Walk the configured path through inventoried FortiGates. Read path.end before interpreting the last managed device; identify filtering from policies at each hop. Needs an unambiguous device/VDOM or source_ip."`
}

type RouteLookupOutput struct {
	inventory.RouteResult
	// DestinationResolution is set when ip was a hostname.
	DestinationResolution *DestinationResolution `json:"destination_resolution,omitempty"`
	Decisions             []RouteDecision        `json:"decisions"`
	// Path is the hop-by-hop walk requested with follow.
	Path *RoutePath `json:"path,omitempty"`
	// OtherAddresses holds the results for further addresses of a hostname.
	OtherAddresses []RouteLookupOutput `json:"other_addresses,omitempty"`
}

// RoutePath is the configured path from the first FortiGate through every
// next hop that is an inventoried FortiGate interface.
type RoutePath struct {
	Hops []RouteHop `json:"hops"`
	// End says why the walk stopped: leaves_managed_network,
	// destination_connected, no_route, blackhole, ambiguous_next_hop,
	// tentative_decision, loop or max_hops.
	End string `json:"end"`
	// LastManagedDevice is the last inventoried FortiGate traced. The end
	// reason determines whether this is an egress or an unresolved stopping point.
	LastManagedDevice string `json:"last_managed_device,omitempty"`
	Note              string `json:"note"`
}

type RouteHop struct {
	Hop              int                      `json:"hop"`
	Profile          string                   `json:"profile"`
	ADOM             string                   `json:"adom"`
	Device           string                   `json:"device"`
	VDOM             string                   `json:"vdom"`
	Ingress          []string                 `json:"ingress,omitempty"`
	Stage            string                   `json:"stage"`
	Confidence       string                   `json:"confidence"`
	EgressInterfaces []string                 `json:"egress_interfaces,omitempty"`
	EgressZones      []string                 `json:"egress_zones,omitempty"`
	Gateways         []string                 `json:"gateways,omitempty"`
	NextHops         []inventory.NextHopOwner `json:"next_hops,omitempty"`
	Notes            []string                 `json:"notes,omitempty"`
}

const (
	maxRouteAddresses = 4
	maxRouteHops      = 8
)

// RouteDecision is the configured forwarding decision of one device VDOM in
// FortiOS order: policy routes, then SD-WAN rules, then the routing table.
type RouteDecision struct {
	Profile          string                     `json:"profile"`
	ADOM             string                     `json:"adom"`
	Device           string                     `json:"device"`
	VDOM             string                     `json:"vdom"`
	Stage            string                     `json:"stage"`
	Confidence       string                     `json:"confidence"`
	EgressInterfaces []string                   `json:"egress_interfaces,omitempty"`
	EgressZones      []string                   `json:"egress_zones,omitempty"`
	Gateways         []string                   `json:"gateways,omitempty"`
	PolicyRoute      *PolicyRouteMatch          `json:"policy_route,omitempty"`
	SDWANRule        *SDWANRuleMatch            `json:"sdwan_rule,omitempty"`
	Routes           []inventory.RouteCandidate `json:"routes,omitempty"`
	// NextHops names the inventoried FortiGate interfaces that own the
	// gateways, so the next managed hop needs no further lookup.
	NextHops []inventory.NextHopOwner `json:"next_hops,omitempty"`
	Notes    []string                 `json:"notes,omitempty"`
}

type PolicyRouteMatch struct {
	SeqNum       int    `json:"seq_num"`
	Action       string `json:"action"`
	OutputDevice string `json:"output_device,omitempty"`
	Gateway      string `json:"gateway,omitempty"`
	Comment      string `json:"comment,omitempty"`
}

type SDWANRuleMatch struct {
	ID        int                    `json:"id"`
	Name      string                 `json:"name,omitempty"`
	Mode      string                 `json:"mode,omitempty"`
	Members   []fortinet.SDWANMember `json:"members,omitempty"`
	Selection string                 `json:"selection"`
}

type routeTuple struct {
	src      netip.Addr
	dst      netip.Addr
	protocol int
	srcPort  int
	dstPort  int
	ingress  []string
}

type matchState int

const (
	noMatch matchState = iota
	fullMatch
	unresolvedMatch
)

// ResolveRoute answers which configured path each FortiGate in scope takes
// to a destination. Only ADOM address objects are read from FortiManager,
// and only when a policy route or SD-WAN rule in scope refers to objects.
// A hostname is resolved first; every evaluated address gets its own result.
func (s *Service) ResolveRoute(ctx context.Context, input RouteLookupInput) (RouteLookupOutput, error) {
	if s.store == nil {
		return RouteLookupOutput{}, fmt.Errorf("inventory store is not configured")
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	target := strings.TrimSpace(input.IP)
	if _, err := netip.ParseAddr(target); err == nil || target == "" {
		return s.resolveRouteAddress(ctx, input, s.store.Snapshot())
	}
	resolved, err := s.resolveDestination(ctx, target)
	if err != nil {
		return RouteLookupOutput{}, err
	}
	addresses := resolved.ips
	if source := net.ParseIP(strings.TrimSpace(input.SourceIP)); source != nil {
		addresses = resolved.sameIPVersionAs(source)
		if len(addresses) == 0 {
			return RouteLookupOutput{}, fmt.Errorf("hostname %q resolved to no address of the source's IP family (%s)", target, strings.Join(resolved.info.Addresses, ", "))
		}
	}
	if len(addresses) > maxRouteAddresses {
		addresses = addresses[:maxRouteAddresses]
	}
	resolved.info.EvaluatedAddresses = ipStrings(addresses)
	resolved.info.ExcludedAddresses = differenceIPStrings(resolved.ips, addresses)
	snapshot := s.store.Snapshot()
	outputs := make([]RouteLookupOutput, 0, len(addresses))
	for _, address := range addresses {
		next := input
		next.IP = address.String()
		output, err := s.resolveRouteAddress(ctx, next, snapshot)
		if err != nil {
			return RouteLookupOutput{}, err
		}
		outputs = append(outputs, output)
	}
	first := outputs[0]
	info := resolved.info
	first.DestinationResolution = &info
	first.OtherAddresses = outputs[1:]
	if len(outputs) > 1 {
		first.Warnings = append(first.Warnings, fmt.Sprintf("%q resolved to %d evaluated addresses; each has its own result (other_addresses), and the client may use any of them.", target, len(outputs)))
	}
	return first, nil
}

func (s *Service) resolveRouteAddress(ctx context.Context, input RouteLookupInput, snapshot inventory.Snapshot) (RouteLookupOutput, error) {
	base, err := inventory.ResolveRouteIn(snapshot, inventory.RouteQuery{IP: input.IP, Profile: strings.TrimSpace(input.Profile), ADOM: strings.TrimSpace(input.ADOM), Device: strings.TrimSpace(input.Device), VDOM: strings.TrimSpace(input.VDOM)})
	if err != nil {
		return RouteLookupOutput{}, err
	}
	output := RouteLookupOutput{RouteResult: base, Decisions: []RouteDecision{}}
	tuple := routeTuple{dst: netip.MustParseAddr(base.IP), dstPort: input.DestinationPort, srcPort: input.SourcePort}
	if input.SourcePort < 0 || input.SourcePort > 65535 {
		return output, fmt.Errorf("source_port must be between 0 and 65535")
	}
	if input.DestinationPort < 0 || input.DestinationPort > 65535 {
		return output, fmt.Errorf("destination_port must be between 0 and 65535")
	}
	if raw := strings.TrimSpace(input.SourceIP); raw != "" {
		source, parseErr := netip.ParseAddr(raw)
		if parseErr != nil || source.Zone() != "" {
			return output, fmt.Errorf("source_ip %q is not a valid IP address", raw)
		}
		source = source.Unmap()
		if source.Is4() != tuple.dst.Is4() {
			return output, fmt.Errorf("source_ip %s and ip %s are different IP versions", source, tuple.dst)
		}
		tuple.src = source
	}
	if raw := strings.TrimSpace(input.Protocol); raw != "" {
		number, ok := protocolToNumber(raw)
		if !ok {
			return output, fmt.Errorf("unsupported protocol %q; use tcp, udp, sctp, icmp or a number from 1 to 255", raw)
		}
		tuple.protocol = number
	}

	type scopeKey struct{ profile, adom, device, vdom string }
	seen := make(map[scopeKey]struct{})
	for _, candidate := range base.Candidates {
		key := scopeKey{candidate.Profile, candidate.ADOM, candidate.Device, candidate.VDOM}
		if _, done := seen[key]; done {
			continue
		}
		seen[key] = struct{}{}
		device, ok := findDevice(snapshot, candidate.Profile, candidate.ADOM, candidate.Device)
		if !ok {
			continue
		}
		deviceTuple := tuple
		deviceTuple.ingress = ingressSelectors(device, candidate.VDOM, input.SourceInterface, tuple.src)
		output.Decisions = append(output.Decisions, s.routeDecision(ctx, snapshot, device, candidate.VDOM, deviceTuple, &output.RouteResult))
	}
	if input.Follow {
		output.Path = s.followRoute(ctx, snapshot, input, tuple, &output.RouteResult)
	}
	return output, nil
}

// routeDecision evaluates one device VDOM and names the inventoried
// FortiGates that own its gateways.
func (s *Service) routeDecision(ctx context.Context, snapshot inventory.Snapshot, device fortinet.Device, vdom string, tuple routeTuple, result *inventory.RouteResult) RouteDecision {
	resolver, notes := s.routeResolver(ctx, device, vdom, tuple.dst.Is6(), snapshot.GeneratedAt, result)
	decision := evaluateRouting(device, vdom, tuple, resolver)
	decision.Notes = append(decision.Notes, notes...)
	for _, gateway := range decision.Gateways {
		address, err := netip.ParseAddr(gateway)
		if err != nil {
			continue
		}
		for _, owner := range inventory.NextHopOwners(snapshot, address) {
			if owner.Device != device.Name || owner.Profile != device.Profile {
				decision.NextHops = append(decision.NextHops, owner)
			}
		}
	}
	return decision
}

// followRoute walks the configured path from the first FortiGate (device,
// or the FortiGates the source address is connected to) while the next hop
// is exactly one inventoried FortiGate interface. It stops, and says why, at
// the first hop it cannot decide.
func (s *Service) followRoute(ctx context.Context, snapshot inventory.Snapshot, input RouteLookupInput, tuple routeTuple, result *inventory.RouteResult) *RoutePath {
	path := &RoutePath{Hops: []RouteHop{}}
	var device fortinet.Device
	vdom := strings.TrimSpace(input.VDOM)
	ingress := []string(nil)
	switch {
	case strings.TrimSpace(input.Device) != "":
		var matches []fortinet.Device
		for _, candidate := range snapshot.Devices {
			if candidate.Name == strings.TrimSpace(input.Device) && (input.Profile == "" || candidate.Profile == input.Profile) && (input.ADOM == "" || candidate.ADOM == input.ADOM) {
				matches = append(matches, candidate)
			}
		}
		if len(matches) != 1 {
			path.End, path.Note = "not_resolved", fmt.Sprintf("Device %q matches %d inventoried scopes; pass profile and ADOM to select one starting FortiGate.", input.Device, len(matches))
			return path
		}
		device = matches[0]
	case tuple.src.IsValid():
		var starts []fortinet.Device
		for _, candidate := range snapshot.Devices {
			if input.Profile != "" && candidate.Profile != input.Profile || input.ADOM != "" && candidate.ADOM != input.ADOM {
				continue
			}
			for _, route := range bestConnected(candidate, tuple.src) {
				if (vdom == "" || route.VDOM == vdom) && (input.SourceInterface == "" || route.Interface == input.SourceInterface || route.Zone == input.SourceInterface) {
					starts = append(starts, candidate)
					break
				}
			}
		}
		if len(starts) != 1 {
			path.End = "not_resolved"
			path.Note = fmt.Sprintf("The source %s is connected to %d inventoried FortiGates; pass device to choose where the path starts.", tuple.src, len(starts))
			return path
		}
		device = starts[0]
	default:
		path.End, path.Note = "not_resolved", "follow needs device or source_ip to know the first FortiGate."
		return path
	}
	if vdom == "" {
		var starts []string
		if tuple.src.IsValid() {
			for _, connected := range bestConnected(device, tuple.src) {
				if input.SourceInterface == "" || connected.Interface == input.SourceInterface || connected.Zone == input.SourceInterface {
					starts = append(starts, connected.VDOM)
				}
			}
		}
		if len(starts) == 0 && input.SourceInterface != "" {
			for _, iface := range device.Interfaces {
				if interfaceSelectorMatches(iface, input.SourceInterface) {
					starts = append(starts, routeVDOM(iface.VDOM))
				}
			}
		}
		if len(starts) == 0 {
			for _, scoped := range policyDeviceScopes(device, "") {
				starts = append(starts, scoped.VDOMs[0])
			}
		}
		starts = uniqueStrings(starts)
		if len(starts) != 1 {
			path.End, path.Note = "not_resolved", fmt.Sprintf("Starting FortiGate %s/%s/%s matches VDOMs %s; pass vdom or an unambiguous source_interface.", device.Profile, device.ADOM, device.Name, strings.Join(starts, ", "))
			return path
		}
		vdom = starts[0]
	}
	if len(policyDeviceScopes(device, vdom)) == 0 {
		path.End, path.Note = "not_resolved", fmt.Sprintf("VDOM %q is not inventoried on %s/%s/%s.", vdom, device.Profile, device.ADOM, device.Name)
		return path
	}
	if input.SourceInterface != "" {
		found := false
		for _, iface := range device.Interfaces {
			if routeVDOM(iface.VDOM) == vdom && interfaceSelectorMatches(iface, input.SourceInterface) {
				found = true
				break
			}
		}
		if !found {
			path.End, path.Note = "not_resolved", fmt.Sprintf("Ingress selector %q is not inventoried on %s/%s/%s/%s.", input.SourceInterface, device.Profile, device.ADOM, device.Name, vdom)
			return path
		}
	}
	ingress = ingressSelectors(device, vdom, input.SourceInterface, tuple.src)
	visited := make(map[string]bool)
	for hop := 1; ; hop++ {
		key := device.Profile + "\x00" + device.ADOM + "\x00" + device.Name + "\x00" + vdom
		if visited[key] {
			path.End, path.Note = "loop", fmt.Sprintf("The path returns to %s/%s; check the routing of the hops above.", device.Name, vdom)
			return path
		}
		visited[key] = true
		hopTuple := tuple
		hopTuple.ingress = ingress
		decision := s.routeDecision(ctx, snapshot, device, vdom, hopTuple, result)
		path.Hops = append(path.Hops, RouteHop{
			Hop: hop, Profile: device.Profile, ADOM: device.ADOM, Device: device.Name, VDOM: vdom, Ingress: ingress,
			Stage: decision.Stage, Confidence: decision.Confidence, EgressInterfaces: decision.EgressInterfaces,
			EgressZones: decision.EgressZones, Gateways: decision.Gateways, NextHops: decision.NextHops,
			Notes: decision.Notes,
		})
		path.LastManagedDevice = device.Name
		switch {
		case decision.Confidence == "tentative":
			path.End = "tentative_decision"
			path.Note = fmt.Sprintf("Routing on %s/%s is tentative; the path stops here. Read this hop's notes before choosing a continuation.", device.Name, vdom)
			return path
		case decision.Stage == "no_route" || decision.Stage == "blackhole":
			path.End = decision.Stage
			path.Note = fmt.Sprintf("%s/%s has no usable configured route to %s (%s).", device.Name, vdom, tuple.dst, decision.Stage)
			return path
		case len(decision.Gateways) == 0:
			if decision.Stage != "routing_table" || len(decision.Routes) == 0 || decision.Routes[0].Kind != "connected" {
				path.End, path.Note = "not_resolved", fmt.Sprintf("%s/%s has a configured egress (%s) without a gateway that inventory can follow; the destination is not proven connected.", device.Name, vdom, strings.Join(decision.EgressInterfaces, ", "))
				return path
			}
			path.End = "destination_connected"
			path.Note = fmt.Sprintf("%s/%s reaches %s on a connected network (%s).", device.Name, vdom, tuple.dst, strings.Join(decision.EgressInterfaces, ", "))
			return path
		case len(decision.NextHops) == 0:
			path.End = "leaves_managed_network"
			path.Note = fmt.Sprintf("%s/%s has a configured next hop %s with no exact inventoried FortiGate interface owner. The trace ends at this inventory boundary; downstream routing and filtering remain unverified. Check the carrying policy and web filtering at each managed hop.", device.Name, vdom, strings.Join(decision.Gateways, ", "))
			return path
		case hop >= maxRouteHops:
			path.End, path.Note = "max_hops", fmt.Sprintf("Stopped after %d hops.", maxRouteHops)
			return path
		}
		owners := uniqueOwnerDevices(decision.NextHops)
		if len(owners) != 1 || len(decision.Gateways) != 1 {
			path.End = "ambiguous_next_hop"
			path.Note = fmt.Sprintf("%s/%s has several next hops (%s); follow each candidate with resolve_route and device.", device.Name, vdom, strings.Join(decision.Gateways, ", "))
			return path
		}
		owner := decision.NextHops[0]
		next, found := findDevice(snapshot, owner.Profile, owner.ADOM, owner.Device)
		if !found {
			path.End, path.Note = "not_resolved", fmt.Sprintf("Next hop %s is on %s, which is not in the inventory snapshot.", owner.Gateway, owner.Device)
			return path
		}
		device, vdom = next, owner.VDOM
		ingress = []string{owner.Interface}
		if owner.Zone != "" {
			ingress = append(ingress, owner.Zone)
		}
	}
}

// bestConnected returns the connected networks of device that contain ip.
func bestConnected(device fortinet.Device, ip netip.Addr) []inventory.RouteCandidate {
	best, _ := inventory.BestRoutes(device, ip, "")
	var connected []inventory.RouteCandidate
	for _, route := range best {
		if route.Kind == "connected" {
			connected = append(connected, route)
		}
	}
	return connected
}

func uniqueOwnerDevices(owners []inventory.NextHopOwner) []string {
	var devices []string
	for _, owner := range owners {
		devices = append(devices, owner.Profile+"/"+owner.ADOM+"/"+owner.Device+"/"+owner.VDOM)
	}
	return uniqueStrings(devices)
}

func findDevice(snapshot inventory.Snapshot, profile, adom, name string) (fortinet.Device, bool) {
	for _, device := range snapshot.Devices {
		if device.Profile == profile && device.ADOM == adom && device.Name == name {
			return device, true
		}
	}
	return fortinet.Device{}, false
}

// ingressSelectors returns the interface and zone names traffic from src
// enters on, or the explicit interface when given.
func ingressSelectors(device fortinet.Device, vdom, explicit string, src netip.Addr) []string {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		selectors := []string{explicit}
		for _, iface := range device.Interfaces {
			if routeVDOM(iface.VDOM) == routeVDOM(vdom) && iface.Name == explicit && iface.Zone != "" {
				selectors = append(selectors, iface.Zone)
			}
		}
		return selectors
	}
	if !src.IsValid() {
		return nil
	}
	best, _ := inventory.BestRoutes(device, src, vdom)
	var selectors []string
	for _, route := range best {
		if route.Kind != "connected" {
			continue
		}
		selectors = append(selectors, route.Interface)
		if route.Zone != "" {
			selectors = append(selectors, route.Zone)
		}
	}
	return uniqueStrings(selectors)
}

// routeResolver loads ADOM address objects only when a policy route or
// SD-WAN rule of this VDOM refers to object names.
func (s *Service) routeResolver(ctx context.Context, device fortinet.Device, vdom string, ipv6 bool, snapshotAt time.Time, result *inventory.RouteResult) (*addressResolver, []string) {
	needsObjects := false
	for _, route := range device.PolicyRoutes {
		if routeVDOM(route.VDOM) == vdom && (hasObjectNames(route.SrcAddr) || hasObjectNames(route.DstAddr)) {
			needsObjects = true
		}
	}
	for _, config := range device.SDWAN {
		if routeVDOM(config.VDOM) != vdom {
			continue
		}
		for _, rule := range config.Rules {
			if hasObjectNames(rule.Dst) || hasObjectNames(rule.Src) {
				needsObjects = true
			}
		}
	}
	if !needsObjects {
		return nil, nil
	}
	manager, err := s.manager(device.Profile)
	if err != nil {
		return nil, []string{"Address objects unavailable: " + err.Error()}
	}
	// Only address tables are read, in one request; routing never needs
	// service objects.
	objects := s.policyObjects(ctx, manager, device.ADOM, ipv6, false, snapshotAt)
	result.Errors = append(result.Errors, objects.errors...)
	notes := []string{"Rule address objects were resolved with their ADOM values; per-device dynamic mappings were not evaluated."}
	notes = append(notes, objects.warnings...)
	if len(objects.addresses) == 0 {
		return nil, notes
	}
	return newAddressResolver(objects.addresses), notes
}

func routeVDOM(vdom string) string {
	if vdom == "" {
		return "root"
	}
	return vdom
}

func hasObjectNames(names []string) bool {
	for _, name := range names {
		if name != "" && !strings.EqualFold(name, "all") && !strings.EqualFold(name, "all_ipv6") {
			return true
		}
	}
	return false
}

// evaluateRouting applies FortiOS precedence to the configured tables of one
// VDOM. A rule whose conditions cannot be decided makes every later result
// tentative instead of being skipped silently.
func evaluateRouting(device fortinet.Device, vdom string, tuple routeTuple, resolver *addressResolver) RouteDecision {
	vdom = routeVDOM(vdom)
	decision := RouteDecision{Profile: device.Profile, ADOM: device.ADOM, Device: device.Name, VDOM: vdom, Confidence: "configured"}
	table, _ := inventory.BestRoutes(device, tuple.dst, vdom)
	decision.Routes = table
	family := "ipv4"
	if tuple.dst.Is6() {
		family = "ipv6"
	}

	// 1. Policy routes, in configured order.
	skipSDWAN := false
policyLoop:
	for _, route := range device.PolicyRoutes {
		if routeVDOM(route.VDOM) != vdom || route.Status == "disable" || (route.Family != "" && route.Family != family) {
			continue
		}
		state, reason := matchPolicyRoute(route, tuple, resolver)
		switch state {
		case noMatch:
			continue
		case unresolvedMatch:
			decision.Confidence = "tentative"
			decision.Notes = append(decision.Notes, fmt.Sprintf("Policy route %d may match (%s); results below assume it does not.", route.SeqNum, reason))
			continue
		}
		if route.Action == "deny" {
			decision.Notes = append(decision.Notes, fmt.Sprintf("Policy route %d (action deny) matches: policy routing stops and the routing table decides.", route.SeqNum))
			skipSDWAN = true
			break policyLoop
		}
		decision.Stage = "policy_route"
		decision.PolicyRoute = &PolicyRouteMatch{SeqNum: route.SeqNum, Action: route.Action, OutputDevice: route.OutputDevice, Gateway: route.Gateway, Comment: route.Comment}
		addEgress(&decision, device, vdom, route.OutputDevice, route.Gateway)
		decision.Notes = append(decision.Notes, "FortiOS only uses a policy route while its gateway is reachable through the output interface; otherwise the next match or the routing table applies.")
		return decision
	}

	// 2. SD-WAN rules apply when the routing table sends the destination
	// over SD-WAN members.
	sdwanRoute := len(table) > 0 && len(table[0].SDWANMembers) > 0
	if !skipSDWAN && sdwanRoute {
		if config, ok := sdwanConfigFor(device, vdom); ok {
			routeMembers := make(map[int]fortinet.SDWANMember)
			for _, route := range table {
				for _, member := range route.SDWANMembers {
					routeMembers[member.SeqNum] = member
				}
			}
			for _, rule := range config.Rules {
				if rule.Status == "disable" {
					continue
				}
				state, reason := matchSDWANRule(rule, tuple, resolver)
				if state == noMatch {
					continue
				}
				if state == unresolvedMatch {
					decision.Confidence = "tentative"
					decision.Notes = append(decision.Notes, fmt.Sprintf("SD-WAN rule %d %q may match (%s); results below assume it does not.", rule.ID, rule.Name, reason))
					continue
				}
				members := sdwanRuleMembers(config, rule, routeMembers)
				if len(members) == 0 {
					decision.Notes = append(decision.Notes, fmt.Sprintf("SD-WAN rule %d %q matches but none of its members has a route to the destination; FortiOS skips it.", rule.ID, rule.Name))
					continue
				}
				selection := "Live SD-WAN health and SLA state choose among these members in the listed preference order."
				if rule.Mode == "manual" {
					selection = "Manual mode: the first listed member is used while it is up."
				} else if rule.Mode == "load-balance" {
					selection = "Load-balance mode: sessions are distributed across the members that meet the SLA."
				}
				decision.Stage = "sdwan_rule"
				decision.SDWANRule = &SDWANRuleMatch{ID: rule.ID, Name: rule.Name, Mode: rule.Mode, Members: members, Selection: selection}
				for _, member := range members {
					addEgress(&decision, device, vdom, member.Interface, member.Gateway)
				}
				return decision
			}
			decision.Notes = append(decision.Notes, "No SD-WAN rule matched; the implicit rule balances sessions across the SD-WAN members of the best route.")
		}
	}

	// 3. Routing table.
	if len(table) == 0 {
		decision.Stage = "no_route"
		decision.Notes = append(decision.Notes, "No connected network or static route in the FortiManager database covers the destination; a dynamic route may still exist on the FortiGate.")
		return decision
	}
	decision.Stage = "routing_table"
	if table[0].Kind == "blackhole" {
		decision.Stage = "blackhole"
		decision.Notes = append(decision.Notes, fmt.Sprintf("The best configured route %s is a blackhole: traffic is dropped unless a more specific dynamic route exists.", table[0].Destination))
		return decision
	}
	for _, route := range table {
		if len(route.SDWANMembers) > 0 {
			for _, member := range route.SDWANMembers {
				addEgress(&decision, device, vdom, member.Interface, firstNonEmpty(member.Gateway, route.Gateway))
			}
			continue
		}
		addEgress(&decision, device, vdom, route.Interface, route.Gateway)
	}
	if table[0].Kind != "connected" {
		decision.Notes = append(decision.Notes, "A more specific or lower-distance dynamic route (BGP/OSPF) on the FortiGate would override this configured route.")
	}
	return decision
}

func addEgress(decision *RouteDecision, device fortinet.Device, vdom, iface, gateway string) {
	if iface != "" {
		decision.EgressInterfaces = uniqueStrings(append(decision.EgressInterfaces, iface))
		for _, candidate := range device.Interfaces {
			if candidate.Name == iface && candidate.Zone != "" {
				decision.EgressZones = uniqueStrings(append(decision.EgressZones, candidate.Zone))
			}
		}
		if zone := inventory.SDWANMemberZone(device, vdom, iface); zone != "" {
			decision.EgressZones = uniqueStrings(append(decision.EgressZones, zone))
		}
	}
	if gateway != "" {
		decision.Gateways = uniqueStrings(append(decision.Gateways, gateway))
	}
}

func sdwanConfigFor(device fortinet.Device, vdom string) (fortinet.SDWANConfig, bool) {
	for _, config := range device.SDWAN {
		if routeVDOM(config.VDOM) == vdom {
			return config, true
		}
	}
	return fortinet.SDWANConfig{}, false
}

// sdwanRuleMembers lists the rule's members in preference order, keeping only
// members that have a route to the destination.
func sdwanRuleMembers(config fortinet.SDWANConfig, rule fortinet.SDWANRule, routed map[int]fortinet.SDWANMember) []fortinet.SDWANMember {
	bySeq := make(map[int]fortinet.SDWANMember, len(config.Members))
	for _, member := range config.Members {
		bySeq[member.SeqNum] = member
	}
	var ordered []fortinet.SDWANMember
	for _, seq := range rule.PriorityMembers {
		if member, ok := bySeq[seq]; ok {
			ordered = append(ordered, member)
		}
	}
	for _, zone := range rule.PriorityZones {
		for _, member := range config.Members {
			if member.Zone == zone {
				ordered = append(ordered, member)
			}
		}
	}
	if len(rule.PriorityMembers) == 0 && len(rule.PriorityZones) == 0 {
		ordered = append(ordered, config.Members...)
		sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].SeqNum < ordered[j].SeqNum })
	}
	result := make([]fortinet.SDWANMember, 0, len(ordered))
	seen := make(map[int]bool)
	for _, member := range ordered {
		if seen[member.SeqNum] || member.Status == "disable" {
			continue
		}
		if _, ok := routed[member.SeqNum]; !ok {
			continue
		}
		seen[member.SeqNum] = true
		result = append(result, member)
	}
	return result
}

func matchPolicyRoute(route fortinet.PolicyRoute, tuple routeTuple, resolver *addressResolver) (matchState, string) {
	var reasons []string
	combine := func(state matchState, reason string) bool {
		if state == noMatch {
			return false
		}
		if state == unresolvedMatch {
			reasons = append(reasons, reason)
		}
		return true
	}
	if len(route.InternetServices) > 0 {
		reasons = append(reasons, "internet-service condition")
	}
	if route.TOSMatch {
		reasons = append(reasons, "TOS condition")
	}
	if !combine(matchIngress(route.InputDevices, route.InputNegate, tuple.ingress)) {
		return noMatch, ""
	}
	if !combine(matchRouteAddress(route.Src, route.SrcAddr, route.SrcNegate, tuple.src, resolver, "source")) {
		return noMatch, ""
	}
	if !combine(matchRouteAddress(route.Dst, route.DstAddr, route.DstNegate, tuple.dst, resolver, "destination")) {
		return noMatch, ""
	}
	if !combine(matchProtocolPorts(route.Protocol, route.StartPort, route.EndPort, tuple.protocol, tuple.dstPort)) {
		return noMatch, ""
	}
	if restrictedPortRange(route.StartSourcePort, route.EndSourcePort) {
		if tuple.srcPort == 0 {
			reasons = append(reasons, "source port range")
		} else if tuple.srcPort < route.StartSourcePort || tuple.srcPort > route.EndSourcePort {
			return noMatch, ""
		}
	}
	if len(reasons) > 0 {
		return unresolvedMatch, strings.Join(reasons, ", ")
	}
	return fullMatch, ""
}

func matchSDWANRule(rule fortinet.SDWANRule, tuple routeTuple, resolver *addressResolver) (matchState, string) {
	var reasons []string
	combine := func(state matchState, reason string) bool {
		if state == noMatch {
			return false
		}
		if state == unresolvedMatch {
			reasons = append(reasons, reason)
		}
		return true
	}
	if rule.InternetService {
		reasons = append(reasons, "internet-service condition")
	}
	if rule.Identity {
		reasons = append(reasons, "user or group condition")
	}
	if !combine(matchIngress(rule.InputDevices, false, tuple.ingress)) {
		return noMatch, ""
	}
	if !combine(matchRouteAddress(nil, rule.Src, rule.SrcNegate, tuple.src, resolver, "source")) {
		return noMatch, ""
	}
	if !rule.InternetService || hasObjectNames(rule.Dst) {
		if !combine(matchRouteAddress(nil, rule.Dst, rule.DstNegate, tuple.dst, resolver, "destination")) {
			return noMatch, ""
		}
	}
	if !combine(matchProtocolPorts(rule.Protocol, rule.StartPort, rule.EndPort, tuple.protocol, tuple.dstPort)) {
		return noMatch, ""
	}
	if len(reasons) > 0 {
		return unresolvedMatch, strings.Join(reasons, ", ")
	}
	return fullMatch, ""
}

func matchIngress(devices []string, negate bool, ingress []string) (matchState, string) {
	if len(devices) == 0 {
		return fullMatch, ""
	}
	if len(ingress) == 0 {
		return unresolvedMatch, "ingress interface unknown"
	}
	matched := false
	for _, device := range devices {
		if containsFold(ingress, device) {
			matched = true
			break
		}
	}
	if matched != negate {
		return fullMatch, ""
	}
	return noMatch, ""
}

// matchRouteAddress evaluates literal subnets and address object names.
// Empty conditions and "all" match every address.
func matchRouteAddress(subnets, objects []string, negate bool, address netip.Addr, resolver *addressResolver, label string) (matchState, string) {
	if len(subnets) == 0 && !hasObjectNames(objects) {
		return fullMatch, ""
	}
	if !address.IsValid() {
		return unresolvedMatch, label + " address unknown"
	}
	matched, known := false, true
	for _, subnet := range subnets {
		if prefix, err := netip.ParsePrefix(subnet); err == nil && prefix.Contains(address) {
			matched = true
		}
	}
	if !matched && hasObjectNames(objects) {
		if resolver == nil {
			known = false
		} else {
			ip := net.IP(address.AsSlice())
			objectMatched, objectKnown, _ := resolver.matches(objects, ip, false)
			matched = objectMatched
			known = objectKnown || objectMatched
		}
	}
	if !matched && !known {
		return unresolvedMatch, label + " address object not resolvable"
	}
	if matched != negate {
		return fullMatch, ""
	}
	return noMatch, ""
}

func matchProtocolPorts(protocol, startPort, endPort, wantProtocol, wantPort int) (matchState, string) {
	if protocol == 0 {
		return fullMatch, ""
	}
	if wantProtocol == 0 {
		return unresolvedMatch, "protocol unknown"
	}
	if protocol != wantProtocol {
		return noMatch, ""
	}
	if (protocol == 6 || protocol == 17 || protocol == 132) && restrictedPortRange(startPort, endPort) {
		if wantPort == 0 {
			return unresolvedMatch, "destination port unknown"
		}
		if wantPort < startPort || (endPort > 0 && wantPort > endPort) {
			return noMatch, ""
		}
	}
	return fullMatch, ""
}

func restrictedPortRange(start, end int) bool {
	return start > 1 || (end > 0 && end < 65535)
}

func protocolToNumber(value string) (int, bool) {
	switch normalizeProtocol(value) {
	case "any":
		return 0, true
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "sctp":
		return 132, true
	case "icmp":
		return 1, true
	case "":
		return 0, false
	default:
		number, err := strconv.Atoi(normalizeProtocol(value))
		return number, err == nil
	}
}

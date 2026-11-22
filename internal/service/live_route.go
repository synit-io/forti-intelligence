package service

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

type LiveRouteEvidence struct {
	DeviceScope
	Status   string           `json:"status"`
	Resource string           `json:"resource"`
	Matches  []LiveRouteMatch `json:"matches"`
	Warnings []string         `json:"warnings,omitempty"`
	Error    string           `json:"error,omitempty"`
}

type LiveRouteMatch struct {
	Prefix   string             `json:"prefix"`
	VRF      *int               `json:"vrf,omitempty"`
	NextHops []LiveRouteNextHop `json:"next_hops"`
}

type LiveRouteNextHop struct {
	Gateway   string `json:"gateway,omitempty"`
	Interface string `json:"interface,omitempty"`
	Type      string `json:"type,omitempty"`
	Distance  *int   `json:"distance,omitempty"`
	Metric    *int   `json:"metric,omitempty"`
	Priority  *int   `json:"priority,omitempty"`
	EqualCost bool   `json:"equal_cost,omitempty"`
}

func (s *Service) liveRoute(ctx context.Context, snapshot inventory.Snapshot, scope inventory.RouteQuery, dest netip.Addr) *LiveRouteEvidence {
	resource := "/api/v2/monitor/router/ipv4"
	if dest.Is6() {
		resource = "/api/v2/monitor/router/ipv6"
	}
	evidence := &LiveRouteEvidence{
		Profile: scope.Profile, ADOM: scope.ADOM, Device: scope.Device, VDOM: scope.VDOM,
		Status: "unavailable", Resource: resource, Matches: []LiveRouteMatch{},
	}
	var devices []fortinet.Device
	for _, device := range snapshot.Devices {
		if device.Name == scope.Device && (scope.Profile == "" || scope.Profile == device.Profile) && (scope.ADOM == "" || scope.ADOM == device.ADOM) {
			devices = append(devices, device)
		}
	}
	if len(devices) != 1 {
		evidence.Error = fmt.Sprintf("Device %q matches %d inventory scopes. Use a unique device, profile and ADOM after inventory is ready.", scope.Device, len(devices))
		return evidence
	}
	device := devices[0]
	evidence.Profile, evidence.ADOM = device.Profile, device.ADOM
	if len(policyDeviceScopes(device, scope.VDOM)) == 0 {
		evidence.Error = fmt.Sprintf("VDOM %q is not inventoried on this device", scope.VDOM)
		return evidence
	}
	proxy, err := s.GetFortiManagerSettings(ctx, device.Profile, device.ADOM, device.Name, scope.VDOM, resource)
	if err != nil {
		evidence.Error = err.Error()
		return evidence
	}
	readLiveRoute(proxy.Data, dest, evidence)
	return evidence
}

func readLiveRoute(data any, dest netip.Addr, evidence *LiveRouteEvidence) {
	rows, envelope, skipped := monitorRecords(data)
	if rows == nil {
		evidence.Error = "The routing monitor returned an unrecognized response."
		return
	}
	if envelope.vdom != "" && envelope.vdom != evidence.VDOM {
		evidence.Error = fmt.Sprintf("The routing monitor returned VDOM %q instead of %q.", envelope.vdom, evidence.VDOM)
		return
	}
	evidence.Status = "available"
	partial := func(warning string) {
		evidence.Status = "partial"
		evidence.Warnings = append(evidence.Warnings, warning)
	}
	if envelope.truncated {
		partial("The appliance indicated that more routing rows were available.")
	}
	type bestPrefix struct {
		bits  int
		match LiveRouteMatch
	}
	const unknownVRF = -1
	best := make(map[int]bestPrefix)
	missingVRF := false
	parsed := 0
	for _, row := range rows {
		prefix, err := netip.ParsePrefix(monitorText(row, "ip_mask", "prefix", "network", "destination"))
		if err != nil || prefix.Addr().Is4() != dest.Is4() {
			skipped++
			continue
		}
		if vdom := monitorText(row, "vdom"); vdom != "" && vdom != evidence.VDOM {
			skipped++
			continue
		}
		parsed++
		if !prefix.Contains(dest) {
			continue
		}
		vrf := monitorNumber(row, "vrf")
		vrfKey := unknownVRF
		if vrf != nil {
			vrfKey = *vrf
		} else {
			missingVRF = true
		}
		group, exists := best[vrfKey]
		if !exists || prefix.Bits() > group.bits {
			group = bestPrefix{bits: prefix.Bits(), match: LiveRouteMatch{Prefix: prefix.Masked().String(), VRF: vrf}}
		}
		if prefix.Bits() == group.bits {
			group.match.NextHops = append(group.match.NextHops, LiveRouteNextHop{
				Gateway: monitorText(row, "gateway"), Interface: monitorText(row, "interface"), Type: monitorText(row, "type", "protocol"),
				Distance: monitorNumber(row, "distance"), Metric: monitorNumber(row, "metric"), Priority: monitorNumber(row, "priority"),
			})
			best[vrfKey] = group
		}
	}
	if skipped > 0 {
		partial(fmt.Sprintf("%d routing monitor rows could not be interpreted for this address family and VDOM.", skipped))
	}
	if parsed == 0 && skipped > 0 {
		evidence.Status = "unavailable"
		evidence.Error = "No routing monitor rows could be interpreted for the requested scope."
		return
	}
	if missingVRF {
		partial("Some matching rows omit VRF. They are grouped separately and cannot establish equal-cost paths in a known routing instance.")
	}
	vrfs := make([]int, 0, len(best))
	for vrf := range best {
		vrfs = append(vrfs, vrf)
	}
	sort.Ints(vrfs)
	unknownCost := false
	for _, vrf := range vrfs {
		match := best[vrf].match
		hops := match.NextHops
		type cost struct {
			routeType                  string
			distance, metric, priority int
		}
		firstByCost := make(map[cost]int)
		for i := range hops {
			hop := &hops[i]
			if !hop.hasCosts() {
				unknownCost = unknownCost || len(hops) > 1
				continue
			}
			if vrf == unknownVRF {
				continue
			}
			key := cost{strings.ToLower(hop.Type), *hop.Distance, *hop.Metric, *hop.Priority}
			first, exists := firstByCost[key]
			if !exists {
				firstByCost[key] = i
			} else if hop.Gateway != hops[first].Gateway || hop.Interface != hops[first].Interface {
				hop.EqualCost, hops[first].EqualCost = true, true
			}
		}
		evidence.Matches = append(evidence.Matches, match)
	}
	if unknownCost {
		partial("Some matching rows omit route type or costs needed to compare next hops.")
	}
}

func (hop LiveRouteNextHop) hasCosts() bool {
	return hop.Type != "" && hop.Distance != nil && hop.Metric != nil && hop.Priority != nil && (hop.Gateway != "" || hop.Interface != "")
}

func monitorText(row map[string]any, fields ...string) string {
	value, _ := firstField(row, fields...).(string)
	return strings.TrimSpace(value)
}

func monitorNumber(row map[string]any, field string) *int {
	n, err := strconv.Atoi(fmt.Sprint(firstField(row, field)))
	if err != nil || n < 0 {
		return nil
	}
	return &n
}

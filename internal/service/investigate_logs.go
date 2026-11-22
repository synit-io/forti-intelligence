package service

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

func (s *Service) investigateLogs(ctx context.Context, input InvestigateInput, output *InvestigateOutput) (fortinet.LogSearchResult, error) {
	filter := investigationLogFilter(input, output.Route)
	if filter == "" {
		return fortinet.LogSearchResult{}, fmt.Errorf("no concrete destination of the source address family was resolved; traffic search skipped")
	}
	adom, _, err := s.resolveAnalyzerADOM(input.LogProfile, input.LogADOM)
	if err != nil {
		return fortinet.LogSearchResult{}, err
	}
	request := fortinet.LogSearchRequest{ADOM: adom, LogType: "traffic", Filter: filter, StartTime: input.LogStart, EndTime: input.LogEnd, Limit: 25}
	device, vdom := s.investigationLogOrigin(input, output)
	if device.Name != "" {
		matches, err := s.analyzerDeviceMatches(ctx, input.LogProfile, adom, device.Serial, device.Hostname, device.Name)
		if err != nil {
			output.Warnings = append(output.Warnings, "logs: analyzer device mapping failed: "+err.Error())
		} else {
			request.Device = investigationLoggedName(matches, device.Serial)
		}
	}
	var scopeNote string
	switch {
	case request.Device == "":
		scopeNote = "Analyzer device and VDOM scope could not be verified. The search spans the ADOM; returned rows are candidates and need device and VDOM verification."
	case vdom == "":
		scopeNote = "Source VDOM could not be verified. The search spans this analyzer device's VDOMs; returned rows need VDOM verification."
	default:
		request.Filter = andFilter(request.Filter, "vd="+strconv.Quote(vdom))
	}
	if scopeNote != "" {
		output.Warnings = append(output.Warnings, "logs: "+scopeNote)
	}
	logs, err := s.SearchLogs(ctx, input.LogProfile, request)
	if scopeNote != "" && logResultUsable(logs) {
		logs.Warnings = append(logs.Warnings, scopeNote)
	}
	return logs, err
}

func investigationLoggedName(matches []map[string]any, serial string) string {
	var verified, possible []map[string]any
	for _, match := range matches {
		record, _ := match["device"].(map[string]any)
		switch {
		case serial != "" && fieldEqualsFold(record, serial, "sn", "serial", "devid"):
			verified = append(verified, record)
		case serial == "" || monitorText(record, "sn", "serial") == "":
			possible = append(possible, record)
		}
	}
	if len(verified) == 1 {
		return monitorText(verified[0], "devname")
	}
	if len(verified) == 0 && len(possible) == 1 {
		return monitorText(possible[0], "devname")
	}
	return ""
}

func (s *Service) investigationLogOrigin(input InvestigateInput, output *InvestigateOutput) (fortinet.Device, string) {
	if s.store == nil {
		return fortinet.Device{}, ""
	}
	scope := DeviceScope{Profile: input.Profile, ADOM: input.ADOM, Device: input.Device, VDOM: input.VDOM}
	var origins []DeviceScope
	for _, hop := range output.Hops {
		if hop.Route.Hop == 1 {
			origins = append(origins, DeviceScope{Profile: hop.Route.Profile, ADOM: hop.Route.ADOM, Device: hop.Route.Device, VDOM: hop.Route.VDOM})
		}
	}
	if len(origins) == 0 {
		selector := strings.TrimSpace(input.SourceInterface)
		for _, owner := range output.Ownership.Candidates {
			if selector != "" && owner.Interface != selector && owner.Zone != selector {
				continue
			}
			origins = append(origins, DeviceScope{Profile: owner.Profile, ADOM: owner.ADOM, Device: owner.Device, VDOM: owner.VDOM})
		}
	}
	if len(origins) > 0 {
		scope = origins[0]
		for _, candidate := range origins[1:] {
			if candidate.Device != scope.Device || candidate.Profile != scope.Profile || candidate.ADOM != scope.ADOM {
				return fortinet.Device{}, ""
			}
			if candidate.VDOM != scope.VDOM {
				scope.VDOM = ""
			}
		}
	}
	devices := s.store.FindDevices(strings.TrimSpace(scope.Profile), strings.TrimSpace(scope.ADOM), scope.Device)
	if len(devices) != 1 {
		return fortinet.Device{}, ""
	}
	vdoms := policyDeviceScopes(devices[0], strings.TrimSpace(scope.VDOM))
	if len(vdoms) != 1 {
		return devices[0], ""
	}
	return devices[0], vdoms[0].VDOMs[0]
}

func investigationLogFilter(input InvestigateInput, route RouteLookupOutput) string {
	source := net.ParseIP(input.SourceIP)
	addresses := []string{input.DestinationIP, route.IP}
	for _, other := range route.OtherAddresses {
		addresses = append(addresses, other.IP)
	}
	var destinations []string
	for _, address := range addresses {
		if ip := net.ParseIP(address); ip != nil && !ip.IsUnspecified() && (source.To4() == nil) == (ip.To4() == nil) {
			destinations = append(destinations, "dstip="+strconv.Quote(ip.String()))
		}
	}
	destinations = uniqueStrings(destinations)
	if len(destinations) == 0 {
		return ""
	}
	destinationFilter := destinations[0]
	if len(destinations) > 1 {
		destinationFilter = "(" + strings.Join(destinations, " OR ") + ")"
	}
	filter := andFilter("srcip="+strconv.Quote(source.String()), destinationFilter)
	if input.DestinationPort > 0 {
		filter = andFilter(filter, "dstport="+strconv.Itoa(input.DestinationPort))
	}
	if input.SourcePort > 0 {
		filter = andFilter(filter, "srcport="+strconv.Itoa(input.SourcePort))
	}
	if proto, ok := protocolToNumber(input.Protocol); ok && proto > 0 {
		filter = andFilter(filter, "proto="+strconv.Itoa(proto))
	}
	return filter
}

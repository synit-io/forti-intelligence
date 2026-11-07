package service

// CompactInvestigation retains diagnostic evidence while removing duplicate
// first-hop copies and raw appliance detail. Full remains the default contract.
type CompactInvestigation struct {
	Detail string          `json:"detail"`
	Flow   InvestigateFlow `json:"flow"`
	InvestigateOutput
	EvidenceSources []string              `json:"evidence_sources"`
	Coverage        InvestigationCoverage `json:"coverage"`
	Omitted         map[string]int        `json:"omitted"`
	OmissionNotice  string                `json:"omission_notice"`
}

type InvestigateFlow struct {
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	SourceInterface string `json:"source_interface,omitempty"`
	Profile         string `json:"profile,omitempty"`
	ADOM            string `json:"adom,omitempty"`
	Device          string `json:"device,omitempty"`
	VDOM            string `json:"vdom,omitempty"`
	URL             string `json:"url,omitempty"`
}

type InvestigationCoverage struct {
	Policy     string `json:"policy"`
	WebFilter  string `json:"web_filter"`
	Logs       string `json:"logs"`
	NAT        string `json:"nat"`
	ReturnPath string `json:"return_path"`
}

// CompactInvestigate is a pure projection: it does not change completeness,
// warning text, scoped alternatives or the full response's backing slices.
func CompactInvestigate(input InvestigateInput, full InvestigateOutput) CompactInvestigation {
	if full.Input != nil {
		input = *full.Input
	}
	out := CompactInvestigation{Detail: "compact", InvestigateOutput: full,
		Flow:            InvestigateFlow{SourceIP: input.SourceIP, DestinationIP: input.DestinationIP, SourcePort: input.SourcePort, DestinationPort: input.DestinationPort, Protocol: input.Protocol, SourceInterface: input.SourceInterface, Profile: input.Profile, ADOM: input.ADOM, Device: input.Device, VDOM: input.VDOM, URL: input.URL},
		EvidenceSources: []string{"FortiManager inventory and configured routing", "FortiManager configured policy and scoped FortiGate live lookup when available"},
		Coverage:        InvestigationCoverage{Policy: "inspect per-hop complete, errors and warnings", WebFilter: "not requested", Logs: "not requested", NAT: "Upstream NAT is not resolved; downstream lookups use the original tuple.", ReturnPath: "not checked"},
		Omitted:         make(map[string]int), OmissionNotice: "Duplicate first-hop policy/web-filter and route-hop copies, plus raw live-lookup payloads, are omitted. Counts describe representation only, not evidence completeness. Scoped identifiers remain usable with focused tools or detail=full."}
	if input.DestinationPort == 0 {
		out.Coverage.Policy = "skipped: destination_port omitted"
	}
	if input.URL != "" {
		out.Coverage.WebFilter = "inspect per-hop complete, errors and warnings"
	}
	if input.IncludeLogs {
		out.Coverage.Logs = "not completed; inspect errors"
		if full.Logs != nil {
			out.Coverage.Logs = "inspect logs.complete, error_details and next_action"
			out.EvidenceSources = append(out.EvidenceSources, "FortiAnalyzer observed logs")
		}
	}
	out.Route = compactRoute(full.Route, out.Omitted)
	out.Hops = append([]InvestigateHop(nil), full.Hops...)
	for i := range out.Hops {
		out.Hops[i].Policy = compactPolicy(out.Hops[i].Policy, out.Omitted)
	}
	// Keep the fallback policy when no traced hop owns it.
	if len(out.Hops) > 0 {
		if full.Policy != nil {
			out.Omitted["duplicate_policy"] = 1
		}
		out.Policy = nil
		if full.WebFilter != nil {
			out.Omitted["duplicate_web_filter"] = 1
		}
		out.WebFilter = nil
	} else {
		out.Policy = compactPolicy(full.Policy, out.Omitted)
	}
	return out
}

func compactRoute(full RouteLookupOutput, omitted map[string]int) RouteLookupOutput {
	out := full
	if full.Path != nil {
		path := *full.Path
		omitted["duplicate_route_hops"] += len(path.Hops)
		path.Hops = nil
		out.Path = &path
	}
	out.OtherAddresses = append([]RouteLookupOutput(nil), full.OtherAddresses...)
	for i := range out.OtherAddresses {
		out.OtherAddresses[i] = compactRoute(out.OtherAddresses[i], omitted)
	}
	return out
}

func compactPolicy(full *PolicyLookupOutput, omitted map[string]int) *PolicyLookupOutput {
	if full == nil {
		return nil
	}
	out := *full
	out.LiveLookups = append([]LivePolicyLookup(nil), full.LiveLookups...)
	for i := range out.LiveLookups {
		if out.LiveLookups[i].Result != nil {
			omitted["live_lookup_raw"]++
			out.LiveLookups[i].Result = nil
		}
	}
	return &out
}

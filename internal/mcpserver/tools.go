package mcpserver

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/service"
)

type inventoryInput struct {
	Profile           string `json:"profile,omitempty" jsonschema:"Limit to one FortiManager profile name"`
	ADOM              string `json:"adom,omitempty" jsonschema:"Limit to one ADOM name"`
	IncludeInterfaces bool   `json:"include_interfaces,omitempty" jsonschema:"Include every device's interface list (large). Prefer resolve_ip_ownership or get_fortigate_interfaces for one device."`
	IncludeRoutes     bool   `json:"include_routes,omitempty" jsonschema:"Include every device's configured static routes (large). Prefer resolve_route for one destination."`
	IncludeRaw        bool   `json:"include_raw,omitempty" jsonschema:"Include the raw appliance records (large). Parsed fields already carry the evidence; leave false unless a field is missing."`
}

type investigateToolInput struct {
	Detail          string `json:"detail,omitempty" jsonschema:"full (default) retains all existing fields; compact omits duplicate evidence and raw live lookup payloads, preserving scope and uncertainty"`
	SourceIP        string `json:"source_ip" jsonschema:"Source IPv4 or IPv6 address of the flow"`
	DestinationIP   string `json:"destination_ip" jsonschema:"Destination IP address or hostname"`
	DestinationPort int    `json:"destination_port,omitempty" jsonschema:"Destination port. When set, the firewall policy lookup runs; when omitted, that step is skipped."`
	Protocol        string `json:"protocol,omitempty" jsonschema:"tcp, udp, sctp, icmp, any, or an IP protocol number. When omitted the live policy lookup runs for TCP and UDP."`
	SourcePort      int    `json:"source_port,omitempty" jsonschema:"Source port for configured routing and service matching, and the live policy lookup. Omit only when unknown; source-port constraints then remain tentative."`
	SourceInterface string `json:"source_interface,omitempty" jsonschema:"Ingress interface or zone when inventory cannot infer it"`
	Profile         string `json:"profile,omitempty" jsonschema:"FortiManager profile name. All inventoried profiles are searched when omitted."`
	ADOM            string `json:"adom,omitempty" jsonschema:"Limit candidates to one ADOM"`
	Device          string `json:"device,omitempty" jsonschema:"Limit candidates to one managed FortiGate"`
	VDOM            string `json:"vdom,omitempty" jsonschema:"Limit ownership, routing, policy and web-filter scope to this VDOM"`
	URL             string `json:"url,omitempty" jsonschema:"When set, rate this URL and check web filter profiles for it"`
	IncludeLogs     bool   `json:"include_logs,omitempty" jsonschema:"Also submit a FortiAnalyzer traffic log search for this flow"`
	LogProfile      string `json:"log_profile,omitempty" jsonschema:"FortiAnalyzer profile for include_logs. The default FortiAnalyzer profile is used when omitted."`
	LogADOM         string `json:"log_adom,omitempty" jsonschema:"FortiAnalyzer ADOM for include_logs, not the FortiManager ADOM"`
	LogStart        string `json:"log_start,omitempty" jsonschema:"Log search start as RFC3339 with an explicit offset. One hour ago when omitted."`
	LogEnd          string `json:"log_end,omitempty" jsonschema:"Log search end as RFC3339 with an explicit offset. Now when omitted."`
}

type refreshInput struct{}

type interfacesInput struct {
	Profile    string `json:"profile,omitempty" jsonschema:"FortiManager profile name from the server configuration. The default profile is used when omitted."`
	ADOM       string `json:"adom,omitempty" jsonschema:"ADOM that manages the FortiGate; taken from the inventory when omitted"`
	Device     string `json:"device" jsonschema:"Managed FortiGate name as shown in inventory_status"`
	VDOM       string `json:"vdom,omitempty" jsonschema:"Return only interfaces of this VDOM"`
	Fresh      bool   `json:"fresh,omitempty" jsonschema:"Read FortiManager now instead of the inventory snapshot (for example right after an interface change)"`
	IncludeRaw bool   `json:"include_raw,omitempty" jsonschema:"Include the raw appliance records (large). Parsed fields already carry the evidence; leave false unless a field is missing."`
}

type settingsInput struct {
	Profile  string `json:"profile,omitempty" jsonschema:"FortiManager profile name from the server configuration. The default profile is used when omitted."`
	ADOM     string `json:"adom,omitempty" jsonschema:"ADOM that manages the FortiGate; taken from the inventory when omitted"`
	Device   string `json:"device" jsonschema:"Managed FortiGate name; the read is proxied live to this device"`
	VDOM     string `json:"vdom,omitempty" jsonschema:"VDOM for the FortiOS request; root when omitted"`
	Resource string `json:"resource" jsonschema:"FortiOS REST path starting with /api/v2/monitor/ or /api/v2/cmdb/, query string allowed, for example /api/v2/monitor/router/ipv4?vdom=root or /api/v2/cmdb/system/interface. Aliases: routing-table, routing-table6, sdwan-health, sessions, interfaces, ha-peer, ha-checksums, ipsec, ssl-vpn, bgp-neighbors, ospf-neighbors, sdwan-sla, license."`
}

type managerReadInput struct {
	Profile  string         `json:"profile,omitempty" jsonschema:"FortiManager profile name from the server configuration. The default profile is used when omitted."`
	Resource string         `json:"resource" jsonschema:"FortiManager JSON-RPC path under /sys, /dvmdb, /pm, /task or /securityconsole, for example /sys/status, /dvmdb/adom/<adom>/device, /task/task/<id>, /pm/config/adom/<adom>/_package/status/<device>/<vdom>"`
	Data     map[string]any `json:"data,omitempty" jsonschema:"Optional extra JSON-RPC parameters for the get request such as fields, filter, loadsub, option, range"`
}

type policiesInput struct {
	Profile    string `json:"profile,omitempty" jsonschema:"FortiManager profile name from the server configuration. The default profile is used when omitted."`
	ADOM       string `json:"adom,omitempty" jsonschema:"ADOM containing the policy package; taken from the inventory when device is given"`
	Package    string `json:"package,omitempty" jsonschema:"Policy package name or nested path such as folder/package; all packages of the ADOM (or of the device) when omitted"`
	Device     string `json:"device,omitempty" jsonschema:"Limit to packages assigned to this managed FortiGate"`
	IPVersion  string `json:"ip_version,omitempty" jsonschema:"ipv4 (default) or ipv6; FortiOS 6.4+ keeps both in one policy table and each policy is listed for the families it has addresses for"`
	PolicyID   int    `json:"policy_id,omitempty" jsonschema:"Return only this policy ID (for example one reported by lookup_firewall_policy)"`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum policies to return across packages, default 100, at most 1000"`
	Offset     int    `json:"offset,omitempty" jsonschema:"Number of matching policies to skip, for paging"`
	IncludeRaw bool   `json:"include_raw,omitempty" jsonschema:"Include the raw appliance records (large). Parsed fields already carry the evidence; leave false unless a field is missing."`
}

type objectsInput struct {
	Profile               string `json:"profile,omitempty" jsonschema:"FortiManager profile name from the server configuration. The default profile is used when omitted."`
	ADOM                  string `json:"adom,omitempty" jsonschema:"ADOM containing the objects; taken from the inventory when device is given"`
	Device                string `json:"device,omitempty" jsonschema:"A managed FortiGate name, used only to find the ADOM when adom is omitted"`
	ObjectType            string `json:"object_type" jsonschema:"Object path after /obj/, must start with firewall/: firewall/address, firewall/addrgrp, firewall/vip, firewall/service/custom, firewall/service/group, firewall/ippool"`
	Name                  string `json:"name,omitempty" jsonschema:"Read one object by exact name instead of the whole table"`
	Limit                 int    `json:"limit,omitempty" jsonschema:"Maximum objects per page, default 100, at most 1000; FortiManager returns only this page"`
	Offset                int    `json:"offset,omitempty" jsonschema:"Number of objects to skip, for paging"`
	IncludeDynamicMapping bool   `json:"include_dynamic_mapping,omitempty" jsonschema:"Include per-device mappings (dynamic_mapping), which can be large"`
}

type analyzerInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"FortiAnalyzer profile name from the server configuration. The default profile is used when omitted."`
}

type logSearchInput struct {
	Profile string `json:"profile,omitempty" jsonschema:"FortiAnalyzer profile name from the server configuration. The default profile is used when omitted."`
	ADOM    string `json:"adom,omitempty" jsonschema:"FortiAnalyzer ADOM (not the FortiManager ADOM). The configured ADOM is used when the profile allows exactly one."`
	LogType string `json:"log_type,omitempty" jsonschema:"traffic (default), event, webfilter, app-ctrl, attack (IPS), virus, dns, ssl, emailfilter, dlp, or another Log View log type of the FortiAnalyzer release"`
	Filter  string `json:"filter,omitempty" jsonschema:"FortiAnalyzer Log View filter, for example srcip=10.0.0.5 and dstport=443 and action!=accept. Field names are listed by get_fortianalyzer_data /logview/adom/<adom>/logfields"`
	Start   string `json:"start,omitempty" jsonschema:"Range start as RFC3339 with explicit offset, for example 2026-09-22T14:00:00+02:00; one hour ago when omitted"`
	End     string `json:"end,omitempty" jsonschema:"Range end as RFC3339 with explicit offset; now when omitted"`
	Device  string `json:"device,omitempty" jsonschema:"Logged device name (devname) to filter on; all devices when omitted"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Match budget of the submit; omitted, zero or negative defaults to 25; above 500 clamps to 500. FortiAnalyzer stops collecting once it has this many matches. A later page of the same task exists only when this budget is larger than the page."`
	Offset  int    `json:"offset,omitempty" jsonschema:"Record offset. On a new search this is where collection starts. With task_id it pages inside the budget of the original submit."`
	TaskID  string `json:"task_id,omitempty" jsonschema:"Task ID of a search that has not reached 100%, or of a submit whose limit is larger than one page. A full page that used up the submit limit needs a new search without task_id at the next offset. Keep profile and adom the same."`
}

type analyzerReadInput struct {
	Profile  string         `json:"profile,omitempty" jsonschema:"FortiAnalyzer profile name from the server configuration. The default profile is used when omitted."`
	Resource string         `json:"resource" jsonschema:"FortiAnalyzer JSON-RPC path under /sys, /dvmdb, /task, /logview, /fortiview, /report, /event, /eventmgmt or /incidents, for example /dvmdb/adom/<adom>/device, /logview/adom/<adom>/logfields, /logview/adom/<adom>/logsearch/<task_id>"`
	Data     map[string]any `json:"data,omitempty" jsonschema:"Optional request parameters such as limit, offset, devtype, logtype, filter, time-range"`
}

// addReadTool registers a read-only tool whose handler errors are logged
// with structured Fortinet details and whose panics are converted into tool
// errors, so one faulty request never takes the server down.
func addReadTool[In any](s *Server, name, title, description string, run func(context.Context, In) (any, error)) {
	if !s.config.ToolEnabled(name) {
		return
	}
	schema, schemaErr := jsonschema.For[In](nil)
	if schemaErr != nil {
		panic(schemaErr)
	}
	constrainToolSchema(name, schema)
	mcp.AddTool(s.mcp, &mcp.Tool{Name: name, Title: title, Description: description, Annotations: readonlyAnnotations(title), InputSchema: schema},
		func(ctx context.Context, req *mcp.CallToolRequest, input In) (response *mcp.CallToolResult, output any, err error) {
			// Apply request timeout to the tool context to prevent unbounded execution
			toolCtx, timeoutCancel := context.WithTimeout(ctx, s.config.RequestTimeoutDuration())
			defer timeoutCancel()

			// Every call logs its duration and where the time went (waiting for
			// the serial request lane, on the wire, retries, slowest resource),
			// so a slow or timed-out call can be traced to its cause.
			toolCtx, stats := fortinet.WithRequestStats(toolCtx)
			started := time.Now()
			defer func() {
				outcome := "ok"
				if err != nil || (response != nil && response.IsError) {
					outcome = "error"
				}
				requests := stats.Snapshot()
				elapsed := time.Since(started)
				s.recordTool(name, outcome, elapsed, requests.LaneWait, requests.Requests)
				attrs := []any{"tool", name, "outcome", outcome, "duration", elapsed.Round(time.Millisecond), "fortinet_requests", requests.Requests}
				if requests.Requests > 0 {
					attrs = append(attrs, "lane_wait", requests.LaneWait.Round(time.Millisecond), "wire_time", requests.Wire.Round(time.Millisecond),
						"retries", requests.Retries, "slowest", requests.Slowest.Round(time.Millisecond), "slowest_resource", requests.SlowestResource)
				}
				s.logger.Info("MCP tool completed", attrs...)
			}()
			defer func() {
				if recovered := recover(); recovered != nil {
					s.logger.Error("MCP tool panicked", "tool", name, "panic", fmt.Sprint(recovered), "stack", string(debug.Stack()))
					response, output = nil, nil
					err = fmt.Errorf("internal error in %s: %v; the server recovered and stays available, retry with a narrower scope and report this to the server administrator", name, recovered)
				}
			}()
			value, runErr := run(toolCtx, input)
			if runErr != nil {
				logs, usable := value.(fortinet.LogSearchResult)
				if name != "search_fortianalyzer_logs" || !usable || !service.LogResultUsable(logs) {
					return s.toolError(req, name, runErr)
				}
				// Return a constructed error result with a nil Go error: the SDK
				// otherwise replaces it with a plain error and loses task state.
				s.toolError(req, name, runErr)
				value = logs
			}
			response, output, err = s.encodeResult(name, value)
			if response != nil && runErr != nil {
				response.IsError = true
			}
			if err != nil {
				return s.toolError(req, name, err)
			}
			return response, output, nil
		})
}

func (s *Server) registerTools() {
	addReadTool(s, "investigate_traffic", "Investigate a traffic flow",
		"Investigate ownership, configured paths, policy and optional URL filtering across hops/destinations. Requires source_ip/destination_ip; destination_port enables policy lookup. Scope profile/adom/device/vdom. Read hops for every supported hop; compact removes duplicates/raw live payloads but retains fallback policy when no hops exist. Inspect errors/warnings and path.end for failed/skipped stages and tracing limits. include_logs retains partial task state/next_action. Keep ambiguous scopes and DNS alternatives separate. Routing alone proves neither delivery nor policy permission; upstream NAT and return-path coverage remain unverified.",
		func(ctx context.Context, input investigateToolInput) (any, error) {
			start, err := parseTime(input.LogStart)
			if err != nil {
				return nil, err
			}
			end, err := parseTime(input.LogEnd)
			if err != nil {
				return nil, err
			}
			if input.Detail != "" && input.Detail != "full" && input.Detail != "compact" {
				return nil, fmt.Errorf("detail must be full or compact")
			}
			serviceInput := service.InvestigateInput{
				SourceIP: input.SourceIP, DestinationIP: input.DestinationIP, DestinationPort: input.DestinationPort,
				Protocol: input.Protocol, SourcePort: input.SourcePort, SourceInterface: input.SourceInterface,
				Profile: input.Profile, ADOM: input.ADOM, Device: input.Device, VDOM: input.VDOM, URL: input.URL,
				IncludeLogs: input.IncludeLogs, LogProfile: input.LogProfile, LogADOM: input.LogADOM,
				LogStart: start, LogEnd: end,
			}
			full, err := s.app.Investigate(ctx, serviceInput)
			if err == nil && input.Detail == "compact" {
				return service.CompactInvestigate(serviceInput, full), nil
			}
			return full, err
		})
	addReadTool(s, "resolve_ip_ownership", "Resolve connected IP ownership",
		"Find connected-network candidates for ip in cached inventory, most-specific first; no appliance calls. Filter profile/adom/device/vdom. Returns scoped interfaces, zones, packages, status, timestamps and freshness/errors. Overlaps stay ambiguous; no match does not prove absence. Establishes neither endpoint ownership, routing, ingress/egress nor policy permission. ready=false with refresh_in_progress: retry shortly. Offline devices retain manager data under unavailable_devices; do not refresh solely for them.",
		func(ctx context.Context, input inventory.OwnershipQuery) (any, error) {
			return s.app.ResolveIPOwnership(ctx, input)
		})
	addReadTool(s, "resolve_route", "Resolve configured routing for a destination",
		"Resolve configured forwarding: ordered policy routes, SD-WAN rules, then connected/static routes by prefix, distance and priority. Supply known source/ingress/protocol/ports; missing conditions stay tentative. Keep hostname alternatives separate. follow=true traces managed hops until ambiguity; returns scoped decisions, egress/gateways and inventoried next-hop owners. Read path.end before last_managed_device; check carrying policies at every supported hop. Routing proves neither delivery, policy permission, NAT nor return-path symmetry. Use get_fortigate_settings for dynamic routes/live SD-WAN health.",
		func(ctx context.Context, input service.RouteLookupInput) (any, error) {
			return s.app.ResolveRoute(ctx, input)
		})
	addReadTool(s, "inventory_status", "FortiGate inventory status",
		"Read the background inventory: ADOMs, devices/data_as_of, VDOMs, groups, packages, refresh state and structured errors. ADOM-level read failures mark profiles stale; offline devices in unavailable_devices do not. Device-level failures carry data_error and retained data_as_of. Interfaces, routes and raw records are opt-in.",
		func(ctx context.Context, input inventoryInput) (any, error) {
			return s.app.ListFortiGates(ctx, input.Profile, input.ADOM, input.IncludeInterfaces, input.IncludeRoutes, input.IncludeRaw)
		})
	addReadTool(s, "refresh_inventory", "Refresh FortiGate inventory",
		"Refresh all FortiManager profiles and clear their object, policy, monitor, live-lookup, web-filter and rating caches; FortiAnalyzer TTLs stay unchanged. Use only for requested current data or known manager changes, not offline devices, timestamps within the refresh interval or loading inventory. Returns inventory_status summary. Reuses an overlapping refresh; work continues after the caller stops waiting. Check refresh_in_progress with inventory_status.",
		func(ctx context.Context, _ refreshInput) (any, error) {
			return s.app.RefreshInventory(ctx)
		})
	addReadTool(s, "get_fortigate_interfaces", "Get FortiGate interfaces",
		"Read one device's interfaces from cached FortiManager inventory, optionally one VDOM: addresses/networks, IPv6, alias/type, status/role, parent and zone. Check data_as_of; fresh=true reads the manager database now, not live FortiGate state. Omitted adom is inferred from inventory.",
		func(ctx context.Context, input interfacesInput) (any, error) {
			return s.app.GetInterfaces(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, input.IncludeRaw, input.Fresh)
		})
	addReadTool(s, "get_fortigate_settings", "Get FortiGate settings",
		"GET a live FortiGate monitor/CMDB resource through FortiManager; requires device and an allowed resource (aliases in field schema). Infer omitted ADOM from inventory. Stable monitors cache 30s; sessions do not. Silent appliances time out before the request deadline. Prefer resolve_route for configured routes and focused session/VPN/HA/routing-neighbor tools for operational evidence.",
		func(ctx context.Context, input settingsInput) (any, error) {
			return s.app.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, input.Resource)
		})
	addReadTool(s, "get_fortimanager_status", "Get FortiManager status",
		"GET FortiManager status, tasks, devices/ADOMs/groups, packages/objects, install status or security-console state. Only /sys, /dvmdb, /pm, /task and /securityconsole paths are allowed; no writes.",
		func(ctx context.Context, input managerReadInput) (any, error) {
			return s.app.GetFortiManagerRead(ctx, input.Profile, input.Resource, input.Data)
		})
	addReadTool(s, "list_firewall_policies", "List firewall policies",
		"List ADOM IPv4/IPv6 policies in package order; filter package, device packages or policy_id. Device can infer ADOM. Preserves package/policy provenance, match conditions, UTM/profiles and install-on scope. limit/offset page across selected policies (default 100); inspect total/truncated. Shares lookup_firewall_policy cache.",
		func(ctx context.Context, input policiesInput) (any, error) {
			return s.app.ListPolicies(ctx, service.PolicyListInput{
				Profile: input.Profile, ADOM: input.ADOM, Package: input.Package, Device: input.Device, IPVersion: input.IPVersion,
				PolicyID: input.PolicyID, Limit: input.Limit, Offset: input.Offset, IncludeRaw: input.IncludeRaw,
			})
		})
	addReadTool(s, "list_policy_objects", "List policy objects",
		"Read an ADOM firewall object table or named object, e.g. addresses, groups, VIPs or services. Use list_firewall_policies for policy entries. object_type follows /obj/ and must start firewall/. Appliance-paged limit/offset (default 100); dynamic_mapping is opt-in.",
		func(ctx context.Context, input objectsInput) (any, error) {
			return s.app.ListObjects(ctx, service.ObjectListInput{
				Profile: input.Profile, ADOM: input.ADOM, Device: input.Device, ObjectType: input.ObjectType, Name: input.Name,
				Limit: input.Limit, Offset: input.Offset, IncludeDynamicMappings: input.IncludeDynamicMapping,
			})
		})
	addReadTool(s, "lookup_firewall_policy", "Lookup firewall policy across ADOMs",
		"Find configured first-match flow verdicts; requires source_ip/destination_ip/destination_port. Scope profile/adom/device/vdom and known source port/ingress; omitted scope searches inventory candidates. Evaluate DNS alternatives separately. decisions gives scoped package/destination verdicts; matches preserves order. Unresolved identity/schedules/mappings/source-port constraints stay tentative. VIP matching uses mapped addresses, not downstream NAT/return-path proof. Compare live lookups only in matching scope (max 4, 10s each). ambiguous_configured_verdict: check installed packages. complete=false: missing matches prove nothing; implicit_deny requires all reads to succeed.",
		func(ctx context.Context, input service.PolicyLookupInput) (any, error) {
			return s.app.LookupPolicies(ctx, input)
		})
	ratingDescription := "Get URL category (id/name/group) via a managed FortiGate through FortiManager; never auto-selects a device. Cached 15m: inspect rating.cached/rated_at and attempt_errors for failures. Pass category and url to check_web_filter for filtering decisions."
	if device := s.app.RatingDevice(); device != "" {
		ratingDescription += " Configured rating FortiGate: " + device + "; device is optional. Rating can run during path discovery."
	} else {
		ratingDescription += " No dedicated rating FortiGate: device is required."
	}
	addReadTool(s, "rate_url", "FortiGuard category of a URL",
		ratingDescription,
		func(ctx context.Context, input service.RateURLInput) (any, error) {
			return s.app.RateURL(ctx, input)
		})
	addReadTool(s, "check_web_filter", "Where a web category is blocked or allowed",
		"Explain configured URL/category filtering and profile applicability, not live enforcement. Get category via rate_url; include url for static entries/local overrides. Scope device and known carrying policy_id. Returns decisions, enabled firewall/IPv6/security/proxy policy references, device/VDOM targets and stored package status. Missing category entries allow that category; URL actions/overrides may change it. complete=false retains partial reads: retry shortly for cached progress; missing profiles prove no absence.",
		func(ctx context.Context, input service.CheckWebFilterInput) (any, error) {
			return s.app.CheckWebFilter(ctx, input)
		})
	addReadTool(s, "fortianalyzer_status", "Get FortiAnalyzer status",
		"Read configured FortiAnalyzer system status via JSON-RPC.",
		func(ctx context.Context, input analyzerInput) (any, error) {
			return s.app.FortiAnalyzerStatus(ctx, input.Profile)
		})
	addReadTool(s, "search_fortianalyzer_logs", "Search FortiAnalyzer logs",
		"Search Log View in verified analyzer profile/ADOM, logged devname (map_analyzer_device), filter and absolute time window. Returns scope/time, task/progress, newest-first rows and next_action. Validate callable tool/arguments: poll the SAME partial page, page a task or restart an exhausted budget; separate searches may see different snapshots. Submit limit is a match budget. complete means execution finished, not exhaustive matches; total_count may count scanned logs. Partial failures retain evidence with isError=true; unfinished searches are resumable. Correct unknown task scope/persistent permission errors before retrying. Zero rows mean no retrieved matches; receipt attaches when available at offset 0.",
		func(ctx context.Context, input logSearchInput) (any, error) {
			start, err := parseTime(input.Start)
			if err != nil {
				return nil, err
			}
			end, err := parseTime(input.End)
			if err != nil {
				return nil, err
			}
			return s.app.SearchLogs(ctx, input.Profile, fortinet.LogSearchRequest{
				ADOM: input.ADOM, LogType: input.LogType, Filter: input.Filter, StartTime: start, EndTime: end,
				Device: input.Device, Limit: input.Limit, Offset: input.Offset, TaskID: input.TaskID,
			})
		})
	addReadTool(s, "get_fortianalyzer_data", "Get FortiAnalyzer data",
		"GET analyzer data under /sys, /dvmdb, /task, /logview, /fortiview, /report, /event, /eventmgmt or /incidents only. Existing logsearch/<task_id> reads return progress/records. Status, device lists, logfields and logstats cache 5m. Prefer map_analyzer_device for logged identity and get_log_receipt for last-received times.",
		func(ctx context.Context, input analyzerReadInput) (any, error) {
			return s.app.FortiAnalyzerRead(ctx, input.Profile, input.Resource, input.Data)
		})
	addReadTool(s, "get_firewall_sessions", "Filtered live firewall sessions",
		"Read an uncached live session slice, then filter source/destination/port/protocol/policy locally because FortiOS may ignore filters. count defaults to 50, max 200; filtered_locally indicates matches outside the slice may be missed. Returns tuples, policy, SNAT, duration and bytes.",
		func(ctx context.Context, input service.SessionQuery) (any, error) {
			return s.app.GetFirewallSessions(ctx, input)
		})
	addReadTool(s, "resolve_address_identity", "Who holds an address now",
		"Find one IP in a FortiGate's live DHCP, ARP, FSSO and firewall-user tables; uncached. Failed sources appear in errors; others still return. Empty results do not prove past absence. Use resolve_ip_ownership for connected-subnet ownership.",
		func(ctx context.Context, input service.AddressIdentityQuery) (any, error) {
			return s.app.ResolveAddressIdentity(ctx, input)
		})
	addReadTool(s, "get_vpn_status", "IPsec and SSL-VPN status",
		"Read one FortiGate's IPsec tunnel status/gateway/bytes and SSL-VPN user/host/duration; cached 30s. Operational state, not configured phase1 objects.",
		func(ctx context.Context, input service.DeviceScope) (any, error) {
			return s.app.GetVPNStatus(ctx, input)
		})
	addReadTool(s, "get_ha_status", "HA role, peers and checksums",
		"Read one FortiGate's HA peers, checksums and HA configuration; cached 30s. checksum_sync requires at least two equal checksums; false also covers failed peer/checksum reads, listed in errors.",
		func(ctx context.Context, input service.DeviceScope) (any, error) {
			return s.app.GetHAStatus(ctx, input)
		})
	addReadTool(s, "get_package_install_status", "Package install state of one FortiGate",
		"Read manager-stored package install state (installed/modified/unknown), not running FortiGate checksum. Empty vdom covers inventoried VDOMs, max 48. Shares check_web_filter cache.",
		func(ctx context.Context, input service.DeviceScope) (any, error) {
			return s.app.GetPackageInstallStatus(ctx, input)
		})
	addReadTool(s, "count_fortianalyzer_logs", "Count FortiAnalyzer matches before rows",
		"Run a Log View search plus its count read; omit rows. focus selects all/deny/webfilter/ips. Submit limit is a match budget (default/max 500), so counts may understate matches; total_count may count scanned logs. If count fails, retain search total_count with count_error. Not an exhaustive log answer. Use map_analyzer_device for device.",
		func(ctx context.Context, input service.LogFocusQuery) (any, error) {
			return s.app.CountFortiAnalyzerLogs(ctx, input)
		})
	addReadTool(s, "map_analyzer_device", "Map a FortiGate to its FortiAnalyzer devname",
		"Map inventoried FortiGate serial/hostname/name to analyzer logged devname for log searches; do not assume manager names match. analyzer_adom defaults to the profile's sole allowed ADOM, or root for unrestricted profiles. Device list caches 5m.",
		func(ctx context.Context, input service.AnalyzerDeviceQuery) (any, error) {
			return s.app.MapAnalyzerDevice(ctx, input)
		})
	addReadTool(s, "get_nat_for_flow", "Central SNAT, IP pool and VIP for a flow",
		"Find source/destination/port text in cached ADOM central SNAT, IP pool and VIP tables (first 200 objects each). Named references remain names; results are candidates, not observed translations. Confirm with get_firewall_sessions or traffic logs.",
		func(ctx context.Context, input service.NATQuery) (any, error) {
			return s.app.GetNATMapping(ctx, input)
		})
	addReadTool(s, "get_routing_neighbors", "BGP, OSPF and SD-WAN SLA",
		"Read one FortiGate's BGP/OSPF neighbors and SD-WAN SLA (interface, latency, jitter, loss, state); cached 30s. Use resolve_route for configured routes.",
		func(ctx context.Context, input service.DeviceScope) (any, error) {
			return s.app.GetRoutingNeighbors(ctx, input)
		})
	addReadTool(s, "get_package_history", "Package oid, install state and device revision",
		"Return inventory package oid, stored install status, device conf_status and best-effort revision for one FortiGate. Failed revision reads appear in errors; other evidence remains. No exec-based install history.",
		func(ctx context.Context, input service.PackageHistoryQuery) (any, error) {
			return s.app.GetPackageHistory(ctx, input)
		})
	addReadTool(s, "get_policy_usage", "Policy hit counts and where an object is used",
		"Read uncached live policy hits/bytes/last-used. With name, where_used scans ADOM firewall/IPv6/security/proxy tables for address, service or ssl-ssh references; not the manager where-used exec. where_used_complete=false when a table failed or name was omitted. Retain partial references; errors identify failed profile/ADOM/package/table.",
		func(ctx context.Context, input service.PolicyUsageQuery) (any, error) {
			return s.app.GetPolicyUsage(ctx, input)
		})
	addReadTool(s, "get_ssl_ssh_profile", "SSL/SSH inspection profile",
		"Read an ADOM ssl-ssh profile: inspection mode, HTTPS/SSH settings, untrusted-certificate action and raw object. Determines certificate versus deep inspection per protocol; distinct from policy inspection-mode.",
		func(ctx context.Context, input service.SSLProfileQuery) (any, error) {
			return s.app.GetSSLSSHProfile(ctx, input)
		})
	addReadTool(s, "get_log_receipt", "When a device last sent logs",
		"Read analyzer /logview/adom/<adom>/logstats (5m cache); optionally match device by name/serial/devname. Missing or old receipt may explain empty searches as logging gaps. Completed zero-row searches at offset 0 attach receipt when available.",
		func(ctx context.Context, input service.LogReceiptQuery) (any, error) {
			return s.app.GetLogReceipt(ctx, input)
		})
}

func parseTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed, nil
	}
	return time.Time{}, &timeParseError{value: value}
}

type timeParseError struct{ value string }

func (e *timeParseError) Error() string {
	return "invalid time " + e.value + "; use RFC3339 with an explicit timezone, for example 2026-09-22T14:05:00+02:00"
}

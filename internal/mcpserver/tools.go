package mcpserver

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

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
	SourceIP        string `json:"source_ip" jsonschema:"Source IPv4 or IPv6 address of the flow"`
	DestinationIP   string `json:"destination_ip" jsonschema:"Destination IP address or hostname"`
	DestinationPort int    `json:"destination_port,omitempty" jsonschema:"Destination port. When set, the firewall policy lookup runs; when omitted, that step is skipped."`
	Protocol        string `json:"protocol,omitempty" jsonschema:"tcp, udp, sctp, icmp, any, or an IP protocol number. When omitted the live policy lookup runs for TCP and UDP."`
	SourcePort      int    `json:"source_port,omitempty" jsonschema:"Source port for configured routing and service matching, and the live policy lookup. Omit only when unknown; source-port constraints then remain tentative."`
	SourceInterface string `json:"source_interface,omitempty" jsonschema:"Ingress interface or zone when inventory cannot infer it"`
	Profile         string `json:"profile,omitempty" jsonschema:"FortiManager profile name. All inventoried profiles are searched when omitted."`
	ADOM            string `json:"adom,omitempty" jsonschema:"Limit candidates to one ADOM"`
	Device          string `json:"device,omitempty" jsonschema:"Limit candidates to one managed FortiGate"`
	VDOM            string `json:"vdom,omitempty" jsonschema:"Limit web filter results to this VDOM"`
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
	Resource string `json:"resource" jsonschema:"FortiOS REST path starting with /api/v2/monitor/ or /api/v2/cmdb/, query string allowed, for example /api/v2/monitor/router/ipv4?vdom=root or /api/v2/cmdb/system/interface. Aliases: routing-table, routing-table6, sdwan-health, sessions, interfaces."`
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
	Limit   int    `json:"limit,omitempty" jsonschema:"Match budget of the submit, 1-500, default 25. FortiAnalyzer stops collecting once it has this many matches. A later page of the same task exists only when this budget is larger than the page."`
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
	mcp.AddTool(s.mcp, &mcp.Tool{Name: name, Title: title, Description: description, Annotations: readonlyAnnotations(title)},
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
				if err != nil {
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
				return s.toolError(req, name, runErr)
			}
			response, output, err = result(name, value, s.config.MaxResultBytes)
			if err != nil {
				return s.toolError(req, name, err)
			}
			return response, output, nil
		})
}

func (s *Server) registerTools() {
	addReadTool(s, "investigate_traffic", "Investigate a traffic flow",
		"Investigate connected ownership, configured routing with follow, and scoped policy decisions at every traced hop and destination address. Pass url to rate it once and check web filtering at each managed hop. Read hops for all policy and web-filter evidence; top-level policy and web_filter retain only the first hop. Upstream NAT and the return path remain unverified. include_logs adds a FortiAnalyzer traffic search and returns whatever finished before the deadline; resume timed-out searches with task_id. Failed steps remain in errors. Scope with profile, adom, device and vdom when known. "+routeTraceGuidance,
		func(ctx context.Context, input investigateToolInput) (any, error) {
			start, err := parseTime(input.LogStart)
			if err != nil {
				return nil, err
			}
			end, err := parseTime(input.LogEnd)
			if err != nil {
				return nil, err
			}
			return s.app.Investigate(ctx, service.InvestigateInput{
				SourceIP: input.SourceIP, DestinationIP: input.DestinationIP, DestinationPort: input.DestinationPort,
				Protocol: input.Protocol, SourcePort: input.SourcePort, SourceInterface: input.SourceInterface,
				Profile: input.Profile, ADOM: input.ADOM, Device: input.Device, VDOM: input.VDOM, URL: input.URL,
				IncludeLogs: input.IncludeLogs, LogProfile: input.LogProfile, LogADOM: input.LogADOM,
				LogStart: start, LogEnd: end,
			})
		})
	addReadTool(s, "resolve_ip_ownership", "Resolve connected IP ownership",
		"First read for IP ownership: query the in-memory inventory prefix index without appliance calls or raw interface payloads. Supply ip and optional profile/adom/device/vdom filters. Returns all matching connected-network candidates, most-specific first, with scoped interface, zone, package targets, status, timestamp, profile freshness and refresh errors. Overlaps remain ambiguous; no match does not prove absence. Does not establish routing, actual ingress/egress, endpoint ownership or policy permission. ready=false with refresh_in_progress means the background inventory is still loading: retry shortly. Offline FortiGates are listed under unavailable_devices and still contribute their FortiManager data; they are not a reason to refresh.",
		func(ctx context.Context, input inventory.OwnershipQuery) (any, error) {
			return s.app.ResolveIPOwnership(ctx, input)
		})
	addReadTool(s, "resolve_route", "Resolve configured routing for a destination",
		"Resolve configured forwarding from the FortiManager database: policy routes in order, then SD-WAN rules, then connected/static routes by longest prefix, lowest distance and lowest priority. Returns stage, confidence, egress interfaces/zones, gateways and their exact inventoried interface owners, plus policy-route or SD-WAN evidence. ip may be a hostname; each evaluated address has its own result. Give source_ip, source_interface, protocol, destination_port and source_port when known. follow=true traces ordered managed hops and stops at ambiguity or tentative decisions. Dynamic routes and live SD-WAN health require get_fortigate_settings when they can change the answer. "+routeTraceGuidance,
		func(ctx context.Context, input service.RouteLookupInput) (any, error) {
			return s.app.ResolveRoute(ctx, input)
		})
	addReadTool(s, "inventory_status", "FortiGate inventory status",
		"Return the latest background inventory snapshot: ADOMs, managed FortiGates with data_as_of, VDOMs, device-group memberships, policy-package associations, whether a refresh is running, offline FortiGates under unavailable_devices (informational), and refresh errors with kind, appliance code, resource, retry state, and operator hint. A profile is stale only when an ADOM-level FortiManager read failed; offline devices never make it stale, and a device whose own reads failed carries data_error with data retained from data_as_of. Interfaces, routing (static routes, policy routes, SD-WAN) and raw records are omitted unless requested.",
		func(ctx context.Context, input inventoryInput) (any, error) {
			return s.app.ListFortiGates(ctx, input.Profile, input.ADOM, input.IncludeInterfaces, input.IncludeRoutes, input.IncludeRaw)
		})
	addReadTool(s, "refresh_inventory", "Refresh FortiGate inventory",
		"Force a read-only refresh of all configured FortiManager profiles and drop cached FortiManager objects, policies, monitor reads, live policy lookups, web filter settings and ratings. FortiAnalyzer reads keep their own TTL. Inventory already refreshes in the background on the configured interval; call this only when the user asks for current data or after a known FortiManager change. Offline FortiGates, stale-looking timestamps within the interval, or a loading inventory are not reasons to call it. Returns the inventory summary (as inventory_status). The refresh continues even if this call stops waiting; then the summary shows refresh_in_progress and inventory_status shows the result later. If a refresh finished while this call waited, its snapshot is returned without repeating the appliance reads.",
		func(ctx context.Context, _ refreshInput) (any, error) {
			return s.app.RefreshInventory(ctx)
		})
	addReadTool(s, "get_fortigate_interfaces", "Get FortiGate interfaces",
		"Interfaces of one managed FortiGate from the FortiManager device database, optionally limited to one VDOM: name, alias, type, IP/netmask, connected networks, IPv6, VDOM, status, role, parent and zone. Served from the inventory snapshot (see data_as_of) without an appliance request; fresh=true reads FortiManager now. adom is taken from the inventory when omitted.",
		func(ctx context.Context, input interfacesInput) (any, error) {
			return s.app.GetInterfaces(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, input.IncludeRaw, input.Fresh)
		})
	addReadTool(s, "get_fortigate_settings", "Get FortiGate settings",
		"Read a FortiOS 7.x REST monitor or CMDB resource live from a managed FortiGate through the FortiManager /sys/proxy/json tunnel. Only GET-style /api/v2/monitor/* and /api/v2/cmdb/* resources are accepted. Aliases: routing-table (/api/v2/monitor/router/ipv4), routing-table6 (/api/v2/monitor/router/ipv6), sdwan-health (/api/v2/monitor/virtual-wan/health-check), sessions (/api/v2/monitor/firewall/session), interfaces (/api/v2/monitor/system/interface), ha-peer, ha-checksums, ipsec, ssl-vpn, bgp-neighbors, ospf-neighbors, sdwan-sla, license. Stable monitor reads are reused for 30 seconds; the session table is not cached. FortiManager waits for the FortiGate at most until shortly before the request deadline, so a silent FortiGate answers with a timeout. adom is taken from the inventory when omitted. Prefer resolve_route for configured routing, get_firewall_sessions for a filtered session, and get_vpn_status, get_ha_status or get_routing_neighbors for those short answers.",
		func(ctx context.Context, input settingsInput) (any, error) {
			return s.app.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, input.Resource)
		})
	addReadTool(s, "get_fortimanager_status", "Get FortiManager status",
		"Read a FortiManager JSON-RPC resource with method get: system status, tasks, DVMDB devices/ADOMs/groups, policy packages and objects, package installation status, or security-console state. Paths outside /sys, /dvmdb, /pm, /task and /securityconsole are rejected; nothing is written.",
		func(ctx context.Context, input managerReadInput) (any, error) {
			return s.app.GetFortiManagerRead(ctx, input.Profile, input.Resource, input.Data)
		})
	addReadTool(s, "list_firewall_policies", "List firewall policies",
		"List IPv4 or IPv6 firewall policies of one ADOM, optionally one package, one device's packages (adom is then taken from the inventory) or one policy_id, in package order. Results preserve package and policy provenance, interfaces, IPv4 and IPv6 addresses, internet services, users and groups, services, schedule, UTM status, security profiles and install-on scope. Paged: limit (default 100) and offset over all selected policies, with total and truncated. Reads share the cache of lookup_firewall_policy.",
		func(ctx context.Context, input policiesInput) (any, error) {
			return s.app.ListPolicies(ctx, service.PolicyListInput{
				Profile: input.Profile, ADOM: input.ADOM, Package: input.Package, Device: input.Device, IPVersion: input.IPVersion,
				PolicyID: input.PolicyID, Limit: input.Limit, Offset: input.Offset, IncludeRaw: input.IncludeRaw,
			})
		})
	addReadTool(s, "list_policy_objects", "List policy objects",
		"Read a FortiManager ADOM firewall object table such as firewall/address, firewall/addrgrp, firewall/vip, firewall/service/custom or firewall/service/group, or one object by name. Use list_firewall_policies for policy entries. object_type is the path after /obj/ and must start with firewall/. Paged by FortiManager: limit (default 100) and offset; per-device mappings (dynamic_mapping) are omitted unless include_dynamic_mapping is set.",
		func(ctx context.Context, input objectsInput) (any, error) {
			return s.app.ListObjects(ctx, service.ObjectListInput{
				Profile: input.Profile, ADOM: input.ADOM, Device: input.Device, ObjectType: input.ObjectType, Name: input.Name,
				Limit: input.Limit, Offset: input.Offset, IncludeDynamicMappings: input.IncludeDynamicMapping,
			})
		})
	addReadTool(s, "lookup_firewall_policy", "Lookup firewall policy across ADOMs",
		"Find which FortiGate firewall policy handles a flow, across inventoried FortiManager ADOMs. Give source_ip, destination_ip (literal IP or FQDN), and destination_port; profile, adom, device, vdom, source_port, protocol, and source_interface are optional. FQDNs are resolved with system DNS, including CNAME targets, and each matching A/AAAA address is evaluated. The server derives candidate FortiGates and ingress interfaces from inventory and the egress interface from configured policy routes, SD-WAN rules and the routing table (see routing on each candidate), evaluates the FortiManager policy packages in FortiOS order (IPv4/IPv6 addresses per family, VIPs against their mapped address, services, install-on scope) and reports per profile, ADOM, device, VDOM, package and destination the configured verdict under decisions: the first matching policy, or implicit_deny when none matches and every read succeeded. matches lists all matching policies in evaluation order (first_match marks the verdict); conditions it cannot evaluate (internet services, users, per-device mappings, schedules) make a match tentative. Custom services honor destination and source-port ranges; an omitted constrained source port remains tentative. Afterwards it asks the FortiGates' live policy-lookup (at most 4 per call, each bounded to 10 s) and compares within that exact scope; several package verdicts produce ambiguous_configured_verdict. complete=false means a read failed, so a missing match proves nothing.",
		func(ctx context.Context, input service.PolicyLookupInput) (any, error) {
			return s.app.LookupPolicies(ctx, input)
		})
	ratingDescription := "Return the live FortiGuard category (id, name, group) of a URL, rated by a managed FortiGate through the FortiManager proxy: the server's dedicated rating FortiGate when configured, otherwise the given device (trace the user's traffic to find it); it never picks a device on its own. Usually one request and a few seconds; a URL rated in the last 15 minutes is answered from cache (rating.cached, rated_at). rating.attempt_errors explains each failed device. Next, call check_web_filter with the returned category and the url."
	if device := s.app.RatingDevice(); device != "" {
		ratingDescription += " This server rates with its configured FortiGate " + device + ", so device is optional and the rating can run while the user's path is still being traced."
	} else {
		ratingDescription += " This server has no dedicated rating FortiGate: pass device."
	}
	addReadTool(s, "rate_url", "FortiGuard category of a URL",
		ratingDescription,
		func(ctx context.Context, input service.RateURLInput) (any, error) {
			return s.app.RateURL(ctx, input)
		})
	addReadTool(s, "check_web_filter", "Where a web category is blocked or allowed",
		"Explain how each web filter profile treats a FortiGuard category (from rate_url) and where the profiles are enforced. Pass url as well for a concrete site: static URL filter entries (simple/wildcard/regex, block/allow/exempt/monitor) and FortiGuard local rating overrides match the URL, not its category. Category actions: block, monitor, warning, authenticate; a missing entry means allow; category groups are expanded. Each profile is mapped to the enabled firewall, IPv6, NGFW security and explicit proxy policies, packages and device VDOMs that apply it, with FortiManager's stored package and config status. Pass device to read only that FortiGate's packages, and policy_id (the policy that carries the user's traffic, from lookup_firewall_policy) to evaluate only the profile that policy applies. Reads FortiManager configuration only and answers within the request timeout; complete=false means some reads were still running, so repeat the check shortly (served from cache). Live enforcement is not tested.",
		func(ctx context.Context, input service.CheckWebFilterInput) (any, error) {
			return s.app.CheckWebFilter(ctx, input)
		})
	addReadTool(s, "fortianalyzer_status", "Get FortiAnalyzer status",
		"Read system status from a configured FortiAnalyzer profile using the JSON-RPC API.",
		func(ctx context.Context, input analyzerInput) (any, error) {
			return s.app.FortiAnalyzerStatus(ctx, input.Profile)
		})
	addReadTool(s, "search_fortianalyzer_logs", "Search FortiAnalyzer logs",
		"Submit an ADOM-scoped FortiAnalyzer Log View search and poll it (0.5 s growing to 2 s) until it finishes or shortly before the request deadline. Use a bounded RFC3339 time window with explicit offset (sent with its UTC offset) and the appliance's filter grammar. device is the FortiAnalyzer devname from map_analyzer_device, not the FortiManager name. Returns profile, ADOM, device/filter scope, the time range as sent to the appliance, task ID, progress, completion and timeout state, records (newest first), total_count (FortiAnalyzer's total-count, which can count scanned rather than matching logs) and a hint. complete is true only at 100 %. A search still running returns timed_out with its task_id: call again with that task_id (same profile and adom) to continue polling. limit on submit is the match budget. When a page fills that budget, submit a new search without task_id at offset equal to the previous offset plus count, or submit once with a larger limit (up to 500) and page that task with task_id. task_id plus a higher offset is the next page only when the original submit asked for more matches than the page. An identical search within 3 minutes reuses the remembered task. A finished search with zero rows attaches log receipt when /logstats answers. Zero records are no retrieved match under that scope, not proof that traffic did not occur.",
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
		"Read a FortiAnalyzer JSON-RPC resource with method get: system status, DVMDB devices/ADOMs (to map FortiGate names to logged device identity), tasks, Log View fields and existing searches (a logsearch/<task_id> read returns progress with the records), log statistics (/logview/adom/<adom>/logstats where available), FortiView, reports, events, and incidents. System status, device lists, log field lists and logstats are cached for 5 minutes. Paths outside /sys, /dvmdb, /task, /logview, /fortiview, /report, /event, /eventmgmt and /incidents are rejected. Prefer map_analyzer_device for the logged devname and get_log_receipt for last-received times.",
		func(ctx context.Context, input analyzerReadInput) (any, error) {
			return s.app.FortiAnalyzerRead(ctx, input.Profile, input.Resource, input.Data)
		})
	addReadTool(s, "get_firewall_sessions", "Filtered live firewall sessions",
		"Read a short slice of the live FortiGate session table and keep rows that match source, destination, port, protocol or policy id. FortiOS often ignores a session filter, so count rows are requested (default 50, at most 200) and filtered locally. filtered_locally is set, and a later matching session can be absent when the page is shorter than the table. The table is not cached. Each row has src, dst, sport, dport, proto, policy id, SNAT, duration and bytes.",
		func(ctx context.Context, input service.SessionQuery) (any, error) {
			return s.app.GetFirewallSessions(ctx, input)
		})
	addReadTool(s, "resolve_address_identity", "Who holds an address now",
		"Look up one IP in the live DHCP leases, ARP table, FSSO and firewall user table of one FortiGate. A failed source is listed under errors and the others still return. This is not connected-subnet ownership (use resolve_ip_ownership for that) and an empty source is not proof the address was never used. The reads are not cached.",
		func(ctx context.Context, input service.AddressIdentityQuery) (any, error) {
			return s.app.ResolveAddressIdentity(ctx, input)
		})
	addReadTool(s, "get_vpn_status", "IPsec and SSL-VPN status",
		"Short live rows for IPsec tunnels (name, remote gateway, status, bytes) and SSL-VPN logins (user, remote host, duration) on one FortiGate. Both monitor reads are reused for 30 seconds. This is not the configured phase1 object.",
		func(ctx context.Context, input service.DeviceScope) (any, error) {
			return s.app.GetVPNStatus(ctx, input)
		})
	addReadTool(s, "get_ha_status", "HA role, peers and checksums",
		"Read HA peers, checksums and the system HA configuration of one FortiGate. checksum_sync is true only when at least two checksums were read and they are equal. A failed peer or checksum read leaves checksum_sync false and is listed under errors. The reads are reused for 30 seconds.",
		func(ctx context.Context, input service.DeviceScope) (any, error) {
			return s.app.GetHAStatus(ctx, input)
		})
	addReadTool(s, "get_package_install_status", "Package install state of one FortiGate",
		"FortiManager's stored package install state for one device. vdom empty reads every inventoried VDOM, at most 48. status is installed, modified or unknown. It is not the FortiGate's running checksum. The same cache serves check_web_filter.",
		func(ctx context.Context, input service.DeviceScope) (any, error) {
			return s.app.GetPackageInstallStatus(ctx, input)
		})
	addReadTool(s, "count_fortianalyzer_logs", "Count FortiAnalyzer matches before rows",
		"Submit a Log View search and read /logview/adom/<adom>/logsearch/count/<task_id>. Rows are omitted. focus is all, deny (traffic action deny), webfilter, or ips. limit is the match budget (default 500, at most 500): FortiAnalyzer stops collecting once it has that many matches, so the count can be lower than the number of matching logs. total_count can count scanned lines. If the count read fails, the search total_count is still returned with count_error. Do not treat this count as a complete log answer. Use map_analyzer_device for device.",
		func(ctx context.Context, input service.LogFocusQuery) (any, error) {
			return s.app.CountFortiAnalyzerLogs(ctx, input)
		})
	addReadTool(s, "map_analyzer_device", "Map a FortiGate to its FortiAnalyzer devname",
		"Match an inventoried FortiGate serial, hostname or name to the FortiAnalyzer device list and return the logged name to use as search_fortianalyzer_logs device. Copying the FortiManager name into a log filter is a common empty search. analyzer_adom defaults to the profile's single configured ADOM, or root when the profile allows every ADOM. The device list is cached for 5 minutes.",
		func(ctx context.Context, input service.AnalyzerDeviceQuery) (any, error) {
			return s.app.MapAnalyzerDevice(ctx, input)
		})
	addReadTool(s, "get_nat_for_flow", "Central SNAT, IP pool and VIP for a flow",
		"Read the ADOM central SNAT map, IP pools and VIPs (the first 200 objects of each table, from the object cache) and keep rows that contain the source, destination or port text. This is not the address the FortiGate wrote on the wire. Confirm with get_firewall_sessions or a traffic log. When a row only names another object, that name is what was stored.",
		func(ctx context.Context, input service.NATQuery) (any, error) {
			return s.app.GetNATMapping(ctx, input)
		})
	addReadTool(s, "get_routing_neighbors", "BGP, OSPF and SD-WAN SLA",
		"Short live rows for BGP neighbors, OSPF neighbors, and SD-WAN SLA samples (interface, latency, jitter, loss, state) on one FortiGate. The monitor reads are reused for 30 seconds. Configured routes stay on resolve_route.",
		func(ctx context.Context, input service.DeviceScope) (any, error) {
			return s.app.GetRoutingNeighbors(ctx, input)
		})
	addReadTool(s, "get_package_history", "Package oid, install state and device revision",
		"For one FortiGate, return the inventory package oid, the stored install status, the device conf_status, and a best-effort device revision get. A revision get that this FortiManager release refuses is reported under errors and the other fields are still returned. Install history that would need an exec call is not requested.",
		func(ctx context.Context, input service.PackageHistoryQuery) (any, error) {
			return s.app.GetPackageHistory(ctx, input)
		})
	addReadTool(s, "get_policy_usage", "Policy hit counts and where an object is used",
		"Live hit counts from the FortiGate policy monitor (policy id, name, hit count, bytes, last used), not cached. When name is set, where_used scans the ADOM firewall, IPv6, security and proxy policy tables for that address, service or ssl-ssh profile name. where_used_complete is false if a table failed or no name was requested; partial references remain available and errors identify failed profile, ADOM, package and table. The scan is local to those tables and is not FortiManager's where-used exec.",
		func(ctx context.Context, input service.PolicyUsageQuery) (any, error) {
			return s.app.GetPolicyUsage(ctx, input)
		})
	addReadTool(s, "get_ssl_ssh_profile", "SSL/SSH inspection profile",
		"Read one ADOM firewall ssl-ssh profile and return its inspection mode, https and ssh sections, and untrusted-certificate action, plus the profile object. The policy field inspection-mode is the policy's own mode; this object decides certificate inspection versus deep inspection per protocol.",
		func(ctx context.Context, input service.SSLProfileQuery) (any, error) {
			return s.app.GetSSLSSHProfile(ctx, input)
		})
	addReadTool(s, "get_log_receipt", "When a device last sent logs",
		"Read FortiAnalyzer /logview/adom/<adom>/logstats, cached for 5 minutes, and optionally keep the row whose name, serial or devname matches device. A missing row or an old last-received time means a zero log search may be a logging gap. A finished search with zero rows also attaches this read.",
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

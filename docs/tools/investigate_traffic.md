# `investigate_traffic`

Start a traffic investigation with ownership, an ordered configured path, and policy evidence for each traced hop and destination.

**Evidence and freshness:** Combines inventory, configured routing, policy reads/live lookup, optional URL rating and web-filter configuration, and optional FortiAnalyzer traffic logs.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `detail` | string | No | `full` (default) or `compact`; compact removes duplicate first-hop/route-hop copies and raw live payloads while preserving diagnostic evidence. |
| `source_ip` | string | Yes | Source IPv4 or IPv6 address of the flow |
| `destination_ip` | string | Yes | Destination IP address or hostname |
| `destination_port` | integer | No | Destination port. Enables policy lookup for non-ICMP flows. Omit for ICMP and ICMPv6. |
| `protocol` | string | No | tcp, udp, sctp, icmp, icmpv6, any, or an IP protocol number. Omitted or any evaluates TCP and UDP separately in policy lookup. |
| `source_port` | integer | No | Source port for configured routing, service matching and live policy lookup. Omit when unknown or when the flow uses ICMP. |
| `icmp_type` | integer | No | ICMP or ICMPv6 message type, 0–255, when known. |
| `icmp_code` | integer | No | ICMP or ICMPv6 message code, 0–255, when known. |
| `source_interface` | string | No | Ingress interface or zone when inventory cannot infer it |
| `profile` | string | No | FortiManager profile name. All inventoried profiles are searched when omitted. |
| `adom` | string | No | Limit candidates to one ADOM |
| `device` | string | No | Limit candidates to one managed FortiGate |
| `vdom` | string | No | Limit ownership, routing, policy and web-filter scope to this VDOM |
| `url` | string | No | When set, rate this URL and check web filter profiles for it |
| `include_logs` | boolean | No | Also submit a FortiAnalyzer traffic log search for this flow |
| `log_profile` | string | No | FortiAnalyzer profile for include_logs. The default FortiAnalyzer profile is used when omitted. |
| `log_adom` | string | No | FortiAnalyzer ADOM for include_logs, not the FortiManager ADOM |
| `log_start` | string | No | Log search start as RFC3339 with an explicit offset. One hour ago when omitted. |
| `log_end` | string | No | Log search end as RFC3339 with an explicit offset. Now when omitted. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root",
  "source_ip": "10.1.0.10",
  "destination_ip": "10.30.0.20",
  "destination_port": 443,
  "protocol": "tcp",
  "include_logs": true,
  "log_profile": "example-faz",
  "log_adom": "example-adom",
  "log_start": "2026-10-02T10:00:00Z",
  "log_end": "2026-10-02T10:10:00Z"
}
```

## Behavior and limits

`investigate_traffic` accepts a source, destination, protocol and ports, plus optional explicit scope and `url`. Its `hops` array joins route, policy, web-filter, warnings and errors for each traced hop and destination address. In the full view, top-level `policy` and `web_filter` duplicate the first hop's evidence when hops exist; a policy lookup without traced hops remains at top level. With `url`, the server rates once and reuses the category across scoped hop checks. A configured denial skips web filtering on that policy; its confidence and unresolved conditions still apply; an unresolved carrying policy returns candidate profiles with a warning. One hop's failure does not suppress other evidence.

Omitting `detail` or using `full` retains the existing JSON shape. `compact` keeps ordered evidence in `hops`, path endings and alternative destinations in `route`, inventory timestamps/freshness, all policy decisions/matches and live/configured disagreements, warnings/errors, web-filter evidence and optional log task state. It adds `flow`, `evidence_sources`, `coverage`, `omitted` counts and an omission notice. Read the canonical top-level `hops`: compact mode sets the duplicate `route.path.hops` and corresponding `other_addresses` path-hop arrays to null while retaining path endings. When routing has no scoped hop, the fallback top-level policy remains available. Omission counts describe representation, not evidence completeness; raw live lookup payloads can be requested with `detail: full` or focused tools.

Oversized investigations return `isError: true`, `representation_truncated` and narrowing guidance. Request `detail: compact`, one destination and device/VDOM, or focused tools. The first fallback places retained compact results under `evidence`; smaller fallbacks may retain only flow, coverage, errors and log recovery metadata. Inspect the actual fields and omission notices before drawing conclusions. Any omitted log rows need the same offset with a smaller limit when a callable recovery action is available; otherwise follow the scope/permission recovery hint.

The investigation evaluates downstream hops using the original flow tuple and states that limit. Verify NAT with sessions or logs, then repeat downstream lookups using the translated tuple. Configured routing and policy matches do not establish observed delivery or return-path symmetry.

`source_ip` and `destination_ip` are required. To investigate portless traffic, specify `protocol: "icmp"` or `protocol: "icmpv6"` and omit both ports. Set `icmp_type` and `icmp_code` when known. For other protocols, omitting `destination_port` skips the policy step. Provide ingress when known and keep unresolved scopes separate.

`include_logs` adds one traffic search with a 25-row budget, using the analyzer profile, ADOM and time window. The default window is the last hour. The search uses the source IP and the concrete destination IPs evaluated for the source's address family. Known source and destination ports and the numeric IP protocol constrain the filter. An unresolved destination skips the search and reports the gap. The tool uses a unique source-side analyzer `devname` and adds `vd` when the source VDOM is known. If either scope cannot be verified, warnings identify the broader search and the rows that need scope verification. The result retains partial task state and `next_action`. Search each downstream hop separately when the tuple may have changed. [Fortinet Log View API examples](https://community.fortinet.com/fortianalyzer-6/technical-tip-api-calls-to-search-logs-from-analytics-database-logview-in-fortianalyzer-188625) · [Flow guide](../use-cases.md)

## Related tools

[`resolve_route`](resolve_route.md), [`lookup_firewall_policy`](lookup_firewall_policy.md), [`get_firewall_sessions`](get_firewall_sessions.md), [`map_analyzer_device`](map_analyzer_device.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md).

[v2.0.0 tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

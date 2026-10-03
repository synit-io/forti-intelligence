# `investigate_traffic`

Start a traffic investigation with ownership, an ordered configured path, and policy evidence for each traced hop and destination.

**Evidence and freshness:** Combines inventory, configured routing, policy reads/live lookup, optional URL rating and web-filter configuration, and optional FortiAnalyzer traffic logs.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `source_ip` | string | Yes | Source IPv4 or IPv6 address of the flow |
| `destination_ip` | string | Yes | Destination IP address or hostname |
| `destination_port` | integer | No | Destination port. When set, the firewall policy lookup runs; when omitted, that step is skipped. |
| `protocol` | string | No | tcp, udp, sctp, icmp, any, or an IP protocol number. When omitted the live policy lookup runs for TCP and UDP. |
| `source_port` | integer | No | Source port for configured routing and service matching, and the live policy lookup. Omit only when unknown; source-port constraints then remain tentative. |
| `source_interface` | string | No | Ingress interface or zone when inventory cannot infer it |
| `profile` | string | No | FortiManager profile name. All inventoried profiles are searched when omitted. |
| `adom` | string | No | Limit candidates to one ADOM |
| `device` | string | No | Limit candidates to one managed FortiGate |
| `vdom` | string | No | Limit web filter results to this VDOM |
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

`investigate_traffic` accepts a source, destination, protocol and ports, plus optional explicit scope and `url`. Its `hops` array joins route, policy, web-filter, warnings and errors for each traced hop and destination address. Top-level `policy` and `web_filter` retain only the first hop's evidence for existing clients. With `url`, the server rates once and reuses the category across scoped hop checks. A configured denial skips web filtering on that policy; its confidence and unresolved conditions still apply; an unresolved carrying policy returns candidate profiles with a warning. One hop's failure does not suppress other evidence.

The investigation evaluates downstream hops using the original flow tuple and states that limit. Verify NAT with sessions or logs, then repeat downstream lookups using the translated tuple. Configured routing and policy matches do not establish observed delivery or return-path symmetry.

`source_ip` and `destination_ip` are required. A missing `destination_port` skips the policy step. Provide `source_port` and ingress when known, and keep unresolved scopes separate.

`include_logs` adds a traffic search using the analyzer profile/ADOM and time window, defaulting to the last hour. It returns what finished before the request deadline; inspect errors and resume unfinished searches with their `task_id`. This does not replace separately mapped, per-hop searches with translated tuples. See the [flow guide](../use-cases.md) and [SYSTEM.md](../../SYSTEM.md) for that process.

## Related tools

[`resolve_route`](resolve_route.md), [`lookup_firewall_policy`](lookup_firewall_policy.md), [`get_firewall_sessions`](get_firewall_sessions.md), [`map_analyzer_device`](map_analyzer_device.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

# `get_fortigate_settings`

Read a supported FortiGate monitor or CMDB resource when focused tools leave a specific operational question unanswered.

**Evidence and freshness:** FortiGate REST GET through the FortiManager `/sys/proxy/json` tunnel. Stable monitor reads are reused for 30 seconds; sessions are not cached.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name from the server configuration. The default profile is used when omitted. |
| `adom` | string | No | ADOM that manages the FortiGate; taken from the inventory when omitted |
| `device` | string | Yes | Managed FortiGate name; the read is proxied live to this device |
| `vdom` | string | No | VDOM for the FortiOS request; root when omitted |
| `resource` | string | Yes | FortiOS REST path starting with /api/v2/monitor/ or /api/v2/cmdb/, query string allowed, for example /api/v2/monitor/router/ipv4?vdom=root or /api/v2/cmdb/system/interface. Aliases: routing-table, routing-table6, sdwan-health, sessions, interfaces. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root",
  "resource": "routing-table"
}
```

## Behavior and limits

Only GET-style paths under `/api/v2/monitor/` and `/api/v2/cmdb/` are accepted. Query strings may narrow the response. Sensitive administrator and credential paths, nested escapes, and traversal are rejected.

Aliases include `routing-table`, `routing-table6`, `sdwan-health`, `sessions`, `interfaces`, `ha-peer`, `ha-checksums`, `ipsec`, `ssl-vpn`, `bgp-neighbors`, `ospf-neighbors`, `sdwan-sla`, and `license`. Routing aliases read `/api/v2/monitor/router/ipv4` or `/ipv6`; `sdwan-health` reads `/api/v2/monitor/virtual-wan/health-check`.

The ADOM is resolved from inventory when omitted; VDOM defaults to `root`. Proxy waiting is bounded to shortly before the request deadline. An offline FortiGate can still have useful FortiManager configuration, but cannot supply this live evidence.

Prefer the focused session, VPN, HA, and routing-neighbor tools for shorter answers. Use `resolve_route` for configured routing and this tool for operational routing when dynamic routes or live SD-WAN selection matter. Supported resources and response fields depend on the target FortiOS version and permissions.

## Related tools

[`resolve_route`](resolve_route.md), [`get_firewall_sessions`](get_firewall_sessions.md), [`get_vpn_status`](get_vpn_status.md), [`get_ha_status`](get_ha_status.md), [`get_routing_neighbors`](get_routing_neighbors.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

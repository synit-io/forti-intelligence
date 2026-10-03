# `get_routing_neighbors`

Check BGP, OSPF, and SD-WAN SLA state when operational routing can differ from the configured path.

**Evidence and freshness:** FortiGate BGP/OSPF neighbor and SD-WAN SLA monitors through FortiManager; reused for 30 seconds.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name. The default profile is used when omitted. |
| `adom` | string | No | ADOM that manages the FortiGate; taken from the inventory when omitted |
| `device` | string | Yes | Managed FortiGate name as shown in inventory_status |
| `vdom` | string | No | VDOM; root when omitted |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root"
}
```

## Behavior and limits

Returns short `bgp_neighbors`, `ospf_neighbors`, and `sdwan_sla` rows. Available fields include neighbor/router identity and state, plus SD-WAN interface, latency, jitter, loss, and state.

Monitor failures are listed independently under `errors`; available sources still return. Configured routes remain on `resolve_route`.

Neighbor reachability or SLA samples alone do not establish the active route selected for this flow. Use a live routing-table or SD-WAN health read when the missing selection affects the conclusion.

## Related tools

[`resolve_route`](resolve_route.md), [`get_fortigate_settings`](get_fortigate_settings.md), [`get_vpn_status`](get_vpn_status.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

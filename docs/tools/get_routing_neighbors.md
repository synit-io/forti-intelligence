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

Each failed monitor has an entry in `errors`. Use neighbor and SLA samples to explain routing changes. To check the installed prefix and next hops for one destination IP, call `resolve_route` with `live: true`, the device and its VDOM. For current SD-WAN health details, use the `sdwan-health` resource on `get_fortigate_settings`. [Route lookup](resolve_route.md) · [FortiGate settings](get_fortigate_settings.md)

## Related tools

[`resolve_route`](resolve_route.md), [`get_fortigate_settings`](get_fortigate_settings.md), [`get_vpn_status`](get_vpn_status.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

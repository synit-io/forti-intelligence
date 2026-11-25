# `get_vpn_status`

Check current IPsec tunnel and SSL-VPN login state on a FortiGate involved in the path.

**Evidence and freshness:** FortiGate IPsec and SSL-VPN monitors through FortiManager; reused for 30 seconds.

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

Returns short `ipsec_tunnels` rows with tunnel name, remote gateway, status, and byte counters, plus `ssl_vpn` rows with user, remote host, and duration when available.

The two reads fail independently; inspect `errors` before treating a missing tunnel or login as absence. This is monitor state, not the configured phase1 object.

A tunnel reported up does not establish that this flow uses it, matches policy, or reaches the remote application. Relate tunnel evidence to routing and the flow tuple; keep tunnel inner traffic separate from its outer transport.

## Related tools

[`resolve_route`](resolve_route.md), [`get_firewall_sessions`](get_firewall_sessions.md), [`get_fortigate_settings`](get_fortigate_settings.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

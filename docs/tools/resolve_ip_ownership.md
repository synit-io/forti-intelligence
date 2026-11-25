# `resolve_ip_ownership`

Find the FortiGate interfaces whose configured networks contain an IP address. Start here when the site, device, or VDOM is unknown.

**Evidence and freshness:** In-memory connected-network index built by the background FortiManager inventory refresh; no appliance request.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `ip` | string | Yes | IPv4 or IPv6 address to locate, for example 10.49.0.17 |
| `profile` | string | No | Limit to one FortiManager profile name |
| `adom` | string | No | Limit to one ADOM name |
| `device` | string | No | Limit to one managed FortiGate name |
| `vdom` | string | No | Limit to one VDOM name |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "ip": "10.1.0.10"
}
```

## Behavior and limits

The result includes every matching candidate, most-specific first, with its profile, ADOM, device, serial, VDOM, interface, zone, connected network, package targets, and `data_as_of`. Check `ambiguous`, profile freshness, refresh errors, and `unavailable_devices` before selecting a scope.

Connected ownership identifies a configured subnet attachment. It does not establish endpoint identity, actual ingress, routing, reachability, or policy permission. Overlapping candidates remain separate; no candidate is a visibility gap.

`ready: false` with `refresh_in_progress: true` means the first snapshot is still loading. Retry shortly rather than triggering another refresh. Offline devices still contribute their FortiManager database evidence.

## Related tools

[`resolve_route`](resolve_route.md), [`resolve_address_identity`](resolve_address_identity.md), [`inventory_status`](inventory_status.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

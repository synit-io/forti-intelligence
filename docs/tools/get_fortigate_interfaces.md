# `get_fortigate_interfaces`

Inspect one FortiGate interface and zone inventory without dumping every managed device.

**Evidence and freshness:** FortiManager device database, served from the inventory snapshot by default; `fresh: true` reads FortiManager now.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name from the server configuration. The default profile is used when omitted. |
| `adom` | string | No | ADOM that manages the FortiGate; taken from the inventory when omitted |
| `device` | string | Yes | Managed FortiGate name as shown in inventory_status |
| `vdom` | string | No | Return only interfaces of this VDOM |
| `fresh` | boolean | No | Read FortiManager now instead of the inventory snapshot (for example right after an interface change) |
| `include_raw` | boolean | No | Include the raw appliance records (large). Parsed fields already carry the evidence; leave false unless a field is missing. |

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

Parsed interfaces include name, alias, type, IP/netmask, connected networks, IPv6, VDOM, status, role, parent, and zone membership. `data_as_of` identifies the age of the device evidence. Omit `include_raw` unless a necessary field is missing.

Use `fresh: true` immediately after a relevant interface change. This remains a FortiManager database read, not live FortiGate operational state. Interfaces come from `global/system/interface`; zones come from `vdom/<vdom>/system/zone` for each discovered VDOM.

The ADOM is resolved from inventory when omitted. Equal interface or zone names on different devices do not establish a link.

## Related tools

[`resolve_ip_ownership`](resolve_ip_ownership.md), [`resolve_route`](resolve_route.md), [`get_fortigate_settings`](get_fortigate_settings.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

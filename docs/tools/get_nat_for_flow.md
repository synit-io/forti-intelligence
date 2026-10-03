# `get_nat_for_flow`

Find configured central SNAT, IP pool, and VIP objects that mention a flow.

**Evidence and freshness:** FortiManager ADOM object tables, using the object cache; reads the first 200 objects of each table.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name. The default profile is used when omitted. |
| `adom` | string | No | ADOM that manages the FortiGate; taken from the inventory when omitted |
| `device` | string | Yes | Managed FortiGate name as shown in inventory_status |
| `vdom` | string | No | VDOM; root when omitted |
| `source_ip` | string | No | Source address of the flow, matched against central SNAT and IP pools when those objects carry an address |
| `destination_ip` | string | No | Destination address, matched against VIP external addresses |
| `port` | integer | No | Destination port, matched against VIP external ports when present |

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
  "port": 443
}
```

## Behavior and limits

Reads `firewall/central-snat-map`, `firewall/ippool`, and `firewall/vip`. A row is kept when it contains the source, destination, or port text. Matching is textual rather than a complete NAT-rule evaluation; indirect object references remain names.

The result includes `central_snat`, `ippool`, `vip`, and per-table `errors`. The first-200-object bound can omit relevant rows; use paged object reads to inspect additional configuration when needed.

These are candidate mappings, not the address or port written on the wire. Verify translation with a session or traffic log before changing downstream routing, policy, or log queries. Do not select a single translated address from a pool without evidence.

## Related tools

[`get_firewall_sessions`](get_firewall_sessions.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md), [`list_policy_objects`](list_policy_objects.md), [`lookup_firewall_policy`](lookup_firewall_policy.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

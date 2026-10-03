# `get_policy_usage`

Check live policy hit counts and locate policy references to an address, service, or SSL/SSH profile name.

**Evidence and freshness:** Uncached FortiGate policy monitor for hits, plus cached FortiManager ADOM policy tables for references.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name. The default profile is used when omitted. |
| `adom` | string | No | ADOM that manages the FortiGate; taken from the inventory when omitted |
| `device` | string | Yes | Managed FortiGate name as shown in inventory_status |
| `vdom` | string | No | VDOM; root when omitted |
| `policy_id` | integer | No | Limit hit counts to this policy id |
| `object_type` | string | No | firewall/address, firewall/service/custom, or another firewall object path. Used with name for where-used. |
| `name` | string | No | Object name to find in the ADOM policy tables |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root",
  "policy_id": 44,
  "object_type": "firewall/address",
  "name": "branch-clients"
}
```

## Behavior and limits

`hit_counts` includes policy ID, name, hit count, bytes, and last-used fields when available. `policy_id` narrows the live hits; aggregate hits do not prove this incident tuple matched.

When `name` is set, `where_used` scans firewall, legacy IPv6, security, and proxy policy tables across the ADOM's packages. It lists references by package, table, policy ID, and matching fields; it is not FortiManager's cross-object where-used exec or a recursive dependency audit.

`where_used_complete` is true only when a requested scan succeeds for every table. Without `name`, or when a table read fails, it is false. Successful references remain available alongside errors naming the failed profile, ADOM, package, and table. An incomplete empty result does not prove the object is unused.

## Related tools

[`list_firewall_policies`](list_firewall_policies.md), [`list_policy_objects`](list_policy_objects.md), [`get_firewall_sessions`](get_firewall_sessions.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

# `list_policy_objects`

Inspect address, service, VIP, IP pool, or other firewall objects referenced by a policy.

**Evidence and freshness:** FortiManager ADOM object reads; object data is reused for five minutes.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name from the server configuration. The default profile is used when omitted. |
| `adom` | string | No | ADOM containing the objects; taken from the inventory when device is given |
| `device` | string | No | A managed FortiGate name, used only to find the ADOM when adom is omitted |
| `object_type` | string | Yes | Object path after /obj/, must start with firewall/: firewall/address, firewall/addrgrp, firewall/vip, firewall/service/custom, firewall/service/group, firewall/ippool |
| `name` | string | No | Read one object by exact name instead of the whole table |
| `limit` | integer | No | Maximum objects per page, default 100, at most 1000; FortiManager returns only this page |
| `offset` | integer | No | Number of objects to skip, for paging |
| `include_dynamic_mapping` | boolean | No | Include per-device mappings (dynamic_mapping), which can be large |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "object_type": "firewall/address",
  "name": "branch-clients"
}
```

## Behavior and limits

`object_type` is the path after `/obj/` and must start with `firewall/`, for example `firewall/address`, `firewall/addrgrp`, `firewall/vip`, `firewall/service/custom`, `firewall/service/group`, or `firewall/ippool`. Use `list_firewall_policies` for policy entries.

Supply the ADOM or a device whose inventory identifies it. `name` reads one exact object; otherwise FortiManager returns the requested page. `limit` defaults to 100 and is capped at 1,000, with `offset` for subsequent pages.

Per-device `dynamic_mapping` records are omitted unless `include_dynamic_mapping` is true. Reads with dynamic mappings are not cached. Inspect mappings when they affect the device under investigation; an object definition alone does not prove where it is applied.

## Related tools

[`list_firewall_policies`](list_firewall_policies.md), [`get_policy_usage`](get_policy_usage.md), [`get_nat_for_flow`](get_nat_for_flow.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

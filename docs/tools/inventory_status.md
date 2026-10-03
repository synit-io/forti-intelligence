# `inventory_status`

Check what the server can see and whether an investigation is using current or retained inventory.

**Evidence and freshness:** Latest background FortiManager snapshot and refresh state; this call does not refresh appliances.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | Limit to one FortiManager profile name |
| `adom` | string | No | Limit to one ADOM name |
| `include_interfaces` | boolean | No | Include every device's interface list (large). Prefer resolve_ip_ownership or get_fortigate_interfaces for one device. |
| `include_routes` | boolean | No | Include every device's configured static routes, policy routes, and SD-WAN (large). Prefer resolve_route for one destination. |
| `include_raw` | boolean | No | Include the raw appliance records (large). Parsed fields already carry the evidence; leave false unless a field is missing. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network"
}
```

## Behavior and limits

The summary includes ADOMs, devices and VDOMs, device groups, policy-package associations, snapshot time, refresh state, offline devices, and refresh errors. Interfaces, configured routes, and raw records are opt-in because they can be large.

A profile is `stale` when an ADOM-level inventory read fails. A failed device read instead sets that device's `data_error` and retains its previous data with `data_as_of`. An offline FortiGate is informational and does not make the profile stale; FortiManager can still serve its device database.

Errors preserve the failed stage, kind, FortiManager code or HTTP status, resource URL, retry attempts, retryability, and an operator hint. Inspect those details before treating a missing device or old record as absence.

## Related tools

[`refresh_inventory`](refresh_inventory.md), [`resolve_ip_ownership`](resolve_ip_ownership.md), [`get_fortigate_interfaces`](get_fortigate_interfaces.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

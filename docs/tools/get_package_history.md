# `get_package_history`

Compare inventory package identity, stored installation state, device configuration state, and any readable revision information.

**Evidence and freshness:** FortiManager inventory packages, stored package-status cache, and best-effort device/revision GET reads.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name. The default profile is used when omitted. |
| `adom` | string | No | ADOM that manages the FortiGate; taken from the inventory when omitted |
| `device` | string | Yes | Managed FortiGate name as shown in inventory_status |
| `vdom` | string | No | VDOM; root when omitted |
| `package` | string | No | Policy package name. The device's assigned packages are used when omitted. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root",
  "package": "branch-policy"
}
```

## Behavior and limits

Returns package names and `oid` values, `install_status`, a short `device_record`, `revisions` when readable, and per-source `errors`. The package oid changes when FortiManager changes the package.

A FortiManager release can reject the device revision GET. The tool reports that gap while preserving other fields. It does not request install history timestamps that require an exec call.

The name describes the available history evidence; this is not a complete installation audit or the FortiGate running checksum. Use it to investigate a specific configuration/live discrepancy, and state unsupported revision detail explicitly.

## Related tools

[`get_package_install_status`](get_package_install_status.md), [`lookup_firewall_policy`](lookup_firewall_policy.md), [`get_fortimanager_status`](get_fortimanager_status.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

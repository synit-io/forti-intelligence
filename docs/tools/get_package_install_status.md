# `get_package_install_status`

Check whether FortiManager reports a device policy package as installed, modified, or unknown.

**Evidence and freshness:** FortiManager stored package status; shares the five-minute package-status cache with web-filter checks.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name. The default profile is used when omitted. |
| `adom` | string | No | ADOM that manages the FortiGate; taken from the inventory when omitted |
| `device` | string | Yes | Managed FortiGate name as shown in inventory_status |
| `vdom` | string | No | One VDOM; all inventoried VDOMs when omitted, at most 48. |

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

Returns profile, ADOM, device, device configuration status, `install_status`, and `truncated`. An empty `vdom` reads every inventoried VDOM, capped at 48; unlike most device monitor tools, it does not restrict the read to `root`.

This is stored installation state, not the FortiGate's running checksum. An assigned package does not establish that its current revision is installed.

Use this check when a configured policy and live lookup differ, several candidate packages remain, or a web-filter result reports a modified package. Keep configuration and live evidence separate while resolving that discrepancy.

## Related tools

[`lookup_firewall_policy`](lookup_firewall_policy.md), [`get_package_history`](get_package_history.md), [`check_web_filter`](check_web_filter.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

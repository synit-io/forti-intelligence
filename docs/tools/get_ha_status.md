# `get_ha_status`

Check HA role, peer information, and available configuration checksums for a FortiGate cluster.

**Evidence and freshness:** FortiGate HA peer/checksum monitors and system HA configuration through FortiManager; stable monitor reads are reused for 30 seconds.

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

Returns `ha` configuration, peer rows, checksums, `checksum_sync`, and per-source `errors`. `checksum_sync` is true only when at least two checksum values were read and all are equal.

A false synchronization flag can mean unequal values or insufficient checksum evidence. Inspect the checksums and errors before claiming a mismatch.

Treat HA members as one cluster context unless evidence establishes separate traffic boundaries. Peer state and equal checksums do not prove flow delivery or complete cluster health.

## Related tools

[`inventory_status`](inventory_status.md), [`get_fortigate_settings`](get_fortigate_settings.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

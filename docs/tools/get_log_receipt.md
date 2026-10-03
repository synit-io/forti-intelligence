# `get_log_receipt`

Check whether FortiAnalyzer has recent log-receipt evidence for a device before interpreting an empty search.

**Evidence and freshness:** FortiAnalyzer `/logview/adom/<adom>/logstats`; cached for five minutes.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiAnalyzer profile. The default profile is used when omitted. |
| `adom` | string | No | FortiAnalyzer ADOM |
| `device` | string | No | Keep the logstats row whose name, serial or devname matches. All rows when omitted. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-faz",
  "adom": "example-adom",
  "device": "Branch-FW-logged"
}
```

## Behavior and limits

Returns `devices` from the selected ADOM's logstats resource. With `device`, keeps rows whose name, serial, or devname matches; without it, returns all rows. Use analyzer identity rather than an unverified FortiManager name.

A missing row or old last-received time can indicate an ingestion gap. It does not prove that traffic never occurred. Resource availability and row fields depend on the analyzer release.

A completed initial log search with zero rows also attempts to attach this receipt evidence. Check scope, filters, retention, completion, and logging availability before drawing conclusions from missing logs.

## Related tools

[`map_analyzer_device`](map_analyzer_device.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md), [`fortianalyzer_status`](fortianalyzer_status.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

# `fortianalyzer_status`

Check a configured FortiAnalyzer connection and its system status before investigating analyzer-specific failures.

**Evidence and freshness:** FortiAnalyzer `/sys/status` through JSON-RPC; cached for five minutes.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiAnalyzer profile name from the server configuration. The default profile is used when omitted. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-faz"
}
```

## Behavior and limits

The result includes the selected analyzer `profile` and its system `status` response. Omit `profile` to use the default FortiAnalyzer profile.

A successful status read proves only that this resource was readable. Log View search task creation has separate permissions, and status does not establish device identity, log ingestion, retention, or search completeness.

## Related tools

[`get_log_receipt`](get_log_receipt.md), [`map_analyzer_device`](map_analyzer_device.md), [`get_fortianalyzer_data`](get_fortianalyzer_data.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

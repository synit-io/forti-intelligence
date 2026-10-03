# `get_fortianalyzer_data`

Read analyzer device lists, filter fields, existing task state, reports, events, or incidents when a focused tool does not cover the required resource.

**Evidence and freshness:** FortiAnalyzer JSON-RPC `get`; system status, device lists, log fields, and logstats are cached for five minutes.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiAnalyzer profile name from the server configuration. The default profile is used when omitted. |
| `resource` | string | Yes | FortiAnalyzer JSON-RPC path under /sys, /dvmdb, /task, /logview, /fortiview, /report, /event, /eventmgmt or /incidents, for example /dvmdb/adom/<adom>/device, /logview/adom/<adom>/logfields, /logview/adom/<adom>/logsearch/<task_id> |
| `data` | object | No | Optional request parameters such as limit, offset, devtype, logtype, filter, time-range |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-faz",
  "resource": "/logview/adom/example-adom/logfields"
}
```

## Behavior and limits

Accepted prefixes are `/sys`, `/dvmdb`, `/task`, `/logview`, `/fortiview`, `/report`, `/event`, `/eventmgmt`, and `/incidents`. ADOM-scoped paths must belong to the profile's allowlist. No task or configuration change is requested by this tool.

`data` passes supported GET parameters such as `limit`, `offset`, `devtype`, `logtype`, `filter`, or `time-range`. Resource support and response fields depend on the analyzer release.

Use `/logview/adom/<adom>/logfields` to discover filter fields, and `/logview/adom/<adom>/logsearch/<task_id>` to inspect an existing search's progress and records. Prefer `map_analyzer_device` for logged device identity and `get_log_receipt` for ingestion evidence. Use `search_fortianalyzer_logs` to submit and poll a new search.

## Related tools

[`fortianalyzer_status`](fortianalyzer_status.md), [`map_analyzer_device`](map_analyzer_device.md), [`get_log_receipt`](get_log_receipt.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

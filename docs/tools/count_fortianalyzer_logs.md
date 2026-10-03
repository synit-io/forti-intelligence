# `count_fortianalyzer_logs`

Get a bounded match count before retrieving log rows, with optional deny, web-filter, or IPS focus.

**Evidence and freshness:** FortiAnalyzer Log View search plus `/logview/adom/<adom>/logsearch/count/<task_id>`; rows are omitted.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiAnalyzer profile. The default profile is used when omitted. |
| `adom` | string | No | FortiAnalyzer ADOM, not the FortiManager ADOM |
| `device` | string | No | Logged device name (devname). Use map_analyzer_device to translate a FortiManager FortiGate name. |
| `filter` | string | No | Extra Log View filter, ANDed with the focus filter |
| `start` | string | No | Range start as RFC3339 with an explicit offset; one hour ago when omitted |
| `end` | string | No | Range end as RFC3339 with an explicit offset; now when omitted |
| `focus` | string | No | all (default), deny (traffic action deny), webfilter, or ips |
| `limit` | integer | No | Match budget of the count search, default 500, at most 500. The rows are not returned. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-faz",
  "adom": "example-adom",
  "start": "2026-10-02T10:00:00Z",
  "end": "2026-10-02T10:10:00Z",
  "device": "Core-FW-logged",
  "focus": "deny",
  "filter": "srcip=172.16.0.1 and dstip=10.30.0.20 and dstport=443"
}
```

## Behavior and limits

`focus` accepts `all` (default), `deny` (traffic with action deny), `webfilter`, or `ips` (attack logs). The additional `filter` is ANDed with the focus filter. Map the logged device name before filtering.

`limit` is a match budget, default and maximum 500. FortiAnalyzer can stop collecting at that budget, so this is not an exhaustive count. `total_count` can count scanned lines rather than matching logs.

The result preserves task ID, completion, progress, timeout, budget, warnings, and count data. `count_error` leaves the search metadata available if the count read fails; a missing task ID means no count resource was read. Do not treat incomplete or bounded counts as a complete incident answer. Retrieve rows with `search_fortianalyzer_logs` and follow its task and pagination rules.

Search task creation requires the same [Log View permissions](search_fortianalyzer_logs.md#behavior-and-limits) as a row search.

## Related tools

[`map_analyzer_device`](map_analyzer_device.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md), [`get_log_receipt`](get_log_receipt.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

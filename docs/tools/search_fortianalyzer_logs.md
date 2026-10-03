# `search_fortianalyzer_logs`

Retrieve observed traffic, security, or event evidence in a bounded incident window.

**Evidence and freshness:** FortiAnalyzer ADOM-scoped Log View search; submits a read-oriented task and polls until completion or the request deadline.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiAnalyzer profile name from the server configuration. The default profile is used when omitted. |
| `adom` | string | No | FortiAnalyzer ADOM (not the FortiManager ADOM). The configured ADOM is used when the profile allows exactly one. |
| `log_type` | string | No | traffic (default), event, webfilter, app-ctrl, attack (IPS), virus, dns, ssl, emailfilter, dlp, or another Log View log type of the FortiAnalyzer release |
| `filter` | string | No | FortiAnalyzer Log View filter, for example srcip=10.0.0.5 and dstport=443 and action!=accept. Field names are listed by get_fortianalyzer_data /logview/adom/<adom>/logfields |
| `start` | string | No | Range start as RFC3339 with explicit offset, for example 2026-09-22T14:00:00+02:00; one hour ago when omitted |
| `end` | string | No | Range end as RFC3339 with explicit offset; now when omitted |
| `device` | string | No | Logged device name (devname) to filter on; all devices when omitted |
| `limit` | integer | No | Match budget of the submit, 1-500, default 25. FortiAnalyzer stops collecting once it has this many matches. A later page of the same task exists only when this budget is larger than the page. |
| `offset` | integer | No | Record offset. On a new search this is where collection starts. With task_id it pages inside the budget of the original submit. |
| `task_id` | string | No | Task ID of a search that has not reached 100%, or of a submit whose limit is larger than one page. A full page that used up the submit limit needs a new search without task_id at the next offset. Keep profile and adom the same. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-faz",
  "adom": "example-adom",
  "start": "2026-10-02T10:00:00Z",
  "end": "2026-10-02T10:10:00Z",
  "device": "Branch-FW-logged",
  "log_type": "traffic",
  "filter": "srcip=10.1.0.10 and dstip=10.30.0.20 and dstport=443",
  "limit": 25
}
```

## Behavior and limits

Log View search creates a search task (JSON-RPC method `add`), so the FortiAnalyzer API administrator needs an admin profile with Log View access, assignment to the searched ADOM, and JSON API access that permits task creation. On many releases that means JSON API Read-Write; keep every other admin-profile permission at None or Read so the account still cannot change configuration. When FortiAnalyzer refuses it, the tool reports `permission_denied` with `Access denied … userfrom=JSON(<admin>)`, while status and other reads with the same key may still work.

The search selector is `All_Devices` in the requested ADOM with `devname` applied as a filter when `device` is given. Time ranges are sent as ISO timestamps with their UTC offset (`2026-09-22T14:05:00+02:00`), expressed in the profile `timezone` when set. An appliance that rejects that form gets the same wall clock without offset, then the space-separated form; the first accepted form is remembered, so later searches submit once. The server polls the task at 0.5 s, 1 s and then every 2 s until it finishes or shortly before the request deadline. A search counts as finished only when FortiAnalyzer reports 100 %: its status message says "succeeded" for every successful poll, also while the search runs. A search that is still running returns `timed_out: true`, its `task_id`, progress, and the records fetched so far; call the tool again with the same `profile`, `adom` and `task_id` to continue polling (the result reports the query it was submitted with). The `limit` on submit is the match budget, not only a page size. When a page fills that budget, continue with a new search and no `task_id` at `offset` equal to the previous offset plus count, or submit once with a larger limit (up to 500) and page that task with `task_id` and `offset`. `task_id` plus a higher offset is the next page only when the original submit asked for more matches than the page. Pages hold 25 records by default and at most 500. An identical search (same ADOM, filter, device, window, limit and offset) within 3 minutes reuses the remembered task. `total_count` is FortiAnalyzer's `total-count`, which can count scanned rather than matching logs; `count` is the returned page, and a full page means more records may match. A finished search with zero rows attaches `/logstats` when that read succeeds. Field names for filters come from `get_fortianalyzer_data` with `/logview/adom/<adom>/logfields`. Logged device names come from `map_analyzer_device` or `/dvmdb/adom/<adom>/device` on the FortiAnalyzer, which usually differ from FortiManager ADOM and device names.

FortiAnalyzer results preserve the selected profile, ADOM, device filter, log type, effective filter, offset, limit, task ID, completion/progress state, the time range as sent to the appliance, the appliance time zone, warnings, a hint, and whether polling timed out. Returned records are observed log evidence; an incomplete or empty search is not proof that traffic did not occur.

## Related tools

[`map_analyzer_device`](map_analyzer_device.md), [`count_fortianalyzer_logs`](count_fortianalyzer_logs.md), [`get_log_receipt`](get_log_receipt.md), [`get_fortianalyzer_data`](get_fortianalyzer_data.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

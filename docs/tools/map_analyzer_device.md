# `map_analyzer_device`

Map an inventoried FortiGate to its analyzer identity before filtering logs.

**Evidence and freshness:** FortiManager inventory identity matched against the FortiAnalyzer ADOM device list; the analyzer list is cached for five minutes.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile of the FortiGate |
| `adom` | string | No | FortiManager ADOM; taken from the inventory when omitted |
| `device` | string | Yes | FortiManager FortiGate name |
| `analyzer_profile` | string | No | FortiAnalyzer profile. The default profile is used when omitted. |
| `analyzer_adom` | string | No | FortiAnalyzer ADOM. The configured ADOM is used when the profile allows exactly one. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "analyzer_profile": "example-faz",
  "analyzer_adom": "example-adom"
}
```

## Behavior and limits

The tool compares the FortiGate serial, hostname, and name with analyzer device records, returning matching records and the identifier that matched. Inspect `matches` before choosing the logged name or serial for a log filter.

FortiManager and FortiAnalyzer profiles, ADOMs, and device names are separate scopes. `profile`/`adom` select FortiManager; `analyzer_profile`/`analyzer_adom` select FortiAnalyzer. If the analyzer profile has one permitted ADOM, it is used when omitted; an unrestricted profile falls back to `root`. A profile with several permitted ADOMs requires an explicit choice.

No match or several plausible matches leave a mapping gap. Do not silently copy the manager name or choose an arbitrary analyzer record; resolve serial/HA identity and VDOM where applicable.

## Related tools

[`search_fortianalyzer_logs`](search_fortianalyzer_logs.md), [`count_fortianalyzer_logs`](count_fortianalyzer_logs.md), [`get_log_receipt`](get_log_receipt.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

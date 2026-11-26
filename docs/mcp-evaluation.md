# MCP evaluation

Use the repository's synthetic fixtures to check what an MCP client receives from Forti Intelligence. Compare the evidence in each response before comparing its size. The fixtures run locally without appliance credentials or a model API.

## Run the fixtures

From the repository root, run the [evaluation script](../scripts/evaluate-mcp.sh) with the Go version declared in [go.mod](../go.mod).

```sh
scripts/evaluate-mcp.sh "${TMPDIR:-/tmp}/forti-mcp-evaluation"
```

Use a separate output directory for each revision you compare. The script writes the following files.

| Output | What to check |
| --- | --- |
| `manifest.txt` | Git revision, Go version, and working-tree changes for this run. |
| `catalog-*.json`, `instructions-*.txt` | Advertised tool names, input schemas, and session instructions with and without a dedicated rating device. |
| `investigation-*-full.json`, `investigation-*-compact.json` | Compare the same flow in both views. Check every hop, destination, policy decision, warning, and evidence gap. |
| `ownership-*.json`, `policy-*.json` | Inspect the underlying scope and policy evidence for each investigation fixture. |
| `logs-*.json` | Check empty, unfinished, and complete pages, plus recovery when a result exceeds the size limit. |
| `measurements.txt` | Test results and byte counts for the serialized catalog, instructions, and results. For overflow, compare the attempted and returned sizes. |

## Implementation status

| Area | Available in v2.2.0 |
| --- | --- |
| Tool discovery | The server advertises 29 tools by default. Disabling a tool removes it from discovery and rejects direct calls. The fixture script measures the default catalog in both rating configurations. |
| Investigation results | Full detail is the default. The compact view removes duplicate evidence and raw live lookup data. Fixtures compare policy decisions, unknown source ports, multiple destinations, and partial reads across both views. |
| Log recovery and size limits | Results expose task state and follow-up arguments when available. Oversized results return an explicit error. The overflow fixture uses a 64 KiB cap to exercise recovery at the same unseen offset. The server default is 512 KiB. |
| Audit logging | Tests cover action outcomes, audit IDs in tool diagnostics, forwarding over TCP or TLS, and the stderr fallback when HTTP stdout is suppressed. |

Run `go test -race ./...` for the broader suite, including audit and tool-availability checks. The fixture script measures serialized bytes. Token usage, tool selection, and answer quality require a run in an MCP client. [Tool reference](tools/README.md) · [Audit fields and result metrics](operations.md)

## Compare results in an MCP client

Use the same prompt, synthetic appliance responses, enabled tools, cache state, and client and model versions across runs. Change one variable at a time, such as full versus compact detail. Reserve scenarios that were not used to tune the descriptions.

| Scenario | What a supported answer should establish |
| --- | --- |
| A flow crosses two firewalls and changes source address | Use the observed translation for downstream checks. Identify the blocking hop and any unverified return path. |
| A hostname resolves to several addresses, or a source port is unknown | Keep the candidate decisions separate and identify the missing evidence. |
| A log search is incomplete, expired, or oversized | Use the returned continuation and its original scope when available. Recover an omitted page at the same offset. |
| A tool is disabled, an analyzer is absent, or a live device read fails | Use the remaining evidence and state which conclusion the missing read prevents. |

For each run, record the chosen tools and arguments, retries, follow-up calls, unsupported claims, evidence cited, and elapsed time. Record token counts only when the client reports them. Repeat each scenario and report the variation. The [investigation examples](use-cases.md) provide fictional flows and expected evidence.

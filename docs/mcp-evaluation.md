# MCP evaluation

The server keeps 29 tool names, text-only results and the 512 KiB default cap. `detail: compact` is optional; omitted/full investigation calls keep their existing fields. This procedure prepares synthetic evaluation artifacts and byte measurements. Live model runs are excluded from this implementation at the user's request.

## Prepare repeatable artifacts

Run from a clean checkout or record its working changes:

```sh
GOCACHE="${TMPDIR:-/tmp}/forti-evaluation-go-cache" scripts/evaluate-mcp.sh "${TMPDIR:-/tmp}/forti-mcp-evaluation"
```

The script runs selected Go fixture tests, exports both rating-device catalog variants, initialization instructions, full/compact investigation, ownership, policy and log/overflow JSON, and writes measurements and a revision/working-tree manifest. It uses no model API or production appliances. Synthetic result observation timestamps are fixed to `2026-11-07T00:00:00Z` for repeatable byte counts; production timestamps stay unchanged. Large rows are generated in tests rather than committed as snapshots.

Inspect the generated JSON as evidence, not instructions. Match content across full and compact views before comparing sizes. Standard checks remain `go test ./...`, `go vet ./...` and race tests for shared metrics/task state.

## Initial byte measurements

Baseline catalog evidence was captured from commit `6e1a1d71888ac43e1089c803311fd5c91da274d0`; the implementation measurements below use the default rating configuration. Catalog sizes use the same compact serialized **tool array**, excluding transport metadata. Instructions are reported separately.

| Measure | Baseline bytes | Revised bytes |
| --- | ---: | ---: |
| Tool array | 47,676 | 46,058 |
| Description strings combined | 16,368 | 14,167 |
| Input schemas combined | 24,049 | 24,632 |
| Initialization instructions | 2,707 | 2,845 |

The six largest descriptions were edited; compatible bounds and the new detail input account for schema growth. The revised configured-rating variant is 46,148 tool-array bytes. These measurements establish neither token savings nor tool-selection accuracy.

Fixed synthetic investigation fixtures (all request logs with no analyzer configured; the log gap remains explicit in both views):

| Scenario | Full bytes | Compact bytes |
| --- | ---: | ---: |
| One-hop allow | 6,094 | 5,026 |
| One-hop deny | 6,086 | 5,022 |
| Unknown constrained source port | 6,704 | 5,311 |
| Multiple destination addresses | 9,904 | 8,662 |
| Injected incomplete policy evidence | 6,129 | 5,060 |

The corresponding ownership fixture is 786 bytes; one-hop allow policy evidence is 1,738 bytes. Synthetic log fixtures are 192 bytes (zero), 1,986 (unfinished), and 2,040 (page). The generated 83,973-byte overflow fixture returns a 734-byte explicit error with same-offset recovery at a 64 KiB cap. Run the script after changes to refresh these figures. Compact can add overhead where no duplicated evidence exists; full remains the default. Separate SSL/SSH or policy projection inputs are deferred until focused payload measurements justify them.

## Compatible input acceptance

Bounds mirror existing runtime rejection; runtime validation remains independent. Normalized values keep open schemas to avoid rejecting previously accepted calls.

| Inputs | Existing acceptance and normalization | Advertised constraint |
| --- | --- | --- |
| Policy destination port | Required, 1–65535; zero/negative/above range rejected | Minimum 1, maximum 65535 |
| Policy source port; investigation/route ports | Omitted/zero means unknown/skipped; negatives and above 65535 rejected | Minimum 0, maximum 65535 |
| Log/list offsets | Omitted/zero accepted; negatives rejected | Minimum 0 |
| Policy/object list limit | Omitted, zero, negative → 100; above 1000 → 1000 | Open integer; normalization retained |
| Log search limit | Omitted, zero, negative → 25; above 500 → 500 | Open integer; normalization retained |
| Count-log limit | Omitted, zero, negative → 500; above 500 clamps in analyzer | Open integer |
| Session count | Omitted, zero, negative → 50; above 200 → 200 | Open integer |
| Policy/route protocol | Case/whitespace normalized; tcp/udp/sctp/icmp, any/all, numeric 1–255 aliases; unsupported values rejected | Open string to retain aliases/case |
| Session ports/protocol | Existing positive-port filtering and permissive protocol normalization retained | Open fields; no new rejection |
| Log focus | Case/whitespace normalized; empty/all, deny, webfilter/web-filter/web_filter, ips/attack | Open string to retain aliases/case |
| Policy IP family | Empty/4/ipv4 or 6/ipv6, case/whitespace normalized | Open string to retain aliases/case |
| Investigation detail | Empty/full → legacy; compact → projected evidence | Enum empty/full/compact |
| Log type and generic resources | Appliance/version-specific domains | Existing runtime resource checks; no new enum |

## Prepared host comparison

Use the same fictional or sanitized scenario inputs, host/model version, tool configuration and grading rules for each variant. Keep a tuning set (one-hop allow/deny, unknown source port, zero/unfinished logs) separate from a held-out set (multiple hops, overlapping VDOMs, alternative DNS addresses, NAT limits, configured/live disagreement, partial/stale/loading inventory, expired tasks, exhausted budgets, overflow and no analyzer). Existing Go fixture tests supply deterministic evidence; live diagnosis quality is not inferred from their byte counts.

For each scenario, record the prompt, scope, cold/warm cache state, chosen tools/arguments, invalid calls, retries, redundant reads, continuation correctness, unsupported claims, final evidence coverage, total follow-up calls and end-to-end latency. Record input/output/total tokens and cached tokens only if the selected host exposes them. Repeat runs and report variability. An unavailable usage field stays unavailable; bytes are not a tokenizer estimate.

Prepared prompt set; use fictional fixture scope and replayed responses in a host harness, never a production appliance. Keep held-out prompts out of description tuning.

| Set | Scenario prompt | Required evidence or behavior |
| --- | --- | --- |
| Tuning | Can 10.0.0.42 reach 203.0.113.50 on TCP 443? | Ownership/path, scoped policy/action, configured versus live evidence |
| Tuning | Why is that same flow denied? | First configured verdict; distinguish observed denial from predicted denial |
| Tuning | The source port is unknown. Can this restricted service pass? | Keep source-port conditions tentative |
| Tuning | No rows were returned for this incident window. Did the traffic occur? | Scope/time, receipt/retention and absence limitations |
| Tuning | This task is still running with partial rows. Continue it. | Execute same-task/same-offset action; no missing-row conclusion |
| Held out | Trace 10.1.0.10 to 8.8.8.8 on TCP 443 across the branch and hub. | Every hop, path.end, unverified NAT and return path |
| Held out | The address overlaps root and blue VDOMs. Which policy applies? | Preserve both scopes and request distinguishing evidence |
| Held out | The hostname resolves to two destinations. Is the site allowed? | Separate DNS branches and policy outcomes |
| Held out | The upstream session translates the source. Check the downstream hop. | Use evidenced translated tuple; flag wrapper original-tuple limitation |
| Held out | Configured policy 7 permits, but live lookup selects policy 9. Explain. | Preserve disagreement and installed-package uncertainty |
| Held out | Inventory is loading, stale, or has a failed device read. What is known? | Distinguish ready/freshness/errors and retained data; use refresh criteria |
| Held out | Resume an expired task whose original query is unknown. | Recover scope; no invented bounds/filter or automatic new query |
| Held out | This full page exhausted a search submitted at offset 100. Continue. | Absolute next offset and original absolute bounds/filter/device |
| Held out | Recover the oversized log/investigation response. | Explicit truncation; smaller page at same unseen offset, compact/scoped follow-up |
| Held out | Investigate with include_logs but no analyzer configured. | Preserve usable configured evidence and explicit missing log stage |
| Held out | A page read failed with permission_denied. Continue. | Correct scope/permissions; retain task/completion, no automatic retry |

Copy this evaluation record for each future host run; leave unmeasured fields null:

```json
{
  "scenario": "held-out-overflow",
  "variant": "full-or-compact",
  "revision": "commit-and-working-tree-manifest",
  "host_version": null,
  "model_version": null,
  "exposed_tools": "all-29",
  "cache_state": "cold-or-warm",
  "repeat": 1,
  "tool_calls": [],
  "invalid_calls": null,
  "retries": null,
  "redundant_reads": null,
  "continuation_correct": null,
  "unsupported_claims": [],
  "required_facts_present": [],
  "evidence_gaps_reported": [],
  "response_bytes": null,
  "input_tokens": null,
  "cached_tokens": null,
  "output_tokens": null,
  "total_tokens": null,
  "end_to_end_ms": null,
  "notes": "Preparation only; no live result recorded."
}
```

Run experiments in this order when live evaluation is separately requested:

1. Baseline versus revised descriptions with all tools exposed. Preserve required inputs, ambiguity and scope in grading.
2. Full versus compact results, including any extra calls needed to recover omitted detail. Require the same diagnostic conclusions and uncertainty.
3. Eager versus host-supported deferred tool discovery. Record what catalog/instructions the host actually exposes; keep server tool names unchanged.
4. A focused typed tool with structured output, in each intended client. First establish whether text and structured copies both enter model context; the production contract remains text-only.
5. Programmatic filtering only if an existing host execution environment supports it. No new runtime is assumed.

Scheduling changes also require measured missed stages under the shared deadline before comparing reserved budgets or independent analyzer work. This implementation preserves investigation order, appliance lanes and cancellation. Lower caps/defaults, hidden tool families, annotation changes and global admission remain separate decisions.

## Implementation status

A–G are implemented with catalog/result measurement, corrected guidance, typed partial log recovery, explicit continuation, opt-in compact investigation, bounded overflow and compatible constraints. H evaluation preparation is complete; live host/model runs, token usage, discovery and structured-output experiments were intentionally excluded by the user. Server tests cannot establish those host outcomes.

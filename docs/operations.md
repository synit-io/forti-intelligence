# Operations, freshness, and diagnostics

Use this reference when an investigation returns stale, partial, denied, offline, or slow evidence. See [configuration](configuration.md) for setup and [individual tools](tools/README.md) for tool-specific behavior.

## Shared tool contract

Every tool input field carries a schema description, so an MCP client can see accepted values without consulting this file. Tool errors name the rejected input, list the accepted alternatives (profile names, configured ADOMs, permitted path prefixes) and end with an operator hint. Results are sent once as compact JSON text; raw appliance records are omitted unless `include_raw` is set. A result larger than `server.max_result_bytes` (default 512 KiB) is not sent; the tool returns an error that says how to narrow the request instead. Tools that act on one FortiGate take the ADOM from the inventory when only `device` is given.

## Inventory freshness and scope

Inventory and its ownership index are built only in the background: the first refresh starts at process start and later ones run every `server.refresh_interval`, each bounded by `server.refresh_timeout`. The MCP transport answers immediately, so stdio clients do not hit their startup timeout. Until the first snapshot is published, `resolve_ip_ownership` and `resolve_route` return `ready: false` with `refresh_in_progress: true`, and inventory-based lookups return a "still loading" error that says to retry shortly. The only other refresh trigger is an explicit `refresh_inventory` call; nothing refreshes because data looks old or a device is offline.

FortiAnalyzer profiles are used by the analyzer tools and are not treated as FortiManager inventory sources. Inventory refresh failures are written to stderr as structured `inventory refresh stage failed` records and remain available in `inventory_status`; direct MCP tool failures are written as `MCP tool failed` records without logging request credentials or arguments.

Interfaces use the device's `global/system/interface` resource; zones use `vdom/<vdom>/system/zone` for each discovered interface VDOM. Routing uses the same device database: `vdom/<vdom>/router/static` and `router/policy` (plus `static6`/`policy6` for VDOMs with IPv6 addresses) and `vdom/<vdom>/system/sdwan` with members, zones and rules. No proxy call to the FortiGate is needed. Route reads share the interface batching, retries and permission hints; each table keeps its last-known-good data independently, and failures appear as `list_routes` errors. Missing policy-route or SD-WAN tables mean "not configured".

Every JSON-RPC read retries transient failures (timeouts, connection errors, HTTP 5xx/429) up to three times with 300ms/600ms backoff inside the caller's deadline. Task-creating calls such as a FortiAnalyzer search submission retry only when no response arrived at all, so an appliance never receives duplicate tasks. A `refresh_inventory` request that arrives while a refresh is already running returns that refresh's snapshot instead of repeating the appliance reads.

`server.refresh_interval` controls how often the background refresh runs; it defaults to one hour. `server.refresh_timeout` gives that fan-out its own deadline, separate from the shorter per-request `request_timeout`.

Every FortiManager and FortiAnalyzer profile has exactly one in-flight JSON-RPC request at a time, shared by inventory refreshes, tool calls and web filter lookups. Waiting tool requests are served before waiting inventory-refresh requests, so a running refresh does not delay answers. Each tool call logs `MCP tool completed` with its duration, the appliance requests it made (`fortinet_requests`), lane wait, wire time, retries and the slowest resource. The reason for the single lane: FortiManager answers overlapping requests of one API key or session with spurious `code -11: No permission for the resource` results for random ADOMs. `max_concurrent_calls` still bounds work across profiles.

ADOMs of one profile are refreshed one after another, never interleaved: FortiManager evaluates ADOM-less device database paths (`/pm/config/device/<dev>/…`) in the ADOM of the preceding request, so interleaving made reads of healthy devices fail at random.

When a device database read is still denied, the client pauses, sends one read scoped to the device's ADOM (`/dvmdb/adom/<adom>/device`), and re-reads the denied items (in one request when several were denied, falling back to single reads), holding the lane from the pause through the re-read so no other request can slip in between; only a denial that survives this is reported.

Other reads denied with `-11` are re-checked once after 500ms; a denial that disappears on the re-check is counted under `transient_permission_denials` in `/healthz` and means another client uses the same credential, so give each server process its own API account.

FortiGates are queried in batches of eight interface/zone/route reads; if a FortiManager rejects a multi-device PM/config batch, the client verifies those reads individually. Transient failures get up to three total attempts with 300ms/600ms backoff inside the client; the inventory does not add a second retry loop around it.

ADOMs are refreshed oldest data first, so an ADOM a timed-out refresh did not reach is read first next time, and the refresh error names the skipped ADOMs. Discovered ADOMs restricted to other Fortinet products (FortiMail, FortiWeb, ...) are skipped.

An offline FortiGate (FortiManager reports `conn_status` down) is not a refresh failure: FortiManager serves its device database regardless of connectivity, so its interfaces and routing are read like any other device. It is listed under `unavailable_devices` with the reason, `data_source` (`fortimanager_database`, `retained` or `none`), `data_as_of` and any read error, and it never marks the profile stale.

A profile is `stale` only when an ADOM-level FortiManager read failed (ADOM list, device list, device groups, policy packages). A failed interface, zone or routing read of one device is device-level: that device keeps its last-known-good data, names the failed stages in `data_error`, and is counted in the profile's `device_read_errors`, while the error stays listed. Every device carries `data_as_of`.

Policy lookups still evaluate offline devices against their FortiManager configuration and skip only the live FortiOS lookup through them. `inventory_status` exposes each failure's stage, kind, FortiManager code/HTTP status, resource URL, retry attempts, retryability, and operator hint. `refresh_inventory` triggers an immediate refresh on client request.

Interface and zone read envelopes contain at most eight requests, including multi-VDOM devices. Batch results are matched by resource URL when supplied; missing results remain errors rather than being assigned to another device. Ambiguous responses are rejected. Expired sessions in read-batch items permit one session renewal; ordinary permission denials do not.

## Requests, caching, and diagnosis

All requests of one FortiManager or FortiAnalyzer account go through one serial request lane: an API key always shares one appliance session, and overlapping requests caused spurious `-11` denials and mixed ADOM contexts. Tool calls are served before background inventory work, and every background request is bounded to 20 s on the wire, so a tool never waits long behind a refresh. Speed therefore comes from fewer and lighter requests:

- Reads that share a URL prefix are multiplexed into one JSON-RPC request (at most eight items): the object tables of a policy lookup (addresses and services), the web filter objects of an ADOM, the policy tables of one package, device group members, interface, zone and route reads. A multiplexed request that times out or answers unusably is split into single reads.
- Caches: policy tables for 5 minutes while the package `oid` is unchanged (objects stay on the 5-minute TTL; both are shared by `lookup_firewall_policy`, `list_firewall_policies`, `resolve_route` and `check_web_filter`, and concurrent calls share one read), web filter configuration and package status for 5 minutes, FortiGate category lists for an hour, URL ratings for 15 minutes, FortiAnalyzer status, device lists, log fields and logstats for 5 minutes, FortiManager status and the ADOM list for 5 minutes, and stable monitor reads (routing, HA, VPN, BGP, OSPF, SD-WAN SLA, license) for 30 seconds. The session table and a partial log page are not cached. An identical log search within 3 minutes reuses its task. Tables that do not exist in an ADOM's schema (for example the legacy IPv6 policy table on FortiOS 6.4+) are cached as empty. `refresh_inventory` drops the FortiManager caches and separates subsequent reads from pre-refresh in-flight work. Existing callers may finish their original reads; those results cannot repopulate cleared caches. FortiAnalyzer reads keep their TTL.
- Live policy-lookup tuples are cached for 30 seconds, with at most 1,024 entries. New inserts prune expired tuples and evict the oldest remaining entry when full.
- Retries are bounded: reads retry transient failures with backoff; a proxied FortiGate read is repeated only when no answer arrived; the FortiAnalyzer search task is re-submitted only when the request provably never left the server. A denied read is re-checked once after 0.5 s with the lane held, so no other request can cause a second spurious denial.

Every tool call logs `MCP tool completed` with its duration, the appliance requests it made, the time spent waiting for the lane and on the wire, retries and the slowest resource. Requests slower than 5 s are logged as `slow Fortinet request`, and web filter loads and inventory refreshes log their own request counts, so a slow call can be traced to its cause. A call that times out while waiting for the lane says so in its hint instead of blaming appliance reachability.

## Interpret evidence

Keep inventory, FortiManager configuration, current FortiGate lookup, and observed analyzer logs separate. Inspect per-source errors, coverage, timestamps, and scope even when the tool call succeeds. A configured permit does not prove delivery, and missing rows do not prove absence. [SYSTEM.md](../SYSTEM.md) defines the investigation and reporting process.

[Project overview](../README.md) · [Tool reference](tools/README.md) · [Investigation flow guide](use-cases.md)

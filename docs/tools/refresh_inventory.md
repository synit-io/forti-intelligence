# `refresh_inventory`

Request current inventory after a known FortiManager change or when the user explicitly needs newer data.

**Evidence and freshness:** Read-only refresh of all configured FortiManager profiles; returns an inventory summary.

## Inputs

No inputs. Pass an empty object.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{}
```

## Behavior and limits

The background refresh already starts at process startup and runs every `server.refresh_interval` (default one hour). Do not refresh only because a device is offline, inventory is loading, or a timestamp looks old within that interval.

The refresh clears FortiManager object, policy, monitor, live policy-lookup, web-filter, and URL-rating caches. Existing callers may finish their original reads, but cannot repopulate cleared caches. FortiAnalyzer reads retain their TTL.

An in-progress refresh is shared rather than repeated. The work continues when the caller stops waiting, bounded by `server.refresh_timeout`; check `inventory_status` when the returned summary has `refresh_in_progress`.

## Related tools

[`inventory_status`](inventory_status.md), [`get_fortigate_interfaces`](get_fortigate_interfaces.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

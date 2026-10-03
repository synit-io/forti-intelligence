# `rate_url`

Get the FortiGuard category of a concrete URL once, then reuse it for every filtering FortiGate on the path.

**Evidence and freshness:** FortiGuard rating through a managed FortiGate and FortiManager proxy; URL ratings are cached for 15 minutes and category lists for one hour.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `url` | string | Yes | Web address to rate, for example https://www.example.com/path or example.com. Host and path are rated; the site is never fetched. |
| `profile` | string | No | FortiManager profile name. The default FortiManager profile is used when omitted. |
| `adom` | string | No | ADOM of the device; resolved from inventory when omitted. |
| `device` | string | No | FortiGate that filters the user's web traffic (trace the client with resolve_ip_ownership and resolve_route). Used when the server has no dedicated rating FortiGate configured, or as fallback. Without device and without a configured rating FortiGate no rating is made. |
| `vdom` | string | No | VDOM for the rating lookup; root when omitted. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root",
  "url": "https://www.example.com/path"
}
```

## Behavior and limits

`rate_url` takes `url` and optional `profile`, `adom`, `device`, `vdom`. A URL rated in the last 15 minutes is answered from cache (`rating.cached`, `rating.rated_at`) without a FortiGate request. It rates the host and path (scheme and trailing slash dropped) through the FortiManager proxy (`/sys/proxy/json`) on one managed FortiGate: the dedicated rating FortiGate `rating.device` when configured, otherwise the `device` given. The agent chooses that device by tracing the user's traffic ([SYSTEM.md](../../SYSTEM.md)); the server never picks an arbitrary FortiGate. If the configured device is offline or fails, the given device is tried. The result lists the categories (id, name, group), `rating.selection` and `rating.account` (which device and account answered), one short reason per failed device in `rating.attempt_errors`, and a `next_step` naming the `check_web_filter` call. It usually needs one proxy request plus the category list, which is cached for an hour.

FortiOS 7.4 serves the rating only as `POST …/utm/rating-lookup/select` (GET returns HTTP 405), and FortiManager forwards a proxied POST only for an account with JSON API Read-Write. Two ways to allow it:

- **Reuse the profile account:** give the FortiManager profile's API administrator JSON API Read-Write.
- **Dedicated rating account** (recommended): set `rating.api_key` (or `rating.username`/`rating.password`) for a separate FortiManager API administrator with JSON API Read-Write, an otherwise read-only admin profile, the ADOM of the rating device, and trusted hosts limited to this server. It uses the connection settings of `rating.fortimanager_profile` (default FortiManager profile), is not inventoried, and is used for every rating on that profile.

Either way, the server enforces its own limits before any request leaves the process. A central request allowlist permits FortiManager `get` reads and limits `exec` to login, logout, and the device proxy. Through the proxy it permits GET reads of `/api/v2/monitor/*` and `/api/v2/cmdb/*`, and POST only to `/api/v2/monitor/utm/rating-lookup/select`, carrying exactly one URL and an optional language. Sensitive administrator and credential resources are checked on their decoded URL path. Nested escapes and traversal are rejected before forwarding. The dedicated rating account may only log in, log out, send that rating lookup, and read the FortiGuard category list. FortiAnalyzer is limited to `get` and the Log View search `add`. The rating POST goes first; the GET forms are only a fallback for older releases. Without Read-Write the server reports the permission boundary once and pauses proxy rating for 15 minutes, then asks again. When the FortiGate answers without a category the server recognises, `rate_url` quotes that answer in `error`, so the category can still be read and passed to `check_web_filter`. Categories FortiOS returns by name (including "Unrated", category 0, and categories newer than the built-in table) are resolved through the FortiGate's own category list. The rating is bounded: FortiManager is asked to wait at most 20s for the FortiGate (`timeout` in the proxy request), each FortiGate gets 25s, and a timed-out proxy request is not repeated; a FortiGate that cannot reach FortiGuard yields "no answer within 25s" instead of a timed-out call.

The URL host and path are rated; the server does not fetch the website. The category alone does not decide access: pass both the category and URL to `check_web_filter` at each relevant hop.

## Related tools

[`resolve_route`](resolve_route.md), [`check_web_filter`](check_web_filter.md), [`get_ssl_ssh_profile`](get_ssl_ssh_profile.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

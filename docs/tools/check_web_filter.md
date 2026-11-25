# `check_web_filter`

Explain which configured web-filter profiles allow, block, exempt, or conditionally handle a category and URL, and where they are applied.

**Evidence and freshness:** FortiManager web-filter, object, policy, and stored package-status configuration; shared configuration caches have a five-minute TTL.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `category` | string | No | FortiGuard category id or name from rate_url, for example 52 or Information Technology; several as a comma-separated list. Optional when url is given, then category actions are reported as unknown. |
| `url` | string | No | The URL itself. Enables static URL filter entries and FortiGuard local rating overrides, which match the URL rather than its category. Pass it whenever the question is about a concrete site. |
| `profile` | string | No | FortiManager profile name. The default FortiManager profile is used when omitted. |
| `adom` | string | No | Limit evaluation to one ADOM. All inventoried ADOMs of the profile are evaluated when omitted and no device is given. |
| `device` | string | No | FortiGate that filters the user's web traffic. Only the policy packages assigned to it are read, and results are limited to profiles applied on it. |
| `vdom` | string | No | Limit results to this VDOM of the device. |
| `policy_id` | integer | No | Firewall policy that carries the user's traffic on device (for example from lookup_firewall_policy): only the web filter profile it applies is evaluated. Requires device. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root",
  "category": "52",
  "url": "https://www.example.com/path",
  "policy_id": 44
}
```

## Behavior and limits

`check_web_filter` takes `category` (id or name from `rate_url`, several comma-separated) and/or `url`, plus optional `profile`, `adom`, `device`, `vdom` and `policy_id` (with `device`: evaluate only the profile that policy applies). It reads only FortiManager configuration:

1. Per ADOM, cached for five minutes: web filter profiles, URL filter tables, FortiGuard local ratings, local categories, security profile groups and FortiManager's category list in one multiplexed request, plus the package list. Profiles, profile groups and URL filter tables that policies refer to but the ADOM lacks are read once, in one request, from the global ADOM.
2. The policies of the packages in scope, one request per package for the firewall (`policy`, which holds IPv4 and IPv6 policies since FortiOS 6.4, and the legacy `policy6`), NGFW security (`security-policy`) and explicit proxy (`proxy-policy`) tables. With `device`, only the packages assigned to that FortiGate are read; missing optional tables are cached as empty. The reads run one after another, so other tool calls are not queued behind the whole load.
3. Each profile is evaluated. With `url`, static URL filter entries come first, in ID order:
   - `block` ends evaluation;
   - `exempt` ends it only when its exempt list is empty or includes `fortiguard` or `all`;
   - `allow` and `monitor` continue to category filtering;
   - referrer conditions and uncompilable regexes are reported as unresolved.

   A matching FortiGuard local rating override then replaces the category. Then the category action applies: for each category, the first filter entry that names it directly or through its category group (`g01`, `g02`, `g04`-`g07`, `g21`, `g22`) decides. A missing entry is an allow, and `ftgd-disable` turns category filtering off. Without `url`, the URL-specific steps are skipped and a warning says so; without `category`, category actions are reported as unknown.
4. Each profile is mapped to the enabled policies that reference it directly or through a profile group, with the device VDOMs from package scope or the policy's install-on list, FortiManager's stored package status (`_package/status`), and the device config and connection status.

The check answers within `server.request_timeout` (default 30s). Reads run as a background load job that concurrent checks share and that keeps filling the caches, bounded by `refresh_timeout`, after the answer is sent. If the budget ends first, the result has `complete: false`: profile decisions are returned as soon as the objects are read, and policies and devices follow on the next call, served from the cache. With `device`, profiles without a policy on that FortiGate are listed under `not_on_device`; `unused_profiles` is only reported for checks without a device, which read every package. The summary lists which profiles block, allow, are conditional, or unknown. `refresh_inventory` drops the cached configuration. The result is configuration evidence; deep-inspection requirements for HTTPS paths, quotas, overrides and schedules are stated as limitations, not verified.

Provide at least `category` or `url`. `policy_id` requires `device`; copy the carrying policy from that hop rather than checking an unrelated rule. See the [website flow guide](../use-cases.md#example-2-explain-a-website-block).

## Related tools

[`rate_url`](rate_url.md), [`lookup_firewall_policy`](lookup_firewall_policy.md), [`get_ssl_ssh_profile`](get_ssl_ssh_profile.md), [`get_package_install_status`](get_package_install_status.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

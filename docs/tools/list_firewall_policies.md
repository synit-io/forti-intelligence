# `list_firewall_policies`

Review the policy rows behind a decision, including rule order, addresses, services, and inspection references.

**Evidence and freshness:** FortiManager policy packages; shares the policy cache with `lookup_firewall_policy`.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name from the server configuration. The default profile is used when omitted. |
| `adom` | string | No | ADOM containing the policy package; taken from the inventory when device is given |
| `package` | string | No | Policy package name or nested path such as folder/package; all packages of the ADOM (or of the device) when omitted |
| `device` | string | No | Limit to packages assigned to this managed FortiGate |
| `ip_version` | string | No | ipv4 (default) or ipv6; FortiOS 6.4+ keeps both in one policy table and each policy is listed for the families it has addresses for |
| `policy_id` | integer | No | Return only this policy ID (for example one reported by lookup_firewall_policy) |
| `limit` | integer | No | Maximum policies to return across packages, default 100, at most 1000 |
| `offset` | integer | No | Number of matching policies to skip, for paging |
| `include_raw` | boolean | No | Include the raw appliance records (large). Parsed fields already carry the evidence; leave false unless a field is missing. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "policy_id": 44,
  "limit": 25
}
```

## Behavior and limits

Select an ADOM explicitly, or supply `device` so inventory resolves it. An omitted package reads the ADOM's packages, or the packages assigned to the selected device. Nested paths such as `folder/package` are preserved.

Rows retain profile, ADOM, package, policy provenance, interfaces, IPv4 and IPv6 addresses, internet services, users/groups, services, schedule, UTM status, security-profile references, and install-on scope. `policy_id` narrows to a rule but is not globally unique.

`ip_version` defaults to `ipv4`. FortiOS 6.4+ stores IPv4 and IPv6 policies in `firewall/policy` with separate address columns; IPv6 reads also check legacy `policy6`, whose absence is cached. `policy64` contains NAT64 policies and is not read as the IPv6 policy table.

`limit` defaults to 100 and is capped at 1,000; `offset` skips matching rows across the selected packages. Check `total` and `truncated`, then page as needed. A row or assigned package alone does not establish the first effective match or installed state.

## Related tools

[`lookup_firewall_policy`](lookup_firewall_policy.md), [`list_policy_objects`](list_policy_objects.md), [`get_ssl_ssh_profile`](get_ssl_ssh_profile.md), [`get_package_install_status`](get_package_install_status.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

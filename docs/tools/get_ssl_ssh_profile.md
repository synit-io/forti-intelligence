# `get_ssl_ssh_profile`

Inspect the SSL/SSH profile referenced by the policy carrying a website or encrypted flow.

**Evidence and freshness:** FortiManager ADOM `firewall/ssl-ssh-profile` object; uses the object cache.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile. The default profile is used when omitted. |
| `adom` | string | No | ADOM that stores the profile; taken from the inventory when device is set |
| `device` | string | No | FortiGate name, used only to find the ADOM when adom is omitted |
| `name` | string | Yes | ssl-ssh-profile name, as shown on the firewall policy |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "name": "deep-inspection"
}
```

## Behavior and limits

Returns inspection mode, HTTPS, SSH and SMTPS sections, untrusted-certificate action, and the profile object. Supply the exact `name` from the carrying policy, and the ADOM or a device that identifies it.

The policy's `inspection-mode` is distinct from this profile's protocol-specific certificate inspection or deep inspection. Inspect the relevant protocol section before explaining whether HTTPS paths are visible to filtering.

Configuration does not establish that a client trusts the inspection certificate, that the package is installed, or that the observed TLS exchange succeeded. Correlate the policy, installation state, and incident logs when those facts matter.

## Related tools

[`list_firewall_policies`](list_firewall_policies.md), [`check_web_filter`](check_web_filter.md), [`get_package_install_status`](get_package_install_status.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

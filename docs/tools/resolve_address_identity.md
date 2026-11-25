# `resolve_address_identity`

Find the DHCP, ARP, FSSO, or authenticated firewall-user records that mention an address now.

**Evidence and freshness:** Live FortiGate monitor reads through FortiManager; not cached.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name. The default profile is used when omitted. |
| `adom` | string | No | ADOM that manages the FortiGate; taken from the inventory when omitted |
| `device` | string | Yes | Managed FortiGate name as shown in inventory_status |
| `vdom` | string | No | VDOM; root when omitted |
| `ip` | string | Yes | IPv4 or IPv6 address to look up in DHCP leases, ARP, FSSO and firewall user tables |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root",
  "ip": "10.1.0.10"
}
```

## Behavior and limits

The tool reads the DHCP lease table, ARP table, FSSO table, and firewall-user table of one scoped device/VDOM, and returns address matches grouped by source.

Each failed source is listed under `errors`; other sources still return. Review failures alongside an empty `matches` entry.

This is current identity evidence, not connected-subnet ownership or a historical assignment. Empty records do not prove the address was never used. Start with `resolve_ip_ownership` when the relevant device is unknown.

## Related tools

[`resolve_ip_ownership`](resolve_ip_ownership.md), [`get_firewall_sessions`](get_firewall_sessions.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

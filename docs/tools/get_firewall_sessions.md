# `get_firewall_sessions`

Check a short slice of current firewall sessions for a flow, policy ID, or observed source translation.

**Evidence and freshness:** Live FortiGate session monitor through FortiManager; not cached.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name. The default profile is used when omitted. |
| `adom` | string | No | ADOM that manages the FortiGate; taken from the inventory when omitted |
| `device` | string | Yes | Managed FortiGate name as shown in inventory_status |
| `vdom` | string | No | VDOM; root when omitted |
| `source_ip` | string | No | Keep sessions whose source address is this IP |
| `destination_ip` | string | No | Keep sessions whose destination address is this IP |
| `source_port` | integer | No | Keep sessions whose source port is this value |
| `destination_port` | integer | No | Keep sessions whose destination port is this value |
| `protocol` | string | No | tcp, udp, icmp, or an IP protocol number |
| `policy_id` | integer | No | Keep sessions matched by this firewall policy id |
| `count` | integer | No | How many sessions to ask the FortiGate for before local filtering. Default 50, at most 200. The session table is not cached. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root",
  "source_ip": "10.1.0.10",
  "destination_ip": "10.30.0.20",
  "destination_port": 443,
  "protocol": "tcp",
  "count": 200
}
```

## Behavior and limits

The FortiGate is asked for `count` rows (default 50, at most 200). The request sends applicable filters using the `/firewall/session` monitor's `source`, `destination`, `sourceport`, `destport`, `policyid`, and supported protocol names (`tcp`, `udp`, `icmp`, `igmp`). An IPv6 address or ICMPv6 selects an IPv6 sample. All requested fields are checked locally. Other protocol numbers are checked only locally. Firmware support for the endpoint and request parameters varies. [Fortinet monitor reference](https://ansible-galaxy-fortios-docs.readthedocs.io/en/latest/fortios_monitor_fact.html)

`requested` is the row budget, `received` is the number of rows the monitor sent, `inspected` is the number checked locally within that budget, and `returned` is the count that matched. `unreadable_rows` counts malformed or out-of-VDOM rows encountered. `appliance_filter_status` is `unverified` when the inspected rows cannot establish appliance filtering, `not_fully_applied` when a returned field conflicts with a sent filter, `rejected` when the appliance declined the filtered request and the tool retrieved a sample without filters, or `not_requested` when no filter was sent. `sampled` stays true even when `limit_reached` is false. Fortinet documents that its session monitors can omit sessions visible elsewhere. [Fortinet session monitor coverage](https://community.fortinet.com/fortinac-f-57/troubleshooting-tip-fortinac-ui-missing-firewall-sessions-from-fortigate-203089)

Rows preserve source/destination addresses and ports, protocol, policy ID, source NAT (SNAT), duration, and bytes when available. Use a returned session to establish the tuple seen on that device at the read time.

A short or empty sample leaves other sessions unverified. A matching row may be beyond the requested budget, or the incident session may already have ended. Raise `count` within its cap or inspect incident logs. A returned row may show source translation and some traffic counters.

## Related tools

[`get_nat_for_flow`](get_nat_for_flow.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md), [`lookup_firewall_policy`](lookup_firewall_policy.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

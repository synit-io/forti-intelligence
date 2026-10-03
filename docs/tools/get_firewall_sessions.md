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

The FortiGate is asked for `count` rows (default 50, at most 200); filters are then applied locally because FortiOS may ignore session filters. `filtered_locally` is true, and `requested` and `returned` describe this slice.

Rows preserve source/destination addresses and ports, protocol, policy ID, source NAT (SNAT), duration, and bytes when available. Use a returned session to establish the tuple seen on that device at the read time.

An empty slice does not prove no session exists: a matching row may be beyond the first requested rows, or the incident session may already have ended. Raise `count` within its cap, scope by `policy_id`, or inspect incident logs. Do not infer every NAT transformation or a completed application exchange from one short session row.

## Related tools

[`get_nat_for_flow`](get_nat_for_flow.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md), [`lookup_firewall_policy`](lookup_firewall_policy.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

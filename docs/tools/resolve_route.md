# `resolve_route`

Explain the configured forwarding decision for a destination and follow the path across inventoried FortiGates.

**Evidence and freshness:** FortiManager device-database configuration from the inventory snapshot; hostname resolution uses the MCP host DNS resolver.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `ip` | string | Yes | Destination IPv4 or IPv6 address, or a hostname resolved with the MCP host's DNS (up to 4 addresses of the source's family are evaluated), for example 8.8.8.8 or www.example.com |
| `source_ip` | string | No | Source address of the flow; needed to evaluate policy routes and SD-WAN rules with source conditions |
| `source_interface` | string | No | Ingress interface or zone; derived from source_ip ownership when omitted |
| `protocol` | string | No | tcp, udp, sctp, icmp or an IP protocol number; rules with a protocol condition stay tentative when omitted |
| `destination_port` | integer | No | Destination port for rules with a port range |
| `source_port` | integer | No | Source port for policy-route source-port conditions; matching restricted rules remain tentative when omitted |
| `profile` | string | No | Limit to one FortiManager profile name |
| `adom` | string | No | Limit to one ADOM name |
| `device` | string | No | Limit to one managed FortiGate name; use the source-side FortiGate from resolve_ip_ownership |
| `vdom` | string | No | Limit to one VDOM name |
| `follow` | boolean | No | Walk the configured path through inventoried FortiGates. Read path.end before interpreting the last managed device; identify filtering from policies at each hop. Needs an unambiguous device/VDOM or source_ip. |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "adom": "example-network",
  "device": "Branch-FW",
  "vdom": "root",
  "ip": "10.30.0.20",
  "source_ip": "10.1.0.10",
  "destination_port": 443,
  "protocol": "tcp",
  "follow": true
}
```

## Behavior and limits

`resolve_route` applies FortiOS precedence to each device VDOM in scope: policy routes in sequence order, then SD-WAN rules when the destination is routed over SD-WAN, then connected/static routes by longest prefix, lowest distance and lowest priority. Only routes equal on all three criteria form an equal-cost tier. Administratively down interfaces are excluded, with a warning. Pass `source_ip`, `source_interface`, `protocol`, `destination_port` and `source_port` when known; missing rule conditions make the decision tentative. Hostnames are resolved with the host's DNS, and up to four same-family addresses have separate results under `other_addresses`.

Each decision lists `next_hops`: inventoried FortiGate interfaces whose own address exactly matches a gateway. With `follow: true`, supply a unique starting device scope or source-side ingress. Duplicate device names require `profile`/`adom`; overlapping VDOMs require `vdom` or an unambiguous ingress selector. The ordered `path.hops` preserve scope, interfaces, gateways, confidence and explanatory `notes`. The walk stops at ambiguity or a tentative decision before claiming a terminal outcome. `path.end` can be `not_resolved`, `leaves_managed_network`, `destination_connected`, `no_route`, `blackhole`, `ambiguous_next_hop`, `tentative_decision`, `loop` or `max_hops`.

Read `path.end` before interpreting `last_managed_device`. An unowned gateway marks the boundary of visible inventory; it does not establish the internet edge or successful delivery. Check carrying policy and web filtering at every relevant hop. Dynamic routes, live SD-WAN health, NAT translations and return routing need separate evidence.

The followed trace is bounded to eight managed hops. It does not evaluate per-hop policy, security inspection, NAT, or the return path. See the [traffic flow guide](../use-cases.md#example-1-find-a-block-across-two-firewalls) for the reads that complete an investigation.

## Related tools

[`lookup_firewall_policy`](lookup_firewall_policy.md), [`get_routing_neighbors`](get_routing_neighbors.md), [`get_fortigate_settings`](get_fortigate_settings.md), [`investigate_traffic`](investigate_traffic.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

# `lookup_firewall_policy`

Find the configured first-match policy for a flow and compare it with bounded live FortiGate lookups.

**Evidence and freshness:** FortiManager policy/object configuration plus live policy lookup through the FortiManager proxy; live tuples are cached for 30 seconds.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name; all inventoried FortiManager profiles are searched when omitted |
| `adom` | string | No | Limit candidates to one ADOM |
| `device` | string | No | Limit candidates to one managed FortiGate name |
| `vdom` | string | No | Limit candidates to one VDOM; overlapping VDOMs remain separate when omitted |
| `source_ip` | string | Yes | Source IPv4 or IPv6 address of the flow |
| `destination_ip` | string | Yes | Destination IP address or FQDN; FQDNs use the MCP host's DNS. Up to 16 addresses matching the source IP family are evaluated. |
| `source_port` | integer | No | Source port for configured service constraints and live lookup. Constrained services remain tentative when omitted. Omit for ICMP and ICMPv6. |
| `destination_port` | integer | Conditional | Destination port, 1-65535. Omit for ICMP and ICMPv6. |
| `protocol` | string | No | tcp, udp, sctp, icmp, icmpv6, any, or an IP protocol number 1-255. Omitted or any evaluates TCP and UDP separately. |
| `icmp_type` | integer | No | ICMP or ICMPv6 message type, 0–255, when known. |
| `icmp_code` | integer | No | ICMP or ICMPv6 message code, 0–255, when known. |
| `source_interface` | string | No | Ingress interface or zone name when inventory cannot infer it, for example for routed sources |

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
  "protocol": "tcp"
}
```

## Behavior and limits

The lookup first uses refreshed managed-FortiGate interface addresses, canonical networks/subnets, and device-zone membership to identify candidate FortiGates, source/destination interfaces or zones, ADOMs, and policy-package targets, including direct and nested FortiManager device-group membership. `destination_ip` may be a literal address or an FQDN. FQDNs are resolved with the host system's DNS resolver, CNAME targets are recorded when available, duplicate A/AAAA results are removed, and each selected address is evaluated independently. A DNS failure is returned as a lookup error.

For example, this request automatically selects the inventoried FortiGate and ADOM whose interface contains `10.0.0.1` (such as `10.0.0.0/24`) and derives the source interface:

```json
{
  "source_ip": "10.0.0.1",
  "destination_ip": "8.8.8.8",
  "destination_port": 53,
  "protocol": "udp"
}
```

For an off-subnet destination such as `8.8.8.8`, the egress interface and zone come from configured routing in the source VDOM (see [configured routing](resolve_route.md)). Connected and routed destinations are evaluated separately, so one DNS address cannot borrow another address's egress. Candidate `routing` lists those decisions and their limitations. Overlapping VDOMs retain separate candidates and verdicts; pass `vdom` to narrow them. A proven `source_interface` also supports a routed source outside the ingress subnet. `resolve_route` exposes the same forwarding evidence without policy lookup.

```json
{
  "profile": "fmg-prod",
  "adom": "customer-a",
  "device": "branch-1",
  "source_ip": "10.0.0.1",
  "destination_ip": "dns.example.com",
  "destination_port": 53
}
```

The live FortiOS lookup always sends the ingress interface as `srcintf`, never a zone: FortiOS rejects a zone name with HTTP 400, which FortiManager relays as `code -6: Invalid url`. An explicit physical ingress interface can also be used for a routed source outside its subnet. Zones are used only for static policy matching, and each live result reports the interface and its `source_zone`. An explicit `source_interface` that names a zone is resolved to the member interface holding the source address. The lookup selects the IPv4 or IPv6 policy package automatically, resolves static address groups, VIPs, and service objects, and returns uncertainty warnings for dynamic/FQDN/interface-derived objects. If neither IP matches a known interface subnet, it transparently falls back to all inventoried devices and marks that resolution explicitly.

The FortiManager packages are evaluated first, in FortiOS order. `decisions` states the configured verdict per profile, ADOM, device, VDOM, package, destination and protocol. Each verdict gives the first matching policy and its action and confidence, `implicit_deny` when no policy matches and every read succeeded, or `unknown` when a read failed. `matches` lists all matching policies in evaluation order with `position` and `first_match` for each protocol. Addresses are evaluated for the flow's IP family only (FortiOS 6.4+ keeps IPv4 and IPv6 addresses of one policy in separate columns; IPv6 flows also read the legacy `policy6` table of older ADOMs), a VIP policy is matched against the interface toward its mapped address, excluded address-group members do not match, a policy installed on other devices only (install-on) is skipped, and the ADOM's service objects take precedence over built-in definitions. Custom TCP, UDP and SCTP services honor paired destination:source ranges such as `443:1024-65535`, including groups and negation. If a constrained source port is omitted, that match remains tentative. Conditions that FortiManager data cannot decide (internet services, users and groups, per-device object mappings, schedules) make a match tentative. `complete: false` means a policy, package or object read failed, so a missing match proves nothing.

For ICMP, omit both ports and provide the message type and code when known, including a code of zero. An omitted type or code leaves services that restrict that value tentative. The name `icmp` follows the IP family of the flow. Explicit protocol numbers `1` and `58` select IPv4 ICMP and ICMPv6 respectively. The live request sends the specified ICMP type and code without ports. [Fortinet custom service reference](https://docs.fortinet.com/document/fortigate/7.6.3/cli-reference/198499981/config-firewall-service-custom) · [Fortinet policy lookup parameters](https://ansible-galaxy-fortios-docs.readthedocs.io/en/latest/fortios_monitor_fact.html#parameters)

Live FortiOS policy lookups run afterwards, at most four per call, each bounded to 10 seconds. Timed-out and skipped attempts are reported. Each answer compares its `policy_id` with the configured verdict in the same profile, ADOM, device, VDOM, destination and protocol. `agreement` is `agrees` or `differs` when exactly one configured package verdict exists, `ambiguous_configured_verdict` when several packages remain, or `no_configured_verdict` when none exists. Ambiguous packages are retained for an installed-package check; the first package is never selected as a substitute. Differences warn that installed state may differ from FortiManager.

The result always includes provenance (`profile`, ADOM, device, VDOM, package, policy ID), inventory timestamp, live lookup results, static matches, evaluated counts, and warnings. Nested FortiManager policy-package paths are preserved. A DNS response is capped at 16 same-family addresses per lookup to bound fan-out; excluded or untested addresses are listed explicitly.

## Related tools

[`resolve_ip_ownership`](resolve_ip_ownership.md), [`resolve_route`](resolve_route.md), [`list_firewall_policies`](list_firewall_policies.md), [`get_package_install_status`](get_package_install_status.md), [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md).

[v2.0.0 tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

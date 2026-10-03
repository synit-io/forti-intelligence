# Tool reference

Forti Intelligence exposes 29 read-only MCP tools. Each page documents its inputs, example call, evidence source, freshness, and limits. The live tool descriptions and schemas remain authoritative for your running server.

Start with the [investigation flow guide](../use-cases.md) for task-oriented examples. See [configuration](../configuration.md) for appliance permissions and [operations](../operations.md) for shared caching, scope, and diagnostics.

## Traffic, ownership, and routing

| Tool | When to use it |
| --- | --- |
| [`investigate_traffic`](investigate_traffic.md) | Start a traffic investigation with ownership, an ordered configured path, and policy evidence for each traced hop and destination. |
| [`resolve_ip_ownership`](resolve_ip_ownership.md) | Find the FortiGate interfaces whose configured networks contain an IP address. Start here when the site, device, or VDOM is unknown. |
| [`resolve_route`](resolve_route.md) | Explain the configured forwarding decision for a destination and follow the path across inventoried FortiGates. |
| [`get_fortigate_interfaces`](get_fortigate_interfaces.md) | Inspect one FortiGate interface and zone inventory without dumping every managed device. |
| [`get_routing_neighbors`](get_routing_neighbors.md) | Check BGP, OSPF, and SD-WAN SLA state when operational routing can differ from the configured path. |
| [`get_nat_for_flow`](get_nat_for_flow.md) | Find configured central SNAT, IP pool, and VIP objects that mention a flow. |
| [`get_firewall_sessions`](get_firewall_sessions.md) | Check a short slice of current firewall sessions for a flow, policy ID, or observed source translation. |
| [`resolve_address_identity`](resolve_address_identity.md) | Find the DHCP, ARP, FSSO, or authenticated firewall-user records that mention an address now. |

## Policies, installation, and web inspection

| Tool | When to use it |
| --- | --- |
| [`lookup_firewall_policy`](lookup_firewall_policy.md) | Find the configured first-match policy for a flow and compare it with bounded live FortiGate lookups. |
| [`list_firewall_policies`](list_firewall_policies.md) | Review the policy rows behind a decision, including rule order, addresses, services, and inspection references. |
| [`list_policy_objects`](list_policy_objects.md) | Inspect address, service, VIP, IP pool, or other firewall objects referenced by a policy. |
| [`get_policy_usage`](get_policy_usage.md) | Check live policy hit counts and locate policy references to an address, service, or SSL/SSH profile name. |
| [`get_package_install_status`](get_package_install_status.md) | Check whether FortiManager reports a device policy package as installed, modified, or unknown. |
| [`get_package_history`](get_package_history.md) | Compare inventory package identity, stored installation state, device configuration state, and any readable revision information. |
| [`rate_url`](rate_url.md) | Get the FortiGuard category of a concrete URL once, then reuse it for every filtering FortiGate on the path. |
| [`check_web_filter`](check_web_filter.md) | Explain which configured web-filter profiles allow, block, exempt, or conditionally handle a category and URL, and where they are applied. |
| [`get_ssl_ssh_profile`](get_ssl_ssh_profile.md) | Inspect the SSL/SSH profile referenced by the policy carrying a website or encrypted flow. |

## Inventory and appliance state

| Tool | When to use it |
| --- | --- |
| [`inventory_status`](inventory_status.md) | Check what the server can see and whether an investigation is using current or retained inventory. |
| [`refresh_inventory`](refresh_inventory.md) | Request current inventory after a known FortiManager change or when the user explicitly needs newer data. |
| [`get_fortigate_settings`](get_fortigate_settings.md) | Read a supported FortiGate monitor or CMDB resource when focused tools leave a specific operational question unanswered. |
| [`get_fortimanager_status`](get_fortimanager_status.md) | Inspect FortiManager system status, tasks, device-management records, or package state through a supported read-only resource. |
| [`get_vpn_status`](get_vpn_status.md) | Check current IPsec tunnel and SSL-VPN login state on a FortiGate involved in the path. |
| [`get_ha_status`](get_ha_status.md) | Check HA role, peer information, and available configuration checksums for a FortiGate cluster. |

## FortiAnalyzer evidence

| Tool | When to use it |
| --- | --- |
| [`fortianalyzer_status`](fortianalyzer_status.md) | Check a configured FortiAnalyzer connection and its system status before investigating analyzer-specific failures. |
| [`map_analyzer_device`](map_analyzer_device.md) | Map an inventoried FortiGate to its analyzer identity before filtering logs. |
| [`search_fortianalyzer_logs`](search_fortianalyzer_logs.md) | Retrieve observed traffic, security, or event evidence in a bounded incident window. |
| [`count_fortianalyzer_logs`](count_fortianalyzer_logs.md) | Get a bounded match count before retrieving log rows, with optional deny, web-filter, or IPS focus. |
| [`get_log_receipt`](get_log_receipt.md) | Check whether FortiAnalyzer has recent log-receipt evidence for a device before interpreting an empty search. |
| [`get_fortianalyzer_data`](get_fortianalyzer_data.md) | Read analyzer device lists, filter fields, existing task state, reports, events, or incidents when a focused tool does not cover the required resource. |

[Project overview](../../README.md) · [Example assistant instructions](../../SYSTEM.md)

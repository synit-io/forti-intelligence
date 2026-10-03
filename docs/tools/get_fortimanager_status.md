# `get_fortimanager_status`

Inspect FortiManager system status, tasks, device-management records, or package state through a supported read-only resource.

**Evidence and freshness:** FortiManager JSON-RPC `get`; system status and the ADOM list are cached for five minutes.

## Inputs

| Input | Type | Required | Description |
| --- | --- | --- | --- |
| `profile` | string | No | FortiManager profile name from the server configuration. The default profile is used when omitted. |
| `resource` | string | Yes | FortiManager JSON-RPC path under /sys, /dvmdb, /pm, /task or /securityconsole, for example /sys/status, /dvmdb/adom/<adom>/device, /task/task/<id>, /pm/config/adom/<adom>/_package/status/<device>/<vdom> |
| `data` | object | No | Optional extra JSON-RPC parameters for the get request such as fields, filter, loadsub, option, range |

Required means required by the tool schema; conditional scope requirements are described below. Live MCP schemas are authoritative.

## Example

The identifiers and values below are fictional. Replace them with your verified scope.

```json
{
  "profile": "example-fmg",
  "resource": "/sys/status"
}
```

## Behavior and limits

Permitted resource prefixes are `/sys`, `/dvmdb`, `/pm`, `/task`, and `/securityconsole`; a leading slash is optional. ADOM-scoped paths obey the profile allowlist. Credential and administrator resources are blocked by the request controls.

Pass `data` for parameters such as `fields`, `filter`, `loadsub`, `option`, or `range` when supported by the target resource. This tool reads existing state; it does not run tasks or change configuration.

For device inventory, package policies, or individual objects, prefer the corresponding focused tools. Narrow large responses with resource paths or fields rather than requesting full trees.

## Related tools

[`inventory_status`](inventory_status.md), [`list_firewall_policies`](list_firewall_policies.md), [`list_policy_objects`](list_policy_objects.md), [`get_package_install_status`](get_package_install_status.md).

[Tool index](README.md) · [Shared operation and freshness rules](../operations.md) · [Investigation flow guide](../use-cases.md)

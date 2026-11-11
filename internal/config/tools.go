package config

import "fmt"

// ToolNames returns all configurable MCP tool names.
func ToolNames() []string {
	return []string{
		"check_web_filter",
		"count_fortianalyzer_logs",
		"fortianalyzer_status",
		"get_firewall_sessions",
		"get_fortianalyzer_data",
		"get_fortigate_interfaces",
		"get_fortigate_settings",
		"get_fortimanager_status",
		"get_ha_status",
		"get_log_receipt",
		"get_nat_for_flow",
		"get_package_history",
		"get_package_install_status",
		"get_policy_usage",
		"get_routing_neighbors",
		"get_ssl_ssh_profile",
		"get_vpn_status",
		"inventory_status",
		"investigate_traffic",
		"list_firewall_policies",
		"list_policy_objects",
		"lookup_firewall_policy",
		"map_analyzer_device",
		"rate_url",
		"refresh_inventory",
		"resolve_address_identity",
		"resolve_ip_ownership",
		"resolve_route",
		"search_fortianalyzer_logs",
	}
}

// ToolEnabled preserves the default catalog unless a tool is explicitly disabled.
func (c ServerConfig) ToolEnabled(name string) bool {
	enabled, configured := c.Tools[name]
	return !configured || enabled
}

// ValidateTools rejects misspelled overrides rather than silently enabling a tool.
func (c ServerConfig) ValidateTools() error {
	known := make(map[string]bool)
	for _, name := range ToolNames() {
		known[name] = true
	}
	for name := range c.Tools {
		if !known[name] {
			return fmt.Errorf("server.tools: unknown tool %q; see docs/tools/README.md for supported names", name)
		}
	}
	return nil
}

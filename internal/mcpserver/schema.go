package mcpserver

import "github.com/google/jsonschema-go/jsonschema"

// constrainToolSchema mirrors existing rejection domains only. Limits which
// default/clamp, case-insensitive selectors and numeric protocol aliases remain
// open so advertising constraints does not reject previously accepted calls.
func constrainToolSchema(tool string, schema *jsonschema.Schema) {
	bound := func(field string, low, high float64) {
		if p := schema.Properties[field]; p != nil {
			p.Minimum = &low
			p.Maximum = &high
		}
	}
	offset := func() {
		if p := schema.Properties["offset"]; p != nil {
			low := float64(0)
			p.Minimum = &low
		}
	}
	switch tool {
	case "lookup_firewall_policy":
		bound("source_port", 0, 65535)
		bound("destination_port", 1, 65535)
	case "investigate_traffic", "resolve_route":
		bound("source_port", 0, 65535)
		bound("destination_port", 0, 65535)
		if p := schema.Properties["detail"]; p != nil {
			p.Enum = []any{"", "full", "compact"}
		}
	case "search_fortianalyzer_logs", "list_firewall_policies", "list_policy_objects":
		offset()
	}
}

package mcpserver

import (
	"strings"
	"testing"
	"time"
)

func TestPrometheusRendersInventoryAndTools(t *testing.T) {
	server := &Server{}
	server.recordTool("resolve_route", "ok", time.Second, 10*time.Millisecond, 2)
	server.recordTool("resolve_route", "error", time.Second, 0, 1)
	body := server.Prometheus(map[string]any{
		"inventory_ready":               true,
		"refresh_in_progress":           false,
		"devices":                       3,
		"unavailable_devices":           1,
		"refresh_errors":                0,
		"inventory_age_seconds":         12,
		"last_refresh_duration_seconds": 1.5,
		"stale_profiles":                []string{"fmg"},
		"transient_permission_denials":  map[string]int64{"fmg": 2},
	})
	for _, want := range []string{
		"forti_intelligence_up 1",
		"forti_intelligence_inventory_ready 1",
		"forti_intelligence_devices 3",
		"forti_intelligence_unavailable_devices 1",
		"forti_intelligence_inventory_age_seconds 12",
		"forti_intelligence_last_refresh_duration_seconds 1.5",
		"forti_intelligence_stale_profiles 1",
		`forti_intelligence_transient_permission_denials{profile="fmg"} 2`,
		`forti_intelligence_tool_calls_total{tool="resolve_route",outcome="ok"} 1`,
		`forti_intelligence_tool_calls_total{tool="resolve_route",outcome="error"} 1`,
		`forti_intelligence_tool_fortinet_requests_total{tool="resolve_route"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s\n%s", want, body)
		}
	}
}

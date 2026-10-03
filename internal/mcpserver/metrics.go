package mcpserver

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Prometheus renders inventory gauges and per-tool counters in Prometheus
// text format. health is the map produced for /healthz.
func (s *Server) Prometheus(health map[string]any) string {
	var builder strings.Builder
	writeGauge := func(name, help string, value float64) {
		fmt.Fprintf(&builder, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, value)
	}
	writeGauge("forti_intelligence_up", "Forti Intelligence MCP server is running", 1)
	if health != nil {
		writeGauge("forti_intelligence_inventory_ready", "1 when an inventory snapshot has been published", boolGauge(health["inventory_ready"]))
		writeGauge("forti_intelligence_refresh_in_progress", "1 while an inventory refresh is running", boolGauge(health["refresh_in_progress"]))
		writeGauge("forti_intelligence_devices", "Managed FortiGates in the latest snapshot", numberGauge(health["devices"]))
		writeGauge("forti_intelligence_unavailable_devices", "FortiGates reported offline by FortiManager", numberGauge(health["unavailable_devices"]))
		writeGauge("forti_intelligence_refresh_errors", "Errors recorded on the latest inventory refresh", numberGauge(health["refresh_errors"]))
		if age, ok := health["inventory_age_seconds"]; ok {
			writeGauge("forti_intelligence_inventory_age_seconds", "Seconds since the latest snapshot was published", numberGauge(age))
		}
		if duration, ok := health["last_refresh_duration_seconds"]; ok {
			writeGauge("forti_intelligence_last_refresh_duration_seconds", "Seconds spent in the most recent inventory refresh", numberGauge(duration))
		}
		stale := 0.0
		if names, ok := health["stale_profiles"].([]string); ok {
			stale = float64(len(names))
		}
		writeGauge("forti_intelligence_stale_profiles", "FortiManager profiles whose latest ADOM-level read failed", stale)
		if denials, ok := health["transient_permission_denials"].(map[string]int64); ok {
			fmt.Fprintf(&builder, "# HELP forti_intelligence_transient_permission_denials Permission denials that succeeded on re-check\n# TYPE forti_intelligence_transient_permission_denials counter\n")
			names := make([]string, 0, len(denials))
			for name := range denials {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				fmt.Fprintf(&builder, "forti_intelligence_transient_permission_denials{profile=%q} %d\n", name, denials[name])
			}
		}
	}

	s.toolMu.Lock()
	names := make([]string, 0, len(s.toolStats))
	copied := make(map[string]toolStat, len(s.toolStats))
	for name, stat := range s.toolStats {
		names = append(names, name)
		copied[name] = *stat
	}
	s.toolMu.Unlock()
	sort.Strings(names)
	if len(names) > 0 {
		fmt.Fprintf(&builder, "# HELP forti_intelligence_tool_calls_total Completed MCP tool calls\n# TYPE forti_intelligence_tool_calls_total counter\n")
		fmt.Fprintf(&builder, "# HELP forti_intelligence_tool_duration_seconds_sum Total tool duration in seconds\n# TYPE forti_intelligence_tool_duration_seconds_sum counter\n")
		fmt.Fprintf(&builder, "# HELP forti_intelligence_tool_lane_wait_seconds_sum Time spent waiting for the appliance request lane\n# TYPE forti_intelligence_tool_lane_wait_seconds_sum counter\n")
		fmt.Fprintf(&builder, "# HELP forti_intelligence_tool_fortinet_requests_total Appliance requests made by tool calls\n# TYPE forti_intelligence_tool_fortinet_requests_total counter\n")
		for _, name := range names {
			stat := copied[name]
			label := fmt.Sprintf("tool=%q", name)
			fmt.Fprintf(&builder, "forti_intelligence_tool_calls_total{%s,outcome=\"ok\"} %d\n", label, stat.ok)
			fmt.Fprintf(&builder, "forti_intelligence_tool_calls_total{%s,outcome=\"error\"} %d\n", label, stat.failed)
			fmt.Fprintf(&builder, "forti_intelligence_tool_duration_seconds_sum{%s} %g\n", label, stat.duration.Seconds())
			fmt.Fprintf(&builder, "forti_intelligence_tool_lane_wait_seconds_sum{%s} %g\n", label, stat.lane.Seconds())
			fmt.Fprintf(&builder, "forti_intelligence_tool_fortinet_requests_total{%s} %d\n", label, stat.fortinetRequests)
		}
	}
	return builder.String()
}

func boolGauge(value any) float64 {
	flag, _ := value.(bool)
	if flag {
		return 1
	}
	return 0
}

func numberGauge(value any) float64 {
	switch typed := value.(type) {
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case float64:
		return typed
	case time.Duration:
		return typed.Seconds()
	default:
		return 0
	}
}

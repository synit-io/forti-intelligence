package mcpserver

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/service"
	"strings"
	"testing"
)

func TestToolAvailability(t *testing.T) {
	for _, mode := range []string{"default", "one disabled", "all disabled", "explicit enabled"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.Default()
			cfg.Server.Tools = map[string]bool{}
			switch mode {
			case "one disabled":
				cfg.Server.Tools["rate_url"] = false
			case "all disabled":
				for _, name := range config.ToolNames() {
					cfg.Server.Tools[name] = false
				}
			case "explicit enabled":
				cfg.Server.Tools["rate_url"] = true
			}
			server := New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, nil)
			session := memorySession(t, server)
			listed, err := session.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			actual := map[string]bool{}
			for _, tool := range listed.Tools {
				actual[tool.Name] = true
			}
			expected := 0
			for _, name := range config.ToolNames() {
				enabled := cfg.Server.ToolEnabled(name)
				if enabled {
					expected++
				}
				if actual[name] != enabled {
					t.Errorf("%s advertised=%v, want %v", name, actual[name], enabled)
				}
				if !enabled {
					result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{}})
					if err == nil && (result == nil || !result.IsError) {
						t.Errorf("disabled %s accepted", name)
					}
				}
			}
			if len(actual) != expected {
				t.Fatalf("catalog has %d tools, want %d; update configurable tool names", len(actual), expected)
			}
			restricted := mode == "one disabled" || mode == "all disabled"
			if strings.Contains(session.InitializeResult().Instructions, "Some tools are disabled") != restricted {
				t.Fatal("session instructions do not reflect configured availability")
			}
			if mode == "one disabled" {
				result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "inventory_status", Arguments: map[string]any{}})
				if err != nil || result.IsError {
					t.Fatalf("enabled tool failed: %v, %v", result, err)
				}
			}
		})
	}
}

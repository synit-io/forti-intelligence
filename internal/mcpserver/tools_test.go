package mcpserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/service"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestToolSchemasCarryFieldDescriptionsAndResultsAreCompact(t *testing.T) {
	cfg := config.Default()
	server := New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, nil)
	httpServer := httptest.NewServer(server.StreamableHTTPHandler())
	defer httpServer.Close()
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: httpServer.URL}, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	byName := make(map[string]*mcp.Tool, len(tools.Tools))
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}
	if byName["rate_url"] == nil || byName["check_web_filter"] == nil || byName["lookup_web_filter"] != nil {
		t.Fatal("rate_url and check_web_filter must replace lookup_web_filter")
	}
	for name, property := range map[string]string{
		"search_fortianalyzer_logs": "task_id",
		"inventory_status":          "include_raw",
		"get_fortianalyzer_data":    "resource",
		"rate_url":                  "url",
		"check_web_filter":          "category",
		"lookup_firewall_policy":    "destination_ip",
		"resolve_ip_ownership":      "ip",
		"resolve_route":             "ip",
	} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("tool %s missing", name)
		}
		encoded, _ := json.Marshal(tool.InputSchema)
		var schema struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Fatalf("decode %s schema: %v", name, err)
		}
		if schema.Properties[property].Description == "" {
			t.Errorf("%s.%s has no description: %s", name, property, encoded)
		}
	}

	call, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "resolve_ip_ownership", Arguments: map[string]any{"ip": "10.0.0.1"}})
	if err != nil || call.IsError {
		t.Fatalf("call = %#v err = %v", call, err)
	}
	if len(call.Content) != 1 {
		t.Fatalf("content blocks = %d, want 1", len(call.Content))
	}
	text := call.Content[0].(*mcp.TextContent).Text
	if strings.Contains(text, "\n  ") {
		t.Fatal("result text is indented; expected compact JSON")
	}
	if call.StructuredContent != nil {
		t.Fatalf("structuredContent = %v, want none (payload sent once)", call.StructuredContent)
	}

	rejected, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_fortianalyzer_data", Arguments: map[string]any{"resource": "cli/global/system"}})
	if err != nil || !rejected.IsError {
		t.Fatalf("rejected call = %#v err = %v", rejected, err)
	}
	if message := rejected.Content[0].(*mcp.TextContent).Text; !strings.Contains(message, "/logview") || !strings.Contains(message, "/dvmdb") {
		t.Fatalf("rejection = %q, want accepted prefixes listed", message)
	}
}

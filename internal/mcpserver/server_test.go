package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/service"
)

func TestStreamableHTTPNegotiatesMCP20260728AndListsTools(t *testing.T) {
	cfg := config.Default()
	store := inventory.NewStore(nil, 0, 1)
	app := service.New(cfg, store, nil, nil)
	server := New(app, cfg.Server, nil)
	httpServer := httptest.NewServer(server.StreamableHTTPHandler())
	defer httpServer.Close()

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: httpServer.URL}, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()
	if got := session.InitializeResult().ProtocolVersion; got != "2026-07-28" {
		t.Fatalf("NegotiatedProtocolVersion = %q, want 2026-07-28", got)
	}
	instructions := session.InitializeResult().Instructions
	for _, guidance := range []string{"numbered path", "path.end", "every traced hop and destination", "return-path"} {
		if !strings.Contains(instructions, guidance) {
			t.Errorf("advertised instructions omit %q", guidance)
		}
	}
	if strings.Contains(instructions, "internet-facing FortiGate in one call") {
		t.Fatal("advertised instructions still assume the last managed device is the Internet edge")
	}
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools.Tools) < 10 {
		t.Fatalf("tool count = %d, want at least 10", len(tools.Tools))
	}
	seenLookup := false
	seenOwnership := false
	seenTrafficTools := make(map[string]bool)
	for _, tool := range tools.Tools {
		if tool.Name == "resolve_route" || tool.Name == "investigate_traffic" {
			seenTrafficTools[tool.Name] = true
			for _, guidance := range []string{"path.end", "every supported hop", "return-path"} {
				if !strings.Contains(tool.Description, guidance) {
					t.Errorf("%s description omits %q", tool.Name, guidance)
				}
			}
			encoded, err := json.Marshal(tool.InputSchema)
			if err != nil {
				t.Fatal(err)
			}
			var schema struct {
				Properties map[string]any `json:"properties"`
			}
			if err := json.Unmarshal(encoded, &schema); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"source_port", "vdom"} {
				if _, exists := schema.Properties[field]; !exists {
					t.Errorf("%s schema omits %s", tool.Name, field)
				}
			}
		}
		if tool.Name == "resolve_ip_ownership" {
			seenOwnership = true
		}
		if tool.Name == "lookup_firewall_policy" {
			seenLookup = true
			encoded, err := json.Marshal(tool.InputSchema)
			if err != nil {
				t.Fatalf("marshal lookup schema: %v", err)
			}
			var schema struct {
				Required []string `json:"required"`
			}
			if err := json.Unmarshal(encoded, &schema); err != nil {
				t.Fatalf("decode lookup schema: %v", err)
			}
			for _, required := range []string{"source_ip", "destination_ip", "destination_port"} {
				found := false
				for _, value := range schema.Required {
					if value == required {
						found = true
					}
				}
				if !found {
					t.Errorf("lookup schema required fields = %#v, missing %q", schema.Required, required)
				}
			}
		}
	}
	if !seenLookup {
		t.Fatal("lookup_firewall_policy was not advertised")
	}
	if !seenOwnership {
		t.Fatal("resolve_ip_ownership was not advertised")
	}
	if len(seenTrafficTools) != 2 {
		t.Fatalf("traffic tools advertised=%v", seenTrafficTools)
	}
	ownership, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "resolve_ip_ownership", Arguments: map[string]any{"ip": "10.49.0.17"}})
	if err != nil || ownership.IsError {
		t.Fatalf("ownership call=%+v err=%v", ownership, err)
	}
}

func TestStreamableHTTPBearerAuth(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTPBearerToken = "test-token"
	server := New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, nil)
	handler := server.StreamableHTTPHandler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "http://example.test/mcp", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	authorizedRequest := httptest.NewRequest(http.MethodGet, "http://example.test/mcp", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer test-token")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code == http.StatusUnauthorized {
		t.Fatal("valid bearer token was rejected")
	}

	lowercase := httptest.NewRequest(http.MethodGet, "http://example.test/mcp", nil)
	lowercase.Header.Set("Authorization", "bearer test-token")
	lowercaseResponse := httptest.NewRecorder()
	handler.ServeHTTP(lowercaseResponse, lowercase)
	if lowercaseResponse.Code == http.StatusUnauthorized {
		t.Fatal("lowercase bearer scheme was rejected")
	}
}

func TestToolErrorsAreLoggedWithToolName(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := config.Default()
	server := New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, logger)
	httpServer := httptest.NewServer(server.StreamableHTTPHandler())
	defer httpServer.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: httpServer.URL}, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()

	call, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "get_fortimanager_status",
		Arguments: map[string]any{"resource": "/sys/status"},
	})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if !call.IsError {
		t.Fatalf("CallTool() result = %#v, want tool error", call)
	}
	output := logs.String()
	if !strings.Contains(output, "MCP tool failed") || !strings.Contains(output, "tool=get_fortimanager_status") || !strings.Contains(output, "no FortiManager profile configured") {
		t.Fatalf("logs = %q, want tool and underlying error", output)
	}
}

func TestParseTimeRequiresExplicitTimezone(t *testing.T) {
	if _, err := parseTime("2026-09-22 14:05:00"); err == nil {
		t.Fatal("parseTime() accepted an unzoned timestamp")
	}
	parsed, err := parseTime("2026-09-22T14:05:00+02:00")
	if err != nil || parsed.Location() == nil {
		t.Fatalf("parseTime() = %v, %v; want RFC3339 timestamp", parsed, err)
	}
}

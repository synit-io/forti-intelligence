package mcpserver

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/service"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type panicInput struct {
	Value string `json:"value,omitempty" jsonschema:"test value"`
}

func TestToolPanicBecomesToolErrorAndServerStaysUp(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := config.Default()
	server := New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, logger)
	addReadTool(server, "explode", "Explode", "test tool", func(context.Context, panicInput) (any, error) {
		var values map[string]int
		values["boom"]++
		return nil, nil
	})
	httpServer := httptest.NewServer(server.StreamableHTTPHandler())
	defer httpServer.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: httpServer.URL}, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer session.Close()
	call, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "explode", Arguments: map[string]any{}})
	if err != nil || !call.IsError || !strings.Contains(call.Content[0].(*mcp.TextContent).Text, "internal error in explode") {
		t.Fatalf("call = %#v err = %v", call, err)
	}
	if !strings.Contains(logs.String(), "MCP tool panicked") {
		t.Fatalf("logs = %q", logs.String())
	}
	after, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "resolve_ip_ownership", Arguments: map[string]any{"ip": "10.0.0.1"}})
	if err != nil || after.IsError {
		t.Fatalf("server not usable after panic: %#v %v", after, err)
	}
}

func TestToolCallsLogDurationAndRequestCount(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := config.Default()
	server := New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, logger)
	httpServer := httptest.NewServer(server.StreamableHTTPHandler())
	defer httpServer.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: httpServer.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "resolve_ip_ownership", Arguments: map[string]any{"ip": "10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	output := logs.String()
	if !strings.Contains(output, `msg="MCP tool completed" tool=resolve_ip_ownership outcome=ok duration=`) || !strings.Contains(output, "fortinet_requests=0") {
		t.Fatalf("logs = %q", output)
	}
}

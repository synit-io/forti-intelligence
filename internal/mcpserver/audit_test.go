package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/service"
)

func TestAuditRecordsDispatchedMCPActions(t *testing.T) {
	var local, diagnostics bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&diagnostics, nil))
	cfg := config.Default()
	cfg.Server.HTTPBearerToken = "test-private-token"
	cfg.Server.Tools = map[string]bool{"rate_url": false}
	audit, err := NewAuditLog(&local, cfg.Server.Audit.Syslog, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	server := NewWithAudit(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, logger, audit)
	addReadTool(server, "audit_probe", "Audit probe", "Tests tool outcomes", func(_ context.Context, in panicInput) (any, error) {
		switch in.Value {
		case "fail":
			return nil, errors.New("test-private-error")
		case "panic":
			panic("test-private-panic")
		}
		return "test-private-result", nil
	})
	handler := server.StreamableHTTPHandler()
	seen := make(map[string]bool)
	for _, tc := range []struct {
		name, method, params, tool, outcome string
		handled                             bool
	}{
		{"list", "tools/list", "{}", "", "ok", false},
		{"refresh", "tools/call", `{"name":"refresh_inventory","arguments":{}}`, "refresh_inventory", "ok", true},
		{"success", "tools/call", `{"name":"audit_probe","arguments":{"value":"test-private-argument"}}`, "audit_probe", "ok", true},
		{"unknown", "tools/call", `{"name":"test-private-tool","arguments":{}}`, "", "error", false},
		{"disabled", "tools/call", `{"name":"rate_url","arguments":{}}`, "", "error", false},
		{"invalid arguments", "tools/call", `{"name":"audit_probe","arguments":{"value":123}}`, "audit_probe", "error", false},
		{"handler error", "tools/call", `{"name":"audit_probe","arguments":{"value":"fail"}}`, "audit_probe", "error", true},
		{"recovered panic", "tools/call", `{"name":"audit_probe","arguments":{"value":"panic"}}`, "audit_probe", "error", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local.Reset()
			diagnostics.Reset()
			body := `{"jsonrpc":"2.0","id":1,"method":"` + tc.method + `","params":` + tc.params + `}`
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Authorization", "Bearer "+cfg.Server.HTTPBearerToken)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", response.Code, response.Body)
			}
			var reply struct {
				Error  json.RawMessage
				Result struct{ IsError bool }
			}
			if err := json.Unmarshal(response.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if (reply.Error != nil || reply.Result.IsError) != (tc.outcome == "error") {
				t.Fatalf("unexpected MCP response: %s", response.Body)
			}
			var event struct {
				Timestamp  time.Time
				ID         string `json:"audit_id"`
				Transport  string
				Method     string
				Tool       string
				Outcome    string
				DurationMS *int64 `json:"duration_ms"`
			}
			decoder := json.NewDecoder(bytes.NewReader(local.Bytes()))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&event); err != nil {
				t.Fatal(err)
			}
			if bytes.Count(local.Bytes(), []byte("\n")) != 1 || !strings.HasSuffix(local.String(), "\n") || strings.Contains(local.String(), "test-private") {
				t.Fatalf("expected one safe JSON line, got %q", &local)
			}
			if event.ID == "" || seen[event.ID] || event.Timestamp.IsZero() || event.Timestamp.Location() != time.UTC ||
				event.Transport != "http" || event.Method != tc.method || event.Tool != tc.tool || event.Outcome != tc.outcome ||
				event.DurationMS == nil || *event.DurationMS < 0 {
				t.Fatalf("unexpected audit record %s", &local)
			}
			seen[event.ID] = true
			if tc.handled && !strings.Contains(diagnostics.String(), `"audit_id":"`+event.ID+`"`) {
				t.Fatalf("missing audit ID in tool diagnostics: %s", &diagnostics)
			}
		})
	}
	local.Reset()
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if resp.Code != http.StatusUnauthorized || local.Len() != 0 {
		t.Fatalf("authentication rejection reached audit: status=%d log=%q", resp.Code, &local)
	}
}

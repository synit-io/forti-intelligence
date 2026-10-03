package mcpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/service"
)

const (
	ServerName = "forti-intelligence"
	// serverInstructions is the standing guidance sent with every session.
	serverInstructions           = `Use this server for read-only Fortinet troubleshooting. For each service-desk question, first restate the symptom in plain language and collect the minimum available context: source, destination, port/protocol, time and timezone for observed failures, direction, and known site/device. Resolve profile, ADOM, FortiGate, VDOM, interface, and package before interpreting policy; never silently choose an ambiguous scope. Prefer investigate_traffic when source, destination, and port are known; otherwise lookup_firewall_policy, and combine it with search_fortianalyzer_logs for observed failures. Separate inventory, live policy lookup, configured policy, and FortiAnalyzer log evidence. Explain Fortinet terms briefly while preserving technical identifiers. Report confidence as confirmed, likely, tentative, or inconclusive, include warnings and exact search/inventory scope, and finish with a next action or human Fortinet administrator escalation. Never claim that this server changed appliance state; no tool performs configuration changes.`
	routeTraceGuidance           = "Read path.end before interpreting path.last_managed_device: the last traced FortiGate may be a stopping point. Identify filtering from the carrying policies at every supported hop. Keep ambiguous scopes and alternative destination addresses separate. Configured routing does not prove delivery, policy permission, NAT translations or return-path symmetry."
	trafficReportingInstructions = "Write plain, complete sentences. Report the conclusion and confidence first, then the flow tuple and a numbered path. For each hop, name profile, ADOM, device, VDOM, ingress and egress, policy/action, and the evidence type and freshness. Explain where traffic stops, which hops remain uncertain, and any observed address or port translation. Report return-path evidence or its absence, then the smallest useful next check. In investigate_traffic, read hops for every traced hop and destination; top-level policy and web_filter cover only the first hop."
)

// ServerVersion is the MCP implementation version. The linker sets it with
// -X github.com/synit-io/forti-intelligence/internal/mcpserver.ServerVersion.
var ServerVersion = "0.1.0"

type Server struct {
	app       *service.Service
	config    config.ServerConfig
	logger    *slog.Logger
	mcp       *mcp.Server
	toolMu    sync.Mutex
	toolStats map[string]*toolStat
}

func New(app *service.Service, serverConfig config.ServerConfig, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{
		app:    app,
		config: serverConfig,
		logger: logger,
	}
	server.mcp = mcp.NewServer(&mcp.Implementation{Name: ServerName, Version: ServerVersion}, &mcp.ServerOptions{
		Logger:       sdkLogger(logger),
		Instructions: serverInstructions + " " + trafficReportingInstructions + " " + routeTraceGuidance + " " + "Start IP ownership questions with resolve_ip_ownership. Reuse its scoped interface, zone and package candidates instead of full interface dumps. Inspect freshness and errors; retain overlaps separately. Connected ownership is not forwarding: use resolve_route for configured routing, and the live routing table when dynamic routing or SD-WAN health can change the result. For website questions, trace the client's path with follow=true, rate the URL once, and check filtering at every scoped hop with the carrying policy when known. Inventory refreshes in the background; call refresh_inventory only for requested current data or a known FortiManager change. Resume timed-out FortiAnalyzer searches with their task_id. Act on error hints before retrying.",
	})
	server.registerTools()
	return server
}

func (s *Server) MCPServer() *mcp.Server {
	return s.mcp
}

func (s *Server) StreamableHTTPHandler() http.Handler {
	// MCP 2026-07-28 requires the modern Streamable HTTP request model to be
	// stateless. The application retains vendor sessions and inventory caches;
	// those are intentionally independent from MCP transport sessions.
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return s.mcp
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true,
		PropagateRequestCancellation: true,
		Logger:                       sdkLogger(s.logger),
	})
	return Authorize(s.config.HTTPBearerToken, handler)
}

// Authorize requires Authorization: Bearer when token is set. The scheme is
// case-insensitive. An empty token leaves the handler open.
func Authorize(token string, next http.Handler) http.Handler {
	configured := strings.TrimSpace(token)
	if configured == "" || next == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bearerMatches(r.Header.Get("Authorization"), configured) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="forti-intelligence"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerMatches(header, configured string) bool {
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(token), []byte(configured)) == 1
}

// sdkLogger passes only the SDK's warnings and errors: it logs several
// informational lines per call that repeat what "MCP tool completed" says.
func sdkLogger(logger *slog.Logger) *slog.Logger {
	return slog.New(minLevelHandler{Handler: logger.Handler(), min: slog.LevelWarn})
}

type minLevelHandler struct {
	slog.Handler
	min slog.Level
}

func (h minLevelHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.min && h.Handler.Enabled(ctx, level)
}

func (h minLevelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return minLevelHandler{Handler: h.Handler.WithAttrs(attrs), min: h.min}
}

func (h minLevelHandler) WithGroup(name string) slog.Handler {
	return minLevelHandler{Handler: h.Handler.WithGroup(name), min: h.min}
}

type toolStat struct {
	ok, failed       int64
	duration, lane   time.Duration
	fortinetRequests int64
}

func (s *Server) recordTool(name, outcome string, duration, lane time.Duration, requests int64) {
	s.toolMu.Lock()
	defer s.toolMu.Unlock()
	if s.toolStats == nil {
		s.toolStats = make(map[string]*toolStat)
	}
	stat := s.toolStats[name]
	if stat == nil {
		stat = &toolStat{}
		s.toolStats[name] = stat
	}
	if outcome == "ok" {
		stat.ok++
	} else {
		stat.failed++
	}
	stat.duration += duration
	stat.lane += lane
	stat.fortinetRequests += requests
}

func (s *Server) RunStdio(ctx context.Context) error {
	return s.mcp.Run(ctx, &mcp.StdioTransport{})
}

// result encodes the value once as compact JSON text. Returning it again as
// the typed output would make the SDK marshal it a second time and send both
// copies on the wire; MCP clients read the text block. A result above
// maxBytes is replaced by an error that says how to narrow the request.
func result(tool string, value any, maxBytes int) (*mcp.CallToolResult, any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, nil, fmt.Errorf("encode tool result: %w", err)
	}
	if maxBytes > 0 && len(encoded) > maxBytes {
		return nil, nil, fmt.Errorf("the %s result is %d KB, above the server limit of %d KB (max_result_bytes), and was not returned. %s", tool, len(encoded)>>10, maxBytes>>10, narrowingAdvice(tool))
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}},
	}, nil, nil
}

// narrowingAdvice says how to make a tool's result smaller.
func narrowingAdvice(tool string) string {
	switch tool {
	case "inventory_status":
		return "Filter by profile or adom and leave include_interfaces, include_routes and include_raw off; use resolve_ip_ownership, resolve_route or get_fortigate_interfaces for one device."
	case "list_firewall_policies":
		return "Pass device or package, policy_id, or a smaller limit and page with offset."
	case "list_policy_objects":
		return "Pass name for one object, or a smaller limit and page with offset."
	case "get_fortigate_settings":
		return "Request a narrower FortiOS resource or add FortiOS query parameters such as ?count=, ?filter= or ?format=."
	case "get_fortimanager_status", "get_fortianalyzer_data":
		return "Add fields, filter or range to data, or read a single object path."
	case "search_fortianalyzer_logs":
		return "Narrow the filter or time range. A full page that filled the submit limit needs a new search without task_id at the next offset, or one submit with a larger limit (up to 500) that is then paged with task_id."
	case "get_firewall_sessions":
		return "Pass source_ip, destination_ip, policy_id, or a smaller count."
	case "count_fortianalyzer_logs":
		return "Narrow the filter, time range, device, or focus."
	case "lookup_firewall_policy", "check_web_filter", "resolve_route":
		return "Scope the call with device (and vdom), or pass a single address instead of a hostname."
	default:
		return "Narrow the request scope."
	}
}

func (s *Server) toolError(req *mcp.CallToolRequest, tool string, err error) (*mcp.CallToolResult, any, error) {
	attrs := []any{"tool", tool, "error", err}
	if details := fortinet.DescribeError(err); details.Kind != "" {
		attrs = append(attrs, "kind", details.Kind, "retryable", details.Retryable)
		if details.Code != 0 {
			attrs = append(attrs, "code", details.Code)
		}
		if details.HTTPStatus != 0 {
			attrs = append(attrs, "http_status", details.HTTPStatus)
		}
		if details.Resource != "" {
			attrs = append(attrs, "resource", details.Resource)
		}
		if details.Hint != "" {
			attrs = append(attrs, "hint", details.Hint)
		}
	}
	if req != nil && req.Session != nil {
		// This is empty for the server's stateless Streamable HTTP transport
		// by design. Include it when a stateful transport supplies one, without
		// logging request arguments or credentials.
		attrs = append(attrs, "session_id", req.Session.ID())
	}
	s.logger.Error("MCP tool failed", attrs...)
	return nil, nil, err
}

func readonlyAnnotations(title string) *mcp.ToolAnnotations {
	falseValue := false
	trueValue := true
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    true,
		IdempotentHint:  true,
		DestructiveHint: &falseValue,
		OpenWorldHint:   &trueValue,
	}
}

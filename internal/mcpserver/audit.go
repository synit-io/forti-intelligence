package mcpserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/synit-io/forti-intelligence/internal/config"
)

type auditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	ID         string    `json:"audit_id"`
	Transport  string    `json:"transport"`
	Method     string    `json:"method"`
	Tool       string    `json:"tool,omitempty"`
	Outcome    string    `json:"outcome"`
	DurationMS int64     `json:"duration_ms"`
}

type auditIDKey struct{}

func auditID(ctx context.Context) string {
	id, _ := ctx.Value(auditIDKey{}).(string)
	return id
}

func (s *Server) auditRequests(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		started := time.Now()
		event := auditEvent{ID: rand.Text(), Method: method, Transport: "stdio", Outcome: "ok"}
		if extra := req.GetExtra(); extra != nil && extra.Header != nil {
			event.Transport = "http"
		}
		if call, ok := req.(*mcp.CallToolRequest); ok && call.Params != nil {
			if _, registered := s.auditTools[call.Params.Name]; registered {
				event.Tool = call.Params.Name
			}
		}
		result, err := next(context.WithValue(ctx, auditIDKey{}, event.ID), method, req)
		if tool, ok := result.(*mcp.CallToolResult); err != nil || (ok && tool != nil && tool.IsError) {
			event.Outcome = "error"
		}
		completed := time.Now()
		event.Timestamp = completed.UTC()
		event.DurationMS = completed.Sub(started).Milliseconds()
		s.audit.write(event)
		return result, err
	}
}

// AuditLog writes completion events separately from the diagnostic logger.
type AuditLog struct {
	output   io.Writer
	outputMu sync.Mutex
	logger   *slog.Logger
	syslog   *auditSyslog
}

// NewAuditLog validates syslog settings. It connects on the first event.
// A nil output selects stdout for HTTP and stderr for stdio.
func NewAuditLog(output io.Writer, settings config.AuditSyslogConfig, logger *slog.Logger) (*AuditLog, error) {
	address, tlsConfig, err := settings.Endpoint()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	audit := &AuditLog{output: output, logger: logger}
	if address != "" {
		audit.syslog = &auditSyslog{address: address, tlsConfig: tlsConfig, gate: make(chan struct{}, 1)}
	}
	return audit, nil
}

func (a *AuditLog) write(event auditEvent) {
	payload, err := json.Marshal(event)
	if err != nil {
		a.logger.Warn("MCP audit encoding failed", "audit_id", event.ID, "error", err)
		return
	}
	output := a.output
	if output == nil {
		output = os.Stderr
		if event.Transport == "http" {
			output = os.Stdout
		}
	}
	a.outputMu.Lock()
	_, err = output.Write(append(payload, '\n'))
	a.outputMu.Unlock()
	if err != nil {
		a.logger.Warn("MCP local audit write failed", "audit_id", event.ID, "error", err)
	}
	if a.syslog != nil {
		if err := a.syslog.send(event.Timestamp, payload); err != nil {
			a.logger.Warn("MCP audit syslog forwarding failed", "audit_id", event.ID, "error", err)
		}
	}
}

// Close releases the optional receiver connection.
func (a *AuditLog) Close() {
	if s := a.syslog; s != nil {
		s.gate <- struct{}{}
		defer func() { <-s.gate }()
		s.closed = true
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
		}
	}
}

const syslogTimeout = time.Second

type auditSyslog struct {
	address   string
	tlsConfig *tls.Config
	gate      chan struct{}
	conn      net.Conn // guarded by gate
	closed    bool     // guarded by gate
}

func (s *auditSyslog) send(timestamp time.Time, payload []byte) error {
	// Bound lock wait, dial, handshake and write with a single deadline.
	ctx, cancel := context.WithTimeout(context.Background(), syslogTimeout)
	defer cancel()
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.closed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.conn == nil {
		var err error
		s.conn, err = s.dial(ctx)
		if err != nil {
			return err
		}
	}

	stamp := timestamp.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	message := fmt.Sprintf("<134>1 %s - %s - mcp-audit - %s", stamp, ServerName, payload)
	frame := fmt.Sprintf("%d %s", len(message), message)
	deadline, _ := ctx.Deadline()
	err := s.conn.SetWriteDeadline(deadline)
	if err == nil {
		_, err = io.WriteString(s.conn, frame)
	}
	if err != nil {
		// A timed-out TLS write cannot send a close alert on the broken stream.
		conn := s.conn
		if secured, ok := conn.(*tls.Conn); ok {
			conn = secured.NetConn()
		}
		_ = conn.Close()
		s.conn = nil
	}
	return err
}

func (s *auditSyslog) dial(ctx context.Context) (net.Conn, error) {
	if s.tlsConfig != nil {
		dialer := tls.Dialer{Config: s.tlsConfig}
		return dialer.DialContext(ctx, "tcp", s.address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", s.address)
}

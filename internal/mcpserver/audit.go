package mcpserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

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

	user        string
	httpLocalIP netip.Addr
}

type forwardedAuditEvent struct {
	auditEvent
	User     string `json:"user,omitempty"`
	SystemID string `json:"system_id,omitempty"`
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
			if syslog := s.audit.syslog; syslog != nil {
				addr, _ := ctx.Value(http.LocalAddrContextKey).(net.Addr)
				event.httpLocalIP = auditSocketIP(addr)
				if syslog.userHeader != "" {
					event.user = auditHeaderUser(extra.Header[syslog.userHeader])
				}
			}
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

func auditHeaderUser(values []string) string {
	if len(values) != 1 {
		return ""
	}
	user := strings.Trim(values[0], " ")
	if user == "" || len(user) > 256 || strings.Contains(user, ",") || !utf8.ValidString(user) ||
		strings.ContainsFunc(user, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return ""
	}
	return user
}

// AuditLog writes completion events separately from the diagnostic logger.
type AuditLog struct {
	output             io.Writer
	httpFallback       io.Writer
	outputMu           sync.Mutex
	logger             *slog.Logger
	syslog             *auditSyslog
	suppressHTTPStdout bool
}

// NewAuditLog validates syslog settings. It connects on the first event.
// A nil output selects stdout for HTTP and stderr for stdio.
// When HTTP stdout is suppressed, forwarding failures fall back to stderr.
func NewAuditLog(output io.Writer, settings config.AuditSyslogConfig, logger *slog.Logger) (*AuditLog, error) {
	address, tlsConfig, err := settings.Endpoint()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	audit := &AuditLog{output: output, logger: logger, suppressHTTPStdout: settings.SuppressHTTPStdout}
	if address != "" {
		audit.syslog = &auditSyslog{
			address: address, tlsConfig: tlsConfig, gate: make(chan struct{}, 1),
			userHeader: http.CanonicalHeaderKey(settings.UserHeader), systemID: settings.SystemID,
		}
	}
	return audit, nil
}

func (a *AuditLog) write(event auditEvent) {
	var payload []byte
	httpSyslogOnly := a.suppressHTTPStdout && event.Transport == "http"
	if !httpSyslogOnly {
		payload = a.marshal(event.ID, event)
		if payload == nil {
			return
		}
		output := a.output
		if output == nil && event.Transport == "http" {
			output = os.Stdout
		}
		a.writeLocal(output, event.ID, payload)
	}
	if syslog := a.syslog; syslog != nil {
		if payload == nil || event.user != "" || syslog.systemID != "" {
			payload = a.marshal(event.ID, forwardedAuditEvent{auditEvent: event, User: event.user, SystemID: syslog.systemID})
			if payload == nil {
				return
			}
		}
		if err := syslog.send(event.Timestamp, event.httpLocalIP, payload); err != nil {
			if httpSyslogOnly {
				a.writeLocal(a.httpFallback, event.ID, payload)
			} else if err == errAuditSyslogClosed {
				return
			}
			a.logger.Warn("MCP audit syslog forwarding failed", "audit_id", event.ID, "error", err)
		}
	}
}

func (a *AuditLog) marshal(id string, event any) []byte {
	payload, err := json.Marshal(event)
	if err != nil {
		a.logger.Warn("MCP audit encoding failed", "audit_id", id, "error", err)
		return nil
	}
	return payload
}

func (a *AuditLog) writeLocal(output io.Writer, id string, payload []byte) {
	if output == nil {
		output = os.Stderr
	}
	a.outputMu.Lock()
	_, err := output.Write(append(payload, '\n'))
	a.outputMu.Unlock()
	if err != nil {
		a.logger.Warn("MCP local audit write failed", "audit_id", id, "error", err)
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

var errAuditSyslogClosed = errors.New("audit syslog sender is closed")

type auditSyslog struct {
	address    string
	tlsConfig  *tls.Config
	userHeader string
	systemID   string
	gate       chan struct{}
	conn       net.Conn // guarded by gate
	closed     bool     // guarded by gate
}

func (s *auditSyslog) send(timestamp time.Time, httpLocalIP netip.Addr, payload []byte) error {
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
		return errAuditSyslogClosed
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

	source := httpLocalIP
	if !source.IsValid() {
		source = auditSocketIP(s.conn.LocalAddr())
	}
	hostname := "-"
	if source.IsValid() {
		hostname = source.String()
	}
	stamp := timestamp.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	message := fmt.Sprintf("<134>1 %s %s %s - mcp-audit - %s", stamp, hostname, ServerName, payload)
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

func auditSocketIP(addr net.Addr) netip.Addr {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp == nil {
		return netip.Addr{}
	}
	ip := tcp.AddrPort().Addr().Unmap().WithZone("")
	if ip.IsUnspecified() {
		return netip.Addr{}
	}
	return ip
}

func (s *auditSyslog) dial(ctx context.Context) (net.Conn, error) {
	if s.tlsConfig != nil {
		dialer := tls.Dialer{Config: s.tlsConfig}
		return dialer.DialContext(ctx, "tcp", s.address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", s.address)
}

package mcpserver

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

// Read the RFC 6587/5425 byte count and the RFC 5424 header, as a collector would.
func readAuditMessage(reader *bufio.Reader) (hostname, payload string, err error) {
	prefix, err := reader.ReadString(' ')
	if err != nil {
		return "", "", err
	}
	size, err := strconv.Atoi(strings.TrimSuffix(prefix, " "))
	if err != nil || size <= 0 || size > 8192 {
		return "", "", fmt.Errorf("invalid syslog frame length %q", prefix)
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(reader, frame); err != nil {
		return "", "", err
	}
	fields := strings.SplitN(string(frame), " ", 8)
	if len(fields) != 8 || !strings.HasPrefix(fields[0], "<") || !strings.HasSuffix(fields[0], ">1") || fields[3] != "forti-intelligence" || fields[6] != "-" {
		return "", "", fmt.Errorf("invalid RFC 5424 header in %q", frame)
	}
	return fields[2], fields[7], nil
}

func TestNewAuditLogRejectsSuppressionWithoutTarget(t *testing.T) {
	_, err := NewAuditLog(nil, config.AuditSyslogConfig{SuppressHTTPStdout: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "suppress_http_stdout requires server.audit.syslog.target") {
		t.Fatalf("NewAuditLog() error = %v, want missing target error", err)
	}
}

func TestAuditWriteAfterClose(t *testing.T) {
	event := auditEvent{Timestamp: time.Now().UTC(), ID: "late", Transport: "http", Method: "tools/list", Outcome: "ok", user: "late-user"}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, suppress := range []bool{false, true} {
		t.Run(fmt.Sprintf("suppress=%t", suppress), func(t *testing.T) {
			var local, fallback, diagnostics bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&diagnostics, nil))
			audit, err := NewAuditLog(&local, config.AuditSyslogConfig{
				Target: "tcp://127.0.0.1:514", SuppressHTTPStdout: suppress, SystemID: "mcp-1",
			}, logger)
			if err != nil {
				t.Fatal(err)
			}
			audit.httpFallback = &fallback
			audit.Close()
			audit.write(event)

			wantLocal, wantFallback := string(payload)+"\n", ""
			if suppress {
				wantFallback = strings.TrimSuffix(string(payload), "}") + `,"user":"late-user","system_id":"mcp-1"}` + "\n"
				wantLocal = ""
			}
			if local.String() != wantLocal || fallback.String() != wantFallback {
				t.Fatalf("local audit = %q, want %q, fallback audit = %q, want %q", &local, wantLocal, &fallback, wantFallback)
			}
			if suppress != strings.Contains(diagnostics.String(), `msg="MCP audit syslog forwarding failed" audit_id=late`) {
				t.Fatalf("unexpected forwarding diagnostics: %s", &diagnostics)
			}
		})
	}
}

func TestSyslogForwarding(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	fixture.Close()
	caFile := filepath.Join(t.TempDir(), "test-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, scheme, ca   string
		badHostname        bool
		refuseFirst        bool
		failsTLS           bool
		suppressHTTPStdout bool
		stdio              bool
		ipv6               bool
		systemID           string
	}{
		{name: "plaintext", scheme: "tcp"},
		{name: "IPv6 plaintext", scheme: "tcp", ipv6: true},
		{name: "trusted TLS reconnects after outage", scheme: "tls", ca: caFile, refuseFirst: true},
		{name: "untrusted TLS", scheme: "tls", failsTLS: true},
		{name: "TLS hostname mismatch", scheme: "tls", ca: caFile, badHostname: true, failsTLS: true},
		{name: "HTTP syslog only", scheme: "tcp", suppressHTTPStdout: true},
		{name: "HTTP fallback and recovery", scheme: "tls", ca: caFile, refuseFirst: true, suppressHTTPStdout: true},
		{name: "stdio with HTTP stdout suppressed", scheme: "tls", ca: caFile, refuseFirst: true, suppressHTTPStdout: true, stdio: true, systemID: "mcp-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			network, listenAddress, wantHostname := "tcp4", "127.0.0.1:0", "127.0.0.1"
			if tc.ipv6 {
				network, listenAddress, wantHostname = "tcp6", "[::1]:0", "::1"
			}
			ln, err := net.Listen(network, listenAddress)
			if err != nil {
				if tc.ipv6 {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer ln.Close()
			address := ln.Addr().String()
			if tc.badHostname {
				address = fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port)
			}
			var local, fallback, diagnostics bytes.Buffer
			cfg := config.AuditSyslogConfig{Target: tc.scheme + "://" + address, CAFile: tc.ca, SuppressHTTPStdout: tc.suppressHTTPStdout, SystemID: tc.systemID}
			audit, err := NewAuditLog(&local, cfg, slog.New(slog.NewTextHandler(&diagnostics, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer audit.Close()
			audit.httpFallback = &fallback

			remote := make(chan string, 1)
			go func() {
				if tc.refuseFirst {
					conn, err := ln.Accept()
					if err != nil {
						remote <- err.Error()
						return
					}
					conn.Close()
				}
				conn, err := ln.Accept()
				if err != nil {
					remote <- err.Error()
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if tc.scheme == "tls" {
					secure := tls.Server(conn, fixture.TLS)
					if err := secure.Handshake(); err != nil {
						remote <- "TLS handshake failed"
						return
					}
					conn = secure
				}
				hostname, message, err := readAuditMessage(bufio.NewReader(conn))
				if err != nil {
					remote <- err.Error()
					return
				}
				if hostname != wantHostname {
					remote <- fmt.Sprintf("HOSTNAME = %q, want %q", hostname, wantHostname)
					return
				}
				remote <- message
			}()
			event := auditEvent{Timestamp: time.Now().UTC(), ID: "first", Transport: "http", Method: "tools/list", Outcome: "ok"}
			if tc.stdio {
				event.Transport = "stdio"
			}
			first, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			wantLocal := string(first) + "\n"
			wantForwarded := first
			audit.write(event)
			if tc.refuseFirst {
				event.ID = "second"
				wantForwarded, err = json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				wantLocal += string(wantForwarded) + "\n"
				audit.write(event)
			}
			if tc.systemID != "" {
				wantForwarded = []byte(strings.TrimSuffix(string(wantForwarded), "}") + `,"system_id":"mcp-1"}`)
			}
			wantWarning := tc.refuseFirst || tc.failsTLS
			wantFallback := ""
			if tc.suppressHTTPStdout && !tc.stdio {
				wantLocal = ""
				if wantWarning {
					wantFallback = string(first) + "\n"
				}
			}
			if local.String() != wantLocal || fallback.String() != wantFallback {
				t.Fatalf("local audit = %q, want %q, fallback audit = %q, want %q", &local, wantLocal, &fallback, wantFallback)
			}
			select {
			case received := <-remote:
				if tc.failsTLS {
					if received != "TLS handshake failed" {
						t.Fatalf("collector accepted invalid TLS: %q", received)
					}
				} else if received != string(wantForwarded) {
					t.Fatalf("collector received %q, want %q", received, wantForwarded)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("collector did not finish")
			}
			if wantWarning && (strings.Count(diagnostics.String(), "\n") != 1 ||
				!strings.Contains(diagnostics.String(), `level=WARN msg="MCP audit syslog forwarding failed" audit_id=first`)) {
				t.Fatalf("missing forwarding warning for the failed event: %s", &diagnostics)
			}
			if !wantWarning && diagnostics.Len() != 0 {
				t.Fatalf("unexpected forwarding diagnostics: %s", &diagnostics)
			}
		})
	}
}

func TestConcurrentSyslogFrames(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var local bytes.Buffer
	audit, err := NewAuditLog(&local, config.AuditSyslogConfig{Target: "tcp://" + ln.Addr().String()}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	const count = 12
	var workers sync.WaitGroup
	for i := range count {
		workers.Go(func() {
			audit.write(auditEvent{Timestamp: time.Now().UTC(), ID: strconv.Itoa(i), Transport: "http", Method: "tools/list", Outcome: "ok"})
		})
	}
	workers.Wait()
	// The loopback socket can buffer these small frames while callers finish.
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	localRecords := make(map[string]bool)
	for line := range strings.Lines(local.String()) {
		localRecords[strings.TrimSuffix(line, "\n")] = true
	}
	if len(localRecords) != count {
		t.Fatalf("got %d distinct local records, want %d", len(localRecords), count)
	}
	for range count {
		hostname, message, err := readAuditMessage(reader)
		if err != nil || hostname != "127.0.0.1" || !json.Valid([]byte(message)) || !localRecords[message] {
			t.Fatalf("collector received HOSTNAME %q and %q: %v", hostname, message, err)
		}
		delete(localRecords, message)
	}
}

func TestSyslogNilHostnameWithoutSocketIP(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	defer receiver.Close()
	syslog := auditSyslog{conn: sender, gate: make(chan struct{}, 1)}
	sent := make(chan error, 1)
	go func() { sent <- syslog.send(time.Now(), auditSocketIP(nil), []byte("{}")) }()
	_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	hostname, payload, err := readAuditMessage(bufio.NewReader(receiver))
	if err != nil || hostname != "-" || payload != "{}" {
		t.Fatalf("collector received HOSTNAME %q and %q: %v", hostname, payload, err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestStalledCollectorBoundsConcurrentCalls(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// TCP connects, but the collector never answers the TLS handshake.
	var local bytes.Buffer
	audit, err := NewAuditLog(&local, config.AuditSyslogConfig{Target: "tls://" + ln.Addr().String()}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	const count = 8
	var calls sync.WaitGroup
	start := time.Now()
	for i := range count {
		calls.Go(func() {
			audit.write(auditEvent{Timestamp: time.Now().UTC(), ID: strconv.Itoa(i), Transport: "http", Method: "tools/list", Outcome: "ok"})
		})
	}
	calls.Wait()
	if elapsed := time.Since(start); elapsed > 3*syslogTimeout {
		t.Errorf("a stalled collector delayed concurrent calls for %s", elapsed)
	}
	if records := strings.Count(local.String(), "\n"); records != count {
		t.Errorf("local audit recorded %d of %d calls", records, count)
	}
}

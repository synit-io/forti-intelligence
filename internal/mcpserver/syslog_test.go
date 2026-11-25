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
func readAuditMessage(reader *bufio.Reader) (string, error) {
	prefix, err := reader.ReadString(' ')
	if err != nil {
		return "", err
	}
	size, err := strconv.Atoi(strings.TrimSuffix(prefix, " "))
	if err != nil || size <= 0 || size > 8192 {
		return "", fmt.Errorf("invalid syslog frame length %q", prefix)
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(reader, frame); err != nil {
		return "", err
	}
	fields := strings.SplitN(string(frame), " ", 8)
	if len(fields) != 8 || !strings.HasPrefix(fields[0], "<") || !strings.HasSuffix(fields[0], ">1") || fields[3] != "forti-intelligence" || fields[6] != "-" {
		return "", fmt.Errorf("invalid RFC 5424 header in %q", frame)
	}
	return fields[7], nil
}

func TestSyslogForwarding(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	fixture.Close()
	caFile := filepath.Join(t.TempDir(), "test-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, scheme, ca string
		badHostname      bool
		refuseFirst      bool
		failsTLS         bool
	}{
		{name: "plaintext", scheme: "tcp"},
		{name: "trusted TLS reconnects after outage", scheme: "tls", ca: caFile, refuseFirst: true},
		{name: "untrusted TLS", scheme: "tls", failsTLS: true},
		{name: "TLS hostname mismatch", scheme: "tls", ca: caFile, badHostname: true, failsTLS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			address := ln.Addr().String()
			if tc.badHostname {
				address = fmt.Sprintf("localhost:%d", ln.Addr().(*net.TCPAddr).Port)
			}
			var local, diagnostics bytes.Buffer
			cfg := config.AuditSyslogConfig{Target: tc.scheme + "://" + address, CAFile: tc.ca}
			audit, err := NewAuditLog(&local, cfg, slog.New(slog.NewTextHandler(&diagnostics, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer audit.Close()

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
				message, err := readAuditMessage(bufio.NewReader(conn))
				if err != nil {
					remote <- err.Error()
					return
				}
				remote <- message
			}()
			event := auditEvent{Timestamp: time.Now().UTC(), ID: "first", Transport: "http", Method: "tools/list", Outcome: "ok"}
			audit.write(event)
			if tc.refuseFirst {
				event.ID = "second"
				audit.write(event)
			}
			lines := strings.Split(strings.TrimSuffix(local.String(), "\n"), "\n")
			wantLines := 1
			if tc.refuseFirst {
				wantLines++
			}
			if len(lines) != wantLines || !strings.Contains(lines[0], `"audit_id":"first"`) {
				t.Fatalf("local audit records: %q", lines)
			}
			select {
			case received := <-remote:
				if tc.failsTLS {
					if received != "TLS handshake failed" {
						t.Fatalf("collector accepted invalid TLS: %q", received)
					}
				} else if !json.Valid([]byte(received)) || received != lines[len(lines)-1] {
					t.Fatalf("collector received %q, local records %q", received, lines)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("collector did not finish")
			}
			if (tc.refuseFirst || tc.failsTLS) != strings.Contains(diagnostics.String(), "WARN") {
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
		message, err := readAuditMessage(reader)
		if err != nil || !json.Valid([]byte(message)) || !localRecords[message] {
			t.Fatalf("collector received %q: %v", message, err)
		}
		delete(localRecords, message)
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

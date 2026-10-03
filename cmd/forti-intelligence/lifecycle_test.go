package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/mcpserver"
	"github.com/synit-io/forti-intelligence/internal/service"
)

type listenerLog struct{ started chan string }

func (h listenerLog) Enabled(context.Context, slog.Level) bool { return true }
func (h listenerLog) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h listenerLog) WithGroup(string) slog.Handler            { return h }
func (h listenerLog) Handle(_ context.Context, record slog.Record) error {
	if record.Message == "streamable HTTP server listening" {
		record.Attrs(func(attr slog.Attr) bool {
			if attr.Key == "address" {
				h.started <- attr.Value.String()
			}
			return true
		})
	}
	return nil
}

func lifecycleServer() *mcpserver.Server {
	cfg := config.Default()
	return mcpserver.New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestHTTPStartupRejectsOccupiedAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	err = runHTTP(context.Background(), lifecycleServer(), listener.Addr().String(), "/mcp", "", time.Second, time.Second, slog.Default(), nil, nil)
	var networkError *net.OpError
	if !errors.As(err, &networkError) || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("startup error=%v", err)
	}
}

func TestHTTPShutdownDrainsOrClosesActiveRequest(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		name, shutdownTimeout := "drain", time.Second
		if timeout {
			name, shutdownTimeout = "timeout", 30*time.Millisecond
		}
		t.Run(name, func(t *testing.T) {
			entered, release, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			ctx, cancel := context.WithCancel(context.Background())
			started := make(chan string, 1)
			finished, stopped := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(stopped)
				finished <- runHTTP(ctx, lifecycleServer(), "127.0.0.1:0", "/mcp", "", time.Second, shutdownTimeout, slog.New(listenerLog{started}), nil, func() bool {
					close(entered)
					<-release
					close(handlerDone)
					return true
				})
			}()
			t.Cleanup(func() {
				releaseOnce.Do(func() { close(release) })
				cancel()
				select {
				case <-stopped:
				case <-time.After(3 * time.Second):
					t.Error("HTTP server did not stop")
				}
			})
			var address string
			select {
			case address = <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("HTTP server did not start")
			}
			requestDone := make(chan error, 1)
			go func() {
				client := &http.Client{Timeout: 2 * time.Second}
				response, err := client.Get("http://" + address + "/ready")
				if err == nil {
					response.Body.Close()
					if response.StatusCode != http.StatusOK {
						err = fmt.Errorf("ready status=%d", response.StatusCode)
					}
				}
				requestDone <- err
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("ready request did not reach the handler")
			}
			cancel()
			if !timeout {
				select {
				case err := <-finished:
					t.Fatalf("shutdown returned before active request finished: %v", err)
				case <-time.After(50 * time.Millisecond):
				}
				releaseOnce.Do(func() { close(release) })
			}
			select {
			case err := <-finished:
				if timeout && !errors.Is(err, context.DeadlineExceeded) || !timeout && err != nil {
					t.Fatalf("shutdown error=%v timeout=%v", err, timeout)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("HTTP shutdown exceeded its deadline")
			}
			if conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
				conn.Close()
				t.Fatal("HTTP listener remains open after shutdown")
			}
			select {
			case err := <-requestDone:
				if timeout && err == nil || !timeout && err != nil {
					t.Fatalf("active request error=%v timeout=%v", err, timeout)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("active connection remained open after shutdown")
			}
			releaseOnce.Do(func() { close(release) })
			<-handlerDone
		})
	}
}

// Run the real CLI in a child process so its flags, signals and exit paths
// cannot alter the test runner's process state.
func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("FORTI_TEST_CLI_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	os.Exit(0)
}

func cliCommand(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestCLIHelperProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "FORTI_TEST_CLI_HELPER=1")
	return cmd
}

func TestCLIVersionAndConfigurationFailure(t *testing.T) {
	out, err := cliCommand("--version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Forti Intelligence MCP Server version "+version) {
		t.Fatalf("version output=%s err=%v", out, err)
	}
	out, err = cliCommand("--config", filepath.Join(t.TempDir(), "missing.yaml")).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "configuration failed") {
		t.Fatalf("configuration failure output=%s err=%v", out, err)
	}
}

func TestCLIHTTPStartsAndStopsOnSignal(t *testing.T) {
	appliance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Params []map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		results := make([]any, 0, len(request.Params))
		for _, param := range request.Params {
			results = append(results, map[string]any{"url": param["url"], "status": map[string]any{"code": 0, "message": "OK"}, "data": []any{}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": results})
	}))
	defer appliance.Close()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := fmt.Sprintf("server:\n  http_bearer_token: test-token\nprofiles:\n  - name: test\n    product: fortimanager\n    url: %s\n    api_key: test-api-key\n    allow_insecure_http: true\n", appliance.URL)
	if err := os.WriteFile(configPath, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := cliCommand("--config", configPath, "--transport", "http", "--listen", "127.0.0.1:0", "--log-json")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	started, logsDone := make(chan string, 1), make(chan struct{})
	var logs bytes.Buffer
	go func() {
		defer close(logsDone)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			logs.WriteString(scanner.Text() + "\n")
			var record struct {
				Message string `json:"msg"`
				Address string `json:"address"`
			}
			if json.Unmarshal(scanner.Bytes(), &record) == nil && record.Message == "streamable HTTP server listening" {
				started <- record.Address
			}
		}
	}()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	wait, exited := make(chan error, 1), make(chan struct{})
	go func() { defer close(exited); wait <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-exited:
		default:
			_ = cmd.Process.Kill()
			<-exited
		}
		<-logsDone
	})
	var address string
	select {
	case address = <-started:
	case err := <-wait:
		<-logsDone
		t.Fatalf("CLI exited before listening: %v\n%s", err, logs.String())
	case <-time.After(5 * time.Second):
		t.Fatal("CLI did not start")
	}
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest(http.MethodGet, "http://"+address+"/ready", nil)
		request.Header.Set("Authorization", "Bearer test-token")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			ready = true
			break
		}
		if response.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("ready status=%d", response.StatusCode)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("CLI inventory never became ready")
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-wait:
		<-logsDone
		if err != nil || !strings.Contains(logs.String(), "HTTP server shutting down gracefully") {
			t.Fatalf("CLI shutdown err=%v\n%s", err, logs.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CLI did not stop on SIGINT")
	}
	if conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("CLI left its HTTP listener open")
	}
}

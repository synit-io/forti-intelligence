package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/mcpserver"
)

func TestInventoryHealthReportsReadiness(t *testing.T) {
	store := inventory.NewStore(map[string]fortinet.Manager{}, 0, 1)
	health := inventoryHealth(store)
	if health["inventory_ready"] != false || health["devices"] != 0 || inventoryReady(store) {
		t.Fatalf("health before refresh = %#v", health)
	}
	store.Refresh(context.Background())
	health = inventoryHealth(store)
	if health["inventory_ready"] != true || health["refresh_errors"] != 1 || health["inventory_generated_at"] == nil {
		t.Fatalf("health after refresh = %#v", health)
	}
	if !inventoryReady(store) {
		t.Fatal("ready became false after the first snapshot")
	}
	if _, ok := health["last_refresh_duration_seconds"].(float64); !ok {
		t.Fatalf("last refresh duration = %#v", health["last_refresh_duration_seconds"])
	}
}

func TestReadyStaysJSONAndAuthenticated(t *testing.T) {
	store := inventory.NewStore(map[string]fortinet.Manager{}, 0, 1)
	mcp := &mcpserver.Server{}
	mux := newHTTPMux(http.NotFoundHandler(), "/mcp", "secret", mcp, func() map[string]any {
		return inventoryHealth(store)
	}, func() bool { return inventoryReady(store) })

	unready := httptest.NewRecorder()
	mux.ServeHTTP(unready, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if unready.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /ready = %d", unready.Code)
	}

	notReady := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)
	request.Header.Set("Authorization", "bearer secret")
	mux.ServeHTTP(notReady, request)
	if notReady.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ready before snapshot = %d", notReady.Code)
	}
	if ct := notReady.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type = %q", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(notReady.Body.Bytes(), &body); err != nil || body["ready"] != false {
		t.Fatalf("body = %s err=%v", notReady.Body.Bytes(), err)
	}

	store.Refresh(context.Background())
	ready := httptest.NewRecorder()
	mux.ServeHTTP(ready, request)
	if ready.Code != http.StatusOK {
		t.Fatalf("/ready after snapshot = %d %s", ready.Code, ready.Body.Bytes())
	}

	var metricsBody string
	for _, path := range []string{"/healthz", "/metrics"} {
		denied := httptest.NewRecorder()
		mux.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, path, nil))
		if denied.Code != http.StatusUnauthorized {
			t.Fatalf("%s without token = %d", path, denied.Code)
		}
		allowedRequest := request.Clone(request.Context())
		allowedRequest.URL.Path = path
		allowed := httptest.NewRecorder()
		mux.ServeHTTP(allowed, allowedRequest)
		if allowed.Code != http.StatusOK {
			t.Fatalf("%s with token = %d %s", path, allowed.Code, allowed.Body.Bytes())
		}
		if path == "/metrics" {
			metricsBody = allowed.Body.String()
		}
	}
	if !strings.Contains(metricsBody, "forti_intelligence_up 1") || !strings.Contains(metricsBody, "forti_intelligence_inventory_ready 1") {
		t.Fatalf("metrics = %s", metricsBody)
	}
}

func TestRunHealthcheck(t *testing.T) {
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer open.Close()
	t.Setenv("FORTI_MCP_HTTP_TOKEN", "")
	if code := runHealthcheck(open.URL); code != 0 {
		t.Fatalf("open probe = %d", code)
	}

	guarded := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer guarded.Close()
	t.Setenv("FORTI_MCP_HTTP_TOKEN", "secret")
	if code := runHealthcheck(guarded.URL); code != 0 {
		t.Fatalf("authorized probe = %d", code)
	}
	t.Setenv("FORTI_MCP_HTTP_TOKEN", "wrong")
	if code := runHealthcheck(guarded.URL); code == 0 {
		t.Fatal("wrong token was accepted")
	}
	if code := runHealthcheck("http://127.0.0.1:1/"); code == 0 {
		t.Fatal("unreachable probe succeeded")
	}
	if code := runHealthcheck("://bad"); code == 0 {
		t.Fatal("invalid URL succeeded")
	}
}

func TestOperationalRoutesStayOpenWithoutToken(t *testing.T) {
	mux := newHTTPMux(http.NotFoundHandler(), "/mcp", "", &mcpserver.Server{}, func() map[string]any {
		return map[string]any{"inventory_ready": false}
	}, func() bool { return false })
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("healthz = %d %s", response.Code, body)
	}
}

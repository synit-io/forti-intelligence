package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

// TestInventoryUsesProfileKeyWhenRatingAccountIsConfigured mirrors main's
// wiring and records which API key each request carries.
func TestInventoryUsesProfileKeyWhenRatingAccountIsConfigured(t *testing.T) {
	var mu sync.Mutex
	keysByResource := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		_ = json.NewDecoder(r.Body).Decode(&request)
		params, _ := request["params"].([]any)
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		result := make([]any, 0, len(params))
		for _, raw := range params {
			param, _ := raw.(map[string]any)
			resource, _ := param["url"].(string)
			mu.Lock()
			keysByResource[resource] = key
			mu.Unlock()
			if key != "profile-key" && resource != "/sys/proxy/json" {
				result = append(result, map[string]any{"url": resource, "status": map[string]any{"code": -11, "message": "No permission for the resource"}})
				continue
			}
			item := map[string]any{"url": resource, "status": map[string]any{"code": 0}}
			if strings.HasSuffix(resource, "/device") {
				item["data"] = []any{map[string]any{"name": "test-device-05", "conn_status": "up"}}
			}
			result = append(result, item)
		}
		if len(result) == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": result})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": result})
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-primary", Product: config.ProductFortiManager, URL: server.URL, APIKey: "profile-key", AllowInsecureHTTP: true, ADOMs: []string{"test-adom-primary"}, Default: true}}
	cfg.Rating = config.RatingConfig{Device: "test-device-05", APIKey: "rating-key"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	managers, _, closeClients, err := buildClients(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClients()
	ratingProfile, err := cfg.RatingProfile()
	if err != nil {
		t.Fatal(err)
	}
	ratingClient, err := fortinet.NewFortiManagerRatingClient(ratingProfile)
	if err != nil {
		t.Fatal(err)
	}
	store := inventory.NewStore(managers, 0, 1)
	snapshot := store.Refresh(context.Background())
	if len(snapshot.Devices) != 1 || len(snapshot.Errors) != 0 {
		t.Fatalf("inventory devices=%d errors=%#v", len(snapshot.Devices), snapshot.Errors)
	}
	_, _ = ratingClient.LookupURLRating(context.Background(), "test-adom-primary", "test-device-05", "root", "www.heise.de")
	mu.Lock()
	defer mu.Unlock()
	if keysByResource["/dvmdb/adom/test-adom-primary/device"] != "profile-key" {
		t.Fatalf("inventory used key %q, want the profile key", keysByResource["/dvmdb/adom/test-adom-primary/device"])
	}
	if keysByResource["/sys/proxy/json"] != "rating-key" {
		t.Fatalf("rating used key %q, want the rating key", keysByResource["/sys/proxy/json"])
	}
}

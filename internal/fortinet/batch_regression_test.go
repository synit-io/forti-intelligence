package fortinet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func TestReadBatchesBoundMultiVDOMFanout(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []map[string]any `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		calls++
		if len(req.Params) > 8 {
			t.Errorf("unbounded batch: %d", len(req.Params))
		}
		var result []any
		for _, param := range req.Params {
			result = append(result, map[string]any{"url": param["url"], "status": map[string]any{"code": 0}})
		}
		json.NewEncoder(w).Encode(map[string]any{"result": result})
	}))
	defer server.Close()
	client, err := NewFortiManager(config.ProfileConfig{Name: "test", Product: config.ProductFortiManager, URL: server.URL, APIKey: "test", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	var params []map[string]any
	for i := range 17 {
		params = append(params, map[string]any{"url": fmt.Sprintf("/vdom/%d/system/zone", i)})
	}
	items, err := client.callBatchWithSingleFallback(context.Background(), "", params)
	if err != nil || len(items) != 17 || calls != 3 {
		t.Fatalf("items=%d calls=%d err=%v", len(items), calls, err)
	}
}

func TestBatchMatchesResources(t *testing.T) {
	for _, mode := range []string{"reordered", "missing", "unexpected", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				urls := []string{"/b", "/a"}
				switch mode {
				case "missing":
					urls = []string{"/b"}
				case "unexpected":
					urls = []string{"/b", "/unknown"}
				case "duplicate":
					urls = []string{"/b", "/b"}
				}
				var result []any
				for _, url := range urls {
					result = append(result, map[string]any{"url": url, "status": map[string]any{"code": 0}})
				}
				json.NewEncoder(w).Encode(map[string]any{"result": result})
			}))
			defer server.Close()
			client, err := newRPCClient(config.ProfileConfig{Name: "test", URL: server.URL, APIKey: "test", AllowInsecureHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			items, err := client.callBatch(context.Background(), "get", []map[string]any{{"url": "/a"}, {"url": "/b"}})
			if mode == "unexpected" || mode == "duplicate" {
				if err == nil {
					t.Fatal("ambiguous response accepted")
				}
				return
			}
			if err != nil || len(items) != 2 {
				t.Fatalf("items=%v err=%v", items, err)
			}
			if mode == "missing" {
				if items[0].Err == nil {
					t.Fatal("missing item accepted")
				}
			} else if items[0].Value.(map[string]any)["url"] != "/a" {
				t.Fatal("wrong resource assigned")
			}
			if items[1].Value.(map[string]any)["url"] != "/b" {
				t.Fatal("wrong resource assigned")
			}
		})
	}
}

func TestBatchRenewsExpiredItemSession(t *testing.T) {
	logins, reads := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "exec" {
			logins++
			json.NewEncoder(w).Encode(map[string]any{"session": "fresh", "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
			return
		}
		reads++
		code, message := 0, "OK"
		if reads == 1 {
			code, message = -11, "Invalid session"
		}
		json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"url": "/a", "status": map[string]any{"code": code, "message": message}}}})
	}))
	defer server.Close()
	client, err := newRPCClient(config.ProfileConfig{Name: "test", URL: server.URL, Username: "test", Password: "test", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	client.session = "expired"
	items, err := client.callBatch(context.Background(), "get", []map[string]any{{"url": "/a"}})
	if err != nil || len(items) != 1 || items[0].Err != nil || logins != 1 || reads != 2 {
		t.Fatalf("items=%v err=%v logins=%d reads=%d", items, err, logins, reads)
	}
}

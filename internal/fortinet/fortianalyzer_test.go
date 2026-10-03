package fortinet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func TestLogSearchCountDescribesReturnedPage(t *testing.T) {
	for _, size := range []int{0, 2} {
		records := make([]any, size)
		for i := range records {
			records[i] = map[string]any{"srcip": "10.0.0.1"}
		}
		result := logSearchResult("faz", LogSearchRequest{Limit: 25}, "", "42", 0, 25, map[string]any{"total-count": 100, "percentage": 100, "data": records}, false, nil)
		if result.Count != size || result.TotalCount != 100 {
			t.Fatalf("count=%d total=%d, want %d/100", result.Count, result.TotalCount, size)
		}
	}
}

func TestFortiAnalyzerSessionStatusAndTwoStepLogSearch(t *testing.T) {
	var resources []string
	logFetches := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		resource := ""
		if len(params) > 0 {
			resource, _ = params[0].(map[string]any)["url"].(string)
		}
		resources = append(resources, resource)
		w.Header().Set("Content-Type", "application/json")
		switch resource {
		case "/sys/login/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "session": "faz-session", "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		case "/sys/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": map[string]any{"Hostname": "faz-1", "Version": "v7.6"}}}})
		case "/logview/adom/test-adom-primary/logsearch":
			if request["method"] != "add" {
				t.Errorf("submit method = %v, want add", request["method"])
			}
			parameter, _ := params[0].(map[string]any)
			devices, ok := parameter["device"].([]any)
			if !ok || len(devices) != 1 {
				t.Fatalf("search device selector = %#v, want one All_Devices selector", parameter["device"])
			}
			device, _ := devices[0].(map[string]any)
			if device["devid"] != "All_Devices" {
				t.Errorf("search device selector = %#v, want devid All_Devices", device)
			}
			if parameter["limit"] != float64(10) || parameter["offset"] != float64(0) {
				t.Errorf("search pagination = %#v, want top-level limit/offset", parameter)
			}
			if _, nested := parameter["data"]; nested {
				t.Error("search parameters unexpectedly nested under data")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"status": map[string]any{"code": 0}, "data": map[string]any{"tid": 42}}})
		case "/logview/adom/test-adom-primary/logsearch/42":
			if request["method"] != "get" {
				t.Errorf("result method = %v, want get", request["method"])
			}
			parameter, _ := params[0].(map[string]any)
			if parameter["limit"] != float64(10) || parameter["offset"] != float64(0) {
				t.Errorf("fetch pagination = %#v, want top-level limit/offset", parameter)
			}
			logFetches++
			if logFetches == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{
					"percentage": 25, "total-count": 1, "status": map[string]any{"code": 0, "message": "running"},
				}})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{
					"percentage": 100, "total-count": 1, "status": map[string]any{"code": 0, "message": "succeeded"},
					"data": []any{map[string]any{"srcip": "10.0.0.1", "dstport": 443}},
				}})
			}
		case "/sys/logout":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		}
	}))
	defer server.Close()

	client, err := NewFortiAnalyzer(config.ProfileConfig{Name: "faz", Product: config.ProductFortiAnalyzer, URL: server.URL, Username: "api", Password: "secret", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if statusMap, ok := status.(map[string]any); !ok || statusMap["Hostname"] != "faz-1" {
		t.Fatalf("Status() = %#v", status)
	}
	zone := time.FixedZone("CEST", 2*60*60)
	start := time.Date(2026, 9, 22, 14, 5, 0, 0, zone)
	end := start.Add(5 * time.Minute)
	result, err := client.SearchLogs(ctx, LogSearchRequest{
		ADOM: "test-adom-primary", LogType: "traffic", Filter: "srcip=10.0.0.1", StartTime: start, EndTime: end, Device: "fgt-1", Limit: 10,
	})
	if err != nil {
		t.Fatalf("SearchLogs() error = %v", err)
	}
	if result.TaskID != "42" || result.Count != 1 || result.TotalCount != 1 || result.Progress != 100 || !result.Complete {
		t.Fatalf("SearchLogs() = %#v", result)
	}
	if result.Profile != "faz" || result.Device != "fgt-1" || result.LogType != "traffic" || result.StartTime != start || result.EndTime != end || result.Timezone != "CEST (UTC+02:00)" || !strings.Contains(result.Filter, "devname=\"fgt-1\"") {
		t.Fatalf("SearchLogs() metadata = %#v", result)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(resources) != 6 {
		t.Fatalf("resources = %#v, want login, status, submit, two fetches, logout", resources)
	}
}

func TestFortiAnalyzerLogSearchRejectsUnsafeBounds(t *testing.T) {
	client, err := NewFortiAnalyzer(config.ProfileConfig{
		Name: "faz", Product: config.ProductFortiAnalyzer, URL: "https://faz.invalid", Username: "api", Password: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for _, request := range []LogSearchRequest{
		{Offset: -1},
		{StartTime: time.Date(2026, 9, 21, 2, 0, 0, 0, time.UTC), EndTime: time.Date(2026, 9, 21, 1, 0, 0, 0, time.UTC)},
	} {
		if _, err := client.SearchLogs(context.Background(), request); err == nil {
			t.Fatalf("SearchLogs(%#v) error = nil", request)
		}
	}
}

func TestFortiAnalyzerDeviceTypeErrorIsActionable(t *testing.T) {
	info := classifyError(-32002, 0, "Invalid params: Device type is unknown!", nil)
	if info.Kind != ErrorKindInvalid || info.Code != -32002 || info.Retryable {
		t.Fatalf("classifyError() = %#v, want non-retryable invalid request", info)
	}
	if !strings.Contains(info.Hint, `device:[{"devid":"All_Devices"}]`) {
		t.Fatalf("classifyError() hint = %q, want device selector guidance", info.Hint)
	}
}

func TestFortiAnalyzerAPIV3ReadUsesTopLevelParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer key-123" {
			t.Errorf("Authorization = %q, want bearer API key", r.Header.Get("Authorization"))
		}
		if token := r.URL.Query().Get("access_token"); token != "" {
			t.Errorf("access_token query parameter = %q, want API key header only", token)
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		parameter, _ := params[0].(map[string]any)
		if parameter["apiver"] != float64(3) || parameter["limit"] != float64(25) {
			t.Errorf("API-v3 parameter envelope = %#v", parameter)
		}
		if _, nested := parameter["data"]; nested {
			t.Error("FortiAnalyzer API-v3 options unexpectedly nested under data")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{
			"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "object"}},
		}})
	}))
	defer server.Close()

	client, err := NewFortiAnalyzer(config.ProfileConfig{
		Name: "faz-key", Product: config.ProductFortiAnalyzer, URL: server.URL, APIKey: "key-123", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	value, err := client.Read(context.Background(), "/fortiview/adom/test-adom-primary/fgt-policy-src/run", map[string]any{"limit": 25})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if records, ok := value.([]any); !ok || len(records) != 1 {
		t.Fatalf("Read() = %#v, want one record", value)
	}
}

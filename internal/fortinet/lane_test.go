package fortinet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func init() {
	permissionRecheckDelay = 10 * time.Millisecond
}

func TestRequestsShareOneLanePerCredential(t *testing.T) {
	var inFlight, maxInFlight atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := inFlight.Add(1)
		for {
			seen := maxInFlight.Load()
			if current <= seen || maxInFlight.CompareAndSwap(seen, current) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		inFlight.Add(-1)
		request, _ := decodeRPC(t, r)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for index := range 8 {
		wg.Add(1)
		go func(adom string) {
			defer wg.Done()
			if _, err := client.ListWebFilterProfiles(context.Background(), adom); err != nil {
				t.Errorf("read %s: %v", adom, err)
			}
		}([]string{"test-adom-primary", "test-adom-tenant-internal", "test-adom-secondary"}[index%3])
	}
	wg.Wait()
	if maxInFlight.Load() != 1 {
		t.Fatalf("max concurrent requests = %d, want 1 per credential", maxInFlight.Load())
	}
}

func TestPermissionDenialIsRecheckedOnce(t *testing.T) {
	var calls atomic.Int32
	persistent := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		resource, _ := parameter["url"].(string)
		if calls.Add(1) == 1 || persistent {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": -11, "message": "No permission for the resource"}, "url": resource}}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "corp-web"}}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := client.ListWebFilterProfiles(context.Background(), "test-adom-primary")
	if err != nil || len(profiles) != 1 || calls.Load() != 2 || client.TransientDenials() != 1 {
		t.Fatalf("transient denial: profiles=%v err=%v calls=%d transient=%d", profiles, err, calls.Load(), client.TransientDenials())
	}
	persistent = true
	calls.Store(0)
	_, err = client.ListWebFilterProfiles(context.Background(), "test-adom-primary")
	if err == nil || calls.Load() != 2 || DescribeError(err).Kind != ErrorKindPermission || !strings.Contains(err.Error(), "denied this read twice") {
		t.Fatalf("persistent denial: err=%v calls=%d", err, calls.Load())
	}
}

func TestProxyErrorIncludesFortiGateResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, _ := decodeRPC(t, r)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{
			"status": map[string]any{"code": 0}, "url": "/sys/proxy/json",
			"data": []any{map[string]any{"target": "adom/test-adom-primary/device/fgt", "status": map[string]any{"code": -6, "message": "Invalid url"}, "response": map[string]any{"http_status": 404, "status": "error"}}},
		}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ProxyGet(context.Background(), "test-adom-primary", "fgt", "", "/api/v2/monitor/firewall/policy-lookup/?srcintf=port1")
	if err == nil || !strings.Contains(err.Error(), "FortiGate response") || !strings.Contains(err.Error(), "404") {
		t.Fatalf("proxy error = %v, want FortiGate response detail", err)
	}
}

// fortiOS74RatingServer models the observed FortiOS 7.4 behavior: the base
// path answers GET with HTTP 405, and FortiManager refuses proxied POST for a
// read-only account. arrayWorks controls whether GET select with url=[...]
// succeeds.
func fortiOS74RatingServer(t *testing.T, arrayWorks bool, posts, gets *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		data, _ := parameter["data"].(map[string]any)
		resource, _ := data["resource"].(string)
		reply := func(status map[string]any, response any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "url": "/sys/proxy/json", "data": []any{map[string]any{"target": "fgt", "status": status, "response": response}}}}})
		}
		if data["action"] == "post" {
			posts.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": -11, "message": "No permission for the resource"}, "url": "/sys/proxy/json"}}})
			return
		}
		gets.Add(1)
		switch {
		case !strings.Contains(resource, "/rating-lookup/select"):
			reply(map[string]any{"code": -6, "message": "Invalid url"}, map[string]any{"http_status": 405, "action": "", "name": "rating-lookup", "path": "utm"})
		case strings.Contains(resource, "%5B") && arrayWorks:
			reply(map[string]any{"code": 0}, map[string]any{"results": []any{map[string]any{"url": "www.google.de", "category": 41, "categoryname": "Search Engines and Portals"}}})
		default:
			reply(map[string]any{"code": -6, "message": "Invalid url"}, map[string]any{"http_status": 405, "action": "select", "name": "rating-lookup", "path": "utm"})
		}
	}))
}

func TestRatingLookupRemembersWorkingSelectForm(t *testing.T) {
	var posts, gets atomic.Int32
	server := fortiOS74RatingServer(t, true, &posts, &gets)
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	rating, err := client.LookupURLRating(context.Background(), "test-adom-primary", "test-device-05", "root", "www.google.de")
	if err != nil || len(rating.CategoryIDs) != 1 || rating.CategoryIDs[0] != 41 {
		t.Fatalf("rating = %#v err = %v", rating, err)
	}
	if gets.Load() != 2 || posts.Load() != 1 {
		t.Fatalf("first lookup gets=%d posts=%d, want the refused POST, then plain and array GET select", gets.Load(), posts.Load())
	}
	gets.Store(0)
	if _, err := client.LookupURLRating(context.Background(), "test-adom-primary", "test-device-05", "root", "www.google.de"); err != nil {
		t.Fatal(err)
	}
	if gets.Load() != 1 {
		t.Fatalf("second lookup gets=%d, want the remembered form first", gets.Load())
	}
}

func TestRatingLookupReportsAndCachesPostOnlyReleaseForReadOnlyAccount(t *testing.T) {
	var posts, gets atomic.Int32
	server := fortiOS74RatingServer(t, false, &posts, &gets)
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.LookupURLRating(context.Background(), "test-adom-secondary", "test-device-rating", "root", "www.heise.de")
	info := DescribeError(err)
	if err == nil || info.Kind != ErrorKindPermission || !strings.Contains(info.Hint, "rating.api_key") || info.FortiGateStatus != 405 {
		t.Fatalf("error = %v info = %#v", err, info)
	}
	// One compact line per attempt, no repeated FortiGate payloads.
	if strings.Count(err.Error(), "FortiGate response") != 0 || !strings.Contains(err.Error(), "GET select url: FortiGate HTTP 405") || !strings.Contains(err.Error(), "POST select: FortiManager code -11") {
		t.Fatalf("error text = %q", err.Error())
	}
	if posts.Load() != 1 || gets.Load() != 2 {
		t.Fatalf("posts=%d gets=%d", posts.Load(), gets.Load())
	}
	// Known-impossible proxy rating is not retried for ratingBlockTTL.
	_, err = client.LookupURLRating(context.Background(), "test-adom-tenant-internal", "test-device-proxy", "root", "www.heise.de")
	if err == nil || DescribeError(err).Kind != ErrorKindPermission || !strings.Contains(err.Error(), "unavailable for this API account") || posts.Load() != 1 || gets.Load() != 2 {
		t.Fatalf("cached result: err=%v posts=%d gets=%d", err, posts.Load(), gets.Load())
	}
	// After the block expires the POST is asked again: the account may have
	// been granted Read-Write, or the refusal was a transient -11.
	client.ratingMu.Lock()
	client.ratingBlockedUntil = time.Now().Add(-time.Second)
	client.ratingMu.Unlock()
	_, _ = client.LookupURLRating(context.Background(), "test-adom-secondary", "test-device-rating", "root", "www.heise.de")
	if posts.Load() != 2 {
		t.Fatalf("posts after block expiry = %d, want the POST retried", posts.Load())
	}
	if hint := fortiOSStatusHint(405); !strings.Contains(hint, "HTTP 405") {
		t.Fatalf("405 hint = %q", hint)
	}
}

func TestEmptyListReferenceIsUnset(t *testing.T) {
	if value := firstStringValue([]any{}); value != "" {
		t.Fatalf("firstStringValue([]) = %q", value)
	}
	profiles := parseWebFilterProfiles(map[string]any{"data": []any{map[string]any{"name": "p", "web": map[string]any{"urlfilter-table": []any{}}}}})
	if profiles[0].URLFilterTable != "" {
		t.Fatalf("URLFilterTable = %q, want empty", profiles[0].URLFilterTable)
	}
}

func TestFortiAnalyzerRangeUsesOneTimeZone(t *testing.T) {
	var sent []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		if timeRange, ok := parameter["time-range"].(map[string]any); ok {
			sent = append(sent, timeRange)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"status": map[string]any{"code": 0}, "tid": 1}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"percentage": 100, "status": map[string]any{"code": 0, "message": "succeeded"}, "data": []any{}}})
	}))
	defer server.Close()
	client, err := NewFortiAnalyzer(apiKeyProfile("faz", config.ProductFortiAnalyzer, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	cest := time.FixedZone("CEST", 2*3600)
	start := time.Now().In(cest).Add(-2 * time.Hour)
	// Start with +02:00 and no end: the default end must be in the same zone.
	if _, err := client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "test-adom-primary", StartTime: start}); err != nil {
		t.Fatal(err)
	}
	// Mixed zones: start in +02:00, end in UTC.
	end := time.Now().UTC()
	if _, err := client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "test-adom-primary", StartTime: start, EndTime: end}); err != nil {
		t.Fatal(err)
	}
	for index, timeRange := range sent {
		if timeRange["start"].(string) >= timeRange["end"].(string) {
			t.Fatalf("range %d sent reversed: %#v", index, timeRange)
		}
	}
	if sent[1]["end"] != end.In(cest).Format(logSearchTimeFormats[0]) || !strings.HasSuffix(sent[1]["end"].(string), "+02:00") {
		t.Fatalf("mixed-zone end = %v, want it in the start's zone", sent[1]["end"])
	}
	if info := classifyError(-32603, 0, "Internal error: the start time is later than the end time", nil); info.Kind != ErrorKindInvalid || !strings.Contains(info.Hint, "same time zone") {
		t.Fatalf("classification = %#v", info)
	}
}

// TestDeniedDeviceReadIsRereadInItsADOM simulates FortiManager evaluating
// ADOM-less device paths in the ADOM of the previous request.
func TestDeniedDeviceReadIsRereadInItsADOM(t *testing.T) {
	var mu sync.Mutex
	adomContext := "test-adom-primary"
	var resources []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     any              `json:"id"`
			Params []map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		mu.Lock()
		defer mu.Unlock()
		var response []any
		for _, param := range request.Params {
			resource, _ := param["url"].(string)
			resources = append(resources, resource)
			switch {
			case strings.HasPrefix(resource, "/dvmdb/adom/"):
				adomContext = strings.Split(resource, "/")[3]
				response = append(response, map[string]any{"url": resource, "status": map[string]any{"code": 0}, "data": []any{}})
			case adomContext != "test-adom-secondary":
				response = append(response, map[string]any{"url": resource, "status": map[string]any{"code": -11, "message": "No permission for the resource"}})
			default:
				response = append(response, map[string]any{"url": resource, "status": map[string]any{"code": 0}, "data": []any{map[string]any{"seq-num": 1, "dst": "0.0.0.0 0.0.0.0", "device": "wan1"}}})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request.ID, "result": response})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.ListRoutesBatch(ctxBackground, "test-adom-secondary", []RouteTarget{{Device: "test-device-route", VDOM: "root"}})
	if err != nil {
		t.Fatal(err)
	}
	if result := results["test-device-route"]; result.Err != nil || len(result.Routes) != 1 || !result.StaticOK {
		t.Fatalf("result = %#v, want routes after ADOM-aligned re-read", result)
	}
	if client.TransientDenials() == 0 {
		t.Fatal("recovered denials were not counted")
	}
	aligned := 0
	for _, resource := range resources {
		if resource == "/dvmdb/adom/test-adom-secondary/device" {
			aligned++
		}
	}
	if aligned != 1 {
		t.Fatalf("ADOM-aligned reads = %d, want exactly one per denied batch; resources=%v", aligned, resources)
	}
}

var ctxBackground = context.Background()

func TestProxyHTTP400ExplainsParameterRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, _ := decodeRPC(t, r)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{
			"status": map[string]any{"code": 0}, "url": "/sys/proxy/json",
			"data": []any{map[string]any{
				"response": map[string]any{"build": 2878, "http_method": "GET", "http_status": 400, "name": "policy-lookup", "path": "firewall", "status": "error", "vdom": "root", "version": "v7.4.11"},
				"status":   map[string]any{"code": -6, "message": "Invalid url"}, "target": "test-device-proxy",
			}},
		}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PolicyLookup(context.Background(), "test-adom-tenant-internal", "test-device-proxy", "root", PolicyLookupRequest{SourceIP: "10.49.0.7", DestinationIP: "10.0.7.3", DestinationPort: 88, Protocol: "tcp", SourceInterface: "z_ad_clients"})
	info := DescribeError(err)
	if err == nil || info.Kind != ErrorKindInvalid || !strings.Contains(info.Hint, "srcintf must be an interface name") || !strings.Contains(err.Error(), "v7.4.11") {
		t.Fatalf("error = %v hint = %q", err, info.Hint)
	}
}

func TestFortiAnalyzerAccessDeniedIsPermissionWithLogViewHint(t *testing.T) {
	info := classifyError(-32603, 0, "Internal error: Access denied. user=, userfrom=JSON(api_user).", nil)
	if info.Kind != ErrorKindPermission || info.Retryable || !strings.Contains(info.Hint, "Log View") || !strings.Contains(info.Hint, "method add") {
		t.Fatalf("classification = %#v", info)
	}
}

func TestRatingProxyCarriesTimeoutAndTimedOutExecIsNotRetried(t *testing.T) {
	var timeouts []any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		data, _ := parameter["data"].(map[string]any)
		timeouts = append(timeouts, data["timeout"])
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{
			"status": map[string]any{"code": 0}, "response": map[string]any{"results": []any{map[string]any{"url": "www.heise.de", "category": 36}}},
		}}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.LookupURLRating(context.Background(), "test-adom-primary", "fgt", "root", "www.heise.de"); err != nil {
		t.Fatal(err)
	}
	if len(timeouts) != 1 || timeouts[0] != float64(RatingProxyTimeoutSeconds) {
		t.Fatalf("proxy timeouts = %v, want %d", timeouts, RatingProxyTimeoutSeconds)
	}
	timeout := newRPCFailure(ErrorInfo{Kind: ErrorKindTimeout, Retryable: true, Message: "deadline"}, nil)
	unavailable := newRPCFailure(ErrorInfo{Kind: ErrorKindUnavailable, Retryable: true, Message: "reset"}, nil)
	if retryableRPC("exec", timeout) || !retryableRPC("exec", unavailable) || !retryableRPC("get", timeout) {
		t.Fatal("exec timeouts must not be retried; exec unavailability and get timeouts may be")
	}
}

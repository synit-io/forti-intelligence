package fortinet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func apiKeyProfile(name, product, url string) config.ProfileConfig {
	profile := config.ProfileConfig{Name: name, Product: product, URL: url, APIKey: "key", AllowInsecureHTTP: true}
	if product == config.ProductFortiAnalyzer {
		profile.ADOMs = []string{"test-adom-primary"}
	}
	return profile
}

func decodeRPC(t *testing.T, r *http.Request) (map[string]any, map[string]any) {
	t.Helper()
	var request map[string]any
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	params, _ := request["params"].([]any)
	if len(params) == 0 {
		return request, map[string]any{}
	}
	parameter, _ := params[0].(map[string]any)
	return request, parameter
}

func TestRPCRetriesTransientGetFailures(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, _ := decodeRPC(t, r)
		if calls.Add(1) < 3 {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": map[string]any{"Hostname": "fmg"}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	value, err := client.Read(context.Background(), "/sys/status", nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3 (two retries)", calls.Load())
	}
	if record, ok := value.(map[string]any); !ok || record["Hostname"] != "fmg" {
		t.Fatalf("Read() = %#v", value)
	}
}

func TestRPCDoesNotRetryTaskCreatingMethodOnServerError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()
	client, err := NewFortiAnalyzer(apiKeyProfile("faz", config.ProductFortiAnalyzer, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "test-adom-primary"})
	if err == nil {
		t.Fatal("SearchLogs() error = nil")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1 (add must not be retried after a response)", calls.Load())
	}
	if !retryableRPC("get", err) || retryableRPC("add", err) {
		t.Fatalf("retryableRPC for HTTP 500: get=%v add=%v, want get retried and add not", retryableRPC("get", err), retryableRPC("add", err))
	}
}

func TestProxyPostIsLimitedToRatingLookup(t *testing.T) {
	if !proxyPostAllowed("/api/v2/monitor/utm/rating-lookup/select?vdom=root") {
		t.Fatal("rating lookup select should be allowed")
	}
	if proxyPostAllowed("/api/v2/cmdb/firewall/address") || proxyPostAllowed("/api/v2/monitor/system/reboot") {
		t.Fatal("configuration or action resources must not be allowed for post")
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.proxyCall(context.Background(), "test-adom-primary", "fgt", "", "post", "/api/v2/cmdb/firewall/address", map[string]any{"name": "x"}); err == nil {
		t.Fatal("post to a cmdb resource must be rejected")
	}
	if calls.Load() != 0 {
		t.Fatal("rejected proxy post must not reach the appliance")
	}
}

func TestFortiManagerRatingLookupPostsSelectAndParsesCategories(t *testing.T) {
	var actions, resources []string
	var payloads []any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		data, _ := parameter["data"].(map[string]any)
		action, _ := data["action"].(string)
		resource, _ := data["resource"].(string)
		actions = append(actions, action)
		resources = append(resources, resource)
		payloads = append(payloads, data["payload"])
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{
			"status": map[string]any{"code": 0}, "response": map[string]any{"results": []any{map[string]any{"url": "www.example.com", "category": 52, "categoryname": "Information Technology"}}},
		}}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	rating, err := client.LookupURLRating(context.Background(), "test-adom-primary", "fgt", "", "www.example.com")
	if err != nil {
		t.Fatalf("LookupURLRating() error = %v", err)
	}
	if len(rating.CategoryIDs) != 1 || rating.CategoryIDs[0] != 52 || len(rating.CategoryNames) != 1 || rating.CategoryNames[0] != "Information Technology" {
		t.Fatalf("rating = %#v", rating)
	}
	// FortiOS 7.4 answers only POST, so it goes first: one request.
	payload, _ := json.Marshal(payloads[0])
	if len(actions) != 1 || actions[0] != "post" || resources[0] != "/api/v2/monitor/utm/rating-lookup/select" || string(payload) != `{"lang":"en","url":["www.example.com"]}` {
		t.Fatalf("actions = %v resources = %v payload = %s, want one POST select", actions, resources, payload)
	}
}

// FortiOS answers the rating in several shapes. Each lookup asks for one
// URL, so every record belongs to it whatever form the URL is echoed in.
func TestParseURLRatingAcceptsFortiOSVariants(t *testing.T) {
	envelope := func(response any) ProxyResult {
		return ProxyResult{Data: []any{map[string]any{"target": "fgt", "status": map[string]any{"code": 0}, "response": response}}}
	}
	cases := []struct {
		name     string
		response any
		ids      []int
		names    []string
	}{
		{"url echoed as list", map[string]any{"status": "success", "results": []any{map[string]any{"url": []any{"jacob-tks.com"}, "category": 90}}}, []int{90}, nil},
		{"unrated as text", map[string]any{"results": []any{map[string]any{"url": "jacob-tks.com", "category": "Unrated"}}}, []int{0}, nil},
		{"category unknown to the static table", map[string]any{"results": []any{map[string]any{"url": "jacob-tks.com", "category": "Artificial Intelligence Technology"}}}, nil, []string{"Artificial Intelligence Technology"}},
		{"other host form", map[string]any{"results": []any{map[string]any{"url": "http://www.jacob-tks.com/", "category_id": "52", "catdesc": "Information Technology"}}}, []int{52}, []string{"Information Technology"}},
		{"failed lookup id", map[string]any{"results": []any{map[string]any{"url": "jacob-tks.com", "category": -1}}}, nil, nil},
		{"no category", map[string]any{"results": []any{map[string]any{"url": "jacob-tks.com", "category": nil}}}, nil, nil},
	}
	for _, tc := range cases {
		rating := parseURLRating("jacob-tks.com", envelope(tc.response))
		if fmt.Sprint(rating.CategoryIDs) != fmt.Sprint(tc.ids) && !(len(rating.CategoryIDs) == 0 && len(tc.ids) == 0) {
			t.Errorf("%s: ids = %v, want %v", tc.name, rating.CategoryIDs, tc.ids)
		}
		if fmt.Sprint(rating.CategoryNames) != fmt.Sprint(tc.names) && !(len(rating.CategoryNames) == 0 && len(tc.names) == 0) {
			t.Errorf("%s: names = %v, want %v", tc.name, rating.CategoryNames, tc.names)
		}
	}
}

// An answer without a category is quoted in the error, stops after that
// form, and the answered form is tried first next time.
func TestRatingLookupQuotesAnswerWithoutCategory(t *testing.T) {
	var actions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		data, _ := parameter["data"].(map[string]any)
		action, _ := data["action"].(string)
		actions = append(actions, action)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{
			"status": map[string]any{"code": 0}, "response": map[string]any{"http_method": "POST", "status": "success", "results": []any{map[string]any{"url": "jacob-tks.com", "verdict": "pending"}}},
		}}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.LookupURLRating(context.Background(), "test-adom-primary", "fgt", "root", "jacob-tks.com")
	info := DescribeError(err)
	if err == nil || info.Kind != ErrorKindResponse || !strings.Contains(info.Message, `"verdict":"pending"`) || strings.Contains(info.Message, `"target":"fgt"`) || !strings.Contains(info.Hint, "check_web_filter") {
		t.Fatalf("error = %v info = %#v, want the FortiOS answer quoted without the proxy envelope", err, info)
	}
	if len(actions) != 1 || actions[0] != "post" {
		t.Fatalf("actions = %v, want only the answered POST", actions)
	}
	_, _ = client.LookupURLRating(context.Background(), "test-adom-primary", "fgt", "root", "jacob-tks.com")
	if len(actions) != 2 || actions[1] != "post" {
		t.Fatalf("actions = %v, want the answered form first again", actions)
	}
}

func TestParseWebFilterConfigurationObjects(t *testing.T) {
	profiles := parseWebFilterProfiles([]any{map[string]any{
		"status": map[string]any{"code": 0},
		"data": []any{map[string]any{
			"name": "corp-web", "comment": "c", "inspection-mode": "flow-based",
			"ftgd-wf": map[string]any{
				"options": []any{"rate-server-ip"},
				"filters": []any{
					map[string]any{"id": 1, "category": 37, "action": "block", "log": "enable"},
					map[string]any{"id": 2, "category": "52", "action": "monitor"},
					map[string]any{"id": 3, "category": "g01", "action": "warning", "warning-prompt": "per-domain"},
				},
			},
			"web": map[string]any{"urlfilter-table": []any{"corp-urls"}},
		}, map[string]any{
			"name":    "disabled-web",
			"ftgd-wf": []any{map[string]any{"options": []any{"ftgd-disable"}}},
		}},
	}})
	if len(profiles) != 2 {
		t.Fatalf("profiles = %#v", profiles)
	}
	corp := profiles[0]
	if corp.URLFilterTable != "corp-urls" || len(corp.Filters) != 3 || corp.Filters[0].Category != "37" || corp.Filters[1].Category != "52" || corp.Filters[2].Category != "g01" || corp.Filters[0].Action != "block" || !corp.Filters[0].Log {
		t.Fatalf("corp profile = %#v", corp)
	}
	if !profiles[1].FortiGuardDisabled {
		t.Fatalf("ftgd-disable option not detected: %#v", profiles[1])
	}

	tables := parseURLFilterTables(map[string]any{"data": []any{map[string]any{
		"id": 3, "name": "corp-urls",
		"entries": []any{map[string]any{"id": 1, "url": "*.bad.example", "type": "wildcard", "action": "block", "status": "enable", "exempt": []any{"av"}}},
	}}})
	if len(tables) != 1 || tables[0].ID != 3 || len(tables[0].Entries) != 1 || tables[0].Entries[0].Type != "wildcard" || tables[0].Entries[0].Exempt[0] != "av" {
		t.Fatalf("tables = %#v", tables)
	}

	names := parseCategoryNames([]any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{
		map[string]any{"id": 26, "name": "Malicious Websites"},
		map[string]any{"id": "140", "desc": "Intranet"},
		map[string]any{"id": 1},
	}}})
	if names[26] != "Malicious Websites" || names[140] != "Intranet" || len(names) != 2 {
		t.Fatalf("names = %#v", names)
	}

	policies := parsePolicies([]any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{
		"policyid": 10, "status": "enable", "utm-status": "enable", "profile-type": "group", "profile-group": []any{"grp-a"},
		"webfilter-profile": "corp-web", "ssl-ssh-profile": []any{"deep"}, "_scope": []any{map[string]any{"name": "edge-1", "vdom": "root"}},
	}}}})
	if len(policies) != 1 || policies[0].UTMStatus != "enable" || policies[0].ProfileType != "group" || policies[0].ProfileGroup != "grp-a" || policies[0].WebFilterProfile != "corp-web" || policies[0].SSLSSHProfile != "deep" {
		t.Fatalf("policies = %#v", policies)
	}
	if len(policies[0].Scope) != 1 || policies[0].Scope[0].Device != "edge-1" || policies[0].Scope[0].VDOM != "root" {
		t.Fatalf("scope = %#v", policies[0].Scope)
	}
}

func TestCategoryReferenceParsing(t *testing.T) {
	if id, ok := ParseCategoryReference("Malicious Websites"); !ok || id != 26 {
		t.Fatalf("name lookup = %d,%v", id, ok)
	}
	if id, ok := ParseCategoryReference(float64(52)); !ok || id != 52 {
		t.Fatalf("float lookup = %d,%v", id, ok)
	}
	if _, ok := ParseCategoryReference("g01"); ok {
		t.Fatal("group tokens must stay unresolved")
	}
}

func TestLogSearchStateReadsTotalLinesAndReturnLines(t *testing.T) {
	progress, total, complete := logSearchState(map[string]any{"percentage": 100, "total-lines": 7, "return-lines": 2, "data": []any{map[string]any{}, map[string]any{}}})
	if progress != 100 || total != 7 || !complete {
		t.Fatalf("state = %d %d %v", progress, total, complete)
	}
}

func TestFortiAnalyzerSearchConvertsTimezoneAndResumesTask(t *testing.T) {
	var submits, fetches int
	var sentRange map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		resource, _ := parameter["url"].(string)
		switch {
		case resource == "/logview/adom/test-adom-primary/logsearch":
			submits++
			sentRange, _ = parameter["time-range"].(map[string]any)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"status": map[string]any{"code": 0}, "tid": 7}})
		case strings.HasPrefix(resource, "/logview/adom/test-adom-primary/logsearch/7"):
			fetches++
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{
				"percentage": 100, "return-lines": 1, "total-count": 3, "status": map[string]any{"code": 0, "message": "succeeded"},
				"data": []any{map[string]any{"srcip": "10.0.0.1"}},
			}})
		default:
			t.Errorf("unexpected resource %q", resource)
		}
	}))
	defer server.Close()
	profile := apiKeyProfile("faz", config.ProductFortiAnalyzer, server.URL)
	profile.Timezone = "UTC"
	profile.ADOMs = []string{"test-adom-primary"}
	client, err := NewFortiAnalyzer(profile)
	if err != nil {
		t.Fatal(err)
	}
	zone := time.FixedZone("CEST", 2*60*60)
	start := time.Date(2026, 9, 22, 14, 5, 0, 0, zone)
	result, err := client.SearchLogs(context.Background(), LogSearchRequest{StartTime: start, EndTime: start.Add(time.Hour), Limit: 1})
	if err != nil {
		t.Fatalf("SearchLogs() error = %v", err)
	}
	if sentRange["start"] != "2026-09-22T12:05:00+00:00" || sentRange["end"] != "2026-09-22T13:05:00+00:00" {
		t.Fatalf("time-range sent = %#v, want ISO converted to UTC with its offset", sentRange)
	}
	if result.ApplianceTimezone != "UTC" || result.TimeRangeSent["start"] != "2026-09-22T12:05:00+00:00" || len(result.Warnings) != 0 {
		t.Fatalf("result metadata = %#v", result)
	}
	if !result.Complete || result.Count != 1 || result.TotalCount != 3 || !strings.Contains(result.Hint, "offset=1") || !strings.Contains(result.Hint, "without task_id") {
		t.Fatalf("result = %#v", result)
	}

	resumed, err := client.SearchLogs(context.Background(), LogSearchRequest{TaskID: "7", Offset: 1, Limit: 1})
	if err != nil {
		t.Fatalf("resume error = %v", err)
	}
	if !resumed.Resumed || resumed.TaskID != "7" || submits != 1 || fetches != 2 {
		t.Fatalf("resume = %#v submits=%d fetches=%d", resumed, submits, fetches)
	}
	// The resumed search reports the query it was submitted with.
	if resumed.LogType != "traffic" || !resumed.StartTime.Equal(start) || resumed.TimeRangeSent["start"] != "2026-09-22T12:05:00+00:00" || len(resumed.Warnings) != 0 {
		t.Fatalf("resumed metadata = %#v", resumed)
	}
}

func TestFortiAnalyzerReusesAnIdenticalSearch(t *testing.T) {
	var submits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		resource, _ := parameter["url"].(string)
		if resource == "/logview/adom/test-adom-primary/logsearch" {
			submits++
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"status": map[string]any{"code": 0}, "tid": 11}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{
			"percentage": 100, "total-count": 1, "status": map[string]any{"code": 0, "message": "succeeded"},
			"data": []any{map[string]any{"srcip": "10.0.0.1"}},
		}})
	}))
	defer server.Close()
	client, err := NewFortiAnalyzer(apiKeyProfile("faz", config.ProductFortiAnalyzer, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 9, 22, 14, 5, 0, 0, time.UTC)
	request := LogSearchRequest{StartTime: start, EndTime: start.Add(time.Hour), Limit: 25, Filter: `srcip="10.0.0.1"`}
	if _, err := client.SearchLogs(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	reused, err := client.SearchLogs(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if submits != 1 || !reused.Resumed || !strings.Contains(strings.Join(reused.Warnings, " "), "Reused log search task") {
		t.Fatalf("reused = %#v submits=%d", reused, submits)
	}
	request.Limit = 50
	if _, err := client.SearchLogs(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if submits != 2 {
		t.Fatalf("submits = %d, a different limit is a different search", submits)
	}
}

func TestFortiAnalyzerSearchFallsBackToLegacyTimeFormat(t *testing.T) {
	var ranges []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		resource, _ := parameter["url"].(string)
		if resource == "/logview/adom/test-adom-primary/logsearch" {
			timeRange, _ := parameter["time-range"].(map[string]any)
			ranges = append(ranges, timeRange)
			// This release accepts only the space-separated legacy form.
			if strings.Contains(timeRange["start"].(string), "T") {
				_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"status": map[string]any{"code": -10, "message": "Invalid params: time-range"}}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"status": map[string]any{"code": 0}, "tid": 9}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"percentage": 100, "total-count": 0, "status": map[string]any{"code": 0, "message": "succeeded"}, "data": []any{}}})
	}))
	defer server.Close()
	client, err := NewFortiAnalyzer(apiKeyProfile("faz", config.ProductFortiAnalyzer, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "test-adom-primary"})
	if err != nil {
		t.Fatalf("SearchLogs() error = %v", err)
	}
	if len(ranges) != 3 || !strings.HasSuffix(ranges[0]["start"].(string), "+00:00") || !strings.Contains(ranges[1]["start"].(string), "T") || strings.Contains(ranges[2]["start"].(string), "T") {
		t.Fatalf("ranges = %#v, want ISO with offset, ISO, then legacy", ranges)
	}
	if !result.Complete || result.Count != 0 || !strings.Contains(result.Hint, "Zero records") || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "timezone") {
		t.Fatalf("result = %#v", result)
	}
	// The accepted format is remembered: the next search submits once.
	if _, err := client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "test-adom-primary"}); err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 4 || strings.Contains(ranges[3]["start"].(string), "T") {
		t.Fatalf("ranges = %#v, want the legacy format sent directly", ranges)
	}
}

// FortiAnalyzer answers every successful poll with status "succeeded",
// also while the search is still running. Only the percentage may end the
// polling; a search still running at the deadline is reported as timed out
// with its task ID, never as a finished search without records.
func TestFortiAnalyzerRunningSearchIsNotReportedAsEmpty(t *testing.T) {
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		if parameter["url"] == "/logview/adom/test-adom-primary/logsearch" {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"status": map[string]any{"code": 0, "message": "succeeded"}, "tid": 11}})
			return
		}
		polls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{
			"percentage": 0, "return-lines": 0, "total-count": 5000, "status": map[string]any{"code": 0, "message": "succeeded"},
			"data": []any{map[string]any{"status": "success", "srcip": "10.0.0.9"}},
		}})
	}))
	defer server.Close()
	client, err := NewFortiAnalyzer(apiKeyProfile("faz", config.ProductFortiAnalyzer, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := client.SearchLogs(ctx, LogSearchRequest{ADOM: "test-adom-primary", Limit: 900})
	if err != nil {
		t.Fatalf("SearchLogs() error = %v, want a timed-out partial result", err)
	}
	if result.Complete || !result.TimedOut || result.TaskID != "11" || !strings.Contains(result.Hint, "still running") {
		t.Fatalf("result = %#v, want a running search with its task id", result)
	}
	// Backoff: about 0.5 + 1 + 2 s of pauses fit into the budget.
	if count := polls.Load(); count < 2 || count > 4 {
		t.Fatalf("polls = %d, want backoff instead of a poll every 0.5 s", count)
	}
	if result.Limit != maxLogSearchLimit || len(result.Warnings) == 0 || !strings.Contains(result.Warnings[0], "lowered") {
		t.Fatalf("limit = %d warnings = %v, want the page size capped with a warning", result.Limit, result.Warnings)
	}
	if _, _, complete := logSearchState(map[string]any{"status": map[string]any{"message": "succeeded"}, "percentage": 40, "data": []any{}}); complete {
		t.Fatal("status succeeded at 40% must not complete the search")
	}
}

func TestFortiAnalyzerSearchReturnsPartialDataWhenPollBudgetEnds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		resource, _ := parameter["url"].(string)
		if resource == "/logview/adom/test-adom-primary/logsearch" {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"status": map[string]any{"code": 0}, "tid": 5}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"percentage": 40, "total-count": 50, "status": map[string]any{"code": 0, "message": "running"}, "data": []any{map[string]any{"srcip": "10.0.0.2"}}}})
	}))
	defer server.Close()
	client, err := NewFortiAnalyzer(apiKeyProfile("faz", config.ProductFortiAnalyzer, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	result, err := client.SearchLogs(ctx, LogSearchRequest{ADOM: "test-adom-primary"})
	if err != nil {
		t.Fatalf("SearchLogs() error = %v", err)
	}
	if !result.TimedOut || result.Complete || result.Count != 1 || result.Progress != 40 || result.TaskID != "5" || !strings.Contains(result.Hint, `task_id="5"`) {
		t.Fatalf("result = %#v", result)
	}
	if elapsed := time.Since(started); elapsed > 2900*time.Millisecond {
		t.Fatalf("poll ran %v, must end before the caller deadline", elapsed)
	}
}

func TestFortiAnalyzerADOMErrorListsConfiguredADOMs(t *testing.T) {
	profile := apiKeyProfile("faz", config.ProductFortiAnalyzer, "https://faz.invalid")
	profile.AllowInsecureHTTP = false
	profile.ADOMs = []string{"test-adom-01"}
	client, err := NewFortiAnalyzer(profile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "test-adom-secondary"})
	if err == nil || !strings.Contains(err.Error(), "test-adom-01") {
		t.Fatalf("error = %v, want configured ADOM list", err)
	}
}

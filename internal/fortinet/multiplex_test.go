package fortinet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
)

// multiplexServer answers every param of a request from answer and records
// the URLs of each request.
func multiplexServer(t *testing.T, answer func(param map[string]any) map[string]any) (*httptest.Server, func() [][]string) {
	t.Helper()
	var mu sync.Mutex
	var requests [][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		urls := make([]string, 0, len(params))
		results := make([]any, 0, len(params))
		for _, raw := range params {
			param, _ := raw.(map[string]any)
			url, _ := param["url"].(string)
			urls = append(urls, url)
			item := answer(param)
			item["url"] = url
			results = append(results, item)
		}
		mu.Lock()
		requests = append(requests, urls)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": results})
	}))
	return server, func() [][]string {
		mu.Lock()
		defer mu.Unlock()
		return append([][]string(nil), requests...)
	}
}

func ok(data any) map[string]any {
	return map[string]any{"status": map[string]any{"code": 0}, "data": data}
}

func TestPolicyObjectsAreReadInOneRequest(t *testing.T) {
	server, requests := multiplexServer(t, func(param map[string]any) map[string]any {
		url := param["url"].(string)
		switch {
		case strings.HasSuffix(url, "/firewall/address"):
			return ok([]any{map[string]any{"name": "lan", "subnet": []any{"10.0.0.0", "255.255.255.0"}}})
		case strings.HasSuffix(url, "/firewall/addrgrp"):
			return ok([]any{map[string]any{"name": "grp", "member": []any{"lan"}, "exclude": "enable", "exclude-member": []any{"printer"}}})
		case strings.HasSuffix(url, "/firewall/vipgrp"):
			return map[string]any{"status": map[string]any{"code": -3, "message": "Object does not exist"}}
		case strings.HasSuffix(url, "/service/custom"):
			return ok([]any{map[string]any{"name": "HTTPS", "tcp-portrange": []any{"443"}}})
		default:
			return ok([]any{})
		}
	})
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := client.ListPolicyObjects(context.Background(), "test-adom-primary", append(AddressTables(false), ServiceTables()...))
	if err != nil {
		t.Fatal(err)
	}
	sent := requests()
	if len(sent) != 1 || len(sent[0]) != 6 {
		t.Fatalf("requests = %v, want one request with 6 tables", sent)
	}
	if len(objects.Addresses) != 2 || len(objects.Services) != 1 || len(objects.Errors) != 1 || objects.Errors["firewall/vipgrp"] == nil {
		t.Fatalf("objects = %#v", objects)
	}
	if objects.Addresses[1].Name != "grp" || len(objects.Addresses[1].ExcludeMembers) != 1 {
		t.Fatalf("address group = %#v, want exclude members", objects.Addresses[1])
	}
	if err := objects.TableError("address objects", "test-adom-primary"); err == nil || DescribeError(err).Kind != ErrorKindNotFound {
		t.Fatalf("TableError = %v, want the table's not-found kind", err)
	}
}

func TestPackagePolicyTablesAreReadInOneRequest(t *testing.T) {
	server, requests := multiplexServer(t, func(param map[string]any) map[string]any {
		url := param["url"].(string)
		switch {
		case strings.HasSuffix(url, "/firewall/policy"):
			if fields, _ := param["fields"].([]any); len(fields) == 0 {
				t.Errorf("policy read without field projection")
			}
			return ok([]any{map[string]any{"policyid": 1, "srcaddr": []any{}, "srcaddr6": []any{"v6-lan"}, "dstaddr6": []any{"all"}, "internet-service": "enable"}})
		case strings.HasSuffix(url, "/firewall/policy6"):
			return map[string]any{"status": map[string]any{"code": -6, "message": "Invalid url"}}
		default:
			return ok([]any{})
		}
	})
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	tables := client.ListPackagePolicyTables(context.Background(), "test-adom-primary", "default", []string{"policy", "policy6", "security-policy", "proxy-policy"})
	sent := requests()
	if len(sent) != 1 || len(sent[0]) != 4 {
		t.Fatalf("requests = %v, want one request with 4 tables (absent tables are not re-read)", sent)
	}
	policy := tables["policy"]
	if policy.Err != nil || len(policy.Policies) != 1 || len(policy.Policies[0].SourceAddresses6) != 1 || !policy.Policies[0].DestinationInternetService {
		t.Fatalf("policy table = %#v", policy)
	}
	if kind := DescribeError(tables["policy6"].Err).Kind; kind != ErrorKindInvalid {
		t.Fatalf("policy6 = %#v, want the invalid answer of an absent table", tables["policy6"])
	}
}

func TestWebFilterObjectsAreReadInOneRequest(t *testing.T) {
	server, requests := multiplexServer(t, func(param map[string]any) map[string]any {
		url := param["url"].(string)
		switch {
		case strings.HasSuffix(url, "/webfilter/profile"):
			return ok([]any{map[string]any{"name": "strict", "ftgd-wf": map[string]any{"filters": []any{map[string]any{"id": 1, "category": 26, "action": "block"}}}}})
		case strings.HasSuffix(url, "/firewall/profile-group"):
			return ok([]any{map[string]any{"name": "grp", "webfilter-profile": "strict"}})
		case strings.HasSuffix(url, "/webfilter/ftgd-local-rating"):
			return map[string]any{"status": map[string]any{"code": -11, "message": "No permission for the resource"}}
		default:
			return ok([]any{})
		}
	})
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	restore := permissionRecheckDelay
	permissionRecheckDelay = 0
	defer func() { permissionRecheckDelay = restore }()
	objects := client.ReadWebFilterObjects(context.Background(), "test-adom-primary")
	sent := requests()
	if len(sent) < 1 || len(sent[0]) != 6 {
		t.Fatalf("requests = %v, want one request with 6 tables first", sent)
	}
	if len(objects.Profiles) != 1 || len(objects.ProfileGroups) != 1 || objects.Errors["list_local_ratings"] == nil || len(objects.Errors) != 1 {
		t.Fatalf("objects = %#v", objects)
	}
	global := client.ReadWebFilterObjects(context.Background(), "")
	sent = requests()
	last := sent[len(sent)-1]
	if len(last) != 3 || !strings.HasPrefix(last[0], "/pm/config/global/obj/") || len(global.Errors) != 0 {
		t.Fatalf("global read = %v errors = %v, want 3 global tables", last, global.Errors)
	}
}

func TestPolicyLookupBoundsTheFortiGateWait(t *testing.T) {
	var timeout any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		data, _ := parameter["data"].(map[string]any)
		timeout = data["timeout"]
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"target": "fgt", "status": map[string]any{"code": 0}, "response": map[string]any{"results": map[string]any{"policy_id": 7}}}}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PolicyLookup(context.Background(), "test-adom-primary", "fgt", "root", PolicyLookupRequest{SourceIP: "10.0.0.1", DestinationIP: "10.0.1.1", DestinationPort: 443, Protocol: "tcp", SourceInterface: "port1"}); err != nil {
		t.Fatal(err)
	}
	if timeout != float64(PolicyLookupTimeoutSeconds) {
		t.Fatalf("proxy timeout = %v, want %d", timeout, PolicyLookupTimeoutSeconds)
	}
}

func TestFortiAnalyzerReadKeepsOptionsAndSearchProgress(t *testing.T) {
	var params []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, parameter := decodeRPC(t, r)
		params = append(params, parameter)
		if strings.Contains(parameter["url"].(string), "/logsearch/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": map[string]any{"percentage": 30, "status": map[string]any{"code": 0, "message": "succeeded"}, "data": []any{}}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "fgt"}}}}})
	}))
	defer server.Close()
	client, err := NewFortiAnalyzer(apiKeyProfile("faz", config.ProductFortiAnalyzer, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(context.Background(), "/dvmdb/adom/test-adom-primary/device", map[string]any{"fields": []any{"name"}, "loadsub": 0}); err != nil {
		t.Fatal(err)
	}
	if params[0]["fields"] == nil || params[0]["loadsub"] == nil || params[0]["data"] != nil {
		t.Fatalf("param = %#v, want request options next to url", params[0])
	}
	progress, err := client.Read(context.Background(), "/logview/adom/test-adom-primary/logsearch/5", nil)
	if err != nil {
		t.Fatal(err)
	}
	if envelope, ok := progress.(map[string]any); !ok || envelope["percentage"] == nil {
		t.Fatalf("logsearch read = %#v, want progress with the records", progress)
	}
}

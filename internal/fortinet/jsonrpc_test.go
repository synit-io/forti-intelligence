package fortinet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func TestDescribeErrorClassifiesUnsupportedPolicyObjectPath(t *testing.T) {
	info := DescribeError(errors.New(`unsupported object_type "firewall-policy"; use a firewall/... read-only object path`))
	if info.Kind != ErrorKindInvalid || info.Retryable {
		t.Fatalf("DescribeError() = %#v, want non-retryable invalid request", info)
	}
	if !strings.Contains(info.Hint, "list_firewall_policies") {
		t.Fatalf("hint = %q, want policy-tool guidance", info.Hint)
	}
}

func TestFortiManagerSessionAuthenticationAndInventoryRoutes(t *testing.T) {
	var mu sync.Mutex
	var requests []map[string]any
	var proxyResource string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if request["verbose"] != float64(1) {
			t.Errorf("verbose = %#v, want 1", request["verbose"])
		}
		mu.Lock()
		requests = append(requests, request)
		mu.Unlock()
		params, _ := request["params"].([]any)
		resource := ""
		if len(params) > 0 {
			if parameter, ok := params[0].(map[string]any); ok {
				resource, _ = parameter["url"].(string)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch resource {
		case "/sys/login/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "session": "session-1", "result": []any{map[string]any{"status": map[string]any{"code": 0, "message": "OK"}}}})
		case "/sys/logout":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		case "/dvmdb/adom":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "test-adom-primary", "version": "7.6"}}}}})
		case "/dvmdb/adom/test-adom-primary/device":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "fgt-1", "ostype": "FortiGate", "sn": "FGVM", "os_ver": "v7.6.1", "conn_status": "up", "conf_status": "insync", "vdom": []any{"root"}}, map[string]any{"name": "faz-1", "ostype": "FortiAnalyzer"}}}}})
		case "/dvmdb/adom/test-adom-primary/group":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "branches/east", "object member": []any{map[string]any{"name": "fgt-1", "vdom": "root"}}}}}}})
		case "/pm/pkg/adom/test-adom-primary":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "default", "type": "pkg", "scope member": []any{map[string]any{"name": "fgt-1", "vdom": "root"}}}}}}})
		case "/pm/config/adom/test-adom-primary/pkg/default/firewall/policy6":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"policyid": 6, "srcaddr6": []any{"src6"}, "dstaddr6": []any{"dst6"}}}}}})
		case "/pm/config/device/fgt-1/global/system/interface":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "port1", "ip": []any{"10.0.0.1", "255.255.255.0"}, "vdom": "root"}}}}})
		case "/pm/config/device/fgt-1/vdom/root/system/zone":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "inside", "interface": []any{"port1"}}}}}})
		case "/sys/proxy/json":
			// Proxy responses are deliberately left generic; the client must retain raw data.
			params, _ := request["params"].([]any)
			proxyParam, _ := params[0].(map[string]any)
			proxyData, _ := proxyParam["data"].(map[string]any)
			proxyResource, _ = proxyData["resource"].(string)
			targets, _ := proxyData["target"].([]any)
			if len(targets) != 1 || targets[0] != "adom/test-adom-primary/device/fgt-1" {
				t.Errorf("proxy target = %#v, want escaped ADOM/device target", targets)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": map[string]any{"policyid": 10}}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		}
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{Name: "fmg", Product: config.ProductFortiManager, URL: server.URL, Username: "api", Password: "secret", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	adoms, err := client.ListADOMs(ctx)
	if err != nil || len(adoms) != 1 || adoms[0].Name != "test-adom-primary" {
		t.Fatalf("ListADOMs() = %#v, %v", adoms, err)
	}
	devices, err := client.ListDevices(ctx, "test-adom-primary")
	if err != nil || len(devices) != 1 || devices[0].Name != "fgt-1" || devices[0].OSType != "FortiGate" || devices[0].Serial != "FGVM" || devices[0].Version != "v7.6.1" || devices[0].ConnectionStatus != "up" || devices[0].ConfigStatus != "insync" {
		t.Fatalf("ListDevices() = %#v, %v", devices, err)
	}
	groups, err := client.ListDeviceGroups(ctx, "test-adom-primary")
	if err != nil || len(groups) != 1 || groups[0].Name != "branches/east" || len(groups[0].Members) != 1 || groups[0].Members[0].Device != "fgt-1" {
		t.Fatalf("ListDeviceGroups() = %#v, %v", groups, err)
	}
	packages, err := client.ListPolicyPackages(ctx, "test-adom-primary")
	if err != nil || len(packages) != 1 || packages[0].Name != "default" || packages[0].Type != "pkg" || len(packages[0].Members) != 1 {
		t.Fatalf("ListPolicyPackages() = %#v, %v", packages, err)
	}
	ipv6Policies, err := client.ListIPv6Policies(ctx, "test-adom-primary", "default")
	if err != nil || len(ipv6Policies) != 1 || ipv6Policies[0].PolicyID != 6 || len(ipv6Policies[0].SourceAddresses6) != 1 || ipv6Policies[0].SourceAddresses6[0] != "src6" || len(ipv6Policies[0].SourceAddresses) != 0 {
		t.Fatalf("ListIPv6Policies() = %#v, %v", ipv6Policies, err)
	}
	interfaces, err := client.ListInterfaces(ctx, "test-adom-primary", "fgt-1")
	if err != nil || len(interfaces) != 1 || interfaces[0].IP != "10.0.0.1" || interfaces[0].Netmask != "255.255.255.0" || interfaces[0].Network != "10.0.0.0/24" || interfaces[0].Zone != "inside" {
		t.Fatalf("ListInterfaces() = %#v, %v", interfaces, err)
	}
	proxy, err := client.PolicyLookup(ctx, "test-adom-primary", "fgt-1", "root", PolicyLookupRequest{SourceIP: "10.0.0.2", DestinationIP: "192.0.2.5", DestinationPort: 443, Protocol: "tcp", SourceInterface: "port1"})
	if err != nil || proxy.Data == nil {
		t.Fatalf("PolicyLookup() = %#v, %v", proxy, err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !strings.Contains(proxyResource, "ipv6=false") {
		t.Fatalf("policy lookup resource = %q, want ipv6=false for IPv4 source", proxyResource)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) < 7 {
		t.Fatalf("request count = %d, want login plus reads and logout", len(requests))
	}
	for _, request := range requests[1:] {
		if session, ok := request["session"].(string); !ok || session != "session-1" {
			t.Errorf("request session = %#v, want session-1", request["session"])
		}
	}
}

func TestFortiManagerListInterfacesMatchesManualAPIKeyRequest(t *testing.T) {
	var request map[string]any
	var interfaceRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer key-123" {
			t.Errorf("Authorization = %q, want bearer API key", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		if len(params) == 1 {
			if parameter, ok := params[0].(map[string]any); ok && parameter["url"] == "/pm/config/device/test-device-01/global/system/interface" {
				interfaceRequest = make(map[string]any, len(request))
				maps.Copy(interfaceRequest, request)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": request["id"],
			"result": []any{map[string]any{
				"status": map[string]any{"code": 0},
				"data":   []any{map[string]any{"name": "port1", "ip": []any{"10.0.0.1", "255.255.255.0"}}},
			}},
		})
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-key", Product: config.ProductFortiManager, URL: server.URL,
		APIKey: "key-123", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.ListInterfaces(context.Background(), "test-adom-secondary", "test-device-01"); err != nil {
		t.Fatalf("ListInterfaces() error = %v", err)
	}

	if interfaceRequest == nil {
		t.Fatal("interface request was not captured")
	}
	request = interfaceRequest
	if got, want := request["method"], "get"; got != want {
		t.Fatalf("method = %#v, want %q", got, want)
	}
	if got, want := request["verbose"], float64(1); got != want {
		t.Fatalf("verbose = %#v, want %v", got, want)
	}
	params, ok := request["params"].([]any)
	if !ok || len(params) != 1 {
		t.Fatalf("params = %#v, want one parameter", request["params"])
	}
	parameter, ok := params[0].(map[string]any)
	if !ok {
		t.Fatalf("parameter = %#v, want object", params[0])
	}
	if got, want := parameter["url"], "/pm/config/device/test-device-01/global/system/interface"; got != want {
		t.Fatalf("url = %#v, want %q", got, want)
	}
	if got, want := parameter["loadsub"], float64(1); got != want {
		t.Fatalf("loadsub = %#v, want %v", got, want)
	}
	fields, ok := parameter["fields"].([]any)
	if !ok {
		t.Fatalf("fields = %#v, want array", parameter["fields"])
	}
	wantFields := []string{"name", "alias", "type", "ip", "ipv6", "vdom", "status", "role", "interface", "secondaryip"}
	if len(fields) != len(wantFields) {
		t.Fatalf("fields = %#v, want %#v", fields, wantFields)
	}
	for index, want := range wantFields {
		if fields[index] != want {
			t.Fatalf("fields[%d] = %#v, want %q", index, fields[index], want)
		}
	}
}

func TestFortiManagerRPCErrorIncludesResourceAndClassification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": request["id"],
			"result": []any{map[string]any{
				"status": map[string]any{"code": -11, "message": "No permission for the resource"},
				"url":    "/dvmdb/adom/test-adom-secondary/device",
			}},
		})
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-errors", Product: config.ProductFortiManager, URL: server.URL,
		APIKey: "key-123", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.ListDevices(context.Background(), "test-adom-secondary")
	if err == nil {
		t.Fatal("ListDevices() error = nil, want permission error")
	}
	info := DescribeError(err)
	if info.Kind != ErrorKindPermission || info.Code != -11 || info.Resource != "/dvmdb/adom/test-adom-secondary/device" || info.Retryable {
		t.Fatalf("DescribeError() = %#v, want non-retryable permission with resource", info)
	}
	for _, want := range []string{"code -11", "kind=permission_denied", "resource=/dvmdb/adom/test-adom-secondary/device", "No permission for the resource"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, missing %q", err, want)
		}
	}
}

func TestFortiManagerBatchesInterfaceAndZoneReads(t *testing.T) {
	var mu sync.Mutex
	var resources []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		response := make([]any, 0, len(params))
		for _, rawParam := range params {
			param, _ := rawParam.(map[string]any)
			resource, _ := param["url"].(string)
			mu.Lock()
			resources = append(resources, resource)
			mu.Unlock()
			if strings.HasSuffix(resource, "/interface") {
				device := strings.Split(resource, "/")[4]
				if device == "denied" {
					response = append(response, map[string]any{
						"status": map[string]any{"code": -11, "message": "No permission for the resource"},
						"url":    resource,
					})
					continue
				}
				response = append(response, map[string]any{
					"status": map[string]any{"code": 0}, "url": resource,
					"data": []any{map[string]any{"name": device + "-wan", "ip": []any{"10.0.0.1", "255.255.255.0"}}},
				})
				continue
			}
			response = append(response, map[string]any{
				"status": map[string]any{"code": 0}, "url": resource,
				"data": []any{map[string]any{"name": "inside", "interface": []any{"allowed-wan"}}},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": response})
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-batch", Product: config.ProductFortiManager, URL: server.URL,
		APIKey: "key-123", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	results, err := client.ListInterfacesBatch(context.Background(), "test-adom-secondary", []string{"allowed", "denied"})
	if err != nil {
		t.Fatalf("ListInterfacesBatch() error = %v", err)
	}
	if len(results["allowed"].Interfaces) != 1 || results["allowed"].Interfaces[0].Name != "allowed-wan" || results["allowed"].Interfaces[0].Zone != "inside" {
		t.Fatalf("allowed result = %#v, want parsed interface and zone", results["allowed"])
	}
	if results["denied"].InterfaceError == nil {
		t.Fatal("denied interface error = nil, want per-device permission error")
	}
	info := DescribeError(results["denied"].InterfaceError)
	if info.Kind != ErrorKindPermission || info.Resource != "/pm/config/device/denied/global/system/interface" {
		t.Fatalf("denied error details = %#v, want permission/resource", info)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(resources) != 5 || resources[0] != "/pm/config/device/allowed/global/system/interface" || resources[1] != "/pm/config/device/denied/global/system/interface" || resources[2] != "/dvmdb/adom/test-adom-secondary/device" || resources[3] != "/pm/config/device/denied/global/system/interface" || resources[4] != "/pm/config/device/allowed/vdom/root/system/zone" {
		t.Fatalf("resources = %#v, want batched interface request, ADOM-aligned read, single denied verification, and one successful zone request", resources)
	}
}

func TestFortiManagerFallsBackToSingleInterfaceReadsWhenBatchIsRejected(t *testing.T) {
	var mu sync.Mutex
	var requestSizes []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		mu.Lock()
		requestSizes = append(requestSizes, len(params))
		mu.Unlock()

		response := make([]any, 0, len(params))
		for _, rawParam := range params {
			param, _ := rawParam.(map[string]any)
			resource, _ := param["url"].(string)
			if len(params) > 1 {
				response = append(response, map[string]any{
					"status": map[string]any{"code": -11, "message": "No permission for the resource"},
					"url":    resource,
				})
				continue
			}
			if strings.HasPrefix(resource, "/dvmdb/adom/") {
				response = append(response, map[string]any{"status": map[string]any{"code": 0}, "url": resource, "data": []any{}})
				continue
			}
			parts := strings.Split(resource, "/")
			device := parts[4]
			if strings.HasSuffix(resource, "/interface") {
				response = append(response, map[string]any{
					"status": map[string]any{"code": 0}, "url": resource,
					"data": []any{map[string]any{"name": device + "-wan", "ip": []any{"10.0.0.1", "255.255.255.0"}}},
				})
				continue
			}
			response = append(response, map[string]any{
				"status": map[string]any{"code": 0}, "url": resource,
				"data": []any{map[string]any{"name": "inside", "interface": []any{device + "-wan"}}},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": response})
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-batch-fallback", Product: config.ProductFortiManager, URL: server.URL,
		APIKey: "key-123", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	results, err := client.ListInterfacesBatch(context.Background(), "test-adom-secondary", []string{"fgt-1", "fgt-2"})
	if err != nil {
		t.Fatalf("ListInterfacesBatch() error = %v", err)
	}
	for _, device := range []string{"fgt-1", "fgt-2"} {
		result := results[device]
		if result.InterfaceError != nil || result.ZoneError != nil || len(result.Interfaces) != 1 || result.Interfaces[0].Zone != "inside" {
			t.Fatalf("result[%q] = %#v, want successful single-request fallback", device, result)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	// Interfaces: rejected batch, ADOM-aligned read, combined re-read (denied
	// again, which is remembered), single reads. Zones: rejected batch,
	// aligned read, then single reads directly.
	want := []int{2, 1, 2, 1, 1, 2, 1, 1, 1}
	if fmt.Sprint(requestSizes) != fmt.Sprint(want) {
		t.Fatalf("request sizes = %#v, want %v", requestSizes, want)
	}
}

func TestFortiManagerSerializesInterfaceReads(t *testing.T) {
	var active atomic.Int32
	var maxActive atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		resource := ""
		if len(params) > 0 {
			if parameter, ok := params[0].(map[string]any); ok {
				resource, _ = parameter["url"].(string)
			}
		}
		if strings.HasSuffix(resource, "/global/system/interface") {
			current := active.Add(1)
			for {
				previous := maxActive.Load()
				if current <= previous || maxActive.CompareAndSwap(previous, current) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			active.Add(-1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": request["id"],
			"result": []any{map[string]any{
				"status": map[string]any{"code": 0},
				"data":   []any{map[string]any{"name": "port1", "ip": []any{"10.0.0.1", "255.255.255.0"}}},
			}},
		})
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-key", Product: config.ProductFortiManager, URL: server.URL,
		APIKey: "key-123", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := client.ListInterfaces(context.Background(), "test-adom-secondary", "test-device-01"); err != nil {
				t.Errorf("ListInterfaces() error = %v", err)
			}
		})
	}
	wg.Wait()
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent interface reads = %d, want 1", got)
	}
}

func TestFortiManagerListPolicyPackagesIgnoresUnsupportedScopeChild(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		resource := ""
		if len(params) > 0 {
			if parameter, ok := params[0].(map[string]any); ok {
				resource, _ = parameter["url"].(string)
			}
		}
		paths = append(paths, resource)
		w.Header().Set("Content-Type", "application/json")
		switch resource {
		case "/sys/login/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "session": "session-1", "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		case "/pm/pkg/adom/test-adom-primary":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "default", "type": "pkg"}}}}})
		case "/pm/pkg/adom/test-adom-primary/default/scope member":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": -10, "message": "The data is invalid for selected url"}}}})
		case "/sys/logout":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		}
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-scope", Product: config.ProductFortiManager, URL: server.URL, Username: "api", Password: "secret", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	packages, err := client.ListPolicyPackages(context.Background(), "test-adom-primary")
	if err != nil {
		t.Fatalf("ListPolicyPackages() error = %v, want package list to survive unsupported scope child", err)
	}
	if len(packages) != 1 || packages[0].Name != "default" {
		t.Fatalf("ListPolicyPackages() = %#v, want default package", packages)
	}
	for _, path := range paths {
		if path == "/pm/pkg/adom/test-adom-primary/default/scope member" {
			t.Fatalf("ListPolicyPackages() requested unsupported scope child path")
		}
	}
}

func TestFortiManager74InventoryAndPolicyRoutes(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		resource := ""
		if len(params) > 0 {
			if parameter, ok := params[0].(map[string]any); ok {
				resource, _ = parameter["url"].(string)
			}
		}
		paths = append(paths, resource)
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}}
		switch resource {
		case "/sys/login/user":
			response["session"] = "fmg-74-session"
		case "/sys/logout":
		case "/dvmdb/adom":
			response["result"] = []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "test-adom-primary", "version": "7.4"}}}}
		case "/dvmdb/adom/test-adom-primary/device":
			response["result"] = []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "fgt-74", "sn": "FGVM74", "os_ver": "v7.4.0", "conn_status": "up", "conf_status": "insync", "vdom": []any{"root"}}}}}
		case "/pm/pkg/adom/test-adom-primary":
			response["result"] = []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "default", "type": "pkg", "scope member": []any{map[string]any{"name": "fgt-74", "vdom": "root"}}}}}}
		case "/pm/config/adom/test-adom-primary/pkg/default/firewall/policy":
			response["result"] = []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"policyid": 74, "srcaddr": []any{"all"}, "dstaddr": []any{"all"}}}}}
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-74", Product: config.ProductFortiManager, URL: server.URL,
		Username: "api", Password: "secret", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()
	adoms, err := client.ListADOMs(ctx)
	if err != nil || len(adoms) != 1 || adoms[0].Version != "7.4" {
		t.Fatalf("ListADOMs() = %#v, %v", adoms, err)
	}
	devices, err := client.ListDevices(ctx, "test-adom-primary")
	if err != nil || len(devices) != 1 || devices[0].Version != "v7.4.0" || devices[0].Serial != "FGVM74" {
		t.Fatalf("ListDevices() = %#v, %v", devices, err)
	}
	packages, err := client.ListPolicyPackages(ctx, "test-adom-primary")
	if err != nil || len(packages) != 1 || len(packages[0].Members) != 1 {
		t.Fatalf("ListPolicyPackages() = %#v, %v", packages, err)
	}
	policies, err := client.ListPolicies(ctx, "test-adom-primary", "default")
	if err != nil || len(policies) != 1 || policies[0].PolicyID != 74 {
		t.Fatalf("ListPolicies() = %#v, %v", policies, err)
	}
	if len(paths) < 5 || paths[1] != "/dvmdb/adom" || paths[2] != "/dvmdb/adom/test-adom-primary/device" || paths[3] != "/pm/pkg/adom/test-adom-primary" || paths[4] != "/pm/config/adom/test-adom-primary/pkg/default/firewall/policy" {
		t.Fatalf("FortiManager 7.4 route sequence = %#v", paths)
	}
}

func TestFortiManagerIPv6PoliciesDoNotFallBackToNAT64Table(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		resource := ""
		if len(params) > 0 {
			if parameter, ok := params[0].(map[string]any); ok {
				resource, _ = parameter["url"].(string)
			}
		}
		paths = append(paths, resource)
		w.Header().Set("Content-Type", "application/json")
		switch resource {
		case "/sys/login/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "session": "policy-session", "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		case "/sys/logout":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		case "/pm/config/adom/test-adom-primary/pkg/default/firewall/policy6":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": -3, "message": "unknown path"}}}})
		case "/pm/config/adom/test-adom-primary/pkg/default/firewall/policy64":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"policyid": 64, "srcaddr6": []any{"src6"}, "dstaddr6": []any{"dst6"}}}}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		}
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-policy64", Product: config.ProductFortiManager, URL: server.URL, Username: "api", Password: "secret", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// policy64 holds NAT64 policies, not IPv6 policies: a missing legacy
	// policy6 table (FortiOS 6.4+ ADOMs keep IPv6 policies in
	// firewall/policy) is reported with its kind and nothing else is read.
	policies, err := client.ListIPv6Policies(context.Background(), "test-adom-primary", "default")
	if err == nil || len(policies) != 0 || DescribeError(err).Kind != ErrorKindInvalid {
		t.Fatalf("ListIPv6Policies() = %#v, %v; want the invalid-path error of the absent policy6 table", policies, err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "/policy64") {
			t.Fatalf("policy64 was read: %#v", paths)
		}
	}
}

func TestFortiManagerAPIKeyUsesBearerWithoutLogin(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer key-123" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		var request map[string]any
		_ = json.NewDecoder(r.Body).Decode(&request)
		params, _ := request["params"].([]any)
		if len(params) > 0 {
			if parameter, ok := params[0].(map[string]any); ok {
				resource := parameter["url"].(string)
				paths = append(paths, resource)
				if resource == "/sys/status" {
					if _, nested := parameter["data"]; nested {
						t.Error("FortiManager get options unexpectedly nested under data")
					}
					if _, present := parameter["fields"]; !present {
						t.Error("FortiManager get options missing top-level fields")
					}
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "test-adom-primary"}}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(config.ProfileConfig{Name: "fmg-key", Product: config.ProductFortiManager, URL: server.URL, APIKey: "key-123", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	if _, err := client.ListADOMs(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(ctx, "/sys/status", map[string]any{"fields": []string{"hostname"}}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || strings.Contains(paths[0], "login") || strings.Contains(paths[1], "login") {
		t.Fatalf("paths = %#v, want only inventory reads", paths)
	}
}

func TestFortiManagerListADOMsUsesMinimalReadAndPreservesPermissionError(t *testing.T) {
	var request map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer key-123" {
			t.Errorf("Authorization = %q, want bearer API key", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": request["id"],
			"result": []any{map[string]any{
				"status": map[string]any{"code": -11, "message": "No permission for the resource"},
			}},
		})
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-key", Product: config.ProductFortiManager, URL: server.URL,
		APIKey: "key-123", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.ListADOMs(context.Background()); err == nil {
		t.Fatal("ListADOMs() error = nil, want permission error")
	} else {
		if !strings.Contains(err.Error(), "code -11: No permission for the resource") {
			t.Errorf("ListADOMs() error = %q, want appliance code/message", err)
		}
		if !strings.Contains(err.Error(), "system-setting") || !strings.Contains(err.Error(), "adom-switch") {
			t.Errorf("ListADOMs() error = %q, want actionable profile hint", err)
		}
	}

	params, ok := request["params"].([]any)
	if !ok || len(params) != 1 {
		t.Fatalf("params = %#v, want one ADOM request", request["params"])
	}
	parameter, ok := params[0].(map[string]any)
	if !ok || parameter["url"] != "/dvmdb/adom" {
		t.Fatalf("ADOM parameter = %#v, want /dvmdb/adom", params[0])
	}
	if _, present := parameter["fields"]; present {
		t.Errorf("ADOM request unexpectedly contains fields projection: %#v", parameter["fields"])
	}
	if _, present := parameter["loadsub"]; present {
		t.Errorf("ADOM request unexpectedly contains loadsub: %#v", parameter["loadsub"])
	}
}

func TestFortiManagerADOMAllowlistFiltersInventoryAndBlocksReads(t *testing.T) {
	var mu sync.Mutex
	var forbiddenCalls int
	var discoveryCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		resource := ""
		if len(params) > 0 {
			if parameter, ok := params[0].(map[string]any); ok {
				resource, _ = parameter["url"].(string)
			}
		}
		if strings.Contains(resource, "/adom/test-adom-denied/") {
			mu.Lock()
			forbiddenCalls++
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		var data any
		switch resource {
		case "/dvmdb/adom":
			mu.Lock()
			discoveryCalls++
			mu.Unlock()
			data = []any{
				map[string]any{"name": "test-adom-primary"},
				map[string]any{"name": "test-adom-customer-a"},
				map[string]any{"name": "test-adom-denied"},
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     request["id"],
			"result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": data}},
		})
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg", Product: config.ProductFortiManager, URL: server.URL, APIKey: "api-key", AllowInsecureHTTP: true,
		ADOMs: []string{"test-adom-primary", "test-adom-customer-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	adoms, err := client.ListADOMs(context.Background())
	if err != nil {
		t.Fatalf("ListADOMs() error = %v", err)
	}
	if got, want := len(adoms), 2; got != want || adoms[0].Name != "test-adom-primary" || adoms[1].Name != "test-adom-customer-a" {
		t.Fatalf("ListADOMs() = %#v, want test-adom-primary and test-adom-customer-a only", adoms)
	}
	if _, err := client.Read(context.Background(), "/pm/config/adom/test-adom-denied/obj/firewall/address", nil); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("Read() error = %v, want configured-ADOM rejection", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if forbiddenCalls != 0 {
		t.Fatalf("forbidden test-adom-denied calls = %d, want zero", forbiddenCalls)
	}
	if discoveryCalls != 0 {
		t.Fatalf("ADOM discovery calls = %d, want zero when an explicit allowlist is configured", discoveryCalls)
	}
}

func TestFortiManagerPreservesNestedPolicyPackagePath(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		if len(params) > 0 {
			if parameter, ok := params[0].(map[string]any); ok {
				gotPath, _ = parameter["url"].(string)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch gotPath {
		case "/sys/login/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "session": "nested-session", "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		case "/sys/logout":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		case "/pm/config/adom/test-adom-primary/pkg/emea/spain/ppkg/firewall/policy":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"policyid": 1}}}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		}
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-nested", Product: config.ProductFortiManager, URL: server.URL, Username: "api", Password: "secret", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	policies, err := client.ListPolicies(context.Background(), "test-adom-primary", "emea/spain/ppkg")
	if err != nil || len(policies) != 1 || policies[0].PolicyID != 1 {
		t.Fatalf("ListPolicies() = %#v, %v", policies, err)
	}
	if gotPath != "/pm/config/adom/test-adom-primary/pkg/emea/spain/ppkg/firewall/policy" {
		t.Fatalf("policy path = %q, want nested package path", gotPath)
	}
}

func TestFortiManagerDeviceGroupMemberFallback(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		resource := ""
		if len(params) > 0 {
			if parameter, ok := params[0].(map[string]any); ok {
				resource, _ = parameter["url"].(string)
			}
		}
		paths = append(paths, resource)
		w.Header().Set("Content-Type", "application/json")
		switch resource {
		case "/sys/login/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "session": "group-session", "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		case "/dvmdb/adom/test-adom-primary/group":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "branches/east"}}}}})
		case "/dvmdb/adom/test-adom-primary/group/branches/east/object member":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{map[string]any{"name": "branch-1", "vdom": "root"}}}}})
		case "/sys/logout":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}}}})
		}
	}))
	defer server.Close()

	client, err := NewFortiManager(config.ProfileConfig{
		Name: "fmg-group", Product: config.ProductFortiManager, URL: server.URL, Username: "api", Password: "secret", AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	groups, err := client.ListDeviceGroups(context.Background(), "test-adom-primary")
	if err != nil || len(groups) != 1 || len(groups[0].Members) != 1 || groups[0].Members[0].Device != "branch-1" {
		t.Fatalf("ListDeviceGroups() = %#v, %v", groups, err)
	}
	if len(paths) != 3 || paths[1] != "/dvmdb/adom/test-adom-primary/group" || paths[2] != "/dvmdb/adom/test-adom-primary/group/branches/east/object member" {
		t.Fatalf("device group paths = %#v", paths)
	}
}

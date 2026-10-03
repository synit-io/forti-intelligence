package fortinet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func TestRequestPolicyBlocksWritesBeforeSending(t *testing.T) {
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sent.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	profile := apiKeyProfile("fmg", config.ProductFortiManager, server.URL)
	manager, err := NewFortiManager(profile)
	if err != nil {
		t.Fatal(err)
	}
	rating, err := NewFortiManagerRatingClient(profile)
	if err != nil {
		t.Fatal(err)
	}
	analyzer, err := NewFortiAnalyzer(apiKeyProfile("faz", config.ProductFortiAnalyzer, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	proxy := func(action, resource string, payload any) []map[string]any {
		data := map[string]any{"action": action, "resource": resource, "target": []string{"adom/test-adom-primary/device/fgt"}}
		if payload != nil {
			data["payload"] = payload
		}
		return []map[string]any{{"url": "/sys/proxy/json", "data": data}}
	}
	cases := []struct {
		name   string
		client *rpcClient
		method string
		params []map[string]any
	}{
		{"fmg set", manager.rpc, "set", []map[string]any{{"url": "/pm/config/adom/test-adom-primary/obj/firewall/address"}}},
		{"fmg delete", manager.rpc, "delete", []map[string]any{{"url": "/dvmdb/adom/test-adom-primary/device/fgt"}}},
		{"fmg add", manager.rpc, "add", []map[string]any{{"url": "/pm/pkg/adom/test-adom-primary"}}},
		{"fmg install", manager.rpc, "exec", []map[string]any{{"url": "/securityconsole/install/package"}}},
		{"fmg script", manager.rpc, "exec", []map[string]any{{"url": "/dvmdb/adom/test-adom-primary/script/execute"}}},
		{"proxy post cmdb", manager.rpc, "exec", proxy("post", "/api/v2/cmdb/firewall/address", map[string]any{"name": "x"})},
		{"proxy put", manager.rpc, "exec", proxy("put", "/api/v2/cmdb/system/interface/port1", map[string]any{})},
		{"proxy delete", manager.rpc, "exec", proxy("delete", "/api/v2/cmdb/firewall/policy/1", nil)},
		{"proxy get outside api", manager.rpc, "exec", proxy("get", "/logindisclaimer", nil)},
		{"rating extra field", manager.rpc, "exec", proxy("post", ratingLookupResource, map[string]any{"url": []string{"a.de"}, "vdom": "root"})},
		{"rating two urls", manager.rpc, "exec", proxy("post", ratingLookupResource, map[string]any{"url": []string{"a.de", "b.de"}})},
		{"rating account db read", rating.rpc, "get", []map[string]any{{"url": "/dvmdb/adom/test-adom-primary/device"}}},
		{"rating account other proxy read", rating.rpc, "exec", proxy("get", "/api/v2/monitor/router/ipv4", nil)},
		{"faz add elsewhere", analyzer.rpc, "add", []map[string]any{{"url": "/report/adom/test-adom-primary/run"}}},
		{"faz exec", analyzer.rpc, "exec", []map[string]any{{"url": "/sys/reboot"}}},
		{"fmg admin read", manager.rpc, "get", []map[string]any{{"url": "/cli/global/system/admin/admin"}}},
		{"fmg proxy admin", manager.rpc, "exec", proxy("get", "/api/v2/cmdb/system/admin", nil)},
		{"fmg encoded proxy admin", manager.rpc, "exec", proxy("get", "/api/v2/cmdb/system/%61dmin?vdom=root", nil)},
		{"fmg encoded proxy slash", manager.rpc, "exec", proxy("get", "/api/v2/cmdb/system%2fadmin", nil)},
		{"fmg nested proxy escape", manager.rpc, "exec", proxy("get", "/api/v2/cmdb/system/%2561dmin", nil)},
		{"fmg encoded admin", manager.rpc, "get", []map[string]any{{"url": "/cli/global/system/%61dmin/admin"}}},
		{"faz encoded admin", analyzer.rpc, "get", []map[string]any{{"url": "/sys/%61dmin"}}},
		{"proxy encoded traversal", manager.rpc, "exec", proxy("get", "/api/v2/cmdb/firewall/%2e%2e/system/admin", nil)},
		{"proxy encoded newline", manager.rpc, "exec", proxy("get", "/api/v2/monitor/router/ipv4%0a", nil)},
		{"proxy encoded null", manager.rpc, "exec", proxy("get", "/api/v2/monitor/router/ipv4%00", nil)},
		{"proxy encoded tab", manager.rpc, "exec", proxy("get", "/api/v2/monitor/router/ipv4%09", nil)},
		{"fmg private key", manager.rpc, "get", []map[string]any{{"url": "/pm/config/adom/test-adom-primary/obj/vpn.certificate/local/example"}}},
		{"batch hides a write", manager.rpc, "set", []map[string]any{{"url": "/dvmdb/adom/test-adom-primary/device"}, {"url": "/dvmdb/adom/test-adom-primary/device/fgt"}}},
	}
	for _, testCase := range cases {
		_, err := testCase.client.callOnce(context.Background(), testCase.method, testCase.params)
		if err == nil || !strings.Contains(err.Error(), "blocked by the MCP server") || DescribeError(err).Kind != ErrorKindInvalid {
			t.Errorf("%s: error = %v, want blocked", testCase.name, err)
		}
	}
	if sent.Load() != 0 {
		t.Fatalf("%d blocked requests reached the appliance", sent.Load())
	}
	for name, check := range map[string]error{
		"fmg read":            policyFortiManager.check("get", []map[string]any{{"url": "/dvmdb/adom/test-adom-primary/device"}}),
		"fmg proxy read":      policyFortiManager.check("exec", proxy("get", "/api/v2/monitor/router/ipv4?vdom=root", nil)),
		"fmg escaped object":  policyFortiManager.check("exec", proxy("get", "/api/v2/cmdb/firewall/address/branch%20network", nil)),
		"fmg rating post":     policyFortiManager.check("exec", proxy("post", ratingLookupResource, map[string]any{"url": []string{"www.heise.de"}, "lang": "en"})),
		"rating account post": policyFortiManagerRating.check("exec", proxy("post", ratingLookupResource, map[string]any{"url": []any{"www.heise.de"}})),
		"rating categories":   policyFortiManagerRating.check("exec", proxy("get", ratingCategoryResource, nil)),
		"login":               policyFortiManagerRating.check("exec", []map[string]any{{"url": "/sys/login/user"}}),
		"faz search":          policyFortiAnalyzer.check("add", []map[string]any{{"url": "/logview/adom/test-adom-01/logsearch"}}),
	} {
		if check != nil {
			t.Errorf("%s: unexpectedly blocked: %v", name, check)
		}
	}
}

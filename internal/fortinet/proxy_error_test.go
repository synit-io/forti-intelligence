package fortinet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func TestProxyPermissionExplainsExecWithoutRetry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var request struct {
			Method string `json:"method"`
			Params []struct {
				URL  string `json:"url"`
				Data struct {
					Action   string   `json:"action"`
					Resource string   `json:"resource"`
					Target   []string `json:"target"`
				} `json:"data"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.Method != "exec" || len(request.Params) != 1 {
			t.Errorf("bad proxy envelope: %+v", request)
			return
		}
		param := request.Params[0]
		if param.URL != "/sys/proxy/json" || param.Data.Action != "get" || param.Data.Resource != "/api/v2/monitor/router/route/?vdom=root" || len(param.Data.Target) != 1 || param.Data.Target[0] != "adom/test-adom-tenant-internal/device/test-device-proxy" {
			t.Errorf("bad proxy params: %+v", param)
		}
		json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{"url": "/sys/proxy/json", "status": map[string]any{"code": -11, "message": "No permission for the resource"}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(config.ProfileConfig{Name: "fmg", Product: config.ProductFortiManager, URL: server.URL, APIKey: "test", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ProxyGet(context.Background(), "test-adom-tenant-internal", "test-device-proxy", "root", "/api/v2/monitor/router/route/?vdom=root")
	info := DescribeError(err)
	if info.Code != -11 || info.Retryable || !strings.Contains(info.Hint, "rpc-permit") || !strings.Contains(info.Hint, "action=get") || calls != 1 {
		t.Fatalf("info=%+v calls=%d", info, calls)
	}
}

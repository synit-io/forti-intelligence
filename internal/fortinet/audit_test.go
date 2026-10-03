package fortinet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func TestZonesUseInterfaceVDOMAndKeepPartialResults(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "partial"}[denied], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					ID     any              `json:"id"`
					Params []map[string]any `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					return
				}
				var response []any
				for _, param := range request.Params {
					resource := param["url"].(string)
					item := map[string]any{"url": resource, "status": map[string]any{"code": 0}}
					switch resource {
					case "/pm/config/device/edge/global/system/interface":
						item["data"] = []any{
							map[string]any{"name": "port1", "vdom": []any{"root"}},
							map[string]any{"name": "port1", "vdom": []any{"tenant"}},
						}
					case "/pm/config/device/edge/vdom/root/system/zone":
						item["data"] = []any{map[string]any{"name": "root-zone", "interface": []any{"port1"}}}
					case "/pm/config/device/edge/vdom/tenant/system/zone":
						item["data"] = []any{map[string]any{"name": "tenant-zone", "interface": []any{"port1"}}}
						if denied {
							item["status"] = map[string]any{"code": -11, "message": "No permission for the resource"}
						}
					case "/dvmdb/adom/test-adom-secondary/device":
						// ADOM-aligned re-read before verifying a denied device read.
						item["data"] = []any{map[string]any{"name": "edge"}}
					default:
						t.Errorf("unexpected resource %s", resource)
						item["status"] = map[string]any{"code": -11, "message": "No permission for the resource"}
					}
					response = append(response, item)
				}
				json.NewEncoder(w).Encode(map[string]any{"id": request.ID, "result": response})
			}))
			defer server.Close()
			client, err := NewFortiManager(config.ProfileConfig{Name: "fmg", Product: config.ProductFortiManager, URL: server.URL, APIKey: "test", AllowInsecureHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			interfaces, err := client.ListInterfaces(context.Background(), "test-adom-secondary", "edge")
			if (err != nil) != denied || len(interfaces) != 2 {
				t.Fatalf("interfaces=%v error=%v", interfaces, err)
			}
			if interfaces[0].Zone != "root-zone" {
				t.Fatalf("root zone=%q", interfaces[0].Zone)
			}
			want := "tenant-zone"
			if denied {
				want = ""
			}
			if interfaces[1].Zone != want {
				t.Fatalf("tenant zone=%q, want %q", interfaces[1].Zone, want)
			}
		})
	}
}

func TestSessionDetectionIgnoresDiagnosticHintAndResource(t *testing.T) {
	err := newRPCFailure(ErrorInfo{Code: -11, Message: "No permission for the resource", Resource: "/session/status", Hint: "Verify the API session"}, nil)
	if isSessionError(err) {
		t.Fatal("permission error triggered session renewal")
	}
	err = newRPCFailure(ErrorInfo{Message: "Invalid session"}, nil)
	if !isSessionError(err) {
		t.Fatal("invalid session must trigger renewal")
	}
}

func TestProxyReadPreservesQueryAndExplicitVDOM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Params []struct {
				Data map[string]any `json:"data"`
			} `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&request)
		resource, _ := request.Params[0].Data["resource"].(string)
		parsed, err := url.Parse(resource)
		if err != nil || parsed.Query().Get("vdom") != "tenant" || parsed.Query().Get("format") != "full" {
			t.Errorf("wrong proxy scope: %s", resource)
		}
		w.Write([]byte(`{"result":[{"status":{"code":0},"data":{}}]}`))
	}))
	defer server.Close()
	client, err := NewFortiManager(config.ProfileConfig{Name: "fmg", Product: config.ProductFortiManager, URL: server.URL, APIKey: "test", AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, resource := range []string{"/api/v2/cmdb/system/interface?format=full", "/api/v2/cmdb/system/interface?format=full&vdom=root"} {
		result, err := client.ProxyGet(context.Background(), "test-adom-secondary", "edge", "tenant", resource)
		if err != nil || !strings.Contains(result.Resource, "tenant") {
			t.Fatalf("proxy=%v err=%v", result, err)
		}
	}
}

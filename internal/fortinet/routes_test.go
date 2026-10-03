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

func TestParseRoutesHandlesFortiOSShapes(t *testing.T) {
	routes := parseRoutes([]any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{
		map[string]any{"seq-num": 1, "dst": []any{"0.0.0.0", "0.0.0.0"}, "gateway": "203.0.113.1", "device": []any{"wan1"}, "distance": 10, "priority": 1, "status": "enable"},
		map[string]any{"seq-num": 2, "dst": "10.0.0.0 255.0.0.0", "gateway": "10.1.1.1", "device": "wan2", "distance": 20, "status": "enable", "comment": "backbone"},
		map[string]any{"seq-num": 3, "dst": "192.168.0.0/16", "blackhole": "enable", "gateway": "0.0.0.0", "status": "enable"},
		map[string]any{"seq-num": 4, "dstaddr": []any{"branch-nets"}, "device": "vpn", "status": "enable"},
		map[string]any{"seq-num": 5, "dst": []any{"0.0.0.0", "0.0.0.0"}, "sdwan-zone": []any{"virtual-wan-link"}, "status": "disable"},
	}}}, "ipv4", "root")
	if len(routes) != 5 {
		t.Fatalf("routes = %#v", routes)
	}
	if routes[0].Destination != "0.0.0.0/0" || routes[0].Interface != "wan1" || routes[0].Gateway != "203.0.113.1" || routes[0].Distance != 10 || routes[0].Priority != 1 || routes[0].VDOM != "root" || routes[0].Family != "ipv4" {
		t.Fatalf("default route = %#v", routes[0])
	}
	if routes[1].Destination != "10.0.0.0/8" || routes[1].Comment != "backbone" {
		t.Fatalf("masked route = %#v", routes[1])
	}
	if !routes[2].Blackhole || routes[2].Gateway != "" || routes[2].Destination != "192.168.0.0/16" {
		t.Fatalf("blackhole route = %#v", routes[2])
	}
	if routes[3].Destination != "" || routes[3].DstAddrObject != "branch-nets" {
		t.Fatalf("object route = %#v", routes[3])
	}
	if routes[4].SDWANZone != "virtual-wan-link" || routes[4].Status != "disable" {
		t.Fatalf("sdwan route = %#v", routes[4])
	}
	ipv6 := parseRoutes(map[string]any{"data": []any{map[string]any{"seq-num": 1, "dst": "::/0", "gateway": "2001:db8::1", "device": "wan1"}}}, "ipv6", "root")
	if len(ipv6) != 1 || ipv6[0].Destination != "::/0" || ipv6[0].Family != "ipv6" {
		t.Fatalf("ipv6 routes = %#v", ipv6)
	}
}

func TestFortiManagerListRoutesBatchReadsStaticTablesPerVDOM(t *testing.T) {
	var resources []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode: %v", err)
			return
		}
		params, _ := request["params"].([]any)
		response := make([]any, 0, len(params))
		for _, rawParam := range params {
			resource, _ := rawParam.(map[string]any)["url"].(string)
			resources = append(resources, resource)
			switch {
			case strings.Contains(resource, "/denied/"):
				response = append(response, map[string]any{"status": map[string]any{"code": -11, "message": "No permission for the resource"}, "url": resource})
			case strings.HasSuffix(resource, "/router/static6"):
				response = append(response, map[string]any{"status": map[string]any{"code": 0}, "url": resource, "data": []any{map[string]any{"seq-num": 1, "dst": "::/0", "device": "wan1"}}})
			default:
				response = append(response, map[string]any{"status": map[string]any{"code": 0}, "url": resource, "data": []any{map[string]any{"seq-num": 1, "dst": []any{"0.0.0.0", "0.0.0.0"}, "device": "wan1", "gateway": "203.0.113.1", "distance": 10}}})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": response})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	results, err := client.ListRoutesBatch(context.Background(), "test-adom-primary", []RouteTarget{
		{Device: "edge", VDOM: "root", IPv6: true}, {Device: "edge", VDOM: "dmz"}, {Device: "denied", VDOM: "root"},
	})
	if err != nil {
		t.Fatalf("ListRoutesBatch() error = %v", err)
	}
	edge := results["edge"]
	if edge.Err != nil || len(edge.Routes) != 3 {
		t.Fatalf("edge = %#v", edge)
	}
	if edge.Routes[0].VDOM != "root" || edge.Routes[0].Family != "ipv4" || edge.Routes[1].Family != "ipv6" || edge.Routes[2].VDOM != "dmz" {
		t.Fatalf("edge routes = %#v", edge.Routes)
	}
	denied := results["denied"]
	if denied.Err == nil || DescribeError(denied.Err).Kind != ErrorKindPermission || !strings.Contains(denied.Err.Error(), "Device Manager") {
		t.Fatalf("denied = %#v", denied)
	}
	want := []string{
		"/pm/config/device/edge/vdom/root/router/static", "/pm/config/device/edge/vdom/root/router/policy", "/pm/config/device/edge/vdom/root/system/sdwan",
		"/pm/config/device/edge/vdom/root/router/static6", "/pm/config/device/edge/vdom/root/router/policy6",
		"/pm/config/device/edge/vdom/dmz/router/static", "/pm/config/device/edge/vdom/dmz/router/policy", "/pm/config/device/edge/vdom/dmz/system/sdwan",
		"/pm/config/device/denied/vdom/root/router/static", "/pm/config/device/denied/vdom/root/router/policy", "/pm/config/device/denied/vdom/root/system/sdwan",
	}
	if strings.Join(resources[:len(want)], ",") != strings.Join(want, ",") {
		t.Fatalf("resources = %#v, want %#v first", resources, want)
	}
	if edge.StaticOK != true || edge.PolicyOK != true || edge.SDWANOK != true || denied.StaticOK || denied.PolicyOK || denied.SDWANOK {
		t.Fatalf("table flags edge=%+v denied=%+v", edge, denied)
	}
}

func TestParsePolicyRoutesSDWANAndPackageStatus(t *testing.T) {
	routes := parsePolicyRoutes(map[string]any{"data": []any{
		map[string]any{"seq-num": 3, "input-device": []any{"lan"}, "src": []any{"10.0.0.0 255.0.0.0"}, "dst": []any{"0.0.0.0 0.0.0.0"}, "dstaddr": []any{"saas"}, "protocol": 6, "start-port": 443, "end-port": 443, "gateway": "10.9.9.1", "output-device": []any{"wan2"}, "action": "permit", "status": "enable", "internet-service-id": []any{}},
		map[string]any{"seq-num": 4, "src": []any{"192.168.0.0", "255.255.0.0"}, "action": "deny", "tos-mask": "0x00"},
	}}, "ipv4", "root")
	if len(routes) != 2 {
		t.Fatalf("routes = %#v", routes)
	}
	first := routes[0]
	if first.SeqNum != 3 || first.InputDevices[0] != "lan" || first.Src[0] != "10.0.0.0/8" || len(first.Dst) != 0 || first.DstAddr[0] != "saas" || first.Protocol != 6 || first.StartPort != 443 || first.OutputDevice != "wan2" || first.Gateway != "10.9.9.1" || len(first.InternetServices) != 0 || first.TOSMatch {
		t.Fatalf("first = %#v", first)
	}
	if routes[1].Action != "deny" || routes[1].Src[0] != "192.168.0.0/16" {
		t.Fatalf("second = %#v", routes[1])
	}

	config, enabled := parseSDWAN(map[string]any{"data": map[string]any{
		"status": "enable",
		"zone":   []any{map[string]any{"name": "virtual-wan-link"}, map[string]any{"name": "underlay"}},
		"members": []any{
			map[string]any{"seq-num": 1, "interface": []any{"wan1"}, "zone": []any{"underlay"}, "gateway": "203.0.113.1", "status": "enable"},
			map[string]any{"seq-num": 2, "interface": "wan2", "gateway": "0.0.0.0"},
		},
		"service": []any{map[string]any{"id": 1, "name": "saas", "mode": "sla", "dst": []any{"saas-net"}, "priority-members": []any{"2", "1"}, "users": []any{"alice"}}},
	}}, "root")
	if !enabled || len(config.Zones) != 2 || len(config.Members) != 2 || config.Members[0].Zone != "underlay" || config.Members[1].Zone != "virtual-wan-link" || config.Members[1].Gateway != "" {
		t.Fatalf("sdwan = %#v enabled=%v", config, enabled)
	}
	if rule := config.Rules[0]; rule.ID != 1 || rule.Mode != "sla" || rule.Dst[0] != "saas-net" || len(rule.PriorityMembers) != 2 || rule.PriorityMembers[0] != 2 || !rule.Identity {
		t.Fatalf("rule = %#v", rule)
	}
	if _, enabled := parseSDWAN(map[string]any{"data": map[string]any{"status": "disable"}}, "root"); enabled {
		t.Fatal("disabled SD-WAN reported as enabled")
	}

	status, ok := parsePackageStatus([]any{map[string]any{"status": map[string]any{"code": 0}, "data": map[string]any{"dev": "fgt", "vdom": "root", "pkg": "default", "status": "modified"}}}, "fgt", "root")
	if !ok || status.Status != "modified" || status.Package != "default" || status.Device != "fgt" {
		t.Fatalf("status = %#v ok=%v", status, ok)
	}
}

func TestPackageStatusBatchAndGlobalWebFilterPaths(t *testing.T) {
	var resources []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		_ = json.NewDecoder(r.Body).Decode(&request)
		params, _ := request["params"].([]any)
		response := make([]any, 0, len(params))
		for _, raw := range params {
			resource, _ := raw.(map[string]any)["url"].(string)
			resources = append(resources, resource)
			switch {
			case strings.Contains(resource, "_package/status/fgt-a"):
				response = append(response, map[string]any{"status": map[string]any{"code": 0}, "url": resource, "data": map[string]any{"dev": "fgt-a", "vdom": "root", "pkg": "default", "status": "installed"}})
			case strings.Contains(resource, "_package/status"):
				response = append(response, map[string]any{"status": map[string]any{"code": -3, "message": "Object does not exist"}, "url": resource})
			default:
				response = append(response, map[string]any{"status": map[string]any{"code": 0}, "url": resource, "data": []any{}})
			}
		}
		if len(response) == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": response})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": response})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := client.PackageStatusBatch(context.Background(), "test-adom-primary", []PackageMember{{Device: "fgt-a"}, {Device: "fgt-b", VDOM: "dmz"}})
	if err != nil {
		t.Fatalf("PackageStatusBatch() error = %v", err)
	}
	if len(statuses) != 1 || statuses["fgt-a/root"].Status != "installed" {
		t.Fatalf("statuses = %#v", statuses)
	}
	if _, err := client.ListWebFilterProfiles(context.Background(), ""); err != nil {
		t.Fatalf("global profiles error = %v", err)
	}
	if !strings.Contains(strings.Join(resources, ","), "/pm/config/global/obj/webfilter/profile") {
		t.Fatalf("resources = %v, want global profile path", resources)
	}
}

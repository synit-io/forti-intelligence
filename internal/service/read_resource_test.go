package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

func TestReadResourceValidationNormalizesAndExplains(t *testing.T) {
	for _, testCase := range []struct {
		validate func(string) (string, error)
		input    string
		want     string
		wantErr  string
	}{
		{validateFortiAnalyzerReadResource, "dvmdb/adom/test-adom-01/device", "/dvmdb/adom/test-adom-01/device", ""},
		{validateFortiAnalyzerReadResource, " /logview/adom/test-adom-x/logsearch/12 ", "/logview/adom/test-adom-x/logsearch/12", ""},
		{validateFortiAnalyzerReadResource, "/task/task/5", "/task/task/5", ""},
		{validateFortiAnalyzerReadResource, "/cli/global/system", "", "/logview"},
		{validateFortiAnalyzerReadResource, "/sys/../cli", "", "traversal"},
		{validateFortiAnalyzerReadResource, "", "", "required"},
		{validateFortiManagerReadResource, "sys/status", "/sys/status", ""},
		{validateFortiManagerReadResource, "/pm/config/adom/test-adom-primary/_package/status/fgt/root?x=1", "/pm/config/adom/test-adom-primary/_package/status/fgt/root?x=1", ""},
		{validateFortiManagerReadResource, "/um/misc", "", "/securityconsole"},
	} {
		got, err := testCase.validate(testCase.input)
		if testCase.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Errorf("validate(%q) error = %v, want %q", testCase.input, err, testCase.wantErr)
			}
			continue
		}
		if err != nil || got != testCase.want {
			t.Errorf("validate(%q) = %q, %v; want %q", testCase.input, got, err, testCase.want)
		}
	}
}

func TestGenericReadsRequireADOMOnRestrictedProfiles(t *testing.T) {
	manager := &countingToolManager{fakeManager: &fakeManager{name: "fmg"}}
	analyzer := &countingAnalyzer{}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{
		{Name: "fmg", Product: config.ProductFortiManager, ADOMs: []string{"allowed ADOM"}},
		{Name: "faz", Product: config.ProductFortiAnalyzer, ADOMs: []string{"allowed ADOM"}},
	}
	app := New(cfg, nil, map[string]fortinet.Manager{"fmg": manager}, map[string]fortinet.Analyzer{"faz": analyzer})
	for _, tc := range []struct {
		name    string
		read    func(context.Context, string, string, map[string]any) (any, error)
		blocked []string
		allowed []string
		calls   func() int
	}{
		{"fmg", app.GetFortiManagerRead,
			[]string{"/pm/config/device/edge/vdom/root", "/securityconsole/package/status", "/pm/config/global/obj/firewall/address"},
			[]string{"/pm/config/adom/allowed%20ADOM/obj/firewall/address/name%2Fpart", "/pm/pkg/adom/allowed%20ADOM"},
			func() int { return len(manager.reads) }},
		{"faz", app.FortiAnalyzerRead,
			[]string{"/logview/logs", "/report/status", "/eventmgmt/event", "/incidents/list"},
			[]string{"/logview/adom/allowed%20ADOM/logstats", "/logview/adom/allowed%20ADOM/logsearch/5"},
			func() int { return int(analyzer.reads.Load()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			for _, resource := range append(tc.blocked, "/dvmdb/device", "/dvmdb/adom", "/sys/device/adom/allowed%20ADOM", "/task/task/1", "/dvmdb/adom/denied/device", "/dvmdb/adom/allowed%20ADOM%2Fdevice", "/dvmdb/adom/allowed%20ADOM/%2e%2e/device", "/dvmdb/adom/allowed%20ADOM%20/device") {
				if _, err := tc.read(ctx, tc.name, resource, map[string]any{"adom": "allowed ADOM"}); err == nil {
					t.Errorf("restricted read of %q succeeded", resource)
				}
			}
			if got := tc.calls(); got != 0 {
				t.Fatalf("%d restricted requests reached the client", got)
			}
			for _, resource := range append(tc.allowed, "/sys/status?fields=version", "/dvmdb/adom/allowed%20ADOM/device") {
				if _, err := tc.read(ctx, tc.name, resource, nil); err != nil {
					t.Fatalf("allowed read of %q failed: %v", resource, err)
				}
			}
			if got := tc.calls(); got != len(tc.allowed)+2 {
				t.Fatalf("client received %d allowed requests", got)
			}
		})
	}

	for i := range cfg.Profiles {
		cfg.Profiles[i].ADOMs = nil
	}
	app = New(cfg, nil, map[string]fortinet.Manager{"fmg": manager}, map[string]fortinet.Analyzer{"faz": analyzer})
	if _, err := app.GetFortiManagerRead(context.Background(), "fmg", "/dvmdb/adom", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FortiAnalyzerRead(context.Background(), "faz", "/dvmdb/device", nil); err != nil {
		t.Fatal(err)
	}
}

func TestLivePolicyIDPreservesRPCInteger(t *testing.T) {
	for _, number := range []any{json.Number("7"), json.Number("7.0"), float64(7)} {
		data := []any{map[string]any{"results": map[string]any{"policy_id": number}}}
		if got := livePolicyID(data); got == nil || *got != 7 {
			t.Fatalf("livePolicyID(%v) = %v, want 7", number, got)
		}
	}
}

func TestInventoryResultsOmitRawUnlessRequested(t *testing.T) {
	manager := &fakeManager{
		name:  "fmg-a",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary", Raw: map[string]any{"oid": 3}}},
		devices: map[string][]fortinet.Device{"test-adom-primary": {{
			Name: "edge-1", ADOM: "test-adom-primary", Profile: "fmg-a", VDOMs: []string{"root"}, Raw: map[string]any{"sn": "X"},
		}}},
		interfaces: map[string][]fortinet.Interface{"test-adom-primary/edge-1": {{Name: "port1", IP: "10.0.0.1", Netmask: "255.255.255.0", VDOM: "root", Raw: map[string]any{"ipv6": map[string]any{"ip6-mode": "static"}}}}},
		policies:   map[string][]fortinet.FirewallPolicy{"test-adom-primary/default": {{PolicyID: 1, Status: "enable", Raw: map[string]any{"obj seq": 1}}}},
		packages:   map[string][]fortinet.PolicyPackage{"test-adom-primary": {{Name: "default"}}},
	}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p"}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": manager}, 0, 1)
	store.Refresh(context.Background())
	app := New(cfg, store, map[string]fortinet.Manager{"fmg-a": manager}, nil)

	lean, err := app.ListFortiGates(context.Background(), "", "", true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if lean.Devices[0].Raw != nil || lean.Devices[0].Interfaces[0].Raw != nil || lean.ADOMs[0].ADOM.Raw != nil {
		t.Fatalf("raw retained: %#v", lean)
	}
	full, err := app.ListFortiGates(context.Background(), "", "", true, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if full.Devices[0].Raw == nil || full.Devices[0].Interfaces[0].Raw == nil {
		t.Fatalf("raw missing when requested: %#v", full)
	}
	if store.Snapshot().Devices[0].Interfaces[0].Raw == nil {
		t.Fatal("stripping must not mutate the store snapshot")
	}

	interfaces, err := app.GetInterfaces(context.Background(), "", "test-adom-primary", "edge-1", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	if list := interfaces.(map[string]any)["interfaces"].([]fortinet.Interface); list[0].Raw != nil {
		t.Fatalf("interface raw retained: %#v", list)
	}
	policies, err := app.ListPolicies(context.Background(), PolicyListInput{Profile: "fmg-a", ADOM: "test-adom-primary", Package: "default", Device: "", IPVersion: "ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	if list := policies.(map[string]any)["packages"].(map[string]any)["default"].([]fortinet.FirewallPolicy); list[0].Raw != nil {
		t.Fatalf("policy raw retained: %#v", list)
	}
}

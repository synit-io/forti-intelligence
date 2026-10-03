package service

import (
	"context"
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

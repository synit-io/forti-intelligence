package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

// countingToolManager counts the FortiManager reads the list tools make.
type countingToolManager struct {
	*fakeManager
	interfaceReads atomic.Int32
	policyReads    atomic.Int32
	packageReads   atomic.Int32
	reads          []map[string]any
	readResult     any
	proxyTimeout   int
}

func (m *countingToolManager) ListInterfaces(ctx context.Context, adom, device string) ([]fortinet.Interface, error) {
	m.interfaceReads.Add(1)
	return m.fakeManager.ListInterfaces(ctx, adom, device)
}

func (m *countingToolManager) ListPolicies(ctx context.Context, adom, pkg string) ([]fortinet.FirewallPolicy, error) {
	m.policyReads.Add(1)
	return m.fakeManager.ListPolicies(ctx, adom, pkg)
}

// ListIPv6Policies answers like a FortiOS 6.4+ ADOM: the legacy policy6
// table does not exist (IPv6 policies live in firewall/policy).
func (m *countingToolManager) ListIPv6Policies(context.Context, string, string) ([]fortinet.FirewallPolicy, error) {
	return nil, errors.New("fmg API result: code -3: Object does not exist")
}

func (m *countingToolManager) ListPolicyPackages(ctx context.Context, adom string) ([]fortinet.PolicyPackage, error) {
	m.packageReads.Add(1)
	return m.fakeManager.ListPolicyPackages(ctx, adom)
}

func (m *countingToolManager) Read(_ context.Context, resource string, data map[string]any) (any, error) {
	m.reads = append(m.reads, map[string]any{"resource": resource, "data": data})
	return m.readResult, nil
}

func (m *countingToolManager) ProxyGetTimeout(_ context.Context, adom, device, vdom, resource string, timeoutSeconds int) (fortinet.ProxyResult, error) {
	m.proxyTimeout = timeoutSeconds
	return fortinet.ProxyResult{ADOM: adom, Device: device, Resource: resource}, nil
}

func toolFixture(t *testing.T) (*Service, *countingToolManager) {
	t.Helper()
	policies := make([]fortinet.FirewallPolicy, 0, 5)
	for id := 1; id <= 4; id++ {
		policies = append(policies, fortinet.FirewallPolicy{PolicyID: id, Status: "enable", Action: "accept", SourceAddresses: []string{"all"}, DestinationAddresses: []string{"all"}})
	}
	policies = append(policies, fortinet.FirewallPolicy{PolicyID: 5, Status: "enable", Action: "accept", SourceAddresses6: []string{"all"}, DestinationAddresses6: []string{"all"}})
	base := &fakeManager{
		name:  "fmg",
		adoms: []fortinet.ADOM{{Name: "test-adom-branch"}},
		devices: map[string][]fortinet.Device{
			"test-adom-branch": {{Name: "fgt", ADOM: "test-adom-branch", Profile: "fmg", VDOMs: []string{"root"}}},
		},
		packages: map[string][]fortinet.PolicyPackage{
			"test-adom-branch": {{Name: "pkg", Members: []fortinet.PackageMember{{Device: "fgt", VDOM: "root"}}}},
		},
		interfaces: map[string][]fortinet.Interface{
			"test-adom-branch/fgt": {{Name: "lan", IP: "10.0.0.1/24", VDOM: "root"}, {Name: "mgmt", IP: "10.9.0.1/24", VDOM: "mgmt"}},
		},
		policies: map[string][]fortinet.FirewallPolicy{"test-adom-branch/pkg": policies},
		live:     map[string]fortinet.ProxyResult{},
	}
	manager := &countingToolManager{fakeManager: base}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p", Default: true}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	store.Refresh(context.Background())
	manager.interfaceReads.Store(0)
	manager.packageReads.Store(0)
	return New(cfg, store, map[string]fortinet.Manager{"fmg": manager}, nil), manager
}

func TestInterfacesComeFromTheSnapshotUnlessFresh(t *testing.T) {
	app, manager := toolFixture(t)
	value, err := app.GetInterfaces(context.Background(), "", "", "fgt", "root", false, false)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	if result["source"] != "inventory_snapshot" || result["adom"] != "test-adom-branch" || len(result["interfaces"].([]fortinet.Interface)) != 1 || manager.interfaceReads.Load() != 0 {
		t.Fatalf("result = %#v reads = %d, want the snapshot without a request and the ADOM from inventory", result, manager.interfaceReads.Load())
	}
	value, err = app.GetInterfaces(context.Background(), "", "", "fgt", "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if value.(map[string]any)["source"] != "fortimanager" || manager.interfaceReads.Load() != 1 {
		t.Fatalf("fresh read = %#v reads = %d", value, manager.interfaceReads.Load())
	}
}

func TestListPoliciesPagesFiltersAndSharesTheCache(t *testing.T) {
	app, manager := toolFixture(t)
	value, err := app.ListPolicies(context.Background(), PolicyListInput{Device: "fgt", Limit: 2, Offset: 1})
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	page := result["packages"].(map[string]any)["pkg"].([]fortinet.FirewallPolicy)
	if result["total"] != 4 || result["returned"] != 2 || result["truncated"] != true || len(page) != 2 || page[0].PolicyID != 2 || page[0].Device != "fgt" {
		t.Fatalf("result = %#v page = %#v, want IPv4 policies 2-3 of 4", result, page)
	}
	// Packages came from the inventory; the policies were read once and the
	// shared cache answers the next calls.
	if manager.packageReads.Load() != 0 || manager.policyReads.Load() != 1 {
		t.Fatalf("package reads = %d policy reads = %d", manager.packageReads.Load(), manager.policyReads.Load())
	}
	value, err = app.ListPolicies(context.Background(), PolicyListInput{ADOM: "test-adom-branch", Device: "fgt", PolicyID: 5, IPVersion: "ipv6"})
	if err != nil {
		t.Fatal(err)
	}
	result = value.(map[string]any)
	if result["total"] != 1 || manager.policyReads.Load() != 1 {
		t.Fatalf("ipv6 result = %#v policy reads = %d, want policy 5 from the cache", result, manager.policyReads.Load())
	}
	// The cached policies were not modified by the listing.
	cached, _ := app.cachedPolicies(context.Background(), manager, "test-adom-branch", "pkg", false, app.store.Snapshot().GeneratedAt)
	if cached[0].Device != "" {
		t.Fatalf("cached policy was changed: %#v", cached[0])
	}
}

func TestListObjectsPagesOnFortiManagerAndOmitsMappings(t *testing.T) {
	app, manager := toolFixture(t)
	manager.readResult = []any{
		map[string]any{"name": "a", "dynamic_mapping": []any{map[string]any{"_scope": []any{}}}},
		map[string]any{"name": "b"},
	}
	value, err := app.ListObjects(context.Background(), ObjectListInput{Device: "fgt", ObjectType: "firewall/address", Limit: 2, Offset: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(manager.reads) != 1 || fmt.Sprint(manager.reads[0]["data"].(map[string]any)["range"]) != "[4 2]" || !strings.Contains(manager.reads[0]["resource"].(string), "/adom/test-adom-branch/") {
		t.Fatalf("reads = %#v, want range [offset limit] in the device's ADOM", manager.reads)
	}
	result := value.(map[string]any)
	first := result["objects"].([]any)[0].(map[string]any)
	if first["dynamic_mapping"] != nil || first["dynamic_mapping_omitted"] != true || result["truncated"] != true {
		t.Fatalf("result = %#v", result)
	}
}

func TestSettingsReadBoundsTheFortiGateWait(t *testing.T) {
	app, manager := toolFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := app.GetFortiManagerSettings(ctx, "", "", "fgt", "root", "/api/v2/monitor/router/ipv4"); err != nil {
		t.Fatal(err)
	}
	if manager.proxyTimeout < 5 || manager.proxyTimeout > 15 {
		t.Fatalf("proxy timeout = %d s, want about 5 s below the 20 s deadline", manager.proxyTimeout)
	}
}

// slowADOMManager holds the ADOM list until released.
type slowRefreshManager struct {
	*fakeManager
	release chan struct{}
}

func (m *slowRefreshManager) ListADOMs(ctx context.Context) ([]fortinet.ADOM, error) {
	select {
	case <-m.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return m.fakeManager.ListADOMs(ctx)
}

func TestRefreshInventoryOutlivesTheCaller(t *testing.T) {
	base := &fakeManager{name: "fmg", adoms: []fortinet.ADOM{{Name: "test-adom-primary"}}, devices: map[string][]fortinet.Device{"test-adom-primary": {{Name: "fgt", ADOM: "test-adom-primary", Profile: "fmg"}}}, live: map[string]fortinet.ProxyResult{}}
	manager := &slowRefreshManager{fakeManager: base, release: make(chan struct{})}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p", Default: true}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	app := New(cfg, store, map[string]fortinet.Manager{"fmg": manager}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	summary, err := app.RefreshInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.RefreshInProgress {
		t.Fatalf("summary = %#v, want refresh_in_progress after the caller stopped waiting", summary)
	}
	close(manager.release)
	deadline := time.Now().Add(5 * time.Second)
	for store.Snapshot().GeneratedAt.IsZero() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	snapshot := store.Snapshot()
	if len(snapshot.Profiles) != 1 || snapshot.Profiles[0].Stale || len(snapshot.Devices) != 1 {
		t.Fatalf("snapshot = %#v, want a complete refresh despite the canceled caller", snapshot)
	}
}

// countingAnalyzer counts FortiAnalyzer reads.
type countingAnalyzer struct {
	reads atomic.Int32
}

func (a *countingAnalyzer) Name() string { return "faz" }
func (a *countingAnalyzer) Status(context.Context) (any, error) {
	a.reads.Add(1)
	return map[string]any{"version": "7.6"}, nil
}
func (a *countingAnalyzer) SearchLogs(context.Context, fortinet.LogSearchRequest) (fortinet.LogSearchResult, error) {
	return fortinet.LogSearchResult{}, nil
}
func (a *countingAnalyzer) Read(context.Context, string, map[string]any) (any, error) {
	a.reads.Add(1)
	return []any{}, nil
}
func (a *countingAnalyzer) Close() error { return nil }

func TestStaticAnalyzerReadsAreCached(t *testing.T) {
	analyzer := &countingAnalyzer{}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "faz", Product: config.ProductFortiAnalyzer, URL: "https://faz.invalid", Username: "u", Password: "p", Default: true}}
	app := New(cfg, nil, nil, map[string]fortinet.Analyzer{"faz": analyzer})
	for range 2 {
		if _, err := app.FortiAnalyzerStatus(context.Background(), ""); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FortiAnalyzerRead(context.Background(), "", "/dvmdb/adom/test-adom-primary/device", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := app.FortiAnalyzerRead(context.Background(), "", "/logview/adom/test-adom-primary/logsearch/5", nil); err != nil {
			t.Fatal(err)
		}
	}
	// Status and device list once each; the running search every time.
	if analyzer.reads.Load() != 4 {
		t.Fatalf("reads = %d, want 4", analyzer.reads.Load())
	}
}

func TestCheckWebFilterForOnePolicy(t *testing.T) {
	app, _ := newWebFilterService(t)
	output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "https://www.example.com/", Device: "edge-1", PolicyID: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Profiles) != 1 || output.Profiles[0].Profile != "corp-web" || len(output.Profiles[0].Policies) != 1 || output.Profiles[0].Policies[0].PolicyID != 10 {
		t.Fatalf("profiles = %#v, want only corp-web through policy 10", output.Profiles)
	}
	if _, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", PolicyID: 10}); err == nil {
		t.Fatal("policy_id without device accepted")
	}
	output, err = app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", Device: "edge-1", PolicyID: 99})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Profiles) != 0 || !strings.Contains(strings.Join(output.Warnings, " "), "Policy 99") {
		t.Fatalf("profiles = %#v warnings = %v", output.Profiles, output.Warnings)
	}
}

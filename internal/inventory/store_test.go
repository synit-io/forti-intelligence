package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

func TestDeviceReadFailureIsDeviceLevelNotProfileStale(t *testing.T) {
	manager := &refreshTestManager{interfaceErr: errors.New("interface endpoint unavailable")}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	snapshot := store.Refresh(context.Background())

	if len(snapshot.Profiles) != 1 || snapshot.Profiles[0].Stale || snapshot.Profiles[0].Error != "" || snapshot.Profiles[0].DeviceReadErrors != 1 {
		t.Fatalf("profiles = %#v, want fresh profile with one device read error", snapshot.Profiles)
	}
	if len(snapshot.Errors) != 1 || snapshot.Errors[0].Stage != "list_interfaces" {
		t.Fatalf("errors = %#v, want visible interface error", snapshot.Errors)
	}
	if len(snapshot.Devices) != 1 || snapshot.Devices[0].DataError != "list_interfaces" {
		t.Fatalf("devices = %#v, want data_error on the device", snapshot.Devices)
	}
}

func TestADOMLevelFailureStillMarksProfileStale(t *testing.T) {
	manager := &adomLevelFailureManager{refreshTestManager: refreshTestManager{}}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	snapshot := store.Refresh(context.Background())
	if len(snapshot.Profiles) != 1 || !snapshot.Profiles[0].Stale || snapshot.Profiles[0].Error == "" {
		t.Fatalf("profiles = %#v, want stale profile after package read failure", snapshot.Profiles)
	}
}

type adomLevelFailureManager struct {
	refreshTestManager
}

func (m *adomLevelFailureManager) ListPolicyPackages(context.Context, string) ([]fortinet.PolicyPackage, error) {
	return nil, errors.New("fmg API result: code -11: No permission for the resource")
}

func TestRefreshLogsUnderlyingApplianceError(t *testing.T) {
	var logs bytes.Buffer
	manager := &refreshTestManager{adomErr: errors.New("fmg API result: code -11: No permission for the resource")}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	store.SetLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))

	snapshot := store.Refresh(context.Background())
	if len(snapshot.Errors) != 1 || snapshot.Errors[0].Stage != "list_adoms" {
		t.Fatalf("errors = %#v, want list_adoms error", snapshot.Errors)
	}
	output := logs.String()
	for _, want := range []string{"inventory refresh stage failed", "profile=fmg", "stage=list_adoms", "code -11", "No permission for the resource"} {
		if !strings.Contains(output, want) {
			t.Errorf("logs = %q, missing %q", output, want)
		}
	}
}

func TestRefreshRetainsLastKnownGoodDeviceDataAfterLaterFailure(t *testing.T) {
	manager := &refreshTestManager{}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	first := store.Refresh(context.Background())
	if len(first.Devices) != 1 || len(first.Devices[0].Interfaces) != 1 {
		t.Fatalf("first snapshot = %#v, want inventoried interface", first)
	}
	lastSuccess := first.Profiles[0].LastSuccess

	manager.interfaceErr = errors.New("interface endpoint unavailable")
	second := store.Refresh(context.Background())
	if len(second.Devices) != 1 || len(second.Devices[0].Interfaces) != 1 || second.Devices[0].Interfaces[0].Name != "port1" {
		t.Fatalf("second snapshot = %#v, want last-known-good interface retained", second)
	}
	if second.Profiles[0].Stale || second.Profiles[0].DeviceReadErrors != 1 || !second.Devices[0].DataAsOf.Equal(first.Devices[0].DataAsOf) || second.Devices[0].DataError != "list_interfaces" {
		t.Fatalf("profile state = %#v device = %#v, want device-level retention with data_as_of from the first refresh", second.Profiles[0], second.Devices[0])
	}
	_ = lastSuccess
	if len(second.Errors) != 1 || second.Errors[0].Stage != "list_interfaces" {
		t.Fatalf("errors = %#v, want current refresh error", second.Errors)
	}
}

func TestGroupsForDeviceIncludesNestedGroups(t *testing.T) {
	groups := []fortinet.DeviceGroup{
		{Name: "branches/east", Members: []fortinet.PackageMember{{Device: "branch-1"}}},
		{Name: "all-branches", Members: []fortinet.PackageMember{{Device: "branches/east"}}},
	}
	got := groupsForDevice(groups, "branch-1")
	want := []string{"all-branches", "branches/east"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("groupsForDevice() = %#v, want %#v", got, want)
	}
}

func TestStartRefreshesImmediatelyAndOnTicker(t *testing.T) {
	var adomCalls atomic.Int32
	manager := &refreshTestManager{adomCalls: &adomCalls}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 5*time.Millisecond, 1)
	ctx := t.Context()
	defer store.Stop()

	started := time.Now()
	store.Start(ctx)
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("Start must not block on the first refresh")
	}
	select {
	case <-store.Ready():
	case <-time.After(time.Second):
		t.Fatal("first background refresh did not publish a snapshot")
	}
	if snapshot := store.Snapshot(); snapshot.GeneratedAt.IsZero() || len(snapshot.Devices) != 1 {
		t.Fatalf("first background snapshot = %+v", snapshot)
	}
	ownership, err := store.ResolveIPOwnership(OwnershipQuery{IP: "10.0.0.1"})
	if err != nil || !ownership.Ready {
		t.Fatalf("startup ownership index not ready: %+v, %v", ownership, err)
	}
	deadline := time.NewTimer(500 * time.Millisecond)
	defer deadline.Stop()
	for adomCalls.Load() < 2 {
		select {
		case <-deadline.C:
			t.Fatalf("startup/ticker refreshes = %d, want at least 2", adomCalls.Load())
		case <-time.After(time.Millisecond):
		}
	}
}

func TestStartPublishesFailureAndReturnsWithinDeadline(t *testing.T) {
	manager := &refreshTestManager{deviceDelay: time.Second}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, time.Hour, 1)
	store.SetRefreshTimeout(20 * time.Millisecond)
	defer store.Stop()
	store.Start(context.Background())
	select {
	case <-store.Ready():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("background refresh did not respect the refresh timeout")
	}
	if snapshot := store.Snapshot(); snapshot.GeneratedAt.IsZero() || len(snapshot.Errors) == 0 {
		t.Fatalf("startup failure not published: %+v", snapshot)
	}
}

func TestRefreshProcessesADOMsWithinRefreshDeadline(t *testing.T) {
	manager := &refreshTestManager{
		adoms:       []fortinet.ADOM{{Name: "test-adom-a"}, {Name: "test-adom-b"}, {Name: "test-adom-c"}},
		deviceDelay: 100 * time.Millisecond,
	}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	snapshot := store.Refresh(ctx)
	if len(snapshot.Devices) != 3 {
		t.Fatalf("devices = %d, want all 3 ADOM devices; errors = %#v", len(snapshot.Devices), snapshot.Errors)
	}
	for _, refreshError := range snapshot.Errors {
		if refreshError.Stage == "list_devices" || refreshError.Stage == "refresh" {
			t.Fatalf("refresh error = %#v, want no deadline failure", refreshError)
		}
	}
}

func TestRefreshSerializesRequestsPerManager(t *testing.T) {
	var active, maxActive atomic.Int32
	manager := &refreshTestManager{
		adoms:     []fortinet.ADOM{{Name: "test-adom-a"}, {Name: "test-adom-b"}, {Name: "test-adom-c"}},
		active:    &active,
		maxActive: &maxActive,
		callDelay: time.Millisecond,
	}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 8)

	snapshot := store.Refresh(context.Background())
	if len(snapshot.Errors) != 0 {
		t.Fatalf("refresh errors = %#v, want none", snapshot.Errors)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent manager calls = %d, want 1", got)
	}
}

func TestRefreshBatchesRetriesAndSkipsOfflineDevices(t *testing.T) {
	devices := make([]fortinet.Device, 0, 10)
	for index := range 9 {
		devices = append(devices, fortinet.Device{Name: fmt.Sprintf("fgt-%d", index), ConnectionStatus: "up"})
	}
	devices = append(devices, fortinet.Device{Name: "fgt-offline", ConnectionStatus: "down"})
	manager := &batchRefreshManager{
		refreshTestManager: refreshTestManager{},
		devices:            devices,
		failFirstBatch:     true,
	}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)

	snapshot := store.Refresh(context.Background())
	if len(snapshot.Devices) != len(devices) {
		t.Fatalf("devices = %d, want %d; errors = %#v", len(snapshot.Devices), len(devices), snapshot.Errors)
	}
	manager.mu.Lock()
	gotCalls := manager.batchCalls
	gotSizes := append([]int(nil), manager.batchSizes...)
	manager.mu.Unlock()
	if gotCalls != 3 || !reflect.DeepEqual(gotSizes, []int{8, 8, 2}) {
		t.Fatalf("batch calls=%d sizes=%v, want retry of first batch then 8+2 (offline devices are read from the FortiManager database too)", gotCalls, gotSizes)
	}
	for _, refreshError := range snapshot.Errors {
		if refreshError.Device == "fgt-offline" {
			t.Fatalf("offline device produced a refresh error: %#v", refreshError)
		}
	}
	if len(snapshot.UnavailableDevices) != 1 || snapshot.UnavailableDevices[0].Device != "fgt-offline" || snapshot.UnavailableDevices[0].DataSource != "fortimanager_database" || snapshot.UnavailableDevices[0].DataAsOf.IsZero() {
		t.Fatalf("unavailable devices = %#v", snapshot.UnavailableDevices)
	}
	if len(snapshot.Profiles) != 1 || snapshot.Profiles[0].Stale || snapshot.Profiles[0].Error != "" || snapshot.Profiles[0].UnavailableDevices != 1 || snapshot.Profiles[0].LastSuccess.IsZero() {
		t.Fatalf("profile state = %#v, want fresh profile with one unavailable device", snapshot.Profiles)
	}
	for _, device := range snapshot.Devices {
		if len(device.Interfaces) != 1 || device.DataAsOf.IsZero() {
			t.Fatalf("device %#v has interfaces=%#v, want complete batch result", device.Name, device.Interfaces)
		}
	}
}

type refreshTestManager struct {
	adomCalls    *atomic.Int32
	active       *atomic.Int32
	maxActive    *atomic.Int32
	adomErr      error
	interfaceErr error
	adoms        []fortinet.ADOM
	deviceDelay  time.Duration
	callDelay    time.Duration
}

type batchRefreshManager struct {
	refreshTestManager
	devices        []fortinet.Device
	failFirstBatch bool

	mu         sync.Mutex
	batchCalls int
	batchSizes []int
}

func (m *batchRefreshManager) ListDevices(_ context.Context, adom string) ([]fortinet.Device, error) {
	devices := make([]fortinet.Device, len(m.devices))
	copy(devices, m.devices)
	for index := range devices {
		if devices[index].ADOM == "" {
			devices[index].ADOM = adom
		}
		if devices[index].Profile == "" {
			devices[index].Profile = "fmg"
		}
	}
	return devices, nil
}

func (m *batchRefreshManager) ListInterfacesBatch(ctx context.Context, _ string, devices []string) (map[string]fortinet.InterfaceBatchResult, error) {
	m.mu.Lock()
	m.batchCalls++
	call := m.batchCalls
	m.batchSizes = append(m.batchSizes, len(devices))
	m.mu.Unlock()
	if m.failFirstBatch && call == 1 {
		return nil, errors.New("connection refused by FortiManager")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	results := make(map[string]fortinet.InterfaceBatchResult, len(devices))
	for _, device := range devices {
		results[device] = fortinet.InterfaceBatchResult{Interfaces: []fortinet.Interface{{Name: device + "-wan", IP: "10.0.0.1", Netmask: "255.255.255.0", Network: "10.0.0.0/24", VDOM: "root"}}}
	}
	return results, nil
}

func (m *refreshTestManager) Name() string { return "fmg" }
func (m *refreshTestManager) ListADOMs(ctx context.Context) ([]fortinet.ADOM, error) {
	defer m.trackCall(ctx)()
	if m.adomCalls != nil {
		m.adomCalls.Add(1)
	}
	if m.adomErr != nil {
		return nil, m.adomErr
	}
	if m.adoms != nil {
		return m.adoms, nil
	}
	return []fortinet.ADOM{{Name: "test-adom-primary"}}, nil
}
func (m *refreshTestManager) ListDevices(ctx context.Context, adom string) ([]fortinet.Device, error) {
	defer m.trackCall(ctx)()
	if m.deviceDelay > 0 {
		timer := time.NewTimer(m.deviceDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []fortinet.Device{{Profile: "fmg", ADOM: adom, Name: "fgt-1", VDOMs: []string{"root"}}}, nil
}
func (m *refreshTestManager) ListDeviceGroups(ctx context.Context, _ string) ([]fortinet.DeviceGroup, error) {
	defer m.trackCall(ctx)()
	return nil, nil
}
func (m *refreshTestManager) ListPolicyPackages(ctx context.Context, _ string) ([]fortinet.PolicyPackage, error) {
	defer m.trackCall(ctx)()
	return nil, nil
}
func (m *refreshTestManager) ListPolicies(context.Context, string, string) ([]fortinet.FirewallPolicy, error) {
	return nil, nil
}
func (m *refreshTestManager) ListIPv6Policies(context.Context, string, string) ([]fortinet.FirewallPolicy, error) {
	return nil, nil
}
func (m *refreshTestManager) ListAddresses(context.Context, string) ([]fortinet.AddressObject, error) {
	return nil, nil
}
func (m *refreshTestManager) ListServices(context.Context, string) ([]fortinet.ServiceObject, error) {
	return nil, nil
}
func (m *refreshTestManager) ListInterfaces(ctx context.Context, _ string, _ string) ([]fortinet.Interface, error) {
	defer m.trackCall(ctx)()
	if m.interfaceErr != nil {
		return nil, m.interfaceErr
	}
	return []fortinet.Interface{{Name: "port1", VDOM: "root"}}, nil
}
func (m *refreshTestManager) ProxyGet(context.Context, string, string, string, string) (fortinet.ProxyResult, error) {
	return fortinet.ProxyResult{}, nil
}
func (m *refreshTestManager) PolicyLookup(context.Context, string, string, string, fortinet.PolicyLookupRequest) (fortinet.ProxyResult, error) {
	return fortinet.ProxyResult{}, nil
}
func (m *refreshTestManager) Read(context.Context, string, map[string]any) (any, error) {
	return nil, nil
}
func (m *refreshTestManager) Close() error { return nil }

func (m *refreshTestManager) trackCall(ctx context.Context) func() {
	if m.active == nil || m.maxActive == nil {
		return func() {}
	}
	current := m.active.Add(1)
	for {
		previous := m.maxActive.Load()
		if current <= previous || m.maxActive.CompareAndSwap(previous, current) {
			break
		}
	}
	if m.callDelay > 0 {
		timer := time.NewTimer(m.callDelay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
		}
	}
	return func() { m.active.Add(-1) }
}

type deniedDeviceListManager struct {
	refreshTestManager
}

func (m *deniedDeviceListManager) ListADOMs(context.Context) ([]fortinet.ADOM, error) {
	return []fortinet.ADOM{{Name: "test-adom-primary"}, {Name: "test-adom-secondary"}}, nil
}

func (m *deniedDeviceListManager) ListDevices(context.Context, string) ([]fortinet.Device, error) {
	return nil, errors.New("fmg API result: code -11: No permission for the resource")
}

func TestEveryDeviceListDeniedNamesTheAccount(t *testing.T) {
	store := NewStore(map[string]fortinet.Manager{"fmg": &deniedDeviceListManager{}}, 0, 1)
	snapshot := store.Refresh(context.Background())
	if len(snapshot.Profiles) != 1 || !snapshot.Profiles[0].Stale || !strings.Contains(snapshot.Profiles[0].Error, "account itself is refused") {
		t.Fatalf("profile = %#v", snapshot.Profiles)
	}
}

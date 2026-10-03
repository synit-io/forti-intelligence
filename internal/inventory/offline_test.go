package inventory

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

// offlineReadManager fails interface reads for chosen devices.
type offlineReadManager struct {
	batchRefreshManager
	failDevices map[string]error
}

func (m *offlineReadManager) ListInterfacesBatch(ctx context.Context, adom string, devices []string) (map[string]fortinet.InterfaceBatchResult, error) {
	results, err := m.batchRefreshManager.ListInterfacesBatch(ctx, adom, devices)
	if err != nil {
		return nil, err
	}
	for device, failure := range m.failDevices {
		if _, ok := results[device]; ok && failure != nil {
			results[device] = fortinet.InterfaceBatchResult{InterfaceError: failure}
		}
	}
	return results, nil
}

func TestOfflineDeviceReadFailureKeepsProfileFreshAndRetainsData(t *testing.T) {
	manager := &offlineReadManager{
		batchRefreshManager: batchRefreshManager{devices: []fortinet.Device{{Name: "edge-up", ConnectionStatus: "up"}, {Name: "edge-down", ConnectionStatus: "up"}}},
		failDevices:         map[string]error{},
	}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	first := store.Refresh(context.Background())
	var firstDataAsOf time.Time
	for _, device := range first.Devices {
		if device.Name == "edge-down" {
			firstDataAsOf = device.DataAsOf
		}
	}

	// The device goes offline and FortiManager refuses its database read.
	manager.devices[1].ConnectionStatus = "down"
	manager.failDevices["edge-down"] = errors.New("fmg API result: code -3: Object does not exist")
	second := store.Refresh(context.Background())
	if len(second.Errors) != 0 || second.Profiles[0].Stale {
		t.Fatalf("offline read failure marked the snapshot stale: errors=%#v profiles=%#v", second.Errors, second.Profiles)
	}
	notice := second.UnavailableDevices
	if len(notice) != 1 || notice[0].DataSource != "retained" || !notice[0].DataAsOf.Equal(firstDataAsOf) || !strings.Contains(notice[0].ReadError, "list_interfaces") || !strings.Contains(notice[0].Reason, "connection_status") {
		t.Fatalf("notice = %#v", notice)
	}
	for _, device := range second.Devices {
		if device.Name == "edge-down" && (len(device.Interfaces) != 1 || !device.DataAsOf.Equal(firstDataAsOf)) {
			t.Fatalf("offline device lost retained data: %#v", device)
		}
	}
	ownership, _ := store.ResolveIPOwnership(OwnershipQuery{IP: "10.0.0.5", Device: "edge-down"})
	if len(ownership.Candidates) != 1 || ownership.Candidates[0].ConnectionStatus != "down" || len(ownership.UnavailableDevices) != 1 || len(ownership.Errors) != 0 {
		t.Fatalf("ownership = %#v", ownership)
	}

	// The same failure on an online device is a visible device-level error;
	// it still does not mark the profile stale.
	manager.devices[1].ConnectionStatus = "up"
	third := store.Refresh(context.Background())
	if len(third.Errors) != 1 || third.Errors[0].Stage != "list_interfaces" || third.Profiles[0].Stale || third.Profiles[0].DeviceReadErrors != 1 || len(third.UnavailableDevices) != 0 {
		t.Fatalf("online failure: errors=%#v profiles=%#v", third.Errors, third.Profiles)
	}
}

type blockingManager struct {
	slowADOMManager
	release chan struct{}
	entered atomic.Bool
}

func (m *blockingManager) ListADOMs(ctx context.Context) ([]fortinet.ADOM, error) {
	m.entered.Store(true)
	select {
	case <-m.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []fortinet.ADOM{{Name: "test-adom-primary"}}, nil
}

func TestSnapshotReportsLoadingUntilFirstRefreshCompletes(t *testing.T) {
	manager := &blockingManager{release: make(chan struct{})}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, time.Hour, 1)
	refreshed := make(chan struct{})
	store.SetAfterRefresh(func(context.Context, Snapshot) { close(refreshed) })
	ctx := t.Context()
	defer store.Stop()
	store.Start(ctx)
	deadline := time.Now().Add(time.Second)
	for !manager.entered.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshot := store.Snapshot()
	if !snapshot.GeneratedAt.IsZero() || !snapshot.RefreshInProgress || snapshot.RefreshStartedAt.IsZero() {
		t.Fatalf("loading snapshot = %+v", snapshot)
	}
	ownership, err := store.ResolveIPOwnership(OwnershipQuery{IP: "10.0.0.1"})
	if err != nil || ownership.Ready || !ownership.RefreshInProgress {
		t.Fatalf("ownership while loading = %+v, %v", ownership, err)
	}
	route, err := store.ResolveRoute(RouteQuery{IP: "10.0.0.1"})
	if err != nil || route.Ready || !route.RefreshInProgress || !strings.Contains(strings.Join(route.Warnings, " "), "still loading") {
		t.Fatalf("route while loading = %+v, %v", route, err)
	}
	close(manager.release)
	select {
	case <-store.Ready():
	case <-time.After(time.Second):
		t.Fatal("snapshot not published after release")
	}
	// Ready signals publication; refresh cleanup finishes before the hook runs.
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("refresh not completed after publication")
	}
	if snapshot := store.Snapshot(); snapshot.RefreshInProgress || snapshot.GeneratedAt.IsZero() {
		t.Fatalf("published snapshot = %+v", snapshot)
	}
}

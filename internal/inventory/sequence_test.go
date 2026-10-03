package inventory

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

// sequenceManager records the ADOM of every appliance call in order.
type sequenceManager struct {
	batchRefreshManager
	mu    sync.Mutex
	calls []string
}

func (m *sequenceManager) record(adom string) {
	m.mu.Lock()
	m.calls = append(m.calls, adom)
	m.mu.Unlock()
}
func (m *sequenceManager) ListADOMs(context.Context) ([]fortinet.ADOM, error) {
	return []fortinet.ADOM{{Name: "test-adom-primary"}, {Name: "test-adom-tenant-internal"}, {Name: "test-adom-secondary"}}, nil
}
func (m *sequenceManager) ListDevices(ctx context.Context, adom string) ([]fortinet.Device, error) {
	m.record(adom)
	return []fortinet.Device{{Name: adom + "-fgt-1", ADOM: adom, Profile: "fmg"}, {Name: adom + "-fgt-2", ADOM: adom, Profile: "fmg"}}, nil
}
func (m *sequenceManager) ListDeviceGroups(_ context.Context, adom string) ([]fortinet.DeviceGroup, error) {
	m.record(adom)
	return nil, nil
}
func (m *sequenceManager) ListPolicyPackages(_ context.Context, adom string) ([]fortinet.PolicyPackage, error) {
	m.record(adom)
	return nil, nil
}
func (m *sequenceManager) ListInterfacesBatch(ctx context.Context, adom string, devices []string) (map[string]fortinet.InterfaceBatchResult, error) {
	m.record(adom)
	return m.batchRefreshManager.ListInterfacesBatch(ctx, adom, devices)
}
func (m *sequenceManager) ListRoutesBatch(_ context.Context, adom string, targets []fortinet.RouteTarget) (map[string]fortinet.RouteBatchResult, error) {
	m.record(adom)
	result := make(map[string]fortinet.RouteBatchResult)
	for _, target := range targets {
		result[target.Device] = fortinet.RouteBatchResult{}
	}
	return result, nil
}

func TestRefreshKeepsEachADOMsRequestsTogether(t *testing.T) {
	manager := &sequenceManager{}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 8)
	snapshot := store.Refresh(context.Background())
	if len(snapshot.Devices) != 6 || len(snapshot.Errors) != 0 {
		t.Fatalf("snapshot devices=%d errors=%#v", len(snapshot.Devices), snapshot.Errors)
	}
	// Collapse consecutive duplicates: every ADOM must appear as one block.
	var blocks []string
	for _, adom := range manager.calls {
		if len(blocks) == 0 || blocks[len(blocks)-1] != adom {
			blocks = append(blocks, adom)
		}
	}
	if strings.Join(blocks, ",") != "test-adom-primary,test-adom-tenant-internal,test-adom-secondary" {
		t.Fatalf("ADOM call order = %v (blocks %v), want one contiguous block per ADOM", manager.calls, blocks)
	}
}

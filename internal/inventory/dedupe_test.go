package inventory

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

type slowADOMManager struct {
	calls atomic.Int32
	delay time.Duration
}

func (m *slowADOMManager) Name() string { return "fmg" }
func (m *slowADOMManager) ListADOMs(ctx context.Context) ([]fortinet.ADOM, error) {
	m.calls.Add(1)
	select {
	case <-time.After(m.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []fortinet.ADOM{{Name: "test-adom-primary"}}, nil
}
func (m *slowADOMManager) ListDevices(context.Context, string) ([]fortinet.Device, error) {
	return nil, nil
}
func (m *slowADOMManager) ListDeviceGroups(context.Context, string) ([]fortinet.DeviceGroup, error) {
	return nil, nil
}
func (m *slowADOMManager) ListPolicyPackages(context.Context, string) ([]fortinet.PolicyPackage, error) {
	return nil, nil
}
func (m *slowADOMManager) ListPolicies(context.Context, string, string) ([]fortinet.FirewallPolicy, error) {
	return nil, nil
}
func (m *slowADOMManager) ListIPv6Policies(context.Context, string, string) ([]fortinet.FirewallPolicy, error) {
	return nil, nil
}
func (m *slowADOMManager) ListAddresses(context.Context, string) ([]fortinet.AddressObject, error) {
	return nil, nil
}
func (m *slowADOMManager) ListServices(context.Context, string) ([]fortinet.ServiceObject, error) {
	return nil, nil
}
func (m *slowADOMManager) ListInterfaces(context.Context, string, string) ([]fortinet.Interface, error) {
	return nil, nil
}
func (m *slowADOMManager) ProxyGet(context.Context, string, string, string, string) (fortinet.ProxyResult, error) {
	return fortinet.ProxyResult{}, nil
}
func (m *slowADOMManager) PolicyLookup(context.Context, string, string, string, fortinet.PolicyLookupRequest) (fortinet.ProxyResult, error) {
	return fortinet.ProxyResult{}, nil
}
func (m *slowADOMManager) Read(context.Context, string, map[string]any) (any, error) { return nil, nil }
func (m *slowADOMManager) Close() error                                              { return nil }

func TestRefreshSkipsRepeatWhenNewerSnapshotLandedWhileWaiting(t *testing.T) {
	manager := &slowADOMManager{delay: 300 * time.Millisecond}
	store := NewStore(map[string]fortinet.Manager{"fmg": manager}, 0, 1)
	first := make(chan Snapshot, 1)
	go func() { first <- store.Refresh(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	second := store.Refresh(context.Background())
	snapshot := <-first
	if manager.calls.Load() != 1 {
		t.Fatalf("ListADOMs calls = %d, want 1 (queued refresh reused the fresh snapshot)", manager.calls.Load())
	}
	if !second.GeneratedAt.Equal(snapshot.GeneratedAt) || len(second.ADOMs) != 1 {
		t.Fatalf("queued refresh = %#v, want the snapshot published by the running refresh", second)
	}
	third := store.Refresh(context.Background())
	if manager.calls.Load() != 2 || third.GeneratedAt.Before(snapshot.GeneratedAt) {
		t.Fatalf("a later refresh must run again: calls=%d", manager.calls.Load())
	}
}

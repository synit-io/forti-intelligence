package inventory

import (
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

func TestSnapshotViewAndDeviceIndex(t *testing.T) {
	store := NewStore(nil, time.Hour, 1)
	store.setSnapshot(Snapshot{
		GeneratedAt: time.Now(),
		Devices: []fortinet.Device{{
			Name:    "edge",
			Profile: "fmg",
			ADOM:    "test-adom-primary",
			Interfaces: []fortinet.Interface{{
				Name: "port1",
			}},
		}},
	})

	view := store.Snapshot()
	view.Devices = append(view.Devices, fortinet.Device{Name: "other"})
	view.Devices[0].Name = "changed"
	again := store.Snapshot()
	if len(again.Devices) != 1 || again.Devices[0].Name != "edge" {
		t.Fatalf("published devices = %#v", again.Devices)
	}

	found := store.FindDevices("fmg", "test-adom-primary", "edge")
	if len(found) != 1 || found[0].Name != "edge" {
		t.Fatalf("FindDevices = %#v", found)
	}
	if len(store.FindDevices("other", "test-adom-primary", "edge")) != 0 || len(store.FindDevices("fmg", "test-adom-other", "edge")) != 0 {
		t.Fatal("FindDevices ignored profile or ADOM")
	}

	store.mu.Lock()
	store.startedAt = time.Now()
	store.mu.Unlock()
	during := store.Snapshot()
	if !store.HasSnapshot() || during.GeneratedAt.IsZero() || !during.RefreshInProgress {
		t.Fatalf("snapshot during refresh: generated=%v in_progress=%v has=%v", during.GeneratedAt, during.RefreshInProgress, store.HasSnapshot())
	}
}

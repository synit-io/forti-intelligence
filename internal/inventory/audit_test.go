package inventory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

type zoneRetryReader struct{ calls int }

func (r *zoneRetryReader) ListInterfacesBatch(context.Context, string, []string) (map[string]fortinet.InterfaceBatchResult, error) {
	r.calls++
	if r.calls > 1 {
		return nil, errors.New("connection reset")
	}
	return map[string]fortinet.InterfaceBatchResult{"edge": {
		Interfaces: []fortinet.Interface{{Name: "port1", VDOM: "root"}},
		ZoneError:  errors.New("connection reset"),
	}}, nil
}

func TestRetryRetainsInterfacesAfterZoneFailure(t *testing.T) {
	reader := &zoneRetryReader{}
	results, attempts := refreshInterfaceBatch(context.Background(), make(chan struct{}, 1), make(chan struct{}, 1), reader, "test-adom-primary", []string{"edge"})
	result := results["edge"]
	if len(result.Interfaces) != 1 || result.InterfaceError != nil || result.ZoneError == nil || attempts["edge"] != 3 {
		t.Fatalf("result=%+v attempts=%v", result, attempts)
	}
}

func TestRefreshQueueHonorsCancellation(t *testing.T) {
	store := NewStore(nil, time.Hour, 1)
	store.refreshGate <- struct{}{}
	defer func() { <-store.refreshGate }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { store.Refresh(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled refresh blocked behind another refresh")
	}
	if !store.Snapshot().GeneratedAt.IsZero() {
		t.Fatal("canceled refresh replaced snapshot")
	}
}

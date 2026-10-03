package fortinet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func TestLaneServesInteractiveBeforeBackground(t *testing.T) {
	var lane requestLane
	if err := lane.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	order := make(chan string, 2)
	background := WithBackgroundPriority(context.Background())
	go func() {
		_ = lane.acquire(background)
		order <- "background"
		lane.release()
	}()
	time.Sleep(20 * time.Millisecond)
	go func() {
		_ = lane.acquire(context.Background())
		order <- "interactive"
		lane.release()
	}()
	time.Sleep(20 * time.Millisecond)
	lane.release()
	if first, second := <-order, <-order; first != "interactive" || second != "background" {
		t.Fatalf("order = %s, %s; want interactive first", first, second)
	}

	// A waiter that gives up leaves the queue; the lane stays usable.
	if err := lane.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := lane.acquire(ctx); err == nil {
		t.Fatal("acquire on a busy lane must fail when its context ends")
	}
	lane.release()
	if err := lane.acquire(context.Background()); err != nil {
		t.Fatalf("lane unusable after abandoned waiter: %v", err)
	}
	lane.release()
}

func TestRequestCounterCountsAppliance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, _ := decodeRPC(t, r)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": request["id"], "result": []any{map[string]any{"status": map[string]any{"code": 0}, "data": []any{}}}})
	}))
	defer server.Close()
	client, err := NewFortiManager(apiKeyProfile("fmg", config.ProductFortiManager, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx, stats := WithRequestStats(context.Background())
	for range 3 {
		if _, err := client.Read(ctx, "/sys/status", nil); err != nil {
			t.Fatal(err)
		}
	}
	if snapshot := stats.Snapshot(); snapshot.Requests != 3 || snapshot.SlowestResource != "/sys/status" {
		t.Fatalf("stats = %#v, want 3 requests with /sys/status as slowest resource", snapshot)
	}
}

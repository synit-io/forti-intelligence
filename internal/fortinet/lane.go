package fortinet

import (
	"context"
	"sync"
	"time"
)

// requestLane admits one in-flight request per credential. Waiting requests
// are served interactive-first: tool calls overtake queued background
// inventory work, so a running refresh no longer delays answers.
type requestLane struct {
	mu   sync.Mutex
	busy bool
	high []chan struct{}
	low  []chan struct{}
}

func (l *requestLane) acquire(ctx context.Context) error {
	low := isBackground(ctx)
	l.mu.Lock()
	if !l.busy {
		l.busy = true
		l.mu.Unlock()
		return nil
	}
	waiter := make(chan struct{})
	if low {
		l.low = append(l.low, waiter)
	} else {
		l.high = append(l.high, waiter)
	}
	l.mu.Unlock()
	select {
	case <-waiter:
		return nil
	case <-ctx.Done():
		l.mu.Lock()
		removed := removeWaiter(&l.high, waiter) || removeWaiter(&l.low, waiter)
		l.mu.Unlock()
		if !removed {
			// The lane was handed over just as the context ended; pass it on.
			l.release()
		}
		return ctx.Err()
	}
}

func (l *requestLane) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	var next chan struct{}
	switch {
	case len(l.high) > 0:
		next, l.high = l.high[0], l.high[1:]
	case len(l.low) > 0:
		next, l.low = l.low[0], l.low[1:]
	default:
		l.busy = false
		return
	}
	close(next) // the lane stays busy and passes to the next waiter
}

func removeWaiter(queue *[]chan struct{}, waiter chan struct{}) bool {
	for index, candidate := range *queue {
		if candidate == waiter {
			*queue = append((*queue)[:index], (*queue)[index+1:]...)
			return true
		}
	}
	return false
}

type backgroundKey struct{}

// WithBackgroundPriority marks work (such as inventory refreshes) that
// yields the appliance lane to interactive tool requests.
func WithBackgroundPriority(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundKey{}, true)
}

func isBackground(ctx context.Context) bool {
	background, _ := ctx.Value(backgroundKey{}).(bool)
	return background
}

type laneHolderKey struct{}

// laneHeldBy reports whether ctx runs inside withLaneHeld of client, so its
// requests reuse the held lane instead of queueing behind it.
func laneHeldBy(ctx context.Context, client *rpcClient) bool {
	holder, _ := ctx.Value(laneHolderKey{}).(*rpcClient)
	return holder != nil && holder == client
}

// RequestStats accumulates the appliance requests made with one context, so
// a tool call or background job can report where its time went: waiting for
// the serial lane, on the wire, or in retries.
type RequestStats struct {
	mu              sync.Mutex
	requests        int64
	retries         int64
	laneWait        time.Duration
	wire            time.Duration
	slowest         time.Duration
	slowestResource string
}

// RequestStatsSnapshot is a point-in-time copy of RequestStats.
type RequestStatsSnapshot struct {
	Requests        int64
	Retries         int64
	LaneWait        time.Duration
	Wire            time.Duration
	Slowest         time.Duration
	SlowestResource string
}

type statsKey struct{}

// WithRequestStats attaches statistics that every appliance request made
// with the returned context updates.
func WithRequestStats(ctx context.Context) (context.Context, *RequestStats) {
	stats := &RequestStats{}
	return context.WithValue(ctx, statsKey{}, stats), stats
}

// Snapshot returns the current totals.
func (s *RequestStats) Snapshot() RequestStatsSnapshot {
	if s == nil {
		return RequestStatsSnapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return RequestStatsSnapshot{
		Requests: s.requests, Retries: s.retries, LaneWait: s.laneWait, Wire: s.wire,
		Slowest: s.slowest, SlowestResource: s.slowestResource,
	}
}

// Requests returns the number of requests sent so far.
func (s *RequestStats) Requests() int64 {
	return s.Snapshot().Requests
}

func statsFrom(ctx context.Context) *RequestStats {
	stats, _ := ctx.Value(statsKey{}).(*RequestStats)
	return stats
}

func recordRequest(ctx context.Context, resource string, laneWait, wire time.Duration) {
	stats := statsFrom(ctx)
	if stats == nil {
		return
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	stats.requests++
	stats.laneWait += laneWait
	stats.wire += wire
	if wire > stats.slowest {
		stats.slowest, stats.slowestResource = wire, resource
	}
}

func recordLaneWait(ctx context.Context, wait time.Duration) {
	if stats := statsFrom(ctx); stats != nil {
		stats.mu.Lock()
		stats.laneWait += wait
		stats.mu.Unlock()
	}
}

func recordRetry(ctx context.Context) {
	if stats := statsFrom(ctx); stats != nil {
		stats.mu.Lock()
		stats.retries++
		stats.mu.Unlock()
	}
}

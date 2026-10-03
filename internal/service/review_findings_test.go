package service

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

func TestFortiGateSettingAliases(t *testing.T) {
	cases := map[string]string{
		"routing-table":  "/api/v2/monitor/router/ipv4",
		"ROUTING-TABLE6": "/api/v2/monitor/router/ipv6",
		"sdwan-health":   "/api/v2/monitor/virtual-wan/health-check",
		"sessions":       "/api/v2/monitor/firewall/session",
		" interfaces ":   "/api/v2/monitor/system/interface",
	}
	for in, want := range cases {
		got := canonicalFortiGateResource(in)
		if got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
		if err := validateFortiGateReadResource(got); err != nil {
			t.Errorf("alias %q rejected: %v", in, err)
		}
	}
	if err := validateFortiGateReadResource(canonicalFortiGateResource("password")); err == nil {
		t.Fatal("unknown alias was accepted as a FortiGate resource")
	}
}

func TestInvestigateRejectsInputAndContinuesAfterStepError(t *testing.T) {
	svc := New(config.Default(), inventory.NewStore(nil, 0, 1), nil, nil)
	ctx := context.Background()
	if _, err := svc.Investigate(ctx, InvestigateInput{SourceIP: "not-an-ip", DestinationIP: "8.8.8.8"}); err == nil {
		t.Fatal("accepted a non-address source")
	}
	if _, err := svc.Investigate(ctx, InvestigateInput{SourceIP: "10.0.0.1", DestinationPort: 80}); err == nil {
		t.Fatal("accepted an empty destination")
	}
	if _, err := svc.Investigate(ctx, InvestigateInput{SourceIP: "10.0.0.1", DestinationIP: "8.8.8.8", DestinationPort: 70000}); err == nil {
		t.Fatal("accepted an out-of-range port")
	}

	output, err := svc.Investigate(ctx, InvestigateInput{
		SourceIP: "10.0.0.1", DestinationIP: "8.8.8.8", IncludeLogs: true,
	})
	if err != nil {
		t.Fatalf("Investigate() error = %v", err)
	}
	if !strings.Contains(strings.Join(output.Warnings, " "), "destination_port") {
		t.Fatalf("warnings = %#v", output.Warnings)
	}
	joined := strings.Join(output.Errors, "\n")
	if !strings.Contains(joined, "logs:") {
		t.Fatalf("errors = %#v, want the log step recorded", output.Errors)
	}
	if output.Logs != nil {
		t.Fatalf("logs = %#v, want the failed search omitted", output.Logs)
	}
}

func TestLogResultUsable(t *testing.T) {
	if logResultUsable(fortinet.LogSearchResult{}) {
		t.Fatal("empty result looked usable")
	}
	if !logResultUsable(fortinet.LogSearchResult{TaskID: float64(12)}) {
		t.Fatal("numeric task id was ignored")
	}
	if !logResultUsable(fortinet.LogSearchResult{Records: []any{map[string]any{"srcip": "10.0.0.1"}}}) {
		t.Fatal("records were ignored")
	}
	if logResultUsable(fortinet.LogSearchResult{TaskID: "", Records: []any{}}) {
		t.Fatal("empty task and records looked usable")
	}
}

func TestCacheEpochDoesNotResurrectAnalyzerRead(t *testing.T) {
	svc := New(config.Default(), inventory.NewStore(nil, 0, 1), nil, nil)
	calls := 0
	read := func() (any, error) {
		calls++
		if calls == 1 {
			svc.clearCaches()
		}
		return "fresh", nil
	}
	if _, err := svc.cachedAnalyzerRead(context.Background(), "faz", "/sys/status", nil, read); err != nil {
		t.Fatal(err)
	}
	svc.cacheMu.Lock()
	stored := len(svc.readCache)
	svc.cacheMu.Unlock()
	if stored != 0 {
		t.Fatalf("stale read was stored, cache size %d", stored)
	}
	if _, err := svc.cachedAnalyzerRead(context.Background(), "faz", "/sys/status", nil, read); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("reads = %d, want a second read after the generation bump", calls)
	}
}

func TestAnalyzerCacheSkipsLiveDevicePathsAndEvicts(t *testing.T) {
	if !cacheableAnalyzerRead("/sys/status") || !cacheableAnalyzerRead("/dvmdb/device?filter=name") || !cacheableAnalyzerRead("/dvmdb/adom/test-adom-primary/device") || !cacheableAnalyzerRead("/logview/adom/test-adom-primary/logfields") {
		t.Fatal("stable analyzer reads were treated as live")
	}
	if cacheableAnalyzerRead("/dvmdb/adom/test-adom-primary/device/edge") || cacheableAnalyzerRead("/dvmdb/adom/test-adom-primary/group") {
		t.Fatal("live dvmdb path was cached")
	}

	svc := New(config.Default(), inventory.NewStore(nil, 0, 1), nil, nil)
	calls := 0
	read := func() (any, error) {
		calls++
		return "live", nil
	}
	for range 2 {
		if _, err := svc.cachedAnalyzerRead(context.Background(), "faz", "/dvmdb/adom/test-adom-primary/device/edge", nil, read); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("live reads = %d, want 2", calls)
	}

	svc.cacheMu.Lock()
	svc.readCache["old"] = readCacheEntry{created: time.Now().Add(-time.Hour), value: "stale"}
	svc.cacheMu.Unlock()
	if _, err := svc.cachedAnalyzerRead(context.Background(), "faz", "/dvmdb/device", nil, func() (any, error) { return "devices", nil }); err != nil {
		t.Fatal(err)
	}
	svc.cacheMu.Lock()
	_, kept := svc.readCache["old"]
	svc.cacheMu.Unlock()
	if kept {
		t.Fatal("expired analyzer cache entry was kept")
	}
}

type stubResolver struct {
	addrs     []net.IPAddr
	addrErr   error
	cname     string
	cnameErr  error
	addrCalls int
	failCtx   bool
}

func (s *stubResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	s.addrCalls++
	if s.failCtx {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	}
	return s.addrs, s.addrErr
}

func (s *stubResolver) LookupCNAME(context.Context, string) (string, error) {
	return s.cname, s.cnameErr
}

func TestDNSCacheSeparatesRecordsAndNegatives(t *testing.T) {
	svc := New(config.Default(), inventory.NewStore(nil, 0, 1), nil, nil)
	resolver := &stubResolver{addrs: []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}}
	svc.resolver = resolver

	got, err := svc.lookupIPAddrWithCache(context.Background(), "copy.example")
	if err != nil || len(got) != 1 {
		t.Fatalf("lookup = %#v %v", got, err)
	}
	got[0].IP[len(got[0].IP)-1] = 9
	again, err := svc.lookupIPAddrWithCache(context.Background(), "copy.example")
	if err != nil || again[0].IP[len(again[0].IP)-1] == 9 {
		t.Fatalf("cached address was aliased: %#v %v", again, err)
	}
	if resolver.addrCalls != 1 {
		t.Fatalf("address lookups = %d, want 1", resolver.addrCalls)
	}

	svc.storeCNAME("cname-only.example", "target.example.", nil)
	if _, _, ok := svc.cachedAddresses("cname-only.example"); ok {
		t.Fatal("a CNAME entry answered an address lookup")
	}

	resolver.addrErr = errors.New("no such host")
	resolver.addrs = nil
	if _, err := svc.lookupIPAddrWithCache(context.Background(), "missing.example"); err == nil {
		t.Fatal("negative lookup returned no error")
	}
	calls := resolver.addrCalls
	if _, err := svc.lookupIPAddrWithCache(context.Background(), "missing.example"); err == nil || resolver.addrCalls != calls {
		t.Fatalf("negative result was not cached (calls %d -> %d)", calls, resolver.addrCalls)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	resolver.failCtx = true
	if _, err := svc.lookupIPAddrWithCache(cancelled, "late.example"); err == nil {
		t.Fatal("cancelled lookup succeeded")
	}
	if _, _, ok := svc.cachedAddresses("late.example"); ok {
		t.Fatal("context error was cached")
	}

	svc.dnsCacheMu.Lock()
	svc.dnsCache["old.example"] = dnsCacheEntry{
		haveAddresses: true,
		addressExpiry: time.Now().Add(-time.Second),
		addresses:     []net.IPAddr{{IP: net.IPv4(1, 2, 3, 4)}},
	}
	svc.dnsCache["mixed.example"] = dnsCacheEntry{
		haveAddresses: true,
		addressExpiry: time.Now().Add(-time.Second),
		haveCNAME:     true,
		cname:         "target.example.",
		cnameExpiry:   time.Now().Add(time.Minute),
	}
	svc.dnsCacheMu.Unlock()
	svc.storeAddresses("new.example", []net.IPAddr{{IP: net.IPv4(5, 6, 7, 8)}}, nil)
	svc.dnsCacheMu.RLock()
	_, oldKept := svc.dnsCache["old.example"]
	_, mixedKept := svc.dnsCache["mixed.example"]
	svc.dnsCacheMu.RUnlock()
	if oldKept {
		t.Fatal("expired DNS entry was kept")
	}
	if !mixedKept {
		t.Fatal("host with a live CNAME was evicted")
	}
}

package service

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

func TestInvestigationLogsUseResolvedTupleAndVerifiedAnalyzerScope(t *testing.T) {
	app, _, analyzer := deskFixture(t)
	app.resolver = &fakeDNSResolver{ips: []net.IPAddr{
		{IP: net.ParseIP("203.0.113.1")}, {IP: net.ParseIP("203.0.113.2")}, {IP: net.ParseIP("2001:db8::1")},
	}}
	var requests []fortinet.LogSearchRequest
	start := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)
	analyzer.search = func(request fortinet.LogSearchRequest) (fortinet.LogSearchResult, error) {
		requests = append(requests, request)
		return fortinet.LogSearchResult{
			TaskID: "17", TimedOut: true,
			NextAction: &fortinet.LogNextAction{Kind: "resume", Tool: "search_fortianalyzer_logs", Arguments: &fortinet.LogSearchArguments{
				TaskID: "17", Device: request.Device, ADOM: request.ADOM, Filter: request.Filter, Limit: request.Limit,
			}},
		}, nil
	}
	out, err := app.Investigate(context.Background(), InvestigateInput{
		SourceIP: "10.1.1.7", DestinationIP: "example.test", Protocol: "TCP", SourcePort: 52000, DestinationPort: 443,
		IncludeLogs: true, LogStart: start, LogEnd: end,
	})
	if err != nil || out.Logs == nil || len(requests) != 1 || len(out.Ownership.Candidates) == 0 || out.Logs.NextAction == nil {
		t.Fatalf("investigation = %#v, %v; %d requests", out, err, len(requests))
	}
	request := requests[0]
	filters := []string{`srcip="10.1.1.7"`, `(dstip="203.0.113.1" OR dstip="203.0.113.2")`, `dstport=443`, `srcport=52000`, `proto=6`, `vd="root"`}
	for _, filter := range filters {
		if !strings.Contains(request.Filter, filter) {
			t.Errorf("filter %q lacks %q", request.Filter, filter)
		}
	}
	if strings.Contains(request.Filter, "2001:") || request.Device != "edge-log" || request.ADOM != "test-adom-analyzer" || request.Limit != 25 || !request.StartTime.Equal(start) || !request.EndTime.Equal(end) {
		t.Fatalf("request = %#v", request)
	}
	if args := out.Logs.NextAction.Arguments; args.Device != request.Device || args.Filter != request.Filter || args.TaskID != "17" {
		t.Fatalf("continuation = %#v", args)
	}
}

func TestInvestigationLogsWarnOnAmbiguousDeviceAndSkipUnresolvedDestination(t *testing.T) {
	app, _, analyzer := deskFixture(t)
	analyzer.devices = []map[string]any{
		{"serial": "FGT123", "devname": "edge-log"},
		{"sn": "FGT123", "hostname": "edge", "devname": "also-edge-log"},
	}
	var searches int
	analyzer.search = func(request fortinet.LogSearchRequest) (fortinet.LogSearchResult, error) {
		searches++
		return fortinet.LogSearchResult{ADOM: request.ADOM, Device: request.Device, Filter: request.Filter, Complete: true, Count: 1}, nil
	}
	input := InvestigateInput{SourceIP: "10.1.1.7", DestinationIP: "10.1.1.72", Device: "fgt", VDOM: "root", IncludeLogs: true, Protocol: "any"}
	out, err := app.Investigate(context.Background(), input)
	if err != nil || out.Logs == nil || out.Logs.Device != "" || strings.Contains(out.Logs.Filter, "vd=") || strings.Contains(out.Logs.Filter, "proto=") || !strings.Contains(strings.Join(out.Logs.Warnings, " "), "returned rows are candidates") {
		t.Fatalf("ambiguous log evidence = %#v, %v", out.Logs, err)
	}
	app.resolver = &fakeDNSResolver{ips: []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}}}
	input.DestinationIP = "ipv6-only.test"
	out, err = app.Investigate(context.Background(), input)
	if err != nil || out.Logs != nil || searches != 1 || !strings.Contains(strings.Join(out.Errors, " "), "traffic search skipped") || len(out.Ownership.Candidates) == 0 {
		t.Fatalf("unresolved destination = %#v, %v; %d requests", out, err, searches)
	}
}

func TestInvestigationLogsUseIPv6ICMPProtocolWithoutPortFilters(t *testing.T) {
	app, _, analyzer := deskFixture(t)
	analyzer.search = func(request fortinet.LogSearchRequest) (fortinet.LogSearchResult, error) {
		return fortinet.LogSearchResult{Filter: request.Filter, Complete: true, Count: 1}, nil
	}
	out, err := app.Investigate(context.Background(), InvestigateInput{
		SourceIP: "2001:db8::1", DestinationIP: "2001:db8::2", Protocol: "icmp", SourcePort: 9, DestinationPort: 9, IncludeLogs: true,
	})
	if err != nil || out.Logs == nil || !strings.Contains(out.Logs.Filter, "proto=58") || strings.Contains(out.Logs.Filter, "port=") {
		t.Fatalf("ICMPv6 logs = %#v, %v", out.Logs, err)
	}
}

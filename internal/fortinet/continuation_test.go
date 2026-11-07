package fortinet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

func TestLogContinuationStatesAndAbsoluteOffsets(t *testing.T) {
	start := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	for _, tc := range []struct {
		name                  string
		complete              bool
		count, offset, budget int
		known                 bool
		kind                  string
		next                  int
	}{
		{"running", false, 2, 100, 50, true, "poll", 100},
		{"next_page", true, 10, 110, 50, true, "page", 120},
		{"exhausted_nonzero_start", true, 10, 140, 50, true, "new_search", 150},
		{"short_page", true, 3, 110, 50, true, "", 0},
		{"unknown", true, 10, 110, 50, false, "recover_scope", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := LogSearchRequest{ADOM: "logs", Device: "logged-fgt", Filter: "srcip=10.0.0.1", LogType: "traffic", StartTime: start, EndTime: end, Limit: 10, Offset: tc.offset}
			result := LogSearchResult{Profile: "faz", ADOM: "logs", TaskID: "42", Complete: tc.complete, Count: tc.count}
			setLogContinuation(&result, request, 100, tc.budget, tc.known)
			if tc.kind == "" {
				if result.NextAction != nil {
					t.Fatalf("unexpected next action %+v", result.NextAction)
				}
				return
			}
			if result.NextAction == nil || result.NextAction.Kind != tc.kind {
				t.Fatalf("action=%+v", result.NextAction)
			}
			args := result.NextAction.Arguments
			if !tc.known {
				if args != nil {
					t.Fatal("manufactured unknown query")
				}
				return
			}
			if args.Offset != tc.next || args.Start != start.Format(time.RFC3339Nano) || args.End != end.Format(time.RFC3339Nano) || args.Filter != request.Filter || args.Device != request.Device {
				t.Fatalf("changed scope/page: %+v", args)
			}
			if tc.kind == "new_search" && args.TaskID != "" {
				t.Fatal("exhausted task reused")
			}
			if result.RecoveryAction.Arguments.Offset != tc.offset {
				t.Fatal("recovery skips unseen records")
			}
		})
	}
}

func TestExecuteSuggestedLogArgumentsPreservesOmittedTimeWindow(t *testing.T) {
	var submits []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     any              `json:"id"`
			Method string           `json:"method"`
			Params []map[string]any `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&request)
		var result any
		switch request.Method {
		case "add":
			submits = append(submits, request.Params[0])
			result = map[string]any{"tid": len(submits)}
		default:
			result = map[string]any{"percentage": 100, "data": []any{map[string]any{"srcip": "10.0.0.1"}}}
		}
		json.NewEncoder(w).Encode(map[string]any{"id": request.ID, "result": result})
	}))
	defer server.Close()
	client, err := NewFortiAnalyzer(config.ProfileConfig{Name: "faz", URL: server.URL, AllowInsecureHTTP: true, APIKey: "test", ADOMs: []string{"logs", "other"}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "logs", Device: "logged-fgt", Filter: "srcip=10.0.0.1", Limit: 1, Offset: 100})
	if err != nil {
		t.Fatal(err)
	}
	if first.NextAction == nil || first.NextAction.Kind != "new_search" {
		t.Fatalf("action=%+v", first.NextAction)
	}
	args := first.NextAction.Arguments
	start, _ := time.Parse(time.RFC3339Nano, args.Start)
	end, _ := time.Parse(time.RFC3339Nano, args.End)
	// Execute exactly the returned arguments; no caller-side filter rewrite.
	next, err := client.SearchLogs(context.Background(), LogSearchRequest{ADOM: args.ADOM, LogType: args.LogType, Filter: args.Filter, Device: args.Device, StartTime: start, EndTime: end, Limit: args.Limit, Offset: args.Offset, TaskID: args.TaskID})
	if err != nil {
		t.Fatal(err)
	}
	if len(submits) != 2 || submits[1]["offset"] != float64(101) || submits[0]["filter"] != submits[1]["filter"] {
		t.Fatalf("submits=%+v", submits)
	}
	firstRange, _ := json.Marshal(submits[0]["time-range"])
	nextRange, _ := json.Marshal(submits[1]["time-range"])
	if string(firstRange) != string(nextRange) || !next.StartTime.Equal(first.StartTime) || !next.EndTime.Equal(first.EndTime) {
		t.Fatalf("window changed: %s -> %s", firstRange, nextRange)
	}
	if strings.Count(submits[1]["filter"].(string), "devname=") != 1 {
		t.Fatal("device filtered twice")
	}
	// Known metadata must override conflicting resume fields, not report a
	// different query while reading the original task.
	resumed, err := client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "logs", TaskID: "1", Filter: "WRONG", Device: "WRONG", LogType: "WRONG", Limit: 1, Offset: 100})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.NextAction.Arguments.Filter != "srcip=10.0.0.1" || resumed.NextAction.Arguments.Device != "logged-fgt" || resumed.NextAction.Arguments.LogType != "traffic" {
		t.Fatalf("resume scope=%+v", resumed.NextAction)
	}
	mismatched, err := client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "other", TaskID: "1", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if mismatched.NextAction == nil || mismatched.NextAction.Kind != "recover_scope" || mismatched.NextAction.Arguments != nil || mismatched.Filter == first.Filter {
		t.Fatalf("cross-ADOM metadata reused: %+v", mismatched)
	}
	client.searchMu.Lock()
	entry := client.searches["1"]
	entry.created = time.Now().Add(-2 * submittedSearchTTL)
	client.searches["1"] = entry
	client.searchMu.Unlock()
	expired, err := client.SearchLogs(context.Background(), LogSearchRequest{ADOM: "logs", TaskID: "1", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if expired.NextAction == nil || expired.NextAction.Kind != "recover_scope" || expired.NextAction.Arguments != nil {
		t.Fatalf("expired recovery=%+v", expired.NextAction)
	}
}

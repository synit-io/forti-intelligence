package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
	"github.com/synit-io/forti-intelligence/internal/service"
)

func memorySession(t testing.TB, s *Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.mcp.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "measurement", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

type recoveryAnalyzer struct {
	fortinet.Analyzer
	result fortinet.LogSearchResult
	err    error
}

func (*recoveryAnalyzer) Name() string { return "faz" }
func (a *recoveryAnalyzer) SearchLogs(context.Context, fortinet.LogSearchRequest) (fortinet.LogSearchResult, error) {
	return a.result, a.err
}
func (*recoveryAnalyzer) Read(context.Context, string, map[string]any) (any, error) { return nil, nil }

func TestMCPLogFailureRetainsTypedState(t *testing.T) {
	for _, tc := range []struct {
		name        string
		result      fortinet.LogSearchResult
		err         error
		wantKind    string
		wantJSON    bool
		wantFailure bool
	}{
		{"submit", fortinet.LogSearchResult{}, errors.New("submit failed"), "", false, true},
		{"first_poll", fortinet.LogSearchResult{TaskID: "42", Profile: "faz", ADOM: "logs", Limit: 25}, errors.New("temporary timeout"), "timeout", true, true},
		{"resumed", fortinet.LogSearchResult{TaskID: "42", Profile: "faz", ADOM: "logs", Resumed: true, Progress: 25, Count: 1, Records: []any{map[string]any{"srcip": "10.0.0.1"}}}, errors.New("temporary timeout"), "timeout", true, true},
		{"budget", fortinet.LogSearchResult{TaskID: "42", Profile: "faz", ADOM: "logs", TimedOut: true, Progress: 25}, nil, "", true, false},
		{"cancel", fortinet.LogSearchResult{TaskID: "42", Profile: "faz", ADOM: "logs", Progress: 25}, context.Canceled, "canceled", true, true},
		{"permission", fortinet.LogSearchResult{TaskID: "42", Profile: "faz", ADOM: "logs", Complete: true, Progress: 100}, errors.New("No permission for the resource"), "permission_denied", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Profiles = []config.ProfileConfig{{Name: "faz", Product: config.ProductFortiAnalyzer, ADOMs: []string{"logs"}, Default: true}}
			analyzer := &recoveryAnalyzer{result: tc.result, err: tc.err}
			app := service.New(cfg, inventory.NewStore(nil, 0, 1), nil, map[string]fortinet.Analyzer{"faz": analyzer})
			server := New(app, cfg.Server, nil)
			session := memorySession(t, server)
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "search_fortianalyzer_logs", Arguments: map[string]any{"profile": "faz", "adom": "logs"}})
			if err != nil || result.IsError != tc.wantFailure {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			text := result.Content[0].(*mcp.TextContent).Text
			if tc.wantJSON {
				var got fortinet.LogSearchResult
				if err := json.Unmarshal([]byte(text), &got); err != nil {
					t.Fatalf("typed result lost: %s", text)
				}
				if got.TaskID != "42" || got.ADOM != "logs" || got.Count != tc.result.Count || got.Complete != tc.result.Complete {
					t.Fatalf("state changed: %+v", got)
				}
				if tc.wantKind != "" && (got.ErrorDetails == nil || string(got.ErrorDetails.Kind) != tc.wantKind) {
					t.Fatalf("error details=%+v", got.ErrorDetails)
				}
				if tc.name == "permission" && (got.NextAction == nil || got.NextAction.Kind != "correct_request") {
					t.Fatalf("permission retry=%+v", got.NextAction)
				}
			} else if json.Valid([]byte(text)) {
				t.Fatalf("submit failure should remain ordinary tool error: %s", text)
			}
			outcome := "ok"
			if tc.wantFailure {
				outcome = "error"
			}
			want := fmt.Sprintf(`forti_intelligence_tool_calls_total{tool="search_fortianalyzer_logs",outcome=%q} 1`, outcome)
			if !strings.Contains(server.Prometheus(nil), want) {
				t.Fatalf("failure not counted: %s", server.Prometheus(nil))
			}
			if result.StructuredContent != nil {
				t.Fatal("duplicate structured payload")
			}
		})
	}
}

func TestOverflowRetainsSameUnseenPage(t *testing.T) {
	for _, task := range []string{"42", ""} {
		t.Run("task="+task, func(t *testing.T) {
			next := &fortinet.LogNextAction{Kind: "new_search", Tool: "search_fortianalyzer_logs", Arguments: &fortinet.LogSearchArguments{Offset: 125, Limit: 25}}
			recover := &fortinet.LogNextAction{Kind: "smaller_page", Tool: "search_fortianalyzer_logs", Arguments: &fortinet.LogSearchArguments{Profile: "faz", ADOM: "logs", TaskID: task, Offset: 100, Limit: 25, Start: "2026-11-07T00:00:00Z", End: "2026-11-07T01:00:00Z"}}
			value := fortinet.LogSearchResult{Profile: "faz", ADOM: "logs", TaskID: task, Offset: 100, Limit: 25, Count: 25, Complete: true, Records: logFixtureRecords(25, true), NextAction: next, RecoveryAction: recover}
			for _, hugeWarnings := range []bool{false, true} {
				if hugeWarnings {
					value.Warnings = []string{strings.Repeat("w", 80<<10)}
				}
				response, measurement, err := encodeResult("search_fortianalyzer_logs", value, 64<<10)
				if err != nil || response == nil || !response.IsError {
					t.Fatalf("overflow response=%+v err=%v", response, err)
				}
				encoded := response.Content[0].(*mcp.TextContent).Text
				if len(encoded) > 64<<10 || !json.Valid([]byte(encoded)) || measurement.outcome != "overflow" {
					t.Fatal("invalid bounded fallback")
				}
				var got struct {
					fortinet.LogSearchResult
					ReturnedRecords         int  `json:"returned_records"`
					OmittedRecords          int  `json:"omitted_records"`
					RepresentationTruncated bool `json:"representation_truncated"`
				}
				if err := json.Unmarshal([]byte(encoded), &got); err != nil {
					t.Fatal(err)
				}
				if got.NextAction == nil || got.NextAction.Arguments == nil || got.NextAction.Arguments.Offset != 100 || got.NextAction.Arguments.Limit >= 25 || got.NextAction.Arguments.TaskID != task || got.TaskID != task || !got.Complete || got.Records != nil || got.OmittedRecords != 25 || !got.RepresentationTruncated {
					t.Fatalf("lost recovery: %s", encoded)
				}
				if strings.Contains(got.Hint, "offset 125") {
					t.Fatal("hint skips unseen records")
				}
			}
		})
	}
}

func TestResultMeasurementsSeparateSerializationOverflowAndState(t *testing.T) {
	server := &Server{config: config.ServerConfig{MaxResultBytes: 64 << 10}}
	values := []any{map[string]any{"value": 1}, fortinet.LogSearchResult{TimedOut: true, TaskID: "42"}, fortinet.LogSearchResult{ErrorDetails: &fortinet.ErrorInfo{Kind: fortinet.ErrorKindPermission}}, map[string]any{"large": strings.Repeat("x", 80<<10)}, make(chan int)}
	for _, value := range values {
		server.encodeResult("search_fortianalyzer_logs", value)
	}
	text := server.Prometheus(nil)
	for _, label := range []string{`outcome="ok",state="unspecified"} 1`, `outcome="ok",state="incomplete"} 1`, `outcome="ok",state="partial"} 1`, `outcome="overflow",state="unspecified"} 1`, `outcome="serialization_error",state="unspecified"} 1`} {
		if !strings.Contains(text, "forti_intelligence_tool_results_total{tool=\"search_fortianalyzer_logs\","+label) {
			t.Fatalf("missing result measurement %s: %s", label, text)
		}
	}
	if strings.Contains(text, "42") || strings.Contains(text, "permission_denied") {
		t.Fatal("payload values used as metric labels")
	}
}

func TestCatalogMeasurements(t *testing.T) {
	for _, ratingDevice := range []string{"", "rating-fgt"} {
		t.Run("rating="+ratingDevice, func(t *testing.T) {
			cfg := config.Default()
			cfg.Rating.Device = ratingDevice
			server := New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, nil)
			session := memorySession(t, server)
			tools, err := session.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			total := 0
			for _, tool := range tools.Tools {
				encoded, err := json.Marshal(tool)
				if err != nil {
					t.Fatal(err)
				}
				total += len(encoded)
				t.Logf("tool=%s definition_bytes=%d description_bytes=%d", tool.Name, len(encoded), len(tool.Description))
			}
			catalog, _ := json.Marshal(tools.Tools)
			variant := "default"
			if ratingDevice != "" {
				variant = "rating"
			}
			writeEvaluationArtifact(t, "catalog-"+variant+".json", catalog)
			writeEvaluationArtifact(t, "instructions-"+variant+".txt", []byte(session.InitializeResult().Instructions))
			t.Logf("catalog_tools=%d definitions_bytes=%d catalog_array_bytes=%d instructions_bytes=%d", len(tools.Tools), total, len(catalog), len(session.InitializeResult().Instructions))
		})
	}
}

func TestAdvertisedConstraintsPreserveNormalization(t *testing.T) {
	cfg := config.Default()
	server := New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, nil)
	tools, err := memorySession(t, server).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		encoded, _ := json.Marshal(tool.InputSchema)
		var schema struct {
			AdditionalProperties *bool `json:"additionalProperties"`
			Properties           map[string]struct {
				Minimum *float64 `json:"minimum"`
				Maximum *float64 `json:"maximum"`
				Enum    []any    `json:"enum"`
			}
		}
		json.Unmarshal(encoded, &schema)
		if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
			t.Fatalf("%s accepts unknown fields", tool.Name)
		}
		for name, property := range schema.Properties {
			if name == "limit" || name == "focus" || name == "ip_version" || name == "protocol" {
				if property.Minimum != nil || property.Maximum != nil || len(property.Enum) > 0 {
					t.Fatalf("%s.%s rejects normalization", tool.Name, name)
				}
			}
		}
		if tool.Name == "lookup_firewall_policy" {
			p := schema.Properties["destination_port"]
			if p.Minimum == nil || *p.Minimum != 1 || p.Maximum == nil || *p.Maximum != 65535 {
				t.Fatalf("port bounds missing: %s", encoded)
			}
		}
		if tool.Name == "search_fortianalyzer_logs" {
			p := schema.Properties["offset"]
			if p.Minimum == nil || *p.Minimum != 0 {
				t.Fatalf("offset bound missing: %s", encoded)
			}
		}
		if tool.Name == "investigate_traffic" && len(schema.Properties["detail"].Enum) != 3 {
			t.Fatal("compact/full enum missing")
		}
	}
}

func TestInvestigationOverflowPreservesFlowAndCoverage(t *testing.T) {
	input := service.InvestigateInput{SourceIP: "10.0.0.1", DestinationIP: "203.0.113.1", DestinationPort: 443, IncludeLogs: true}
	full := service.InvestigateOutput{Input: &input, Errors: []string{strings.Repeat("error", 30<<10)}, Logs: &fortinet.LogSearchResult{TaskID: "42", TimedOut: true}, Hops: []service.InvestigateHop{{DestinationIP: input.DestinationIP}}}
	for _, value := range []any{full, service.CompactInvestigate(input, full)} {
		response, _, err := encodeResult("investigate_traffic", value, 64<<10)
		if err != nil || !response.IsError {
			t.Fatalf("overflow=%+v %v", response, err)
		}
		text := response.Content[0].(*mcp.TextContent).Text
		if !json.Valid([]byte(text)) || len(text) > 64<<10 || !strings.Contains(text, input.SourceIP) || strings.Contains(text, "destination_port omitted") || strings.Contains(text, `"logs":"not requested"`) {
			t.Fatalf("lost actual flow/coverage: %s", text)
		}
	}
}

func TestExpiredTaskOverflowRestartsOriginalWindow(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "faz", Product: config.ProductFortiAnalyzer, ADOMs: []string{"logs"}, Default: true}}
	args := &fortinet.LogSearchArguments{Profile: "faz", ADOM: "logs", TaskID: "42", Start: "2026-11-07T00:00:00Z", End: "2026-11-07T01:00:00Z", Limit: 25, Offset: 100}
	analyzer := &recoveryAnalyzer{err: errors.New("code -3: Object does not exist"), result: fortinet.LogSearchResult{TaskID: "42", Profile: "faz", ADOM: "logs", Resumed: true, Offset: 100, Records: logFixtureRecords(25, true), RecoveryAction: &fortinet.LogNextAction{Kind: "smaller_page", Tool: "search_fortianalyzer_logs", Arguments: args}}}
	app := service.New(cfg, inventory.NewStore(nil, 0, 1), nil, map[string]fortinet.Analyzer{"faz": analyzer})
	server := New(app, cfg.Server, nil)
	server.config.MaxResultBytes = 64 << 10
	response, err := memorySession(t, server).CallTool(context.Background(), &mcp.CallToolParams{Name: "search_fortianalyzer_logs", Arguments: map[string]any{"profile": "faz", "adom": "logs", "task_id": "42", "offset": 100}})
	if err != nil || !response.IsError {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	var got fortinet.LogSearchResult
	text := response.Content[0].(*mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if got.NextAction == nil || got.NextAction.Kind != "new_search" || got.NextAction.Arguments.TaskID != "" || got.NextAction.Arguments.Offset != 100 || got.NextAction.Arguments.Start != args.Start {
		t.Fatalf("expired task re-polled: %s", text)
	}
}

func TestInvestigationOverflowShrinksNestedLogPage(t *testing.T) {
	input := service.InvestigateInput{SourceIP: "10.0.0.1", DestinationIP: "203.0.113.1", DestinationPort: 443, IncludeLogs: true}
	action := &fortinet.LogNextAction{Kind: "smaller_page", Tool: "search_fortianalyzer_logs", Arguments: &fortinet.LogSearchArguments{Profile: "faz", ADOM: "logs", TaskID: "42", Limit: 25, Offset: 100}}
	full := service.InvestigateOutput{Input: &input, Logs: &fortinet.LogSearchResult{TaskID: "42", Offset: 100, Limit: 25, Count: 25, Records: logFixtureRecords(25, true), RecoveryAction: action}}
	response, _, err := encodeResult("investigate_traffic", full, 64<<10)
	if err != nil || !response.IsError {
		t.Fatalf("overflow=%+v %v", response, err)
	}
	var got struct{ Evidence service.CompactInvestigation }
	text := response.Content[0].(*mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	args := got.Evidence.Logs.NextAction.Arguments
	if args.Limit >= 25 || args.Offset != 100 || args.TaskID != "42" || got.Evidence.Logs.Records != nil {
		t.Fatalf("nested recovery skips records: %s", text)
	}
}

func writeEvaluationArtifact(t *testing.T, name string, content []byte) {
	t.Helper()
	if dir := os.Getenv("FORTI_EVAL_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResultFixtureMeasurements(t *testing.T) {
	args := &fortinet.LogSearchArguments{Profile: "faz", ADOM: "logs", LogType: "traffic", Start: "2026-11-07T00:00:00Z", End: "2026-11-07T01:00:00Z", TaskID: "42", Limit: 25, Offset: 100}
	for _, scenario := range []string{"zero", "unfinished", "page", "overflow"} {
		value := fortinet.LogSearchResult{Profile: "faz", ADOM: "logs", TaskID: "42", LogType: "traffic", Progress: 100, Complete: true, Offset: 100, Limit: 25, StartTime: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), EndTime: time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC), RecoveryAction: &fortinet.LogNextAction{Kind: "smaller_page", Tool: "search_fortianalyzer_logs", Arguments: args}}
		if scenario != "zero" {
			value.Count = 25
			value.Records = logFixtureRecords(25, false)
			nextArgs := *args
			nextArgs.Offset = 125
			nextArgs.TaskID = ""
			value.NextAction = &fortinet.LogNextAction{Kind: "new_search", Tool: "search_fortianalyzer_logs", Arguments: &nextArgs, Reason: "Match budget exhausted; separate searches need not share a snapshot."}
		}
		if scenario == "unfinished" {
			value.Complete = false
			value.TimedOut = true
			value.Progress = 25
			value.NextAction = &fortinet.LogNextAction{Kind: "poll", Tool: "search_fortianalyzer_logs", Arguments: args}
		}
		if scenario == "overflow" {
			value.Records = logFixtureRecords(25, true)
		}
		response, measurement, err := encodeResult("search_fortianalyzer_logs", value, 64<<10)
		if err != nil {
			t.Fatal(err)
		}
		encoded := []byte(response.Content[0].(*mcp.TextContent).Text)
		t.Logf("scenario=logs-%s encoded_bytes=%d returned_bytes=%d outcome=%s state=%s", scenario, measurement.encoded, measurement.returned, measurement.outcome, measurement.state)
		writeEvaluationArtifact(t, "logs-"+scenario+".json", encoded)
	}
}

func logFixtureRecords(count int, oversized bool) []any {
	rows := make([]any, count)
	for i := range rows {
		row := map[string]any{"srcip": "10.0.0.1", "dstip": "203.0.113.1", "action": "accept"}
		if i == 0 && oversized {
			row["message"] = strings.Repeat("x", 80<<10)
		}
		rows[i] = row
	}
	return rows
}

func TestMCPInvestigationDetailDefaultRetainsFullContract(t *testing.T) {
	cfg := config.Default()
	server := New(service.New(cfg, inventory.NewStore(nil, 0, 1), nil, nil), cfg.Server, nil)
	session := memorySession(t, server)
	call := func(detail string) string {
		args := map[string]any{"source_ip": "10.0.0.1", "destination_ip": "203.0.113.1"}
		if detail != "" {
			args["detail"] = detail
		}
		response, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "investigate_traffic", Arguments: args})
		if err != nil || response.IsError {
			t.Fatalf("call detail=%q: %+v %v", detail, response, err)
		}
		return response.Content[0].(*mcp.TextContent).Text
	}
	omitted := call("")
	full := call("full")
	compact := call("compact")
	if omitted != full || strings.Contains(full, `"detail"`) || !strings.Contains(compact, `"detail":"compact"`) || !strings.Contains(compact, `"coverage"`) {
		t.Fatal("full/default contract or compact selection changed")
	}
}

func TestOverflowEssentialMetadataStillReturnsBoundedRecoveryError(t *testing.T) {
	query := strings.Repeat("filter", 20<<10)
	value := fortinet.LogSearchResult{Profile: "faz", ADOM: "logs", TaskID: "42", Filter: query, Offset: 100, Limit: 1, Count: 1, Complete: true, Records: logFixtureRecords(1, true), ErrorDetails: &fortinet.ErrorInfo{Kind: fortinet.ErrorKindTimeout, Message: strings.Repeat("timeout", 20<<10)}, RecoveryAction: &fortinet.LogNextAction{Kind: "smaller_page", Tool: "search_fortianalyzer_logs", Arguments: &fortinet.LogSearchArguments{Profile: "faz", ADOM: "logs", Filter: query, TaskID: "42", Limit: 1, Offset: 100}}}
	response, _, err := encodeResult("search_fortianalyzer_logs", value, 64<<10)
	if err != nil || !response.IsError {
		t.Fatalf("overflow=%+v err=%v", response, err)
	}
	text := response.Content[0].(*mcp.TextContent).Text
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil || len(text) > 64<<10 {
		t.Fatalf("invalid fallback: %v", err)
	}
	if got["task_id"] != "42" || got["offset"] != float64(100) || got["representation_truncated"] != true || !strings.Contains(got["hint"].(string), "Essential query metadata") || got["records"] != nil {
		t.Fatalf("essential scope overflow lost recovery: %s", text)
	}
}

package mcpserver

import (
	"encoding/json"
	"fmt"
	"maps"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/service"
)

type resultMeasurement struct {
	outcome, state    string
	encoded, returned int
}

func (s *Server) encodeResult(tool string, value any) (*mcp.CallToolResult, any, error) {
	response, measurement, err := encodeResult(tool, value, s.config.MaxResultBytes)
	s.recordResult(tool, measurement)
	return response, nil, err
}

// encodeResult measures the attempted JSON and returned text exactly once.
// These are bytes, never tokenizer estimates. Outcomes and states are bounded.
func encodeResult(tool string, value any, maxBytes int) (*mcp.CallToolResult, resultMeasurement, error) {
	measure := resultMeasurement{outcome: "ok", state: resultState(value)}
	encoded, err := json.Marshal(value)
	if err != nil {
		measure.outcome = "serialization_error"
		return nil, measure, fmt.Errorf("encode tool result: %w", err)
	}
	measure.encoded = len(encoded)
	overflow := maxBytes > 0 && len(encoded) > maxBytes
	if overflow {
		measure.outcome = "overflow"
		fallbacks, ok := overflowResults(value)
		if !ok {
			return nil, measure, fmt.Errorf("the %s result is %d KB, above the server limit of %d KB (max_result_bytes), and was not returned. %s", tool, len(encoded)>>10, maxBytes>>10, narrowingAdvice(tool))
		}
		encoded = nil
		for _, fallback := range fallbacks {
			candidate, marshalErr := json.Marshal(fallback)
			if marshalErr == nil && len(candidate) <= maxBytes {
				encoded = candidate
				break
			}
		}
		if encoded == nil {
			encoded, _ = json.Marshal(map[string]any{"error": "result_too_large", "representation_truncated": true, "hint": narrowingAdvice(tool)})
		}
		// Valid configurations allow at least 64 KiB; retain valid JSON even in
		// direct tests with artificially tiny caps.
		if len(encoded) > maxBytes {
			encoded = []byte(`{"error":"result_too_large"}`)
		}
		if len(encoded) > maxBytes {
			return nil, measure, fmt.Errorf("max_result_bytes too small for an overflow error")
		}
	}
	measure.returned = len(encoded)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}}, IsError: overflow}, measure, nil
}

func resultState(value any) string {
	switch v := value.(type) {
	case fortinet.LogSearchResult:
		if v.ErrorDetails != nil {
			return "partial"
		}
		if !v.Complete {
			return "incomplete"
		}
		return "complete"
	case service.InvestigateOutput:
		return investigationState(v)
	case service.CompactInvestigation:
		return investigationState(v.InvestigateOutput)
	}
	return "unspecified"
}

func investigationState(v service.InvestigateOutput) string {
	if len(v.Errors) > 0 || len(v.Ownership.Errors) > 0 || len(v.Route.Errors) > 0 {
		return "partial"
	}
	if !v.Ownership.Ready || !v.Route.Ready {
		return "incomplete"
	}
	if v.Policy != nil && !v.Policy.Complete {
		return "incomplete"
	}
	for _, h := range v.Hops {
		if len(h.Errors) > 0 {
			return "partial"
		}
		if h.Policy != nil && !h.Policy.Complete || h.WebFilter != nil && !h.WebFilter.Complete {
			return "incomplete"
		}
	}
	if v.Logs != nil && (!v.Logs.Complete || v.Logs.ErrorDetails != nil) {
		return "incomplete"
	}
	return "complete"
}

func overflowResults(value any) ([]any, bool) {
	switch v := value.(type) {
	case fortinet.LogSearchResult:
		records := v.Count
		v.Records = nil
		v.LogReceipt = nil
		// Count still describes appliance retrieval, not delivery. Separate fields
		// make representation truncation explicit without falsifying completion.
		action := smallerPageAction(v.RecoveryAction)
		v.NextAction = action
		v.Hint = "No records were delivered because this result exceeded max_result_bytes. Inspect next_action to recover the SAME offset; if limit is already 1, narrow the original filter/time window."
		full := struct {
			Error                   string `json:"error"`
			RepresentationTruncated bool   `json:"representation_truncated"`
			ReturnedRecords         int    `json:"returned_records"`
			OmittedRecords          int    `json:"omitted_records"`
			fortinet.LogSearchResult
		}{"result_too_large", true, 0, records, v}
		essential := map[string]any{"error": "result_too_large", "representation_truncated": true, "omitted_records": records, "returned_records": 0, "profile": v.Profile, "adom": v.ADOM, "device": v.Device, "filter": v.Filter, "log_type": v.LogType, "start_time": v.StartTime, "end_time": v.EndTime, "task_id": v.TaskID, "offset": v.Offset, "limit": v.Limit, "complete": v.Complete, "progress": v.Progress, "timed_out": v.TimedOut, "next_action": action, "error_details": boundedError(v.ErrorDetails), "hint": v.Hint, "omitted": "records, log receipt and diagnostic warnings; evidence completeness is unchanged"}
		minimal := map[string]any{"error": "result_too_large", "representation_truncated": true, "task_id": v.TaskID, "offset": v.Offset, "error_details": boundedError(v.ErrorDetails), "hint": "Essential query metadata exceeds max_result_bytes. Recover the original profile/ADOM/filter/device and absolute window, then narrow the filter/window or reduce limit at this SAME offset. No records were delivered."}
		return []any{full, essential, minimal}, true
	case service.InvestigateOutput:
		compact := service.CompactInvestigate(service.InvestigateInput{}, v)
		return investigationOverflow(compact), true
	case service.CompactInvestigation:
		return investigationOverflow(v), true
	}
	return nil, false
}

func smallerPageAction(action *fortinet.LogNextAction) *fortinet.LogNextAction {
	if action == nil || action.Arguments == nil {
		return action
	}
	copied := *action
	args := *action.Arguments
	args.Limit = max(1, args.Limit/2)
	copied.Arguments = &args
	return &copied
}

func boundedError(details *fortinet.ErrorInfo) *fortinet.ErrorInfo {
	if details == nil {
		return nil
	}
	copy := *details
	copy.Message = boundedText(copy.Message)
	copy.Hint = boundedText(copy.Hint)
	copy.Resource = boundedText(copy.Resource)
	return &copy
}
func boundedText(value string) string {
	if len(value) > 512 {
		return value[:512] + " [omitted]"
	}
	return value
}

func investigationOverflow(compact service.CompactInvestigation) []any {
	v := compact.InvestigateOutput
	omitted := make(map[string]int, len(compact.Omitted))
	maps.Copy(omitted, compact.Omitted)
	compact.Omitted = omitted
	if v.Logs != nil {
		logs := *v.Logs
		logs.Records = nil
		logs.LogReceipt = nil
		logs.NextAction = smallerPageAction(logs.RecoveryAction)
		logs.Hint = "Records omitted by the result size limit; recover the same offset with a smaller page."
		compact.Logs = &logs
		compact.Omitted["log_records"] = v.Logs.Count
	}
	hint := "Request detail=compact; if still too large, scope device and vdom, use one destination address, omit include_logs, or use focused tools. No omitted records were delivered."
	full := map[string]any{"error": "result_too_large", "representation_truncated": true, "hint": hint, "evidence": compact}
	errors := make([]string, 0, min(len(v.Errors), 8))
	for _, message := range v.Errors {
		if len(errors) >= 8 {
			break
		}
		errors = append(errors, boundedText(message))
	}
	essential := map[string]any{"error": "result_too_large", "representation_truncated": true, "flow": compact.Flow, "coverage": compact.Coverage, "errors": errors, "error_count": len(v.Errors), "omitted_hops": len(v.Hops), "omitted": "Investigation evidence did not fit; no absence or completeness claim is supported by omitted collections.", "hint": hint}
	if v.Logs != nil {
		logFallbacks, _ := overflowResults(*v.Logs)
		essential["logs"] = logFallbacks[len(logFallbacks)-2]
	}
	return []any{full, essential}
}

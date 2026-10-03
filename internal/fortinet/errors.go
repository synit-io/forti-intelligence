package fortinet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ErrorKind is a stable, machine-readable classification for appliance and
// transport failures. The human message remains available in Message.
type ErrorKind string

const (
	ErrorKindPermission        ErrorKind = "permission_denied"
	ErrorKindAuth              ErrorKind = "authentication_failed"
	ErrorKindNotFound          ErrorKind = "not_found"
	ErrorKindInvalid           ErrorKind = "invalid_request"
	ErrorKindTimeout           ErrorKind = "timeout"
	ErrorKindUnavailable       ErrorKind = "unavailable"
	ErrorKindDeviceUnavailable ErrorKind = "device_unavailable"
	ErrorKindRateLimited       ErrorKind = "rate_limited"
	ErrorKindCanceled          ErrorKind = "canceled"
	ErrorKindResponse          ErrorKind = "invalid_response"
	ErrorKindUnknown           ErrorKind = "unknown"
)

// ErrorInfo is safe to expose in tool and inventory results. It deliberately
// contains no credentials or request bodies.
type ErrorInfo struct {
	Kind       ErrorKind `json:"kind"`
	Code       int       `json:"code,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
	Message    string    `json:"message"`
	Resource   string    `json:"resource,omitempty"`
	// FortiGateStatus is the HTTP status a FortiGate returned, either
	// directly or relayed inside a FortiManager proxy response.
	FortiGateStatus int    `json:"fortigate_http_status,omitempty"`
	Retryable       bool   `json:"retryable"`
	Hint            string `json:"hint,omitempty"`
}

type rpcFailure struct {
	info  ErrorInfo
	cause error
}

func (e *rpcFailure) Error() string {
	if e == nil {
		return ""
	}
	message := e.info.Message
	if e.info.Code != 0 {
		message = fmt.Sprintf("code %d: %s", e.info.Code, message)
	} else if e.info.HTTPStatus != 0 {
		message = fmt.Sprintf("HTTP %d: %s", e.info.HTTPStatus, message)
	}
	details := make([]string, 0, 4)
	if e.info.Kind != "" {
		details = append(details, "kind="+string(e.info.Kind))
	}
	if e.info.Resource != "" {
		details = append(details, "resource="+e.info.Resource)
	}
	if e.info.Hint != "" {
		details = append(details, "hint="+e.info.Hint)
	}
	if len(details) == 0 {
		return message
	}
	return message + " (" + strings.Join(details, "; ") + ")"
}

func (e *rpcFailure) Unwrap() error { return e.cause }

func newRPCFailure(info ErrorInfo, cause error) error {
	if info.Kind == "" {
		classified := classifyError(info.Code, info.HTTPStatus, info.Message, cause)
		info.Kind = classified.Kind
		info.Retryable = classified.Retryable
		if info.Hint == "" {
			info.Hint = classified.Hint
		}
	}
	if info.Message == "" && cause != nil {
		info.Message = cause.Error()
	}
	if info.Message == "" {
		info.Message = "Fortinet request failed"
	}
	return &rpcFailure{info: info, cause: cause}
}

// DescribeError extracts structured details from a wrapped Fortinet or Go
// error. It also classifies errors supplied by test doubles and other Manager
// implementations that do not use the Fortinet RPC client.
func DescribeError(err error) ErrorInfo {
	if err == nil {
		return ErrorInfo{}
	}
	var failure *rpcFailure
	if errors.As(err, &failure) {
		return failure.info
	}
	return classifyError(0, 0, err.Error(), err)
}

func classifyError(code, httpStatus int, message string, cause error) ErrorInfo {
	lower := strings.ToLower(strings.TrimSpace(message))
	if cause != nil {
		if errors.Is(cause, context.Canceled) {
			return ErrorInfo{Kind: ErrorKindCanceled, Message: message, Hint: "The operation was canceled before Fortinet returned a result."}
		}
		if errors.Is(cause, context.DeadlineExceeded) {
			return ErrorInfo{Kind: ErrorKindTimeout, Message: message, Retryable: true, Hint: "Fortinet did not respond before the deadline; check reachability and appliance load, then retry."}
		}
		var netErr net.Error
		if errors.As(cause, &netErr) && netErr.Timeout() {
			return ErrorInfo{Kind: ErrorKindTimeout, Message: message, Retryable: true, Hint: "The Fortinet endpoint timed out; check reachability and appliance load, then retry."}
		}
	}
	if code == -11 || httpStatus == 401 || httpStatus == 403 || containsAny(lower, "no permission", "permission denied", "forbidden") {
		if httpStatus == 401 || containsAny(lower, "unauthorized", "invalid credential", "login required", "authentication") {
			return ErrorInfo{Kind: ErrorKindAuth, Code: code, HTTPStatus: httpStatus, Message: message, Hint: "Verify the API key/session and the administrator's JSON API permissions."}
		}
		return ErrorInfo{Kind: ErrorKindPermission, Code: code, HTTPStatus: httpStatus, Message: message, Hint: "Verify JSON API read access, ADOM assignment, and read permission for the reported resource."}
	}
	if containsAny(lower, "device type is unknown") {
		return ErrorInfo{
			Kind:       ErrorKindInvalid,
			Code:       code,
			HTTPStatus: httpStatus,
			Message:    message,
			Hint:       `FortiAnalyzer Log View requires a device selector such as device:[{"devid":"All_Devices"}] and a log type supported by that device.`,
		}
	}
	if containsAny(lower, "access denied") && containsAny(lower, "userfrom=") {
		return ErrorInfo{
			Kind:       ErrorKindPermission,
			Code:       code,
			HTTPStatus: httpStatus,
			Message:    message,
			Hint:       "FortiAnalyzer authenticated the API administrator named in userfrom but refused the operation for it. A Log View search creates a search task (method add): the administrator needs an admin profile with Log View access, assignment to the ADOM, and JSON API access that permits task creation (Read-Write on many releases; keep every other profile permission at None or Read). Other reads with the same key can still succeed. Retrying does not help.",
		}
	}
	if containsAny(lower, "start time is later than the end time", "invalid time range") {
		return ErrorInfo{
			Kind:       ErrorKindInvalid,
			Code:       code,
			HTTPStatus: httpStatus,
			Message:    message,
			Hint:       "FortiAnalyzer rejected the time range. Give start and end as RFC3339 in the same time zone (or set the profile timezone) with start before end.",
		}
	}
	if containsAny(lower, "unsupported object_type", "invalid object_type", "object_type is required", "empty path segment", "invalid path character") {
		return ErrorInfo{
			Kind:       ErrorKindInvalid,
			Code:       code,
			HTTPStatus: httpStatus,
			Message:    message,
			Hint:       "Use a supported read-only firewall/... object path; use list_firewall_policies for firewall policy packages.",
		}
	}
	if code == -10 || containsAny(lower, "invalid params", "invalid parameter", "invalid argument", "invalid url", "invalid path", "data is invalid for selected url", "unknown path", "invalid request") {
		return ErrorInfo{Kind: ErrorKindInvalid, Code: code, HTTPStatus: httpStatus, Message: message, Hint: "Verify the ADOM, device/package name, resource path, and appliance version."}
	}
	if httpStatus == 404 || containsAny(lower, "not found", "does not exist", "no such device", "unknown device", "unknown package", "object not found") {
		return ErrorInfo{Kind: ErrorKindNotFound, Code: code, HTTPStatus: httpStatus, Message: message, Hint: "Verify the ADOM, device, VDOM, and policy-package name, then refresh inventory."}
	}
	if httpStatus == 429 || containsAny(lower, "too many requests", "rate limit", "temporarily busy") {
		return ErrorInfo{Kind: ErrorKindRateLimited, Code: code, HTTPStatus: httpStatus, Message: message, Retryable: true, Hint: "The appliance is rate limiting or busy; retry with backoff."}
	}
	if httpStatus >= 500 || containsAny(lower, "connection refused", "connection reset", "broken pipe", "no route to host", "network is unreachable", "no such host", "eof", "unreachable", "offline", "disconnected", "unavailable", "service unavailable") {
		return ErrorInfo{Kind: ErrorKindUnavailable, Code: code, HTTPStatus: httpStatus, Message: message, Retryable: true, Hint: "Check reachability of the FortiManager, FortiAnalyzer or FortiGate named in the message and the device connection state, then retry."}
	}
	if containsAny(lower, "deadline exceeded", "timeout", "timed out") {
		return ErrorInfo{Kind: ErrorKindTimeout, Code: code, HTTPStatus: httpStatus, Message: message, Retryable: true, Hint: "The Fortinet endpoint timed out; check reachability and appliance load, then retry."}
	}
	if code == 0 && httpStatus == 0 && lower == "" {
		message = "Fortinet request failed without an error message"
	}
	return ErrorInfo{Kind: ErrorKindUnknown, Code: code, HTTPStatus: httpStatus, Message: message, Hint: "Inspect the reported resource and the appliance's JSON API log."}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func codeFromValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(typed))
		return parsed
	default:
		return 0
	}
}

func errorWithResource(err error, resource string) error {
	if err == nil || resource == "" {
		return err
	}
	var failure *rpcFailure
	if !errors.As(err, &failure) || failure.info.Resource != "" {
		return err
	}
	failure.info.Resource = resource
	return failure
}

// RetriedByClient reports an error from the Fortinet RPC client, which has
// already retried transient failures within its own bounds; callers should
// not wrap another retry loop around it.
func RetriedByClient(err error) bool {
	var failure *rpcFailure
	return errors.As(err, &failure)
}

// errorWithHint replaces the operator hint on a structured Fortinet error
// with a more specific one. Other errors are returned unchanged.
func errorWithHint(err error, hint string) error {
	if err == nil || hint == "" {
		return err
	}
	var failure *rpcFailure
	if !errors.As(err, &failure) {
		return err
	}
	info := failure.info
	info.Hint = hint
	return &rpcFailure{info: info, cause: failure.cause}
}

// shortErrorReason condenses an error to its deciding fact, for listing
// several failed attempts without repeating whole payloads.
func shortErrorReason(err error) string {
	info := DescribeError(err)
	switch {
	case info.FortiGateStatus != 0:
		return fmt.Sprintf("FortiGate HTTP %d", info.FortiGateStatus)
	case info.Code != 0:
		return fmt.Sprintf("FortiManager code %d (%s)", info.Code, info.Kind)
	case info.HTTPStatus != 0:
		return fmt.Sprintf("HTTP %d (%s)", info.HTTPStatus, info.Kind)
	case info.Kind != "":
		return string(info.Kind)
	}
	return truncate(err.Error(), 160)
}

// compactFailure builds one structured error for a multi-attempt operation:
// the summary replaces the nested messages, while kind, code, statuses and
// resource come from the last attempt. hint overrides the attempt's hint.
func compactFailure(summary string, last error, hint string) error {
	info := DescribeError(last)
	info.Message = summary
	if hint != "" {
		info.Hint = hint
	}
	return &rpcFailure{info: info, cause: last}
}

func errorWithFortiGateStatus(err error, status int) error {
	var failure *rpcFailure
	if !errors.As(err, &failure) {
		return err
	}
	info := failure.info
	info.FortiGateStatus = status
	return &rpcFailure{info: info, cause: failure.cause}
}

// errorWithDetail appends diagnostic detail to a structured error message.
func errorWithDetail(err error, detail string) error {
	if err == nil || detail == "" {
		return err
	}
	var failure *rpcFailure
	if !errors.As(err, &failure) {
		return fmt.Errorf("%w (%s)", err, detail)
	}
	info := failure.info
	info.Message = strings.TrimSpace(info.Message + " (" + detail + ")")
	return &rpcFailure{info: info, cause: failure.cause}
}

// DeviceUnavailable reports a DVMDB state that means a managed FortiGate
// should not be queried for live/interface data during this refresh.
func DeviceUnavailable(device Device) (bool, string) {
	connection := strings.ToLower(strings.TrimSpace(device.ConnectionStatus))
	if containsAny(connection, "down", "offline", "disconnected", "unreachable", "not available", "not_available") {
		return true, fmt.Sprintf("FortiGate reports connection_status=%q", device.ConnectionStatus)
	}
	status := strings.ToLower(strings.TrimSpace(device.Status))
	if containsAny(status, "down", "offline", "unreachable", "disconnected") {
		return true, fmt.Sprintf("FortiGate reports status=%q", device.Status)
	}
	return false, ""
}

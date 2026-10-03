package fortinet

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

const (
	defaultMaxResponseBytes = 32 << 20
	defaultHTTPTimeout      = 90 * time.Second
	// backgroundRequestTimeout bounds one background (inventory) request on
	// the wire, so an interactive call never waits longer than this for the
	// serial lane.
	backgroundRequestTimeout = 20 * time.Second
	// slowRequestThreshold logs requests that take longer than this.
	slowRequestThreshold = 5 * time.Second
)

type rpcClient struct {
	profile    config.ProfileConfig
	endpoint   string
	httpClient *http.Client
	requestID  atomic.Uint64

	sessionMu sync.RWMutex
	session   string
	loginMu   sync.Mutex
	// lane allows one in-flight JSON-RPC request per credential.
	// FortiManager answers overlapping requests of one API key or session
	// with spurious "code -11: No permission" results for random ADOMs, so
	// inventory, tools and background work all share this single lane;
	// interactive requests are served before background ones.
	lane             requestLane
	transientDenials atomic.Int64
	// policy is the allowlist every request must pass before it is sent;
	// it keeps the server read-only regardless of the account's rights.
	policy requestPolicy
}

type rpcResponse struct {
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error,omitempty"`
	Session json.RawMessage `json:"session,omitempty"`
}

type rpcError struct {
	Code    any             `json:"code,omitempty"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func newRPCClient(profile config.ProfileConfig) (*rpcClient, error) {
	endpoint, err := url.Parse(strings.TrimRight(profile.URL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse %s URL: %w", profile.Name, err)
	}
	if endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, fmt.Errorf("profile %q URL must include scheme and host", profile.Name)
	}
	if endpoint.User != nil {
		return nil, fmt.Errorf("profile %q URL must not embed credentials; use profile authentication fields", profile.Name)
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && profile.AllowInsecureHTTP) {
		return nil, fmt.Errorf("profile %q URL must use https; allow_insecure_http is only for controlled tests or labs", profile.Name)
	}
	if endpoint.Path == "" || endpoint.Path == "/" {
		endpoint.Path = "/jsonrpc"
	}
	httpClient, err := newTLSHTTPClient(profile.Name, profile.CAFile, profile.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	return &rpcClient{
		profile:    profile,
		endpoint:   endpoint.String(),
		httpClient: httpClient,
	}, nil
}

// newTLSHTTPClient builds an HTTP client that trusts the system roots plus
// an optional CA file. insecureSkipVerify is only for lab appliances.
func newTLSHTTPClient(name, caFile string, insecureSkipVerify bool) (*http.Client, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if caFile != "" {
		pem, readErr := os.ReadFile(caFile)
		if readErr != nil {
			return nil, fmt.Errorf("%s read ca_file: %w", name, readErr)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s ca_file has no readable certificates", name)
		}
	}
	// The default transport brings dial, TLS handshake and idle-connection
	// timeouts; the session cache resumes TLS after an idle connection closed
	// instead of repeating the full handshake.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            rootCAs,
		InsecureSkipVerify: insecureSkipVerify, // explicitly configured for lab/self-signed appliances
		ClientSessionCache: tls.NewLRUClientSessionCache(16),
	}
	// Deadlines come from the request context. A fixed client timeout would
	// cut calls short when server.request_timeout is longer than that value.
	return &http.Client{Transport: transport}, nil
}

// productName names the appliance in messages and hints.
func (c *rpcClient) productName() string {
	if c.profile.Product == config.ProductFortiAnalyzer {
		return "FortiAnalyzer"
	}
	return "FortiManager"
}

func (c *rpcClient) nextID() uint64 {
	return c.requestID.Add(1)
}

func (c *rpcClient) currentSession() string {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.session
}

func (c *rpcClient) setSession(session string) {
	c.sessionMu.Lock()
	c.session = session
	c.sessionMu.Unlock()
}

func (c *rpcClient) clearSession() {
	c.setSession("")
}

const (
	rpcRetryAttempts = 3
	rpcRetryBase     = 300 * time.Millisecond
	rpcRetryMaximum  = 2 * time.Second
)

// call sends one JSON-RPC request with bounded retries for transient
// transport failures. Session expiry is renewed once inside callOnce.
// permissionRecheckDelay separates a read that was denied from its single
// re-check. A denial that disappears on the re-check came from overlapping
// use of the same credential (for example a second server process).
var permissionRecheckDelay = 500 * time.Millisecond

func (c *rpcClient) call(ctx context.Context, method string, params []map[string]any) (any, error) {
	return c.callWith(ctx, method, params, true)
}

// callWith sends one request with transient-failure retries. When
// recheckPermission is set, a denied read is re-checked once after a short
// pause; batch verification passes false because its isolated re-read
// already is that re-check.
func (c *rpcClient) callWith(ctx context.Context, method string, params []map[string]any, recheckPermission bool) (any, error) {
	var lastErr error
	permissionRechecked := !recheckPermission
	for attempt := 1; attempt <= rpcRetryAttempts; attempt++ {
		result, err := c.callOnce(ctx, method, params)
		if err == nil {
			return result, nil
		}
		if method == "get" && !permissionRechecked && ctx.Err() == nil && DescribeError(err).Kind == ErrorKindPermission {
			permissionRechecked = true
			result, recheckErr := c.recheckDenied(ctx, method, params)
			if recheckErr == nil {
				c.transientDenials.Add(1)
				return result, nil
			}
			if ctx.Err() != nil {
				return nil, err
			}
			if DescribeError(recheckErr).Kind == ErrorKindPermission {
				return nil, errorWithHint(recheckErr, c.productName()+" denied this read twice. It answers code -11 when the API account lacks read permission or ADOM assignment for the resource, and also when the API key is not valid for that administrator (regenerated or a different key) or the administrator's trusted hosts exclude this server. Check the account in the profile; retrying will not change a persistent denial.")
			}
			// The re-check failed for another reason (for example the
			// appliance became unavailable): treat it like any other attempt.
			err = recheckErr
		}
		lastErr = err
		if attempt == rpcRetryAttempts || ctx.Err() != nil || !retryableRPC(method, err) {
			return nil, err
		}
		if waitErr := waitRPCRetry(ctx, attempt); waitErr != nil {
			return nil, err
		}
		recordRetry(ctx)
	}
	return nil, lastErr
}

// recheckDenied repeats a denied read once after a short pause. The lane is
// held for the pause and the re-read, so no request for another ADOM can run
// in between and cause a second spurious denial.
func (c *rpcClient) recheckDenied(ctx context.Context, method string, params []map[string]any) (any, error) {
	var result any
	err := c.withLaneHeld(ctx, func(ctx context.Context) error {
		if err := sleepContext(ctx, permissionRecheckDelay); err != nil {
			return err
		}
		var callErr error
		result, callErr = c.callOnce(ctx, method, params)
		return callErr
	})
	return result, err
}

// withLaneHeld runs fn while this client holds its request lane. Requests
// that fn makes with the context it receives reuse the held lane, so a short
// sequence of reads (a denied read's re-check, or an ADOM alignment read and
// the re-read it prepares) cannot be interleaved with other requests.
func (c *rpcClient) withLaneHeld(ctx context.Context, fn func(context.Context) error) error {
	if laneHeldBy(ctx, c) {
		return fn(ctx)
	}
	started := time.Now()
	if err := c.lane.acquire(ctx); err != nil {
		return c.laneWaitError(err, "")
	}
	recordLaneWait(ctx, time.Since(started))
	defer c.lane.release()
	return fn(context.WithValue(ctx, laneHolderKey{}, c))
}

// laneWaitError describes a request that never started because the caller's
// deadline ended while it waited for the serial lane.
func (c *rpcClient) laneWaitError(err error, resource string) error {
	info := classifyError(0, 0, err.Error(), err)
	info.Message = fmt.Sprintf("%s request did not start: it was still waiting for this account's request lane (%v)", c.profile.Name, err)
	info.Resource = resource
	if info.Kind == ErrorKindTimeout {
		info.Hint = "The request never reached the " + c.productName() + ": other requests of this account (a slow FortiGate proxy call, a large read or a running inventory refresh) held the serial request lane until the deadline. Retry shortly or narrow the query; the appliance itself was not asked."
	}
	return newRPCFailure(info, err)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TransientDenials counts reads that FortiManager denied once and allowed
// on the re-check.
func (c *rpcClient) TransientDenials() int64 {
	return c.transientDenials.Load()
}

// retryableRPC limits retries to failures that are safe to repeat. Reads
// (get) and read-oriented exec calls retry on timeouts, unavailability and
// rate limiting. Task-creating methods such as add only retry when no
// response was received at all, so FortiAnalyzer does not get duplicate
// search tasks.
func retryableRPC(method string, err error) bool {
	info := DescribeError(err)
	if !info.Retryable {
		return false
	}
	switch info.Kind {
	case ErrorKindTimeout, ErrorKindUnavailable, ErrorKindRateLimited:
	default:
		return false
	}
	switch method {
	case "get":
		return true
	case "exec":
		// Proxied reads are safe to repeat, but only when the appliance did
		// not answer: a FortiGate that FortiManager reported offline or
		// unreachable stays so, and a timed-out proxy call already waited on
		// the FortiGate.
		if info.Kind == ErrorKindRateLimited {
			return true
		}
		return info.Kind == ErrorKindUnavailable && info.Code == 0 && info.FortiGateStatus == 0
	default:
		// Task-creating methods (the FortiAnalyzer search add) retry only when
		// the request provably never left this server; after a reset or EOF
		// the appliance may already have created the task.
		return requestNotSent(err)
	}
}

// requestNotSent reports transport failures that happen before a request
// reaches the appliance (DNS failure, refused connection), after which a
// retry cannot duplicate work.
func requestNotSent(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

func waitRPCRetry(ctx context.Context, attempt int) error {
	delay := min(rpcRetryBase*time.Duration(1<<(attempt-1)), rpcRetryMaximum)
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
		return context.DeadlineExceeded
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *rpcClient) callOnce(ctx context.Context, method string, params []map[string]any) (any, error) {
	for attempt := range 2 {
		if c.profile.APIKey == "" && c.currentSession() == "" {
			if err := c.ensureSession(ctx); err != nil {
				return nil, err
			}
		}

		session := c.currentSession()
		result, err := c.post(ctx, method, params, session)
		if err == nil {
			return result, nil
		}
		if attempt == 0 && c.profile.APIKey == "" && isSessionError(err) {
			if session == "" || c.currentSession() == session {
				c.clearSession()
			}
			continue
		}
		return nil, err
	}
	return nil, errors.New("unreachable JSON-RPC retry state")
}

func (c *rpcClient) ensureSession(ctx context.Context) error {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	if c.currentSession() != "" {
		return nil
	}
	if c.profile.Username == "" || c.profile.Password == "" {
		return fmt.Errorf("profile %q has no usable username/password", c.profile.Name)
	}
	result, err := c.post(ctx, "exec", []map[string]any{{
		"url": "/sys/login/user",
		"data": map[string]any{
			"user":   c.profile.Username,
			"passwd": c.profile.Password,
		},
	}}, "")
	if err != nil {
		return fmt.Errorf("%s login: %w", c.profile.Name, err)
	}

	// Fortinet appliances return the session at the JSON-RPC envelope level.
	// A few firmware builds also echo it in the result, so accept both forms.
	session := sessionFromResult(result)
	if session == "" {
		return fmt.Errorf("%s login succeeded without a session token", c.profile.Name)
	}
	c.setSession(session)
	return nil
}

func (c *rpcClient) post(ctx context.Context, method string, params []map[string]any, session string) (any, error) {
	response, err := c.postResponse(ctx, method, params, session)
	if err != nil {
		return nil, err
	}
	if len(response.Result) == 0 || string(response.Result) == "null" {
		return response.Result, nil
	}
	var result any
	if err := json.Unmarshal(response.Result, &result); err != nil {
		return nil, newRPCFailure(ErrorInfo{
			Kind:    ErrorKindResponse,
			Message: fmt.Sprintf("decode %s JSON-RPC result: %v", c.profile.Name, err),
			Hint:    c.productName() + " returned a response that the client could not decode.",
		}, err)
	}
	if err := resultStatusError(result); err != nil {
		err = errorWithResource(err, firstRPCResource(params))
		if strings.TrimPrefix(firstRPCResource(params), "/") == "sys/proxy/json" {
			// The per-target FortiOS answer (HTTP status, error text) is the
			// only way to tell a FortiOS-side rejection from a FortiManager one.
			err = errorWithDetail(err, "FortiGate response: "+truncate(compactJSON(dataFromResult(result)), 600))
			if status := findIntField(result, "http_status"); status != 0 {
				err = errorWithFortiGateStatus(err, status)
				if hint := fortiOSStatusHint(status); hint != "" {
					err = errorWithHint(err, hint)
				}
			}
		}
		return nil, fmt.Errorf("%s API result: %w", c.profile.Name, err)
	}
	if response.Session != nil {
		if session := stringValue(response.Session); session != "" {
			// Login callers receive this through the returned value below.
			if method == "exec" && hasLoginParam(params) {
				result = map[string]any{"result": result, "session": session}
			}
		}
	}
	return result, nil
}

type rpcBatchItem struct {
	Value any
	Err   error
}

// callBatch sends several params in one request and retries the whole
// request on transient failures, like call does for single requests.
func (c *rpcClient) callBatch(ctx context.Context, method string, params []map[string]any) ([]rpcBatchItem, error) {
	for attempt := 1; ; attempt++ {
		items, err := c.callBatchOnce(ctx, method, params)
		if err == nil || attempt >= rpcRetryAttempts || ctx.Err() != nil || !retryableRPC(method, err) {
			return items, err
		}
		if len(params) > 1 && DescribeError(err).Kind == ErrorKindTimeout {
			// Repeating a slow multi-item request repeats the wait; callers
			// split it into single reads instead.
			return items, err
		}
		if waitRPCRetry(ctx, attempt) != nil {
			return items, err
		}
		recordRetry(ctx)
	}
}

func (c *rpcClient) callBatchOnce(ctx context.Context, method string, params []map[string]any) ([]rpcBatchItem, error) {
	for attempt := range 2 {
		if c.profile.APIKey == "" && c.currentSession() == "" {
			if err := c.ensureSession(ctx); err != nil {
				return nil, err
			}
		}

		session := c.currentSession()
		result, err := c.postBatch(ctx, method, params, session)
		sessionFailure := isSessionError(err)
		if err == nil && method == "get" {
			for _, item := range result {
				sessionFailure = sessionFailure || isSessionError(item.Err)
			}
		}
		if err == nil && !sessionFailure {
			return result, nil
		}
		if attempt == 0 && c.profile.APIKey == "" && sessionFailure {
			if session == "" || c.currentSession() == session {
				c.clearSession()
			}
			continue
		}
		return result, err
	}
	return nil, errors.New("unreachable JSON-RPC batch retry state")
}

func (c *rpcClient) postBatch(ctx context.Context, method string, params []map[string]any, session string) ([]rpcBatchItem, error) {
	response, err := c.postResponse(ctx, method, params, session)
	if err != nil {
		return nil, err
	}
	var rawResults []json.RawMessage
	if len(response.Result) == 0 || string(response.Result) == "null" {
		return nil, fmt.Errorf("%s JSON-RPC batch returned no result items", c.profile.Name)
	}
	if err := json.Unmarshal(response.Result, &rawResults); err != nil {
		return nil, newRPCFailure(ErrorInfo{
			Kind:    ErrorKindResponse,
			Message: fmt.Sprintf("decode %s JSON-RPC batch result: %v", c.profile.Name, err),
			Hint:    c.productName() + " returned a batch response that the client could not decode.",
		}, err)
	}
	items := make([]rpcBatchItem, len(params))
	seen := make([]bool, len(params))
	for position, raw := range rawResults {
		index := position
		var envelope struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil, fmt.Errorf("%s malformed JSON-RPC batch item: %w", c.profile.Name, err)
		}
		if envelope.URL != "" {
			index = -1
			for candidate, param := range params {
				if param["url"] == envelope.URL && !seen[candidate] {
					index = candidate
					break
				}
			}
		}
		if index < 0 || index >= len(params) || seen[index] || (envelope.URL == "" && len(rawResults) != len(params)) {
			return nil, newRPCFailure(ErrorInfo{Kind: ErrorKindResponse, Message: "JSON-RPC batch response cannot be matched uniquely to requested resources", Resource: envelope.URL}, nil)
		}
		seen[index] = true
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			items[index].Err = newRPCFailure(ErrorInfo{
				Kind:    ErrorKindResponse,
				Message: fmt.Sprintf("decode %s JSON-RPC batch item %d: %v", c.profile.Name, index, err),
				Hint:    c.productName() + " returned a batch item that the client could not decode.",
			}, err)
			continue
		}
		if itemErr := resultStatusError(value); itemErr != nil {
			if index < len(params) {
				itemErr = errorWithResource(itemErr, firstRPCResource([]map[string]any{params[index]}))
			}
			items[index].Err = fmt.Errorf("%s API result: %w", c.profile.Name, itemErr)
			continue
		}
		items[index].Value = value
	}
	for index := range items {
		if !seen[index] {
			items[index].Err = newRPCFailure(ErrorInfo{Kind: ErrorKindResponse, Message: "JSON-RPC batch returned no result for requested resource", Resource: firstRPCResource(params[index : index+1])}, nil)
		}
	}
	return items, nil
}

func (c *rpcClient) postResponse(ctx context.Context, method string, params []map[string]any, session string) (rpcResponse, error) {
	if err := c.policy.check(method, params); err != nil {
		return rpcResponse{}, newRPCFailure(ErrorInfo{
			Kind:     ErrorKindInvalid,
			Message:  fmt.Sprintf("%s request blocked by the MCP server before sending: %v", c.profile.Name, err),
			Resource: firstRPCResource(params),
			Hint:     "The server only sends read requests, FortiAnalyzer log search tasks, and the FortiGuard rating lookup; this request is outside that boundary.",
		}, nil)
	}
	payload := map[string]any{
		"id":     c.nextID(),
		"method": method,
		"params": params,
	}
	if c.profile.Product == config.ProductFortiManager {
		// FortiManager documents verbose responses for API clients so enum and
		// option fields are returned with their readable values.
		payload["verbose"] = 1
	}
	if c.profile.Product == config.ProductFortiAnalyzer && method != "exec" && requiresAPIV3(params) {
		payload["jsonrpc"] = "2.0"
	}
	if session != "" {
		payload["session"] = session
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return rpcResponse{}, fmt.Errorf("marshal JSON-RPC request: %w", err)
	}
	resource := firstRPCResource(params)

	held := laneHeldBy(ctx, c)
	waitStarted := time.Now()
	if !held {
		if err := c.lane.acquire(ctx); err != nil {
			return rpcResponse{}, c.laneWaitError(err, resource)
		}
	}
	laneWait := time.Since(waitStarted)
	responseBody, resp, err := c.exchange(ctx, body)
	if !held {
		c.lane.release()
	}
	wire := time.Since(waitStarted) - laneWait
	recordRequest(ctx, resource, laneWait, wire)
	if wire >= slowRequestThreshold {
		slog.Warn("slow Fortinet request", "profile", c.profile.Name, "method", method, "resource", resource, "items", len(params), "duration", wire.Round(time.Millisecond), "background", isBackground(ctx), "error", err != nil)
	}
	if err != nil {
		message := fmt.Sprintf("%s JSON-RPC request: %v", c.profile.Name, err)
		if isBackground(ctx) && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			message = fmt.Sprintf("%s background request exceeded %s: %v", c.profile.Name, backgroundRequestTimeout, err)
		}
		return rpcResponse{}, newRPCFailure(ErrorInfo{Message: message, Resource: resource}, err)
	}
	if len(responseBody) > defaultMaxResponseBytes {
		return rpcResponse{}, newRPCFailure(ErrorInfo{
			Kind:     ErrorKindResponse,
			Message:  fmt.Sprintf("%s response exceeded the %d MB limit and was not processed", c.profile.Name, defaultMaxResponseBytes>>20),
			Resource: resource,
			Hint:     "The appliance returned more data than the server accepts in one answer. Narrow the request: scope it to one device, package or VDOM, or read fewer records with limit/offset.",
		}, nil)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := fmt.Sprintf("%s JSON-RPC HTTP %s: %s", c.profile.Name, resp.Status, truncate(string(responseBody), 1200))
		info := classifyError(0, resp.StatusCode, message, nil)
		info.Resource = resource
		return rpcResponse{}, newRPCFailure(info, nil)
	}

	var response rpcResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return rpcResponse{}, newRPCFailure(ErrorInfo{
			Kind:     ErrorKindResponse,
			Message:  fmt.Sprintf("decode %s JSON-RPC response: %v", c.profile.Name, err),
			Resource: resource,
			Hint:     c.productName() + " returned a response that the client could not decode.",
		}, err)
	}
	if response.Error != nil {
		code := codeFromValue(response.Error.Code)
		info := classifyError(code, 0, response.Error.Message, nil)
		info.Code = code
		info.Resource = resource
		return rpcResponse{}, newRPCFailure(info, nil)
	}
	return response, nil
}

// exchange sends one request body and reads the answer, at most one byte
// beyond the response limit so an oversized answer is recognised as such.
// Background requests get their own bound on the wire (not on the lane
// wait), so they never hold the lane for long.
func (c *rpcClient) exchange(ctx context.Context, body []byte) ([]byte, *http.Response, error) {
	if isBackground(ctx) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, backgroundRequestTimeout)
		defer cancel()
	} else if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultHTTPTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("create JSON-RPC request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if c.profile.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.profile.APIKey)
	}
	for key, value := range c.profile.Headers {
		req.Header.Set(key, value)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxResponseBytes+1))
	if err != nil {
		return nil, resp, fmt.Errorf("read response: %w", err)
	}
	return responseBody, resp, nil
}

func requiresAPIV3(params []map[string]any) bool {
	for _, param := range params {
		resource := strings.ToLower(fmt.Sprint(param["url"]))
		for _, prefix := range []string{"/logview/", "/fortiview/", "/report/", "/event/", "/eventmgmt/", "/incidents/"} {
			if strings.HasPrefix(resource, prefix) {
				return true
			}
		}
	}
	return false
}

func hasLoginParam(params []map[string]any) bool {
	for _, p := range params {
		if fmt.Sprint(p["url"]) == "/sys/login/user" {
			return true
		}
	}
	return false
}

func (c *rpcClient) logout(ctx context.Context) error {
	if c.profile.APIKey != "" || c.currentSession() == "" {
		return nil
	}
	_, err := c.post(ctx, "exec", []map[string]any{{"url": "/sys/logout"}}, c.currentSession())
	c.clearSession()
	return err
}

func isSessionError(err error) bool {
	if err == nil {
		return false
	}
	// Diagnostic hints and resource names are not authentication evidence.
	message := err.Error()
	var failure *rpcFailure
	if errors.As(err, &failure) {
		message = failure.info.Message
	}
	message = strings.ToLower(message)
	for _, marker := range []string{"invalid session", "session expired", "session timeout", "not authenticated", "unauthorized", "login required", "invalid credential"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func resultStatusError(result any) error {
	var walk func(any, string) error
	walk = func(value any, inheritedResource string) error {
		switch typed := value.(type) {
		case []any:
			for _, child := range typed {
				if err := walk(child, inheritedResource); err != nil {
					return err
				}
			}
		case map[string]any:
			resource := inheritedResource
			if current := stringValueValue(field(typed, "url", "resource", "path")); current != "" {
				resource = current
			}
			if status, ok := field(typed, "status").(map[string]any); ok {
				code := intValue(field(status, "code"))
				if code != 0 {
					message := stringValueValue(field(status, "message", "msg"))
					info := classifyError(code, 0, message, nil)
					info.Code = code
					info.Message = message
					info.Resource = resource
					return newRPCFailure(info, nil)
				}
			}
			for key, child := range typed {
				if strings.EqualFold(key, "status") || strings.EqualFold(key, "url") || strings.EqualFold(key, "resource") || strings.EqualFold(key, "path") {
					continue
				}
				if err := walk(child, resource); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(result, "")
}

func firstRPCResource(params []map[string]any) string {
	if len(params) == 0 {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(params[0]["url"]))
}

func collectStatusMaps(value any, statuses *[]map[string]any) {
	switch typed := value.(type) {
	case []any:
		for _, child := range typed {
			collectStatusMaps(child, statuses)
		}
	case map[string]any:
		for key, child := range typed {
			if strings.EqualFold(key, "status") {
				if status, ok := child.(map[string]any); ok {
					*statuses = append(*statuses, status)
				}
			}
		}
	}
}

func sessionFromResult(result any) string {
	if resultMap, ok := result.(map[string]any); ok {
		if session := stringValueValue(field(resultMap, "session")); session != "" {
			return session
		}
		if nested, ok := resultMap["result"]; ok {
			return sessionFromResult(nested)
		}
	}
	if records, ok := result.([]any); ok {
		for _, record := range records {
			if session := sessionFromResult(record); session != "" {
				return session
			}
		}
	}
	return ""
}

func stringValue(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return stringValueValue(value)
}

func stringValueValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func field(m map[string]any, names ...string) any {
	for _, name := range names {
		if value, ok := m[name]; ok {
			return value
		}
	}
	for key, value := range m {
		for _, name := range names {
			if strings.EqualFold(key, name) {
				return value
			}
		}
	}
	return nil
}

func normalizePath(parts ...string) string {
	encoded := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			encoded = append(encoded, escapeJSONRPCPathSegment(part))
		}
	}
	return "/" + strings.Join(encoded, "/")
}

func escapeJSONRPCPathSegment(value string) string {
	// Fortinet's JSON-RPC resource grammar contains named subresources with
	// literal spaces, for example "object member" and "scope member". Those
	// spaces are part of the JSON-RPC path token, not HTTP URL separators.
	return strings.ReplaceAll(url.PathEscape(value), "%20", " ")
}

// normalizePathWithNestedSegment preserves slash-separated FortiManager paths
// such as "emea/spain/ppkg" while still escaping each individual segment.
// Policy-package paths are hierarchical in FortiManager; escaping the whole
// value would make the appliance look for a package literally named
// "emea%2Fspain%2Fppkg".
func normalizePathWithNestedSegment(prefix []string, nested string, suffix ...string) (string, error) {
	parts, err := nestedPathSegments(nested)
	if err != nil {
		return "", err
	}
	all := make([]string, 0, len(prefix)+len(parts)+len(suffix))
	all = append(all, prefix...)
	all = append(all, parts...)
	all = append(all, suffix...)
	return normalizePath(all...), nil
}

func nestedPathSegments(value string) ([]string, error) {
	value = strings.Trim(value, "/")
	if value == "" {
		return nil, fmt.Errorf("nested path must not be empty")
	}
	segments := strings.Split(value, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "\r\n?#") {
			return nil, fmt.Errorf("invalid nested path %q", value)
		}
	}
	return segments, nil
}

func normalizeRPCPath(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return path.Clean(value)
}

func resourceADOM(resource string) (string, bool) {
	parts := strings.Split(strings.Trim(normalizeRPCPath(resource), "/"), "/")
	for index := 0; index+1 < len(parts); index++ {
		if !strings.EqualFold(parts[index], "adom") {
			continue
		}
		adom, err := url.PathUnescape(parts[index+1])
		if err != nil {
			adom = parts[index+1]
		}
		return adom, adom != ""
	}
	return "", false
}

// fortiOSStatusHint explains the HTTP status a FortiGate returned inside a
// FortiManager proxy response.
func fortiOSStatusHint(status int) string {
	switch {
	case status == 400:
		return "The FortiGate rejected the request parameters (HTTP 400), so FortiManager reports it as an invalid url. Check that every parameter value is valid for this FortiOS release; for policy-lookup, srcintf must be an interface name, not a zone."
	case status == 404:
		return "The FortiGate does not provide this REST resource on its FortiOS release (HTTP 404). Use a resource documented for that release."
	case status == 405:
		return "The FortiGate does not accept this HTTP method or action for the resource (HTTP 405). FortiOS monitor reads usually need the /select action; some lookups accept only POST."
	case status == 401 || status == 403:
		return "The FortiGate refused FortiManager's proxied request (HTTP " + strconv.Itoa(status) + "). The FortiManager-to-FortiGate management credentials lack access to this resource; this is not the MCP server's API account."
	case status == 424:
		return "The FortiGate reported a failed dependency (HTTP 424): a required parameter is missing or a referenced object does not exist."
	case status >= 500:
		return "The FortiGate failed while serving the request (HTTP " + strconv.Itoa(status) + "); retry later or check the FortiGate."
	}
	return ""
}

// findIntField returns the first integer value of name in a nested result.
func findIntField(value any, name string) int {
	switch typed := value.(type) {
	case map[string]any:
		if found, ok := typed[name]; ok {
			return intValue(found)
		}
		for _, child := range typed {
			if found := findIntField(child, name); found != 0 {
				return found
			}
		}
	case []any:
		for _, child := range typed {
			if found := findIntField(child, name); found != 0 {
				return found
			}
		}
	}
	return 0
}

func compactJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(encoded)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

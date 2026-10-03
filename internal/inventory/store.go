package inventory

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

type ADOMRecord struct {
	Profile string        `json:"profile"`
	ADOM    fortinet.ADOM `json:"adom"`
	// Packages is the policy package list from the last successful
	// list_policy_packages for this ADOM (name, type, oid, scope). Raw
	// appliance records are not kept. PackagesKnown distinguishes "read,
	// and there are none" from "not read".
	Packages      []fortinet.PolicyPackage `json:"packages,omitempty"`
	PackagesKnown bool                     `json:"packages_known,omitempty"`
}

type ProfileState struct {
	Profile     string    `json:"profile"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
	Error       string    `json:"error,omitempty"`
	// Stale means a FortiManager read failed and last-known-good data was
	// kept. Offline FortiGates never make a profile stale.
	Stale              bool `json:"stale,omitempty"`
	ADOMCount          int  `json:"adom_count"`
	DeviceCount        int  `json:"device_count"`
	UnavailableDevices int  `json:"unavailable_devices,omitempty"`
	// DeviceReadErrors counts devices whose interface, zone or routing reads
	// failed; those devices keep their data from data_as_of and the profile
	// is not marked stale for them.
	DeviceReadErrors int `json:"device_read_errors,omitempty"`
}

// DeviceNotice records a FortiGate that FortiManager reports as offline.
// It is informational: the device's FortiManager database data stays usable
// and the regular background refresh picks it up when it reconnects.
type DeviceNotice struct {
	Profile          string    `json:"profile"`
	ADOM             string    `json:"adom"`
	Device           string    `json:"device"`
	ConnectionStatus string    `json:"connection_status,omitempty"`
	Reason           string    `json:"reason"`
	DataSource       string    `json:"data_source"`
	DataAsOf         time.Time `json:"data_as_of"`
	ReadError        string    `json:"read_error,omitempty"`
}

type RefreshError struct {
	Profile    string             `json:"profile"`
	ADOM       string             `json:"adom,omitempty"`
	Device     string             `json:"device,omitempty"`
	Package    string             `json:"package,omitempty"`
	Stage      string             `json:"stage"`
	Kind       fortinet.ErrorKind `json:"kind,omitempty"`
	Code       int                `json:"code,omitempty"`
	HTTPStatus int                `json:"http_status,omitempty"`
	Resource   string             `json:"resource,omitempty"`
	Retryable  bool               `json:"retryable"`
	Attempts   int                `json:"attempts,omitempty"`
	Message    string             `json:"message"`
	Hint       string             `json:"hint,omitempty"`
}

type Snapshot struct {
	GeneratedAt time.Time `json:"generated_at"`
	// RefreshInProgress and RefreshStartedAt describe a running refresh;
	// they are filled on read and never stored with the snapshot.
	RefreshInProgress  bool              `json:"refresh_in_progress,omitempty"`
	RefreshStartedAt   time.Time         `json:"refresh_started_at"`
	ADOMs              []ADOMRecord      `json:"adoms,omitempty"`
	Devices            []fortinet.Device `json:"devices,omitempty"`
	Profiles           []ProfileState    `json:"profiles,omitempty"`
	Errors             []RefreshError    `json:"errors,omitempty"`
	UnavailableDevices []DeviceNotice    `json:"unavailable_devices,omitempty"`
}

type Store struct {
	managers       map[string]fortinet.Manager
	interval       time.Duration
	refreshTimeout time.Duration
	maxConcurrent  int

	mu            sync.RWMutex
	snapshot      Snapshot
	ownership     map[netip.Prefix][]OwnershipCandidate
	deviceIndex   map[string][]int
	completedAt   time.Time
	startedAt     time.Time
	lastRefresh   time.Duration
	ready         chan struct{}
	readyOnce     sync.Once
	refreshGate   chan struct{}
	afterRefresh  func(context.Context, Snapshot)
	loggerMu    sync.RWMutex
	logger      *slog.Logger
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

const (
	inventoryRetryAttempts  = 3
	inventoryRetryBase      = 250 * time.Millisecond
	inventoryInterfaceBatch = 8
)

func NewStore(managers map[string]fortinet.Manager, interval time.Duration, maxConcurrent int) *Store {
	if interval <= 0 {
		interval = time.Hour
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 8
	}
	copyManagers := make(map[string]fortinet.Manager, len(managers))
	maps.Copy(copyManagers, managers)
	return &Store{
		managers:       copyManagers,
		interval:       interval,
		refreshTimeout: 2 * time.Minute,
		maxConcurrent:  maxConcurrent,
		refreshGate:    make(chan struct{}, 1),
		ready:          make(chan struct{}),
	}
}

// Ready is closed once the first snapshot has been published.
func (s *Store) Ready() <-chan struct{} {
	return s.ready
}

// SetRefreshTimeout changes the maximum duration used by background refreshes.
// It is separate from the normal request timeout because a refresh fans out
// across every configured profile, ADOM, device, and interface.
func (s *Store) SetRefreshTimeout(timeout time.Duration) {
	if timeout > 0 {
		s.refreshTimeout = timeout
	}
}

// SetLogger configures the logger used for appliance errors encountered by
// background or explicitly requested inventory refreshes. The store keeps the
// original appliance error in the snapshot as well as writing it to the
// server log, so an MCP client can inspect the error without losing the
// operator-facing diagnostic context.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.loggerMu.Lock()
	s.logger = logger
	s.loggerMu.Unlock()
}

func (s *Store) logRefreshError(refreshError RefreshError) {
	s.loggerMu.RLock()
	logger := s.logger
	s.loggerMu.RUnlock()
	if logger == nil {
		return
	}
	attrs := []any{
		"profile", refreshError.Profile,
		"stage", refreshError.Stage,
		"error", refreshError.Message,
	}
	if refreshError.ADOM != "" {
		attrs = append(attrs, "adom", refreshError.ADOM)
	}
	if refreshError.Device != "" {
		attrs = append(attrs, "device", refreshError.Device)
	}
	if refreshError.Package != "" {
		attrs = append(attrs, "package", refreshError.Package)
	}
	if refreshError.Kind != "" {
		attrs = append(attrs, "kind", refreshError.Kind)
	}
	if refreshError.Code != 0 {
		attrs = append(attrs, "code", refreshError.Code)
	}
	if refreshError.HTTPStatus != 0 {
		attrs = append(attrs, "http_status", refreshError.HTTPStatus)
	}
	if refreshError.Resource != "" {
		attrs = append(attrs, "resource", refreshError.Resource)
	}
	if refreshError.Retryable {
		attrs = append(attrs, "retryable", true)
	}
	if refreshError.Attempts > 0 {
		attrs = append(attrs, "attempts", refreshError.Attempts)
	}
	if refreshError.Hint != "" {
		attrs = append(attrs, "hint", refreshError.Hint)
	}
	logger.Error("inventory refresh stage failed", attrs...)
}

// Start runs inventory refreshes in the background: the first one begins
// immediately and later ones follow the configured interval. Start returns
// at once so MCP transports come up without waiting for FortiManager; queries
// before the first snapshot report that inventory is still loading. The only
// other refresh trigger is an explicit refresh_inventory request.
func (s *Store) Start(parent context.Context) {
	if s.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.wg.Go(func() {
		defer s.recoverPanic("background refresh loop")
		s.backgroundRefresh(ctx)
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.backgroundRefresh(ctx)
			}
		}
	})
}

func (s *Store) backgroundRefresh(ctx context.Context) {
	// A panic in one refresh must not end the refresh loop (or the server):
	// the next interval tries again with the last good snapshot kept.
	defer s.recoverPanic("inventory refresh")
	refreshCtx, cancel := context.WithTimeout(ctx, s.refreshTimeout)
	defer cancel()
	snapshotBefore := s.Snapshot()
	s.Refresh(refreshCtx)
	snapshotAfter := s.Snapshot()
	// Log structured statistics about the refresh
	s.logRefreshStatistics(snapshotBefore, snapshotAfter)
	s.mu.RLock()
	hook := s.afterRefresh
	s.mu.RUnlock()
	if hook != nil {
		hook(refreshCtx, snapshotAfter)
	}
}

func (s *Store) recoverPanicLog(profile string, recovered any) {
	s.loggerMu.RLock()
	logger := s.logger
	s.loggerMu.RUnlock()
	if logger != nil {
		logger.Error("profile refresh panicked; last-known-good data is kept", "profile", profile, "panic", fmt.Sprint(recovered), "stack", string(debug.Stack()))
	}
}

// logRefreshStatistics logs structured statistics about inventory refresh results.
func (s *Store) logRefreshStatistics(before, after Snapshot) {
	s.loggerMu.RLock()
	logger := s.logger
	s.loggerMu.RUnlock()
	if logger == nil {
		return
	}

	// Calculate changes
	newDevices := len(after.Devices) - len(before.Devices)
	newErrors := len(after.Errors) - len(before.Errors)
	newUnavailable := len(after.UnavailableDevices) - len(before.UnavailableDevices)

	// Count stale profiles
	staleCount := 0
	for _, profile := range after.Profiles {
		if profile.Stale {
			staleCount++
		}
	}

	attrs := []any{
		"inventory_devices", len(after.Devices),
		"inventory_devices_delta", newDevices,
		"inventory_errors", len(after.Errors),
		"inventory_errors_delta", newErrors,
		"unavailable_devices", len(after.UnavailableDevices),
		"unavailable_devices_delta", newUnavailable,
		"stale_profiles", staleCount,
		"refresh_in_progress", after.RefreshInProgress,
	}

	if !after.GeneratedAt.IsZero() {
		attrs = append(attrs, "generated_at", after.GeneratedAt.UTC())
	}

	logger.Info("inventory refresh completed", attrs...)
}

// recoverPanic logs a panic of a background goroutine instead of letting it
// terminate the process.
func (s *Store) recoverPanic(what string) {
	if recovered := recover(); recovered != nil {
		s.loggerMu.RLock()
		logger := s.logger
		s.loggerMu.RUnlock()
		if logger != nil {
			logger.Error(what+" panicked; the previous snapshot is kept", "panic", fmt.Sprint(recovered), "stack", string(debug.Stack()))
		}
	}
}

func (s *Store) Refresh(ctx context.Context) Snapshot {
	// Inventory work yields the appliance lane to interactive tool requests.
	ctx = fortinet.WithBackgroundPriority(ctx)
	ctx, stats := fortinet.WithRequestStats(ctx)
	requestedAt := time.Now()
	if !acquireSemaphore(ctx, s.refreshGate) {
		return s.Snapshot()
	}
	defer func() { <-s.refreshGate }()

	// Deep copy: retained devices keep their interface and route slices, and
	// later appends must not write into the published snapshot.
	previous := s.cloneLocked()
	if s.lastCompletedAt().After(requestedAt) {
		// A refresh that was already running when this request arrived has
		// published a snapshot newer than the request. Re-running it would
		// only repeat the same appliance reads.
		return previous
	}
	started := time.Now()
	s.mu.Lock()
	s.startedAt = started
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.startedAt = time.Time{}
		s.mu.Unlock()
	}()
	next := Snapshot{GeneratedAt: started}
	if len(s.managers) == 0 {
		next.Errors = append(next.Errors, RefreshError{Stage: "configuration", Message: "no FortiManager profiles configured"})
		s.logRefreshError(next.Errors[0])
		s.setSnapshot(next)
		return next
	}

	managerNames := make([]string, 0, len(s.managers))
	for name := range s.managers {
		managerNames = append(managerNames, name)
	}
	sort.Strings(managerNames)
	results := make(chan profileRefreshResult, len(managerNames))
	callSem := make(chan struct{}, s.maxConcurrent)
	profileSems := make(map[string]chan struct{}, len(managerNames))
	for _, name := range managerNames {
		// Bound appliance load independently for each profile. A permission
		// response alone is not evidence of overload.
		profileSems[name] = make(chan struct{}, 1)
	}
	var refreshWG sync.WaitGroup
	for _, name := range managerNames {
		name, manager := name, s.managers[name]
		refreshWG.Go(func() {
			result := profileRefreshResult{state: ProfileState{Profile: name, LastAttempt: time.Now()}}
			defer func() {
				if recovered := recover(); recovered != nil {
					// Keep this profile's last-known-good data and report the
					// failure; the other profiles are unaffected.
					result = profileRefreshResult{state: ProfileState{Profile: name, LastAttempt: time.Now(), Stale: true, Error: fmt.Sprintf("refresh failed with an internal error: %v", recovered)}}
					result.errors = append(result.errors, RefreshError{Profile: name, Stage: "refresh", Kind: fortinet.ErrorKindUnknown, Message: fmt.Sprintf("internal error while refreshing: %v", recovered)})
					mergePreviousProfileData(&result, previous, name)
					s.recoverPanicLog(name, recovered)
				}
				results <- result
			}()
			result = s.refreshProfile(ctx, name, manager, previous, callSem, profileSems[name])
		})
	}
	refreshWG.Wait()
	close(results)
	for result := range results {
		for _, refreshError := range result.errors {
			s.logRefreshError(refreshError)
		}
		next.ADOMs = append(next.ADOMs, result.adoms...)
		next.Devices = append(next.Devices, result.devices...)
		next.Errors = append(next.Errors, result.errors...)
		next.UnavailableDevices = append(next.UnavailableDevices, result.unavailable...)
		next.Profiles = append(next.Profiles, result.state)
	}
	sort.Slice(next.UnavailableDevices, func(i, j int) bool {
		left, right := next.UnavailableDevices[i], next.UnavailableDevices[j]
		if left.Profile != right.Profile {
			return left.Profile < right.Profile
		}
		if left.ADOM != right.ADOM {
			return left.ADOM < right.ADOM
		}
		return left.Device < right.Device
	})

	sort.Slice(next.ADOMs, func(i, j int) bool {
		if next.ADOMs[i].Profile != next.ADOMs[j].Profile {
			return next.ADOMs[i].Profile < next.ADOMs[j].Profile
		}
		return next.ADOMs[i].ADOM.Name < next.ADOMs[j].ADOM.Name
	})
	sort.Slice(next.Devices, func(i, j int) bool {
		left, right := next.Devices[i], next.Devices[j]
		if left.Profile != right.Profile {
			return left.Profile < right.Profile
		}
		if left.ADOM != right.ADOM {
			return left.ADOM < right.ADOM
		}
		return left.Name < right.Name
	})
	sort.Slice(next.Profiles, func(i, j int) bool {
		return next.Profiles[i].Profile < next.Profiles[j].Profile
	})
	sort.Slice(next.Errors, func(i, j int) bool {
		left, right := next.Errors[i], next.Errors[j]
		if left.Profile != right.Profile {
			return left.Profile < right.Profile
		}
		if left.ADOM != right.ADOM {
			return left.ADOM < right.ADOM
		}
		if left.Device != right.Device {
			return left.Device < right.Device
		}
		if left.Stage != right.Stage {
			return left.Stage < right.Stage
		}
		return left.Message < right.Message
	})
	s.setSnapshot(next)
	duration := time.Since(started)
	s.mu.Lock()
	s.lastRefresh = duration
	s.mu.Unlock()
	s.logRefreshComplete(next, duration, stats.Snapshot())
	return next
}

func (s *Store) logRefreshComplete(snapshot Snapshot, duration time.Duration, requests fortinet.RequestStatsSnapshot) {
	s.loggerMu.RLock()
	logger := s.logger
	s.loggerMu.RUnlock()
	if logger == nil {
		return
	}
	stale := 0
	for _, profile := range snapshot.Profiles {
		if profile.Stale {
			stale++
		}
	}
	logger.Info("inventory refresh complete", "devices", len(snapshot.Devices), "errors", len(snapshot.Errors), "unavailable_devices", len(snapshot.UnavailableDevices), "stale_profiles", stale, "duration", duration.Round(time.Millisecond),
		"fortinet_requests", requests.Requests, "retries", requests.Retries, "lane_wait", requests.LaneWait.Round(time.Millisecond), "wire_time", requests.Wire.Round(time.Millisecond), "slowest_resource", requests.SlowestResource)
}

type profileRefreshResult struct {
	state       ProfileState
	adoms       []ADOMRecord
	devices     []fortinet.Device
	errors      []RefreshError
	unavailable []DeviceNotice
}

func inventoryCallWithAttempts[T any](ctx context.Context, semaphore, profileSemaphore chan struct{}, call func() (T, error)) (T, error, int) {
	var zero T
	var lastErr error
	for attempt := 1; attempt <= inventoryRetryAttempts; attempt++ {
		value, err := callWithSemaphores(ctx, semaphore, profileSemaphore, call)
		if err == nil {
			return value, nil, attempt
		}
		lastErr = err
		// The Fortinet client already retried transient failures; another
		// round here would only multiply requests to an appliance that is
		// struggling. Other managers (tests, adapters) get the retry.
		if ctx.Err() != nil || attempt == inventoryRetryAttempts || !fortinet.DescribeError(err).Retryable || fortinet.RetriedByClient(err) {
			return zero, lastErr, attempt
		}
		if err := waitInventoryRetry(ctx, attempt); err != nil {
			return zero, err, attempt
		}
	}
	return zero, lastErr, inventoryRetryAttempts
}

func callWithSemaphores[T any](ctx context.Context, semaphore, profileSemaphore chan struct{}, call func() (T, error)) (T, error) {
	var zero T
	if !acquireSemaphore(ctx, profileSemaphore) {
		return zero, ctx.Err()
	}
	if profileSemaphore != nil {
		defer func() { <-profileSemaphore }()
	}
	if !acquireSemaphore(ctx, semaphore) {
		return zero, ctx.Err()
	}
	if semaphore != nil {
		defer func() { <-semaphore }()
	}
	return call()
}

func acquireSemaphore(ctx context.Context, semaphore chan struct{}) bool {
	if ctx.Err() != nil {
		return false
	}
	if semaphore == nil {
		return true
	}
	select {
	case semaphore <- struct{}{}:
		if ctx.Err() != nil {
			<-semaphore
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}

func waitInventoryRetry(ctx context.Context, attempt int) error {
	delay := min(inventoryRetryBase*time.Duration(1<<(attempt-1)), 2*time.Second)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func refreshErrorFrom(profile, adom, device, packageName, stage string, err error, attempts int) RefreshError {
	info := fortinet.DescribeError(err)
	message := "inventory stage failed"
	if err != nil {
		message = err.Error()
	}
	return RefreshError{
		Profile:    profile,
		ADOM:       adom,
		Device:     device,
		Package:    packageName,
		Stage:      stage,
		Kind:       info.Kind,
		Code:       info.Code,
		HTTPStatus: info.HTTPStatus,
		Resource:   info.Resource,
		Retryable:  info.Retryable,
		Attempts:   attempts,
		Message:    message,
		Hint:       info.Hint,
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

const accountDeniedMessage = "FortiManager denied the device list of every ADOM for this profile's account (code -11), so no FortiGate could be inventoried. The account itself is refused: the API key is not the one of the intended read-only administrator (regenerated, or the environment variable now holds another key such as a rating key), the administrator's trusted hosts exclude this server's address, or its admin profile or ADOM assignment changed. Test the key with a single /dvmdb/adom/<adom>/device read."

// allDeviceListsDenied reports whether each of the expected ADOMs failed
// its device list with a permission denial.
func allDeviceListsDenied(errors []RefreshError, adoms int) bool {
	if adoms == 0 {
		return false
	}
	denied := make(map[string]bool)
	for _, failure := range errors {
		if failure.Stage == "list_devices" && failure.Kind == fortinet.ErrorKindPermission {
			denied[failure.ADOM] = true
		}
	}
	return len(denied) == adoms
}

func (s *Store) logAccountDenied(profile string) {
	s.loggerMu.RLock()
	logger := s.logger
	s.loggerMu.RUnlock()
	if logger != nil {
		logger.Error("FortiManager account denied on every ADOM", "profile", profile, "hint", accountDeniedMessage)
	}
}

func unavailableDeviceNotice(profile, adom string, device fortinet.Device) DeviceNotice {
	_, reason := fortinet.DeviceUnavailable(device)
	return DeviceNotice{
		Profile:          profile,
		ADOM:             adom,
		Device:           device.Name,
		ConnectionStatus: device.ConnectionStatus,
		Reason:           reason + "; FortiManager database data stays usable, live lookups through this FortiGate fail until it reconnects, and the background refresh updates it without a manual refresh",
	}
}

func (s *Store) refreshProfile(ctx context.Context, name string, manager fortinet.Manager, previous Snapshot, callSem, profileSem chan struct{}) profileRefreshResult {
	previousState := previousProfileState(previous, name)
	result := profileRefreshResult{state: ProfileState{Profile: name, LastAttempt: time.Now(), LastSuccess: previousState.LastSuccess}}
	profileHadError := false
	adoms, err, attempts := inventoryCallWithAttempts(ctx, callSem, profileSem, func() ([]fortinet.ADOM, error) { return manager.ListADOMs(ctx) })
	if err != nil {
		result.state.Error = err.Error()
		result.state.Stale = true
		result.errors = append(result.errors, refreshErrorFrom(name, "", "", "", "list_adoms", err, attempts))
		result.adoms = previousProfileADOMs(previous, name)
		result.devices = previousProfileDevices(previous, name)
		result.state.ADOMCount = len(result.adoms)
		result.state.DeviceCount = len(result.devices)
		return result
	}
	if allowlist, ok := manager.(fortinet.ADOMAllowlist); ok {
		filtered := adoms[:0]
		for _, adom := range adoms {
			if allowlist.AllowsADOM(adom.Name) {
				filtered = append(filtered, adom)
			}
		}
		adoms = filtered
	}
	// Discovered ADOMs of other products (FortiMail, FortiWeb, ...) hold no
	// FortiGates, and reading them is often denied: skip them instead of
	// marking the profile stale on every refresh.
	adoms = fortiGateADOMs(adoms)
	// ADOMs whose data is oldest go first, so an ADOM that a timed-out
	// refresh did not reach is read first next time.
	sortADOMsByDataAge(adoms, previous, name)
	// ADOMs are refreshed one after another. Requests of one profile are
	// serialized anyway, and FortiManager evaluates ADOM-less device database
	// paths in the ADOM of the preceding request: interleaving ADOMs made
	// reads of healthy devices fail at random with code -11.
	deviceReadErrors := 0
	var skipped []string
	for _, adom := range adoms {
		if ctx.Err() != nil {
			skipped = append(skipped, adom.Name)
			continue
		}
		adomResult := s.refreshADOM(ctx, name, manager, previous, adom, callSem, profileSem)
		result.adoms = append(result.adoms, adomResult.adom)
		result.devices = append(result.devices, adomResult.devices...)
		result.errors = append(result.errors, adomResult.errors...)
		result.unavailable = append(result.unavailable, adomResult.unavailable...)
		deviceReadErrors += adomResult.deviceErrors
		profileHadError = profileHadError || adomResult.hadError
	}
	if ctx.Err() != nil {
		profileHadError = true
		refreshErr := ctx.Err()
		if len(skipped) > 0 {
			refreshErr = fmt.Errorf("the refresh budget ended before ADOMs %s were read; their data is kept from the previous refresh and they are read first next time: %w", strings.Join(skipped, ", "), ctx.Err())
		}
		result.errors = append(result.errors, refreshErrorFrom(name, "", "", "", "refresh", refreshErr, 1))
		mergePreviousProfileData(&result, previous, name)
	}
	result.state.ADOMCount = countADOMs(result.adoms, name)
	result.state.DeviceCount = countDevices(result.devices, name)
	result.state.UnavailableDevices = len(result.unavailable)
	result.state.DeviceReadErrors = deviceReadErrors
	if profileHadError {
		result.state.Stale = true
		result.state.Error = "one or more inventory stages failed; inspect errors"
		if allDeviceListsDenied(result.errors, len(adoms)) {
			// Every ADOM refusing its most basic read points at the account,
			// not at individual permissions.
			result.state.Error = accountDeniedMessage
			s.logAccountDenied(name)
		}
	} else {
		result.state.LastSuccess = time.Now()
	}
	return result
}

type adomRefreshResult struct {
	adom        ADOMRecord
	devices     []fortinet.Device
	errors      []RefreshError
	unavailable []DeviceNotice
	// hadError marks ADOM-level failures (devices, groups, packages) that
	// make the profile stale; per-device read failures are counted apart.
	hadError     bool
	deviceErrors int
}

func (s *Store) refreshADOM(ctx context.Context, name string, manager fortinet.Manager, previous Snapshot, adom fortinet.ADOM, callSem, profileSem chan struct{}) adomRefreshResult {
	result := adomRefreshResult{adom: ADOMRecord{Profile: name, ADOM: adom}}
	devices, deviceErr, deviceAttempts := inventoryCallWithAttempts(ctx, callSem, profileSem, func() ([]fortinet.Device, error) { return manager.ListDevices(ctx, adom.Name) })
	if deviceErr != nil {
		result.hadError = true
		result.errors = append(result.errors, refreshErrorFrom(name, adom.Name, "", "", "list_devices", deviceErr, deviceAttempts))
		result.devices = append(result.devices, previousADOMDevices(previous, name, adom.Name)...)
		if previousRecord, ok := previousADOMRecord(previous, name, adom.Name); ok {
			result.adom.Packages = clonePolicyPackages(previousRecord.Packages)
			result.adom.PackagesKnown = previousRecord.PackagesKnown
		}
		return result
	}
	if len(devices) == 0 {
		// Empty/product ADOMs have no managed FortiGate inventory and cannot
		// contribute device groups, package scope, or interfaces.
		return result
	}
	groups, groupErr, groupAttempts := inventoryCallWithAttempts(ctx, callSem, profileSem, func() ([]fortinet.DeviceGroup, error) { return manager.ListDeviceGroups(ctx, adom.Name) })
	if groupErr != nil {
		result.hadError = true
		result.errors = append(result.errors, refreshErrorFrom(name, adom.Name, "", "", "list_device_groups", groupErr, groupAttempts))
	}
	packages, packageErr, packageAttempts := inventoryCallWithAttempts(ctx, callSem, profileSem, func() ([]fortinet.PolicyPackage, error) { return manager.ListPolicyPackages(ctx, adom.Name) })
	if packageErr != nil {
		result.hadError = true
		result.errors = append(result.errors, refreshErrorFrom(name, adom.Name, "", "", "list_policy_packages", packageErr, packageAttempts))
		if previousRecord, ok := previousADOMRecord(previous, name, adom.Name); ok {
			result.adom.Packages = clonePolicyPackages(previousRecord.Packages)
			result.adom.PackagesKnown = previousRecord.PackagesKnown
		}
	} else {
		result.adom.Packages = clonePolicyPackages(packages)
		result.adom.PackagesKnown = true
	}

	// FortiManager serves its device database whether or not the FortiGate
	// is connected, so offline devices are read like online ones. Their read
	// failures become notices instead of refresh errors: an offline FortiGate
	// never marks the ADOM or profile stale.
	names := make([]string, 0, len(devices))
	offline := make(map[string]*DeviceNotice)
	for index := range devices {
		device := &devices[index]
		if device.Profile == "" {
			device.Profile = name
		}
		if device.ADOM == "" {
			device.ADOM = adom.Name
		}
		names = append(names, device.Name)
		if unavailable, _ := fortinet.DeviceUnavailable(*device); unavailable {
			notice := unavailableDeviceNotice(name, adom.Name, *device)
			offline[device.Name] = &notice
		}
	}
	interfaceResults, interfaceAttempts := s.refreshInterfaces(ctx, manager, adom.Name, names, callSem, profileSem)
	// A device read failure is device-level evidence: the device keeps its
	// last-known-good data and records the failed stage, and the error stays
	// visible, but the ADOM and profile are not marked stale for it.
	failedDevices := make(map[string]bool)
	readFailure := func(device *fortinet.Device, stage string, err error, attempts int) {
		if notice, isOffline := offline[device.Name]; isOffline {
			notice.ReadError = strings.TrimSpace(strings.TrimPrefix(notice.ReadError+"; "+stage+": "+err.Error(), "; "))
			return
		}
		device.DataError = strings.TrimPrefix(device.DataError+", "+stage, ", ")
		if !failedDevices[device.Name] {
			failedDevices[device.Name] = true
			result.deviceErrors++
		}
		if ctx.Err() != nil {
			// The refresh budget ended: one profile-level error says so,
			// instead of a "deadline exceeded" entry per device.
			return
		}
		result.errors = append(result.errors, refreshErrorFrom(name, adom.Name, device.Name, "", stage, err, attempts))
	}

	routeTargets := make([]fortinet.RouteTarget, 0, len(devices))
	for index := range devices {
		device := &devices[index]
		previousDevice, hasPrevious := previousDevice(previous, name, adom.Name, device.Name)
		retain := func() {
			if hasPrevious {
				device.Interfaces = append([]fortinet.Interface(nil), previousDevice.Interfaces...)
				device.VDOMs = append([]string(nil), previousDevice.VDOMs...)
				device.DataAsOf = previousDevice.DataAsOf
			}
		}
		attempts := interfaceAttempts[device.Name]
		if interfaceResult, ok := interfaceResults[device.Name]; !ok {
			readFailure(device, "list_interfaces", fmt.Errorf("list interfaces for %s/%s: no batch result returned", adom.Name, device.Name), attempts)
			retain()
		} else {
			if interfaceResult.InterfaceError != nil {
				readFailure(device, "list_interfaces", interfaceResult.InterfaceError, attempts)
				retain()
			} else {
				device.Interfaces = interfaceResult.Interfaces
				device.VDOMs = vdomsFromInterfaces(interfaceResult.Interfaces, device.VDOMs)
				device.DataAsOf = time.Now()
				routeTargets = append(routeTargets, routeTargetsForDevice(*device)...)
			}
			if interfaceResult.ZoneError != nil {
				readFailure(device, "list_interface_zones", interfaceResult.ZoneError, attempts)
			}
		}

		if groupErr != nil {
			if hasPrevious {
				device.Groups = append([]string(nil), previousDevice.Groups...)
			}
		} else {
			device.Groups = groupsForDevice(groups, device.Name)
		}
		if packageErr != nil {
			if hasPrevious {
				device.PackageTargets = append([]fortinet.PackageTarget(nil), previousDevice.PackageTargets...)
				device.Packages = append([]string(nil), previousDevice.Packages...)
			}
		} else {
			device.PackageTargets = packageTargetsForDevice(packages, *device)
			device.Packages = packageNamesForTargets(device.PackageTargets)
		}
		result.devices = append(result.devices, *device)
	}

	routeResults, routeAttempts, routesSupported := s.refreshRoutes(ctx, manager, adom.Name, routeTargets, callSem, profileSem)
	for index := range result.devices {
		device := &result.devices[index]
		previousDevice, hasPrevious := previousDevice(previous, name, adom.Name, device.Name)
		routeResult, fresh := routeResults[device.Name]
		if !fresh {
			if routesSupported && hasPrevious {
				// Interfaces were not refreshed for this device; keep its last
				// known routing together with its last known interfaces.
				device.Routes = append([]fortinet.Route(nil), previousDevice.Routes...)
				device.PolicyRoutes = append([]fortinet.PolicyRoute(nil), previousDevice.PolicyRoutes...)
				device.SDWAN = append([]fortinet.SDWANConfig(nil), previousDevice.SDWAN...)
			}
			continue
		}
		// Each table falls back to last-known-good data independently. A result
		// without an error is complete regardless of its flags.
		if routeResult.Err == nil {
			routeResult.StaticOK, routeResult.PolicyOK, routeResult.SDWANOK = true, true, true
		}
		if routeResult.StaticOK {
			device.Routes = routeResult.Routes
		} else if hasPrevious {
			device.Routes = append([]fortinet.Route(nil), previousDevice.Routes...)
		}
		if routeResult.PolicyOK {
			device.PolicyRoutes = routeResult.PolicyRoutes
		} else if hasPrevious {
			device.PolicyRoutes = append([]fortinet.PolicyRoute(nil), previousDevice.PolicyRoutes...)
		}
		if routeResult.SDWANOK {
			device.SDWAN = routeResult.SDWAN
		} else if hasPrevious {
			device.SDWAN = append([]fortinet.SDWANConfig(nil), previousDevice.SDWAN...)
		}
		if routeResult.Err != nil {
			readFailure(device, "list_routes", routeResult.Err, routeAttempts)
		}
	}
	for index := range result.devices {
		device := result.devices[index]
		notice, isOffline := offline[device.Name]
		if !isOffline {
			continue
		}
		notice.DataAsOf = device.DataAsOf
		switch {
		case notice.ReadError == "":
			notice.DataSource = "fortimanager_database"
		case !device.DataAsOf.IsZero():
			notice.DataSource = "retained"
		default:
			notice.DataSource = "none"
		}
		result.unavailable = append(result.unavailable, *notice)
	}
	return result
}

// routeTargetsForDevice lists each VDOM of a freshly inventoried device and
// whether an IPv6 static table is worth reading.
func routeTargetsForDevice(device fortinet.Device) []fortinet.RouteTarget {
	ipv6ByVDOM := make(map[string]bool)
	for _, iface := range device.Interfaces {
		vdom := iface.VDOM
		if vdom == "" {
			vdom = "root"
		}
		if _, seen := ipv6ByVDOM[vdom]; !seen {
			ipv6ByVDOM[vdom] = false
		}
		if len(iface.IPv6) > 0 {
			ipv6ByVDOM[vdom] = true
		}
	}
	vdoms := make([]string, 0, len(ipv6ByVDOM))
	for vdom := range ipv6ByVDOM {
		vdoms = append(vdoms, vdom)
	}
	sort.Strings(vdoms)
	targets := make([]fortinet.RouteTarget, 0, len(vdoms))
	for _, vdom := range vdoms {
		targets = append(targets, fortinet.RouteTarget{Device: device.Name, VDOM: vdom, IPv6: ipv6ByVDOM[vdom]})
	}
	return targets
}

// refreshRoutes reads configured static routes through the optional
// RouteBatchReader. Managers without it simply provide no route evidence.
func (s *Store) refreshRoutes(ctx context.Context, manager fortinet.Manager, adom string, targets []fortinet.RouteTarget, callSem, profileSem chan struct{}) (map[string]fortinet.RouteBatchResult, int, bool) {
	reader, ok := manager.(fortinet.RouteBatchReader)
	if !ok || len(targets) == 0 {
		return nil, 0, ok
	}
	results, err, attempts := inventoryCallWithAttempts(ctx, callSem, profileSem, func() (map[string]fortinet.RouteBatchResult, error) {
		return reader.ListRoutesBatch(ctx, adom, targets)
	})
	if err != nil {
		results = make(map[string]fortinet.RouteBatchResult, len(targets))
		for _, target := range targets {
			results[target.Device] = fortinet.RouteBatchResult{Err: err}
		}
	}
	return results, attempts, true
}

func (s *Store) refreshInterfaces(ctx context.Context, manager fortinet.Manager, adom string, devices []string, callSem, profileSem chan struct{}) (map[string]fortinet.InterfaceBatchResult, map[string]int) {
	devices = uniqueStrings(devices)
	results := make(map[string]fortinet.InterfaceBatchResult, len(devices))
	attempts := make(map[string]int, len(devices))
	if len(devices) == 0 {
		return results, attempts
	}
	if batchReader, ok := manager.(fortinet.InterfaceBatchReader); ok {
		for start := 0; start < len(devices); start += inventoryInterfaceBatch {
			end := min(start+inventoryInterfaceBatch, len(devices))
			batchResults, batchAttempts := refreshInterfaceBatch(ctx, callSem, profileSem, batchReader, adom, devices[start:end])
			for device, batchResult := range batchResults {
				results[device] = batchResult
				attempts[device] = batchAttempts[device]
			}
		}
		return results, attempts
	}

	// External Manager implementations may not support batching. Keep the
	// fallback bounded and retry each device independently so one bad device
	// cannot prevent the remaining devices from being inventoried.
	for _, device := range devices {
		interfaces, err, deviceAttempts := inventoryCallWithAttempts(ctx, callSem, profileSem, func() ([]fortinet.Interface, error) {
			return manager.ListInterfaces(ctx, adom, device)
		})
		attempts[device] = deviceAttempts
		if err != nil {
			results[device] = fortinet.InterfaceBatchResult{InterfaceError: err}
			continue
		}
		results[device] = fortinet.InterfaceBatchResult{Interfaces: interfaces}
	}
	return results, attempts
}

func refreshInterfaceBatch(ctx context.Context, callSem, profileSem chan struct{}, reader fortinet.InterfaceBatchReader, adom string, devices []string) (map[string]fortinet.InterfaceBatchResult, map[string]int) {
	results := make(map[string]fortinet.InterfaceBatchResult, len(devices))
	attempts := make(map[string]int, len(devices))
	pending := append([]string(nil), devices...)
	for attempt := 1; len(pending) > 0 && attempt <= inventoryRetryAttempts; attempt++ {
		batch, err := callWithSemaphores(ctx, callSem, profileSem, func() (map[string]fortinet.InterfaceBatchResult, error) {
			return reader.ListInterfacesBatch(ctx, adom, pending)
		})
		for _, device := range pending {
			attempts[device]++
		}
		if err != nil {
			for _, device := range pending {
				results[device] = preserveInterfaceResult(results[device], fortinet.InterfaceBatchResult{InterfaceError: err})
			}
			if ctx.Err() != nil || attempt == inventoryRetryAttempts || !fortinet.DescribeError(err).Retryable {
				break
			}
			if waitErr := waitInventoryRetry(ctx, attempt); waitErr != nil {
				for _, device := range pending {
					results[device] = preserveInterfaceResult(results[device], fortinet.InterfaceBatchResult{InterfaceError: waitErr})
				}
				break
			}
			continue
		}

		next := make([]string, 0, len(pending))
		for _, device := range pending {
			item, ok := batch[device]
			if !ok {
				item.InterfaceError = fmt.Errorf("list interfaces for %s/%s: batch omitted device result", adom, device)
			}
			results[device] = preserveInterfaceResult(results[device], item)
			if retryableInterfaceResult(item) && attempt < inventoryRetryAttempts && ctx.Err() == nil {
				next = append(next, device)
			}
		}
		pending = next
		if len(pending) > 0 {
			if waitErr := waitInventoryRetry(ctx, attempt); waitErr != nil {
				for _, device := range pending {
					results[device] = preserveInterfaceResult(results[device], fortinet.InterfaceBatchResult{InterfaceError: waitErr})
				}
				break
			}
		}
	}
	return results, attempts
}

// A failed retry of zone data must not discard interfaces already read during
// this refresh. Keep the failure visible as incomplete zone enrichment.
func preserveInterfaceResult(previous, next fortinet.InterfaceBatchResult) fortinet.InterfaceBatchResult {
	if previous.Interfaces != nil && previous.InterfaceError == nil && next.InterfaceError != nil {
		previous.ZoneError = next.InterfaceError
		return previous
	}
	return next
}

func retryableInterfaceResult(result fortinet.InterfaceBatchResult) bool {
	if result.InterfaceError != nil && fortinet.DescribeError(result.InterfaceError).Retryable {
		return true
	}
	return result.ZoneError != nil && fortinet.DescribeError(result.ZoneError).Retryable
}

// Snapshot returns the published inventory. Top-level slices are copies of
// the struct headers, so replacing a device or ADOM in the result does not
// change the store. Interface, route, and SD-WAN slices are shared with the
// published snapshot and must not be mutated.
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.viewLocked()
}

// cloneLocked is the refresh's private copy. It does not share slices with
// the published snapshot.
func (s *Store) cloneLocked() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot := cloneSnapshot(s.snapshot)
	if !s.startedAt.IsZero() {
		snapshot.RefreshInProgress = true
		snapshot.RefreshStartedAt = s.startedAt
	}
	return snapshot
}

func (s *Store) viewLocked() Snapshot {
	snapshot := viewSnapshot(s.snapshot)
	if !s.startedAt.IsZero() {
		snapshot.RefreshInProgress = true
		snapshot.RefreshStartedAt = s.startedAt
	}
	return snapshot
}

// HasSnapshot reports whether a refresh has published inventory at least once.
func (s *Store) HasSnapshot() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.snapshot.GeneratedAt.IsZero()
}

// LastRefreshDuration is how long the most recent refresh took, including a
// refresh that published only errors.
func (s *Store) LastRefreshDuration() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRefresh
}

// SetAfterRefresh runs hook after each background refresh publishes (or
// keeps) a snapshot. Explicit refresh_inventory calls do not use this hook.
func (s *Store) SetAfterRefresh(hook func(context.Context, Snapshot)) {
	s.mu.Lock()
	s.afterRefresh = hook
	s.mu.Unlock()
}

// FindDevices returns devices with this name. Empty profile or ADOM does not
// filter that field. The device structs are copies; their inner slices alias
// the published snapshot.
func (s *Store) FindDevices(profile, adom, name string) []fortinet.Device {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	indexes := s.deviceIndex[name]
	if len(indexes) == 0 {
		return nil
	}
	matched := make([]fortinet.Device, 0, len(indexes))
	for _, index := range indexes {
		if index < 0 || index >= len(s.snapshot.Devices) {
			continue
		}
		device := s.snapshot.Devices[index]
		if profile != "" && device.Profile != profile {
			continue
		}
		if adom != "" && device.ADOM != adom {
			continue
		}
		matched = append(matched, device)
	}
	return matched
}

func (s *Store) Manager(profile string) (fortinet.Manager, error) {
	manager, ok := s.managers[profile]
	if !ok {
		return nil, fmt.Errorf("FortiManager profile %q not found", profile)
	}
	return manager, nil
}

func (s *Store) Managers() map[string]fortinet.Manager {
	result := make(map[string]fortinet.Manager, len(s.managers))
	maps.Copy(result, s.managers)
	return result
}

func (s *Store) Close() error {
	// Stop waits for the refresh that holds refreshGate. Draining the gate
	// here would steal that permit and leave the refresh blocked on release.
	s.Stop()
	return s.closeManagers()
}

func (s *Store) closeManagers() error {
	var firstErr error
	for _, manager := range s.managers {
		if err := manager.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Stop cancels and waits for the background refresh loop without closing the
// appliance clients. Callers that own those clients can then close them after
// all in-flight inventory work has stopped.
func (s *Store) Stop() {
	if s.cancel != nil {
		s.cancel()
		s.wg.Wait()
	}
}

func (s *Store) setSnapshot(snapshot Snapshot) {
	owned := cloneSnapshot(snapshot)
	index := buildOwnershipIndex(owned)
	devices := buildDeviceIndex(owned)
	s.mu.Lock()
	s.snapshot = owned
	s.ownership = index
	s.deviceIndex = devices
	s.completedAt = time.Now()
	s.mu.Unlock()
	s.readyOnce.Do(func() { close(s.ready) })
}

func buildDeviceIndex(snapshot Snapshot) map[string][]int {
	index := make(map[string][]int)
	for i, device := range snapshot.Devices {
		if device.Name == "" {
			continue
		}
		index[device.Name] = append(index[device.Name], i)
	}
	return index
}

// viewSnapshot copies the top-level slices so callers can reslice them.
// Device interface and route slices stay shared.
func viewSnapshot(snapshot Snapshot) Snapshot {
	view := snapshot
	view.ADOMs = append([]ADOMRecord(nil), snapshot.ADOMs...)
	view.Profiles = append([]ProfileState(nil), snapshot.Profiles...)
	view.Errors = append([]RefreshError(nil), snapshot.Errors...)
	view.UnavailableDevices = append([]DeviceNotice(nil), snapshot.UnavailableDevices...)
	view.Devices = append([]fortinet.Device(nil), snapshot.Devices...)
	return view
}

func (s *Store) lastCompletedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.completedAt
}

func packageTargetsForDevice(packages []fortinet.PolicyPackage, device fortinet.Device) []fortinet.PackageTarget {
	result := make([]fortinet.PackageTarget, 0, len(packages))
	seen := make(map[string]struct{})
	for _, pkg := range packages {
		if len(pkg.Members) == 0 {
			target := fortinet.PackageTarget{Package: pkg.Name}
			if _, exists := seen[target.Package+"\x00"+target.VDOM]; !exists {
				result = append(result, target)
				seen[target.Package+"\x00"+target.VDOM] = struct{}{}
			}
			continue
		}
		for _, member := range pkg.Members {
			if member.Device == device.Name || stringSliceContains(device.Groups, member.Device) {
				target := fortinet.PackageTarget{Package: pkg.Name, VDOM: member.VDOM}
				if _, exists := seen[target.Package+"\x00"+target.VDOM]; exists {
					continue
				}
				result = append(result, target)
				seen[target.Package+"\x00"+target.VDOM] = struct{}{}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Package != result[j].Package {
			return result[i].Package < result[j].Package
		}
		return result[i].VDOM < result[j].VDOM
	})
	return result
}

func packageNamesForTargets(targets []fortinet.PackageTarget) []string {
	result := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.Package == "" {
			continue
		}
		if _, exists := seen[target.Package]; exists {
			continue
		}
		seen[target.Package] = struct{}{}
		result = append(result, target.Package)
	}
	sort.Strings(result)
	return result
}

func stringSliceContains(values []string, target string) bool {
	return slices.Contains(values, target)
}

func groupsForDevice(groups []fortinet.DeviceGroup, device string) []string {
	groupMembers := make(map[string][]string, len(groups))
	for _, group := range groups {
		for _, member := range group.Members {
			if member.Device != "" {
				groupMembers[group.Name] = append(groupMembers[group.Name], member.Device)
			}
		}
	}

	matched := make(map[string]struct{})
	for {
		changed := false
		for group, members := range groupMembers {
			if _, already := matched[group]; already {
				continue
			}
			for _, member := range members {
				if member == device {
					matched[group] = struct{}{}
					changed = true
					break
				}
				if _, nestedGroup := matched[member]; nestedGroup {
					matched[group] = struct{}{}
					changed = true
					break
				}
			}
		}
		if !changed {
			break
		}
	}
	result := make([]string, 0, len(matched))
	for group := range matched {
		result = append(result, group)
	}
	sort.Strings(result)
	return result
}

func vdomsFromInterfaces(interfaces []fortinet.Interface, existing []string) []string {
	seen := make(map[string]struct{}, len(existing)+1)
	result := make([]string, 0, len(existing)+1)
	for _, vdom := range existing {
		if vdom != "" {
			seen[vdom] = struct{}{}
			result = append(result, vdom)
		}
	}
	for _, iface := range interfaces {
		if iface.VDOM != "" {
			if _, ok := seen[iface.VDOM]; !ok {
				seen[iface.VDOM] = struct{}{}
				result = append(result, iface.VDOM)
			}
		}
	}
	if len(result) == 0 {
		result = []string{"root"}
	}
	sort.Strings(result)
	return result
}

func countDevices(devices []fortinet.Device, profile string) int {
	count := 0
	for _, device := range devices {
		if device.Profile == profile {
			count++
		}
	}
	return count
}

func countADOMs(adoms []ADOMRecord, profile string) int {
	count := 0
	for _, adom := range adoms {
		if adom.Profile == profile {
			count++
		}
	}
	return count
}

func previousProfileState(snapshot Snapshot, profile string) ProfileState {
	for _, state := range snapshot.Profiles {
		if state.Profile == profile {
			return state
		}
	}
	return ProfileState{Profile: profile}
}

func previousProfileADOMs(snapshot Snapshot, profile string) []ADOMRecord {
	result := make([]ADOMRecord, 0)
	for _, adom := range snapshot.ADOMs {
		if adom.Profile == profile {
			result = append(result, adom)
		}
	}
	return result
}

func previousProfileDevices(snapshot Snapshot, profile string) []fortinet.Device {
	result := make([]fortinet.Device, 0)
	for _, device := range snapshot.Devices {
		if device.Profile == profile {
			result = append(result, device)
		}
	}
	return result
}

func previousADOMRecord(snapshot Snapshot, profile, adom string) (ADOMRecord, bool) {
	for _, record := range snapshot.ADOMs {
		if record.Profile == profile && record.ADOM.Name == adom {
			return record, true
		}
	}
	return ADOMRecord{}, false
}

// clonePolicyPackages copies the package list without appliance raw records.
// oid and scope members are what later reads reuse instead of calling
// ListPolicyPackages again.
func clonePolicyPackages(packages []fortinet.PolicyPackage) []fortinet.PolicyPackage {
	if len(packages) == 0 {
		return nil
	}
	cloned := make([]fortinet.PolicyPackage, len(packages))
	for i, pkg := range packages {
		cloned[i] = fortinet.PolicyPackage{Name: pkg.Name, Type: pkg.Type, OID: pkg.OID, Members: append([]fortinet.PackageMember(nil), pkg.Members...)}
	}
	return cloned
}

func previousADOMDevices(snapshot Snapshot, profile, adom string) []fortinet.Device {
	result := make([]fortinet.Device, 0)
	for _, device := range snapshot.Devices {
		if device.Profile == profile && device.ADOM == adom {
			result = append(result, device)
		}
	}
	return result
}

func previousDevice(snapshot Snapshot, profile, adom, name string) (fortinet.Device, bool) {
	for _, device := range snapshot.Devices {
		if device.Profile == profile && device.ADOM == adom && device.Name == name {
			return device, true
		}
	}
	return fortinet.Device{}, false
}

// fortiGateADOMs drops discovered ADOMs restricted to other Fortinet
// products. ADOMs without product information (configured allowlists,
// older releases) are kept.
func fortiGateADOMs(adoms []fortinet.ADOM) []fortinet.ADOM {
	kept := adoms[:0]
	for _, adom := range adoms {
		products := strings.ToLower(strings.TrimSpace(fmt.Sprint(adom.Raw["restricted_prds"])))
		if adom.Raw == nil || adom.Raw["restricted_prds"] == nil || products == "" || strings.Contains(products, "fos") || strings.Contains(products, "foc") || strings.Contains(products, "ffw") {
			kept = append(kept, adom)
		}
	}
	return kept
}

// sortADOMsByDataAge orders ADOMs by the oldest device data they had in the
// previous snapshot; ADOMs without data come first.
func sortADOMsByDataAge(adoms []fortinet.ADOM, previous Snapshot, profile string) {
	oldest := make(map[string]time.Time)
	for _, device := range previous.Devices {
		if device.Profile != profile {
			continue
		}
		if current, ok := oldest[device.ADOM]; !ok || device.DataAsOf.Before(current) {
			oldest[device.ADOM] = device.DataAsOf
		}
	}
	sort.SliceStable(adoms, func(i, j int) bool {
		return oldest[adoms[i].Name].Before(oldest[adoms[j].Name])
	})
}

func mergePreviousProfileData(result *profileRefreshResult, snapshot Snapshot, profile string) {
	knownADOMs := make(map[string]struct{}, len(result.adoms))
	for _, adom := range result.adoms {
		knownADOMs[adom.ADOM.Name] = struct{}{}
	}
	for _, adom := range previousProfileADOMs(snapshot, profile) {
		if _, exists := knownADOMs[adom.ADOM.Name]; exists {
			continue
		}
		result.adoms = append(result.adoms, adom)
		knownADOMs[adom.ADOM.Name] = struct{}{}
	}
	knownDevices := make(map[string]struct{}, len(result.devices))
	for _, device := range result.devices {
		knownDevices[device.ADOM+"\x00"+device.Name] = struct{}{}
	}
	for _, device := range previousProfileDevices(snapshot, profile) {
		key := device.ADOM + "\x00" + device.Name
		if _, exists := knownDevices[key]; exists {
			continue
		}
		result.devices = append(result.devices, device)
		knownDevices[key] = struct{}{}
	}
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	clone := snapshot
	clone.ADOMs = make([]ADOMRecord, len(snapshot.ADOMs))
	for i, adom := range snapshot.ADOMs {
		clone.ADOMs[i] = adom
		clone.ADOMs[i].Packages = clonePolicyPackages(adom.Packages)
	}
	clone.Profiles = append([]ProfileState(nil), snapshot.Profiles...)
	clone.Errors = append([]RefreshError(nil), snapshot.Errors...)
	clone.UnavailableDevices = append([]DeviceNotice(nil), snapshot.UnavailableDevices...)
	clone.Devices = make([]fortinet.Device, len(snapshot.Devices))
	for i, device := range snapshot.Devices {
		clone.Devices[i] = device
		clone.Devices[i].VDOMs = append([]string(nil), device.VDOMs...)
		clone.Devices[i].Groups = append([]string(nil), device.Groups...)
		clone.Devices[i].Packages = append([]string(nil), device.Packages...)
		clone.Devices[i].PackageTargets = append([]fortinet.PackageTarget(nil), device.PackageTargets...)
		clone.Devices[i].Routes = append([]fortinet.Route(nil), device.Routes...)
		clone.Devices[i].PolicyRoutes = append([]fortinet.PolicyRoute(nil), device.PolicyRoutes...)
		clone.Devices[i].SDWAN = append([]fortinet.SDWANConfig(nil), device.SDWAN...)
		clone.Devices[i].Interfaces = append([]fortinet.Interface(nil), device.Interfaces...)
		for interfaceIndex := range clone.Devices[i].Interfaces {
			clone.Devices[i].Interfaces[interfaceIndex].IPv6 = append([]string(nil), device.Interfaces[interfaceIndex].IPv6...)
			clone.Devices[i].Interfaces[interfaceIndex].Networks = append([]string(nil), device.Interfaces[interfaceIndex].Networks...)
			clone.Devices[i].Interfaces[interfaceIndex].Addresses = append([]string(nil), device.Interfaces[interfaceIndex].Addresses...)
		}
	}
	return clone
}

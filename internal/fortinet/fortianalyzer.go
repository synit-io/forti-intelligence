package fortinet

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

type FortiAnalyzer struct {
	rpc *rpcClient
	// timeFormat remembers (index+1 into logSearchTimeFormats) the first
	// time format this appliance accepted. Later searches send it directly,
	// so an invalid filter is not re-submitted in other formats.
	timeFormat atomic.Int32
	// searches remembers submitted searches by task ID, so a resumed search
	// reports the log type, filter and time range it was submitted with.
	searchMu sync.Mutex
	searches map[string]submittedSearch
}

type submittedSearch struct {
	created       time.Time
	request       LogSearchRequest
	filter        string
	identity      string
	timeRangeSent map[string]string
	applianceZone string
}

const (
	// maxLogSearchLimit is the most records FortiAnalyzer returns per page.
	maxLogSearchLimit = 500
	// defaultLogSearchLimit keeps pages small: FortiAnalyzer finishes a
	// search once it found the requested number of matches.
	defaultLogSearchLimit = 25
	logSearchPollFirst    = 500 * time.Millisecond
	logSearchPollMaximum  = 2 * time.Second
	// logSearchPollDefault bounds polling only when the caller has no
	// deadline; otherwise polling runs until the deadline minus the reserve.
	logSearchPollDefault = 25 * time.Second
	logSearchPollReserve = 1500 * time.Millisecond
	allLogSearchDevices  = "All_Devices"
	submittedSearchTTL   = time.Hour
	maxSubmittedSearches = 256
	// identicalSearchReuse resumes a search this process submitted moments
	// ago instead of creating a second task for the same window.
	identicalSearchReuse = 3 * time.Minute
)

// MaxLogSearchLimit is the most matches one Log View submit collects.
func MaxLogSearchLimit() int { return maxLogSearchLimit }

// logSearchTimeFormats are tried in order until the appliance accepts one:
// RFC 3339 with the UTC offset, which FortiAnalyzer converts itself; the
// same without offset (wall clock in the appliance or ADOM zone); and the
// space-separated form of older releases.
var logSearchTimeFormats = []string{"2006-01-02T15:04:05-07:00", "2006-01-02T15:04:05", "2006-01-02 15:04:05"}

func NewFortiAnalyzer(profile config.ProfileConfig) (*FortiAnalyzer, error) {
	rpc, err := newRPCClient(profile)
	if err != nil {
		return nil, err
	}
	rpc.policy = policyFortiAnalyzer
	return &FortiAnalyzer{rpc: rpc, searches: make(map[string]submittedSearch)}, nil
}

func (c *FortiAnalyzer) Name() string {
	return c.rpc.profile.Name
}

func (c *FortiAnalyzer) AllowsADOM(adom string) bool {
	return c.rpc.profile.AllowsADOM(adom)
}

func (c *FortiAnalyzer) validateADOM(adom string) error {
	if c.AllowsADOM(adom) {
		return nil
	}
	return fmt.Errorf("ADOM %q is not configured for FortiAnalyzer profile %q; configured ADOMs: %s", adom, c.Name(), strings.Join(c.rpc.profile.ADOMs, ", "))
}

func (c *FortiAnalyzer) Status(ctx context.Context) (any, error) {
	return c.Read(ctx, "/sys/status", nil)
}

func (c *FortiAnalyzer) rememberSearch(taskID string, search submittedSearch) {
	c.searchMu.Lock()
	defer c.searchMu.Unlock()
	if c.searches == nil {
		c.searches = make(map[string]submittedSearch)
	}
	now := time.Now()
	for id, entry := range c.searches {
		if now.Sub(entry.created) > submittedSearchTTL {
			delete(c.searches, id)
		}
	}
	if len(c.searches) >= maxSubmittedSearches {
		oldestID, oldest := "", now
		for id, entry := range c.searches {
			if entry.created.Before(oldest) {
				oldestID, oldest = id, entry.created
			}
		}
		delete(c.searches, oldestID)
	}
	search.created = now
	c.searches[taskID] = search
}

func (c *FortiAnalyzer) submittedSearch(taskID string) (submittedSearch, bool) {
	c.searchMu.Lock()
	defer c.searchMu.Unlock()
	search, ok := c.searches[taskID]
	if ok && time.Since(search.created) > submittedSearchTTL {
		delete(c.searches, taskID)
		return submittedSearch{}, false
	}
	return search, ok
}

// findRecentSearch returns a task this process submitted for the same
// ADOM, log type, filter, device, time window, limit and offset.
func (c *FortiAnalyzer) findRecentSearch(identity string) (string, submittedSearch, bool) {
	c.searchMu.Lock()
	defer c.searchMu.Unlock()
	var foundID string
	var found submittedSearch
	now := time.Now()
	for id, entry := range c.searches {
		if now.Sub(entry.created) > identicalSearchReuse || entry.identity != identity {
			continue
		}
		if foundID == "" || entry.created.After(found.created) {
			foundID, found = id, entry
		}
	}
	return foundID, found, foundID != ""
}

func logSearchIdentity(request LogSearchRequest, filter string) string {
	return strings.Join([]string{
		request.ADOM,
		request.LogType,
		filter,
		request.Device,
		request.StartTime.UTC().Format(time.RFC3339Nano),
		request.EndTime.UTC().Format(time.RFC3339Nano),
		strconv.Itoa(request.Limit),
		strconv.Itoa(request.Offset),
	}, "\x00")
}

// SearchLogs submits (or resumes) a Log View search and polls it for as long
// as the caller's deadline allows. A search that is still running when the
// deadline nears returns the records fetched so far together with the task
// ID, so the caller can continue it.
func (c *FortiAnalyzer) SearchLogs(ctx context.Context, request LogSearchRequest) (LogSearchResult, error) {
	if request.ADOM == "" {
		if len(c.rpc.profile.ADOMs) == 1 {
			request.ADOM = c.rpc.profile.ADOMs[0]
		} else {
			request.ADOM = "root"
		}
	}
	if err := c.validateADOM(request.ADOM); err != nil {
		return LogSearchResult{}, err
	}
	warnings := make([]string, 0, 2)
	if request.Limit <= 0 {
		request.Limit = defaultLogSearchLimit
	}
	if request.Limit > maxLogSearchLimit {
		warnings = append(warnings, fmt.Sprintf("limit %d was lowered to %d, the most FortiAnalyzer returns per page; page further with offset.", request.Limit, maxLogSearchLimit))
		request.Limit = maxLogSearchLimit
	}
	if request.Offset < 0 {
		return LogSearchResult{}, fmt.Errorf("FortiAnalyzer log search offset must not be negative")
	}
	request.TaskID = strings.TrimSpace(request.TaskID)

	if request.TaskID != "" {
		submitted, known := c.submittedSearch(request.TaskID)
		filter := request.Filter
		if known {
			// Report the search as it was submitted; the caller usually passes
			// only task_id and offset when continuing.
			if request.LogType == "" {
				request.LogType = submitted.request.LogType
			}
			if request.Device == "" {
				request.Device = submitted.request.Device
			}
			request.StartTime, request.EndTime = submitted.request.StartTime, submitted.request.EndTime
			filter = submitted.filter
		} else {
			warnings = append(warnings, "This task was not submitted by this server process within the last hour, so its log type, filter and time range are not known here; they are reported as given in this call.")
		}
		if request.LogType == "" {
			request.LogType = "traffic"
		}
		matchBudget := request.Limit
		if known {
			matchBudget = submitted.request.Limit
		}
		result, timedOut, err := c.pollLogSearch(ctx, request.ADOM, request.TaskID, request.Limit, request.Offset)
		searchResult := logSearchResult(c.Name(), request, filter, request.TaskID, request.Offset, matchBudget, result, timedOut, warnings)
		searchResult.Resumed = true
		if known {
			searchResult.TimeRangeSent = submitted.timeRangeSent
			searchResult.ApplianceTimezone = submitted.applianceZone
		}
		if err != nil {
			return searchResult, fmt.Errorf("FortiAnalyzer log search task %s in ADOM %q: %w; a finished task may have expired, submit the search again without task_id", request.TaskID, request.ADOM, err)
		}
		return searchResult, nil
	}
	if request.LogType == "" {
		request.LogType = "traffic"
	}

	// Both ends of the range are expressed in one time zone: the profile
	// zone when configured, otherwise the zone of whichever end the caller
	// supplied. The first format carries the UTC offset, so FortiAnalyzer
	// converts it; the fallback formats send the wall clock of that zone.
	location := c.rpc.profile.Location()
	if location == nil {
		switch {
		case !request.StartTime.IsZero():
			location = request.StartTime.Location()
		case !request.EndTime.IsZero():
			location = request.EndTime.Location()
		default:
			location = time.UTC
		}
	}
	now := time.Now().In(location)
	if request.EndTime.IsZero() {
		request.EndTime = now
	}
	if request.StartTime.IsZero() {
		request.StartTime = request.EndTime.Add(-time.Hour)
	}
	request.StartTime, request.EndTime = request.StartTime.In(location), request.EndTime.In(location)
	if request.EndTime.Before(request.StartTime) {
		return LogSearchResult{}, fmt.Errorf("FortiAnalyzer log search end time %s is before start time %s", request.EndTime.Format(time.RFC3339), request.StartTime.Format(time.RFC3339))
	}
	effectiveFilter := request.Filter
	if request.Device != "" {
		deviceFilter := fmt.Sprintf("devname=\"%s\"", strings.ReplaceAll(request.Device, "\"", "\\\""))
		if effectiveFilter == "" {
			effectiveFilter = deviceFilter
		} else {
			effectiveFilter = fmt.Sprintf("(%s) AND %s", effectiveFilter, deviceFilter)
		}
	}
	applianceZone := ""
	if configured := c.rpc.profile.Location(); configured != nil {
		applianceZone = configured.String()
	}
	start, end := request.StartTime, request.EndTime

	submit := func(format string) (any, map[string]string, error) {
		timeRange := map[string]string{"start": start.Format(format), "end": end.Format(format)}
		searchParam := map[string]any{
			"apiver": 3,
			// Log View needs an explicit device selector to determine the device
			// type; a devname filter alone is rejected with "Device type is
			// unknown". Keep the selector broad and filter by devname below.
			"device":         []map[string]any{{"devid": allLogSearchDevices}},
			"url":            normalizePath("logview", "adom", request.ADOM, "logsearch"),
			"logtype":        request.LogType,
			"limit":          request.Limit,
			"offset":         request.Offset,
			"time-order":     "desc",
			"case-sensitive": false,
			"time-range":     timeRange,
		}
		if effectiveFilter != "" {
			searchParam["filter"] = effectiveFilter
		}
		result, err := c.rpc.call(ctx, "add", []map[string]any{searchParam})
		return result, timeRange, err
	}
	// Probe the time formats only until one was accepted; afterwards an
	// invalid answer is about the filter or log type, not the time.
	order := []int{0, 1, 2}
	if known := int(c.timeFormat.Load()) - 1; known >= 0 && known < len(logSearchTimeFormats) {
		order = []int{known}
	}
	identity := logSearchIdentity(request, effectiveFilter)
	if taskID, previous, ok := c.findRecentSearch(identity); ok {
		warnings = append(warnings, fmt.Sprintf("Reused log search task %s submitted %s ago for the same ADOM, filter, device, time window, limit and offset.", taskID, time.Since(previous.created).Round(time.Second)))
		result, timedOut, err := c.pollLogSearch(ctx, request.ADOM, taskID, request.Limit, request.Offset)
		searchResult := logSearchResult(c.Name(), request, effectiveFilter, taskID, request.Offset, previous.request.Limit, result, timedOut, warnings)
		searchResult.Resumed = true
		searchResult.ApplianceTimezone = previous.applianceZone
		searchResult.TimeRangeSent = previous.timeRangeSent
		if err != nil {
			return searchResult, fmt.Errorf("FortiAnalyzer log search task %s in ADOM %q: %w; a finished task may have expired, submit the search again without task_id", taskID, request.ADOM, err)
		}
		return searchResult, nil
	}

	var (
		result        any
		timeRangeSent map[string]string
		err           error
		accepted      = -1
	)
	for _, index := range order {
		result, timeRangeSent, err = submit(logSearchTimeFormats[index])
		if err == nil {
			accepted = index
			c.timeFormat.Store(int32(index + 1))
			break
		}
		if DescribeError(err).Kind != ErrorKindInvalid || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		return LogSearchResult{}, fmt.Errorf("FortiAnalyzer log search submit in ADOM %q (logtype %s): %w", request.ADOM, request.LogType, err)
	}
	if accepted > 0 && applianceZone == "" {
		warnings = append(warnings, fmt.Sprintf("This FortiAnalyzer does not accept times with a UTC offset, so the range was sent as wall-clock values in %s. FortiAnalyzer applies its own or the ADOM time zone; set profiles[%q].timezone to convert automatically.", timezoneLabel(request.StartTime), c.Name()))
	}
	taskID := taskID(result)
	if taskID == "" {
		if _, isList := logRecords(result).([]any); isList {
			// Releases that answer synchronously return the records directly.
			searchResult := logSearchResult(c.Name(), request, effectiveFilter, "", request.Offset, request.Limit, result, false, warnings)
			searchResult.ApplianceTimezone = applianceZone
			searchResult.TimeRangeSent = timeRangeSent
			return searchResult, nil
		}
		return LogSearchResult{}, newRPCFailure(ErrorInfo{
			Kind:     ErrorKindResponse,
			Message:  fmt.Sprintf("FortiAnalyzer accepted the log search in ADOM %q but returned no task id: %s", request.ADOM, truncate(compactJSON(result), 300)),
			Resource: normalizePath("logview", "adom", request.ADOM, "logsearch"),
			Hint:     "The search cannot be polled without a task id. Check the FortiAnalyzer release and its Log View API; submitting again creates a new search.",
		}, nil)
	}
	c.rememberSearch(taskID, submittedSearch{request: request, filter: effectiveFilter, identity: identity, timeRangeSent: timeRangeSent, applianceZone: applianceZone})

	result, timedOut, err := c.pollLogSearch(ctx, request.ADOM, taskID, request.Limit, request.Offset)
	searchResult := logSearchResult(c.Name(), request, effectiveFilter, taskID, request.Offset, request.Limit, result, timedOut, warnings)
	searchResult.ApplianceTimezone = applianceZone
	searchResult.TimeRangeSent = timeRangeSent
	if err != nil {
		return searchResult, fmt.Errorf("FortiAnalyzer log search result for task %s in ADOM %q: %w", taskID, request.ADOM, err)
	}
	return searchResult, nil
}

// pollLogSearch polls until the search completes or the budget ends, with
// intervals growing from 0.5 s to 2 s. The budget is the caller's remaining
// deadline minus a reserve for encoding the answer. When the budget or the
// caller's deadline ends first, the search is reported as timed out (it
// keeps running on FortiAnalyzer and can be resumed by task ID) with the
// data of the last poll; only other failures are returned as errors.
func (c *FortiAnalyzer) pollLogSearch(ctx context.Context, adom, taskID string, limit, offset int) (any, bool, error) {
	budget := logSearchPollDefault
	if deadline, ok := ctx.Deadline(); ok {
		budget = time.Until(deadline) - logSearchPollReserve
	}
	if budget < logSearchPollFirst {
		budget = logSearchPollFirst
	}
	pollCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	param := []map[string]any{{
		"apiver": 3,
		"limit":  limit,
		"offset": offset,
		"url":    normalizePath("logview", "adom", adom, "logsearch", taskID),
	}}
	timedOut := func() bool {
		return !errors.Is(ctx.Err(), context.Canceled) && pollCtx.Err() != nil
	}
	var last any
	delay := logSearchPollFirst
	for {
		next, err := c.rpc.call(pollCtx, "get", param)
		if err != nil {
			if timedOut() {
				return last, true, nil
			}
			return last, false, err
		}
		last = next
		if _, _, complete := logSearchState(next); complete {
			return next, false, nil
		}
		if sleepContext(pollCtx, delay) != nil {
			if timedOut() {
				return last, true, nil
			}
			return last, false, ctx.Err()
		}
		delay = min(delay*2, logSearchPollMaximum)
	}
}

func logSearchResult(profile string, request LogSearchRequest, filter, taskID string, offset, matchBudget int, result any, timedOut bool, warnings []string) LogSearchResult {
	progress, totalCount, complete := logSearchState(result)
	records := logRecords(result)
	count := 0
	if rows, ok := records.([]any); ok {
		count = len(rows)
	}
	searchResult := LogSearchResult{
		Profile:    profile,
		ADOM:       request.ADOM,
		Device:     request.Device,
		LogType:    request.LogType,
		Filter:     filter,
		StartTime:  request.StartTime,
		EndTime:    request.EndTime,
		TaskID:     taskID,
		Count:      count,
		TotalCount: totalCount,
		Offset:     offset,
		Limit:      request.Limit,
		Progress:   progress,
		Complete:   complete,
		TimedOut:   timedOut,
		Warnings:   append([]string(nil), warnings...),
		Records:    records,
	}
	if !request.StartTime.IsZero() {
		searchResult.Timezone = timezoneLabel(request.StartTime)
	}
	switch {
	case timedOut && taskID != "":
		searchResult.Hint = fmt.Sprintf("The search is still running on FortiAnalyzer (%d%%). Call search_fortianalyzer_logs again with task_id=%q, the same profile and adom, and optional offset to continue; %d records were returned so far. Do not treat the missing records as absence yet.", progress, taskID, count)
	case complete && count == 0 && offset > 0:
		if matchBudget > 0 && offset >= matchBudget {
			searchResult.Hint = fmt.Sprintf("No records at offset %d. This task collected at most %d matches, the limit on the original submit, so the earlier pages of this task are complete. Further matches need a new search without task_id at offset %d, or one submit with a larger limit (up to %d) whose get is then paged with task_id.", offset, matchBudget, offset, maxLogSearchLimit)
		} else {
			searchResult.Hint = fmt.Sprintf("No records at offset %d: the search matched fewer records than that, so the earlier pages hold all of them.", offset)
		}
	case complete && count == 0:
		searchResult.Hint = "Zero records matched under this ADOM, device selector, filter and time range. Before concluding that traffic did not occur, verify the FortiAnalyzer ADOM and logged device name (get_log_receipt or get_fortianalyzer_data /logview/adom/<adom>/logstats shows each device's last log time where the release provides it), the filter field names (see /logview/adom/<adom>/logfields), log retention, and the time zone of the range."
	case complete && count >= request.Limit:
		next := offset + count
		if matchBudget > next {
			searchResult.Hint = fmt.Sprintf("This page is full (%d records) and the task was submitted with a larger match budget. Fetch the next page with task_id=%q and offset=%d.", count, taskID, next)
		} else {
			searchResult.Hint = fmt.Sprintf("This page filled the search budget (%d records). More records may match. Submit a new search without task_id and offset=%d, or submit once with a larger limit (up to %d) and page that task with task_id.", count, next, maxLogSearchLimit)
		}
	}
	return searchResult
}

func timezoneLabel(value time.Time) string {
	name, offset := value.Zone()
	if name == "" {
		name = "UTC"
	}
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	hours := offset / 3600
	minutes := (offset % 3600) / 60
	return fmt.Sprintf("%s (UTC%s%02d:%02d)", name, sign, hours, minutes)
}

// logSearchState reads a Log View answer's progress from its top level (or
// the single envelope around it). FortiAnalyzer reports status "succeeded"
// for every successful request, also while the search still runs, so only
// the percentage decides completion; the log records themselves (which can
// carry their own status fields) are never inspected. Releases that send
// no percentage return the finished page directly.
func logSearchState(result any) (progress, totalCount int, complete bool) {
	envelope := logSearchEnvelope(result)
	if envelope == nil {
		return 0, 0, false
	}
	value := field(envelope, "percentage", "progress", "progress-percent", "progress_percent")
	progress = min(max(intValue(value), 0), 100)
	totalCount = intValue(field(envelope, "total-count", "total_count", "total-lines", "total_lines", "total-logs", "total_logs", "matched-logs", "matched_logs"))
	if value != nil {
		return progress, totalCount, progress >= 100
	}
	return progress, totalCount, field(envelope, "data", "logs") != nil
}

func logSearchEnvelope(result any) map[string]any {
	switch typed := result.(type) {
	case map[string]any:
		if field(typed, "percentage", "progress", "data", "logs") == nil {
			if nested := field(typed, "result", "payload"); nested != nil {
				return logSearchEnvelope(nested)
			}
		}
		return typed
	case []any:
		if len(typed) == 1 {
			return logSearchEnvelope(typed[0])
		}
	}
	return nil
}

// logViewRequestOptions are JSON-RPC get parameters, sent next to url. Other
// keys of a read's data form the request body.
var logViewRequestOptions = map[string]bool{
	"fields": true, "filter": true, "loadsub": true, "option": true, "range": true, "sortings": true,
	"limit": true, "offset": true, "meta fields": true, "expand member": true,
}

func (c *FortiAnalyzer) Read(ctx context.Context, resource string, data map[string]any) (any, error) {
	if adom, ok := resourceADOM(resource); ok {
		if err := c.validateADOM(adom); err != nil {
			return nil, err
		}
	}
	param := map[string]any{
		"url": normalizeRPCPath(resource),
	}
	apiV3 := requiresAPIV3([]map[string]any{param})
	if apiV3 {
		param["apiver"] = 3
	}
	body := make(map[string]any)
	for key, value := range data {
		if key == "url" || key == "apiver" {
			continue
		}
		if apiV3 || logViewRequestOptions[key] {
			param[key] = value
			continue
		}
		// Legacy FortiAnalyzer resources take other request values in a
		// nested data object; request options stay next to url.
		body[key] = value
	}
	if len(body) > 0 {
		param["data"] = body
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{param})
	if err != nil {
		return nil, fmt.Errorf("FortiAnalyzer read %s: %w", resource, err)
	}
	if strings.Contains(strings.ToLower(resource), "/logsearch/") {
		// A search's progress, counts and records belong together: an empty
		// record list alone would look like a finished search without matches.
		return result, nil
	}
	return dataFromResult(result), nil
}

func (c *FortiAnalyzer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.rpc.logout(ctx)
}

func taskID(result any) string {
	if record, ok := result.(map[string]any); ok {
		if value := field(record, "tid", "task_id", "taskid", "id"); value != nil {
			return stringValueValue(value)
		}
		if data := field(record, "data", "result"); data != nil {
			if value := taskID(data); value != "" {
				return value
			}
		}
	}
	if records, ok := result.([]any); ok {
		for _, record := range records {
			if value := taskID(record); value != "" {
				return value
			}
		}
	}
	return ""
}

// logRecords returns the page of log rows. dataFromResult unwraps data,
// payload, records, results and items. Some releases put the same array
// under logs, which completion already notices when percentage is absent.
func logRecords(result any) any {
	records := dataFromResult(result)
	if rows, ok := records.([]any); ok && len(rows) > 0 {
		return records
	}
	if envelope := logSearchEnvelope(result); envelope != nil {
		if logs := field(envelope, "logs"); logs != nil {
			return logs
		}
	}
	return records
}

func countFromResult(result any) int {
	// Total matches describe the whole search, not the returned page.
	if records, ok := logRecords(result).([]any); ok {
		return len(records)
	}
	return 0
}

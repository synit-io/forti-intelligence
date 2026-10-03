package fortinet

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// subObject returns a FortiManager sub-table that may be encoded as a map or
// as a single-element list.
func subObject(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case []any:
		for _, item := range typed {
			if record, ok := item.(map[string]any); ok {
				return record
			}
		}
	}
	return nil
}

// webFilterScope validates the ADOM and returns the object path prefix. An
// empty ADOM selects the global ADOM, which holds shared objects that global
// policy packages and ADOM assignments refer to.
func (c *FortiManager) webFilterScope(adom string) ([]string, error) {
	if strings.TrimSpace(adom) == "" {
		return []string{"pm", "config", "global", "obj"}, nil
	}
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	return []string{"pm", "config", "adom", adom, "obj"}, nil
}

func scopeLabel(adom string) string {
	if strings.TrimSpace(adom) == "" {
		return "global ADOM"
	}
	return fmt.Sprintf("ADOM %q", adom)
}

func categoryReferenceString(value any) string {
	switch typed := value.(type) {
	case []any:
		if len(typed) > 0 {
			return categoryReferenceString(typed[0])
		}
		return ""
	case []string:
		if len(typed) > 0 {
			return typed[0]
		}
		return ""
	case float64:
		return strconv.Itoa(int(typed))
	case int:
		return strconv.Itoa(typed)
	default:
		return strings.TrimSpace(stringValueValue(typed))
	}
}

func (c *FortiManager) ListWebFilterProfiles(ctx context.Context, adom string) ([]WebFilterProfile, error) {
	prefix, err := c.webFilterScope(adom)
	if err != nil {
		return nil, err
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		"url":     normalizePath(append(prefix, "webfilter", "profile")...),
		"loadsub": 1,
	}})
	if err != nil {
		return nil, fmt.Errorf("list web filter profiles in %s: %w", scopeLabel(adom), err)
	}
	return parseWebFilterProfiles(result), nil
}

func parseWebFilterProfiles(result any) []WebFilterProfile {
	records := recordMaps(result)
	profiles := make([]WebFilterProfile, 0, len(records))
	for _, record := range records {
		name := stringValueValue(field(record, "name", "mkey"))
		if name == "" {
			continue
		}
		profile := WebFilterProfile{
			Name:           name,
			Comment:        stringValueValue(field(record, "comment", "comments")),
			InspectionMode: stringValueValue(field(record, "inspection-mode", "inspection_mode")),
			FeatureSet:     stringValueValue(field(record, "feature-set", "feature_set")),
			Raw:            record,
		}
		if ftgd := subObject(field(record, "ftgd-wf", "ftgd_wf")); ftgd != nil {
			profile.FortiGuardOptions = stringSlice(field(ftgd, "options"))
			for _, option := range profile.FortiGuardOptions {
				if strings.EqualFold(strings.TrimSpace(option), "ftgd-disable") {
					profile.FortiGuardDisabled = true
				}
			}
			for _, entry := range recordMaps(field(ftgd, "filters")) {
				profile.Filters = append(profile.Filters, CategoryFilter{
					ID:            intValue(field(entry, "id")),
					Category:      categoryReferenceString(field(entry, "category")),
					Action:        strings.ToLower(strings.TrimSpace(stringValueValue(field(entry, "action")))),
					Log:           boolValue(field(entry, "log")),
					WarningPrompt: stringValueValue(field(entry, "warning-prompt", "warning_prompt")),
					AuthGroups:    stringSlice(field(entry, "auth-usr-grp", "auth_usr_grp")),
				})
			}
		}
		if web := subObject(field(record, "web")); web != nil {
			profile.URLFilterTable = firstStringValue(field(web, "urlfilter-table", "urlfilter_table"))
		}
		if profile.URLFilterTable == "" {
			// Older schemas keep the table reference on the profile itself.
			profile.URLFilterTable = firstStringValue(field(record, "urlfilter-table", "urlfilter_table"))
		}
		profiles = append(profiles, profile)
	}
	return profiles
}

func (c *FortiManager) ListURLFilterTables(ctx context.Context, adom string) ([]URLFilterTable, error) {
	prefix, err := c.webFilterScope(adom)
	if err != nil {
		return nil, err
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		"url":     normalizePath(append(prefix, "webfilter", "urlfilter")...),
		"loadsub": 1,
	}})
	if err != nil {
		return nil, fmt.Errorf("list URL filter tables in %s: %w", scopeLabel(adom), err)
	}
	return parseURLFilterTables(result), nil
}

func parseURLFilterTables(result any) []URLFilterTable {
	records := recordMaps(result)
	tables := make([]URLFilterTable, 0, len(records))
	for _, record := range records {
		table := URLFilterTable{
			ID:      intValue(field(record, "id")),
			Name:    stringValueValue(field(record, "name", "mkey")),
			Comment: stringValueValue(field(record, "comment", "comments")),
		}
		if table.Name == "" && table.ID == 0 {
			continue
		}
		for _, entry := range recordMaps(field(record, "entries")) {
			table.Entries = append(table.Entries, URLFilterEntry{
				ID:           intValue(field(entry, "id")),
				URL:          strings.TrimSpace(stringValueValue(field(entry, "url"))),
				Type:         strings.ToLower(strings.TrimSpace(stringValueValue(field(entry, "type")))),
				Action:       strings.ToLower(strings.TrimSpace(stringValueValue(field(entry, "action")))),
				Status:       strings.ToLower(strings.TrimSpace(stringValueValue(field(entry, "status")))),
				ReferrerHost: stringValueValue(field(entry, "referrer-host", "referrer_host")),
				Exempt:       stringSlice(field(entry, "exempt")),
			})
		}
		tables = append(tables, table)
	}
	return tables
}

func (c *FortiManager) ListLocalRatings(ctx context.Context, adom string) ([]LocalRating, error) {
	prefix, err := c.webFilterScope(adom)
	if err != nil {
		return nil, err
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		"url": normalizePath(append(prefix, "webfilter", "ftgd-local-rating")...),
	}})
	if err != nil {
		return nil, fmt.Errorf("list FortiGuard local ratings in %s: %w", scopeLabel(adom), err)
	}
	return parseLocalRatings(result), nil
}

func parseLocalRatings(result any) []LocalRating {
	records := recordMaps(result)
	ratings := make([]LocalRating, 0, len(records))
	for _, record := range records {
		target := strings.TrimSpace(stringValueValue(field(record, "url", "name", "mkey")))
		if target == "" {
			continue
		}
		ratings = append(ratings, LocalRating{
			URL:     target,
			Rating:  stringSlice(field(record, "rating")),
			Status:  strings.ToLower(strings.TrimSpace(stringValueValue(field(record, "status")))),
			Comment: stringValueValue(field(record, "comment", "comments")),
		})
	}
	return ratings
}

func (c *FortiManager) ListLocalCategories(ctx context.Context, adom string) ([]LocalCategory, error) {
	prefix, err := c.webFilterScope(adom)
	if err != nil {
		return nil, err
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		"url": normalizePath(append(prefix, "webfilter", "ftgd-local-cat")...),
	}})
	if err != nil {
		return nil, fmt.Errorf("list FortiGuard local categories in %s: %w", scopeLabel(adom), err)
	}
	return parseLocalCategories(result), nil
}

func parseLocalCategories(result any) []LocalCategory {
	records := recordMaps(result)
	categories := make([]LocalCategory, 0, len(records))
	for _, record := range records {
		id := intValue(field(record, "id"))
		description := stringValueValue(field(record, "desc", "description", "name"))
		if id == 0 && description == "" {
			continue
		}
		categories = append(categories, LocalCategory{
			ID:          id,
			Description: description,
			Status:      strings.ToLower(strings.TrimSpace(stringValueValue(field(record, "status")))),
		})
	}
	return categories
}

func (c *FortiManager) ListProfileGroups(ctx context.Context, adom string) ([]ProfileGroup, error) {
	prefix, err := c.webFilterScope(adom)
	if err != nil {
		return nil, err
	}
	resource := normalizePath(append(prefix, "firewall", "profile-group")...)
	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		"url":    resource,
		"fields": []string{"name", "webfilter-profile"},
	}})
	if err != nil && DescribeError(err).Kind == ErrorKindInvalid && ctx.Err() == nil {
		result, err = c.rpc.call(ctx, "get", []map[string]any{{"url": resource}})
	}
	if err != nil {
		return nil, fmt.Errorf("list security profile groups in %s: %w", scopeLabel(adom), err)
	}
	return parseProfileGroups(result), nil
}

func parseProfileGroups(result any) []ProfileGroup {
	records := recordMaps(result)
	groups := make([]ProfileGroup, 0, len(records))
	for _, record := range records {
		name := stringValueValue(field(record, "name", "mkey"))
		if name == "" {
			continue
		}
		groups = append(groups, ProfileGroup{
			Name:             name,
			WebFilterProfile: firstStringValue(field(record, "webfilter-profile", "webfilter_profile")),
		})
	}
	return groups
}

// WebFilterObjects is the web filter configuration of one ADOM, or of the
// global ADOM, read in one multiplexed request. Errors holds the tables
// that failed, keyed by stage name (for example list_urlfilter_tables).
type WebFilterObjects struct {
	Profiles        []WebFilterProfile
	URLFilterTables []URLFilterTable
	LocalRatings    []LocalRating
	LocalCategories []LocalCategory
	ProfileGroups   []ProfileGroup
	// Categories is FortiManager's stored FortiGuard catalogue (ADOM only);
	// its failure is optional and reported under list_fortiguard_categories.
	Categories map[int]string
	Errors     map[string]error
}

// ReadWebFilterObjects reads the web filter profiles, URL filter tables,
// local ratings and categories, security profile groups and (for an ADOM)
// the FortiGuard category catalogue in one request; all tables share the
// /pm/config prefix. An empty adom reads the global ADOM, which holds only
// profiles, URL filter tables and profile groups that ADOMs refer to.
func (c *FortiManager) ReadWebFilterObjects(ctx context.Context, adom string) WebFilterObjects {
	objects := WebFilterObjects{Errors: make(map[string]error)}
	prefix, err := c.webFilterScope(adom)
	type table struct {
		stage string
		param map[string]any
	}
	path := func(parts ...string) string {
		return normalizePath(append(append([]string(nil), prefix...), parts...)...)
	}
	tables := []table{
		{"list_webfilter_profiles", map[string]any{"url": path("webfilter", "profile"), "loadsub": 1}},
		{"list_urlfilter_tables", map[string]any{"url": path("webfilter", "urlfilter"), "loadsub": 1}},
		{"list_profile_groups", map[string]any{"url": path("firewall", "profile-group"), "fields": []string{"name", "webfilter-profile"}}},
	}
	if strings.TrimSpace(adom) != "" {
		tables = append(tables,
			table{"list_local_ratings", map[string]any{"url": path("webfilter", "ftgd-local-rating")}},
			table{"list_local_categories", map[string]any{"url": path("webfilter", "ftgd-local-cat")}},
			table{"list_fortiguard_categories", map[string]any{"url": path("webfilter", "categories")}},
		)
	}
	if err != nil {
		for _, entry := range tables {
			objects.Errors[entry.stage] = err
		}
		return objects
	}
	params := make([]map[string]any, len(tables))
	for index, entry := range tables {
		params[index] = entry.param
	}
	items, batchErr := c.callBatchReads(ctx, adom, params, false)
	for index, entry := range tables {
		value, itemErr := any(nil), batchErr
		if itemErr == nil {
			if index < len(items) {
				value, itemErr = items[index].Value, items[index].Err
			} else {
				itemErr = newRPCFailure(ErrorInfo{Kind: ErrorKindResponse, Message: "FortiManager returned no batch item", Resource: entry.param["url"].(string)}, nil)
			}
		}
		if itemErr != nil && entry.stage == "list_profile_groups" && DescribeError(itemErr).Kind == ErrorKindInvalid && ctx.Err() == nil {
			// Releases that reject the field projection answer the full read.
			value, itemErr = c.rpc.call(ctx, "get", []map[string]any{{"url": entry.param["url"]}})
		}
		if itemErr != nil {
			objects.Errors[entry.stage] = fmt.Errorf("%s in %s: %w", strings.ReplaceAll(strings.TrimPrefix(entry.stage, "list_"), "_", " "), scopeLabel(adom), itemErr)
			continue
		}
		switch entry.stage {
		case "list_webfilter_profiles":
			objects.Profiles = parseWebFilterProfiles(value)
		case "list_urlfilter_tables":
			objects.URLFilterTables = parseURLFilterTables(value)
		case "list_profile_groups":
			objects.ProfileGroups = parseProfileGroups(value)
		case "list_local_ratings":
			objects.LocalRatings = parseLocalRatings(value)
		case "list_local_categories":
			objects.LocalCategories = parseLocalCategories(value)
		case "list_fortiguard_categories":
			objects.Categories = parseCategoryNames(value)
		}
	}
	return objects
}

// ListFortiGuardCategories reads FortiManager's stored category catalogue.
// Releases that expose only ids yield an empty map, which callers treat as
// "no names available" rather than as a failure.
func (c *FortiManager) ListFortiGuardCategories(ctx context.Context, adom string) (map[int]string, error) {
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		"url": normalizePath("pm", "config", "adom", adom, "obj", "webfilter", "categories"),
	}})
	if err != nil {
		return nil, fmt.Errorf("list FortiGuard categories in ADOM %q: %w", adom, err)
	}
	return parseCategoryNames(result), nil
}

// ListFortiGateCategories reads the live FortiGuard category catalogue from a
// managed FortiGate through the FortiManager proxy.
func (c *FortiManager) ListFortiGateCategories(ctx context.Context, adom, device, vdom string) (map[int]string, error) {
	result, err := c.ProxyGet(ctx, adom, device, vdom, "/api/v2/monitor/webfilter/fortiguard-categories")
	if err != nil {
		return nil, err
	}
	names := parseCategoryNames(result.Data)
	if len(names) == 0 {
		return nil, fmt.Errorf("FortiGate %s/%s returned no FortiGuard category names from %s", adom, device, result.Resource)
	}
	return names, nil
}

func parseCategoryNames(result any) map[int]string {
	names := make(map[int]string)
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			idValue := field(typed, "id", "category", "cat", "category_id", "category-id")
			name := strings.TrimSpace(stringValueValue(field(typed, "name", "desc", "description", "category_name", "category-name", "categoryname", "catdesc")))
			if idValue != nil && name != "" {
				if id, ok := ParseCategoryReference(idValue); ok {
					names[id] = name
					return
				}
			}
			for key, child := range typed {
				if strings.EqualFold(key, "id") {
					continue
				}
				walk(child)
			}
		}
	}
	walk(dataFromResult(result))
	return names
}

// RatingProxyTimeoutSeconds bounds how long FortiManager waits for the
// FortiGate's FortiGuard answer. A FortiGate that cannot reach FortiGuard
// otherwise holds the proxy request for FortiManager's 60s default.
const RatingProxyTimeoutSeconds = 20

type ratingForm struct {
	label   string
	action  string
	path    string
	payload map[string]any
}

// ratingForms lists the FortiOS rating lookup request forms in preference
// order. FortiOS 7.4 answers GET on .../utm/rating-lookup with HTTP 405
// (no action); monitor reads use the "select" action. The GET forms work
// with a read-only FortiManager JSON API account. POST needs an account that
// may send request bodies through the proxy and is tried last.
func ratingForms(target string) []ratingForm {
	plain := url.Values{}
	plain.Set("url", target)
	array := url.Values{}
	array.Set("url", `["`+strings.ReplaceAll(target, `"`, ``)+`"]`)
	// FortiOS 7.4 answers only POST (GET returns HTTP 405). The GET forms
	// stay as a fallback for accounts FortiManager refuses POST for, on
	// releases that still answer GET.
	return []ratingForm{
		{"POST select", "post", "/api/v2/monitor/utm/rating-lookup/select", map[string]any{"url": []string{target}, "lang": "en"}},
		{"GET select url", "get", "/api/v2/monitor/utm/rating-lookup/select?" + plain.Encode(), nil},
		{"GET select url[]", "get", "/api/v2/monitor/utm/rating-lookup/select?" + array.Encode(), nil},
	}
}

// LookupURLRating asks a managed FortiGate for the live FortiGuard category
// of one URL through the FortiManager proxy. The form the FortiGate answered
// last is tried first; a proxied POST refused by FortiManager is skipped
// until the permission block expires.
func (c *FortiManager) LookupURLRating(ctx context.Context, adom, device, vdom, target string) (URLRating, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return URLRating{}, fmt.Errorf("url is required for a FortiGuard rating lookup")
	}
	c.ratingMu.Lock()
	blockedUntil, blockedErr := c.ratingBlockedUntil, c.ratingBlockedErr
	if blockedErr != nil && !time.Now().Before(blockedUntil) {
		// The block expired: ask again, POST included, in case the account
		// was changed or the refusal was transient.
		c.ratingBlockedErr, blockedErr = nil, nil
		c.ratingPostDenied.Store(false)
	}
	c.ratingMu.Unlock()
	if blockedErr != nil {
		return URLRating{URL: target}, compactFailure(fmt.Sprintf("FortiGuard rating through FortiManager is unavailable for this API account (found %s ago, checked again after %s)", time.Since(blockedUntil.Add(-ratingBlockTTL)).Round(time.Second), blockedUntil.Format(time.RFC3339)), blockedErr, "")
	}
	forms := ratingForms(target)
	order := make([]int, 0, len(forms))
	if known := int(c.ratingForm.Load()) - 1; known >= 0 && known < len(forms) {
		order = append(order, known)
	}
	for index := range forms {
		if len(order) == 0 || order[0] != index {
			order = append(order, index)
		}
	}
	var failures []string
	var lastErr error
	postRefused, methodRejected, rejectedStatus := c.ratingPostDenied.Load(), false, 0
	for _, index := range order {
		form := forms[index]
		if form.action == "post" && c.ratingPostDenied.Load() {
			failures = append(failures, form.label+": skipped, refused earlier by FortiManager")
			continue
		}
		result, err := c.proxyCallTimeout(ctx, adom, device, vdom, form.action, form.path, form.payload, RatingProxyTimeoutSeconds)
		if err == nil {
			// The FortiGate answered this form: try it first next time,
			// whether or not the answer carries a category.
			c.ratingForm.Store(int32(index + 1))
			rating := parseURLRating(target, result)
			if len(rating.CategoryIDs) > 0 || len(rating.CategoryNames) > 0 {
				return rating, nil
			}
			// Quote the answer so the agent can read the category itself
			// and an unknown response format is visible at once.
			failures = append(failures, form.label+": FortiGate answered without a recognised category: "+ratingResponseExcerpt(result.Data))
			lastErr = newRPCFailure(ErrorInfo{
				Kind:     ErrorKindResponse,
				Message:  "no category in the " + form.label + " answer",
				Resource: form.path,
				Hint:     "The FortiGate answered the rating lookup, but the MCP server found no category in the quoted response. If the response names a category, pass it to check_web_filter as category; otherwise treat the rating as unknown and compare with scripts/fmg-rating-check.sh step 5.",
			}, nil)
			// The other forms return the same FortiGuard answer.
			break
		}
		lastErr = err
		failures = append(failures, form.label+": "+shortErrorReason(err))
		kind := DescribeError(err).Kind
		if form.action == "post" && kind == ErrorKindPermission {
			c.ratingPostDenied.Store(true)
			postRefused = true
			continue
		}
		if kind == ErrorKindInvalid {
			methodRejected = true
			if status := DescribeError(err).FortiGateStatus; status != 0 {
				rejectedStatus = status
			}
		}
		if ctx.Err() != nil || kind == ErrorKindPermission || kind == ErrorKindAuth || kind == ErrorKindDeviceUnavailable || kind == ErrorKindTimeout {
			break
		}
	}
	summary := fmt.Sprintf("FortiGuard rating lookup for %q via %s/%s failed (%s)", target, adom, device, strings.Join(failures, "; "))
	if postRefused && methodRejected {
		// The FortiGate accepts only POST and FortiManager refuses to proxy
		// POST for this account: no device can do better, so report it as a
		// permission boundary and stop repeating the calls for a while.
		info := DescribeError(lastErr)
		info.Kind, info.Retryable = ErrorKindPermission, false
		info.Message = summary
		if rejectedStatus != 0 {
			info.FortiGateStatus = rejectedStatus
		}
		info.Hint = "FortiOS accepts the FortiGuard rating lookup only as POST, and FortiManager refuses proxied POST requests for this read-only API account. Configure a dedicated rating account (rating.api_key or rating.username/password: a FortiManager API administrator with JSON API Read-Write and an otherwise read-only admin profile), or pass the category to check_web_filter directly."
		blocked := &rpcFailure{info: info, cause: lastErr}
		c.ratingMu.Lock()
		c.ratingBlockedUntil, c.ratingBlockedErr = time.Now().Add(ratingBlockTTL), blocked
		c.ratingMu.Unlock()
		return URLRating{URL: target}, blocked
	}
	return URLRating{URL: target}, compactFailure(summary, lastErr, "")
}

var ratingCategoryKeys = []string{"category", "categories", "cat", "category_id", "category-id", "categoryid", "rating", "ratings"}
var ratingNameKeys = []string{"categoryname", "category_name", "category-name", "catdesc", "category_desc", "category_description"}

// parseURLRating walks the proxied FortiOS body (usually wrapped in the
// FortiManager proxy "response" envelope) and collects category ids and
// names. Every lookup asks for exactly one URL, so every record belongs to
// it; records are not filtered by URL because FortiOS may echo the URL in
// another form (for example as the requested list). A category FortiOS
// names but the static table does not know is kept as a name so the caller
// can resolve it through the FortiGate's category list.
func parseURLRating(target string, result ProxyResult) URLRating {
	rating := URLRating{URL: target, Resource: result.Resource, Raw: result.Data}
	ids := make(map[int]struct{})
	names := make(map[string]struct{})
	addName := func(value any) {
		if name := strings.TrimSpace(stringValueValue(value)); name != "" {
			names[name] = struct{}{}
		}
	}
	addCategory := func(value any) {
		if id, ok := ParseCategoryReference(value); ok {
			// Negative ids mark a failed lookup, not a category.
			if id >= 0 {
				ids[id] = struct{}{}
			}
			return
		}
		if text, ok := value.(string); ok {
			addName(text)
		}
	}
	var collect func(any)
	collect = func(value any) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				collect(item)
			}
		case map[string]any:
			if id := field(typed, "id", "category", "cat", "category_id", "category-id", "categoryid"); id != nil {
				addCategory(id)
			}
			addName(field(typed, "categoryname", "category_name", "category-name", "catdesc", "category_desc", "name"))
		case nil:
		default:
			addCategory(typed)
		}
	}
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			found := false
			for _, key := range ratingCategoryKeys {
				if value := field(typed, key); value != nil {
					found = true
					collect(value)
				}
			}
			if name := field(typed, ratingNameKeys...); name != nil {
				found = true
				addName(name)
			}
			if found {
				return
			}
			for key, child := range typed {
				if strings.EqualFold(key, "status") {
					continue
				}
				walk(child)
			}
		}
	}
	walk(result.Data)
	rating.CategoryIDs = SortedCategoryIDs(ids)
	for name := range names {
		rating.CategoryNames = append(rating.CategoryNames, name)
	}
	sort.Strings(rating.CategoryNames)
	return rating
}

// ratingResponseExcerpt returns the FortiOS answer without the FortiManager
// proxy envelope, shortened for an error message.
func ratingResponseExcerpt(data any) string {
	body := data
	if items, ok := body.([]any); ok && len(items) == 1 {
		body = items[0]
	}
	if item, ok := body.(map[string]any); ok {
		if response := field(item, "response"); response != nil {
			body = response
		}
	}
	return truncate(compactJSON(body), 500)
}

package service

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

// ratingAttemptTimeout bounds one rating attempt (one FortiGate), slightly
// above the FortiManager proxy timeout, so a silent FortiGate cannot hold the
// whole lookup.
var ratingAttemptTimeout = time.Duration(fortinet.RatingProxyTimeoutSeconds+5) * time.Second

const (
	webFilterConfigTTL    = 5 * time.Minute
	fortiGateCategoryTTL  = time.Hour
	maxPackageStatusReads = 48
)

// RateURLInput asks for the live FortiGuard category of one URL.
type RateURLInput struct {
	URL     string `json:"url" jsonschema:"Web address to rate, for example https://www.example.com/path or example.com. Host and path are rated; the site is never fetched."`
	Profile string `json:"profile,omitempty" jsonschema:"FortiManager profile name. The default FortiManager profile is used when omitted."`
	ADOM    string `json:"adom,omitempty" jsonschema:"ADOM of the device; resolved from inventory when omitted."`
	Device  string `json:"device,omitempty" jsonschema:"FortiGate that filters the user's web traffic (trace the client with resolve_ip_ownership and resolve_route). Used when the server has no dedicated rating FortiGate configured, or as fallback. Without device and without a configured rating FortiGate no rating is made."`
	VDOM    string `json:"vdom,omitempty" jsonschema:"VDOM for the rating lookup; root when omitted."`
}

// RateURLOutput is the FortiGuard category of a URL and how it was obtained.
type RateURLOutput struct {
	Query    RateURLInput   `json:"query"`
	Host     string         `json:"host"`
	Path     string         `json:"path,omitempty"`
	Rating   RatingEvidence `json:"rating"`
	NextStep string         `json:"next_step,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
}

// CheckWebFilterInput asks which web filter profiles block or allow a
// FortiGuard category, optionally for a concrete URL.
type CheckWebFilterInput struct {
	Category string `json:"category,omitempty" jsonschema:"FortiGuard category id or name from rate_url, for example 52 or Information Technology; several as a comma-separated list. Optional when url is given, then category actions are reported as unknown."`
	URL      string `json:"url,omitempty" jsonschema:"The URL itself. Enables static URL filter entries and FortiGuard local rating overrides, which match the URL rather than its category. Pass it whenever the question is about a concrete site."`
	Profile  string `json:"profile,omitempty" jsonschema:"FortiManager profile name. The default FortiManager profile is used when omitted."`
	ADOM     string `json:"adom,omitempty" jsonschema:"Limit evaluation to one ADOM. All inventoried ADOMs of the profile are evaluated when omitted and no device is given."`
	Device   string `json:"device,omitempty" jsonschema:"FortiGate that filters the user's web traffic. Only the policy packages assigned to it are read, and results are limited to profiles applied on it."`
	VDOM     string `json:"vdom,omitempty" jsonschema:"Limit results to this VDOM of the device."`
	PolicyID int    `json:"policy_id,omitempty" jsonschema:"Firewall policy that carries the user's traffic on device (for example from lookup_firewall_policy): only the web filter profile it applies is evaluated. Requires device."`
}

// ratingScope names the device a rating is requested for.
type ratingScope struct {
	Device, ADOM, VDOM string
}

type CategoryRef struct {
	ID         int    `json:"id"`
	Name       string `json:"name,omitempty"`
	Group      string `json:"group,omitempty"`
	NameSource string `json:"name_source,omitempty"`
}

type RatingEvidence struct {
	Source       string              `json:"source"`
	Profile      string              `json:"profile,omitempty"`
	ADOM         string              `json:"adom,omitempty"`
	Device       string              `json:"device,omitempty"`
	VDOM         string              `json:"vdom,omitempty"`
	Resource     string              `json:"resource,omitempty"`
	Categories   []CategoryRef       `json:"categories,omitempty"`
	Error        string              `json:"error,omitempty"`
	ErrorDetails *fortinet.ErrorInfo `json:"error_details,omitempty"`
	Attempts     []string            `json:"attempted_devices,omitempty"`
	// AttemptErrors holds one short line per failed or skipped source.
	AttemptErrors []string `json:"attempt_errors,omitempty"`
	// Selection says why the rating FortiGate was used (configured rating
	// device or requested device); Account names the FortiManager account.
	Selection string `json:"selection,omitempty"`
	Account   string `json:"account,omitempty"`
	// RatedAt is when the FortiGate rated the URL; Cached marks a rating
	// reused from an earlier call within ratingCacheTTL.
	RatedAt time.Time `json:"rated_at"`
	Cached  bool      `json:"cached,omitempty"`
}

// ratingCacheTTL bounds how long a live FortiGuard rating is reused.
// Categories change rarely; a recategorisation request shows up after
// this time or after refresh_inventory.
const ratingCacheTTL = 15 * time.Minute

type ratingCacheEntry struct {
	created  time.Time
	evidence RatingEvidence
}

type CategoryFilterEvidence struct {
	EntryID  int    `json:"entry_id,omitempty"`
	Category string `json:"category"`
	Action   string `json:"action"`
	ViaGroup string `json:"via_group,omitempty"`
	Implicit bool   `json:"implicit,omitempty"`
}

type URLFilterEvidence struct {
	Table   string   `json:"table"`
	EntryID int      `json:"entry_id"`
	Pattern string   `json:"pattern"`
	Type    string   `json:"type"`
	Action  string   `json:"action"`
	Exempt  []string `json:"exempt,omitempty"`
}

type LocalRatingEvidence struct {
	URL        string        `json:"url"`
	Categories []CategoryRef `json:"categories"`
}

type WebFilterPolicyUsage struct {
	Package       string                   `json:"package"`
	Table         string                   `json:"table"`
	PolicyID      int                      `json:"policy_id"`
	Name          string                   `json:"name,omitempty"`
	Action        string                   `json:"action,omitempty"`
	Via           string                   `json:"via"`
	SSLSSHProfile string                   `json:"ssl_ssh_profile,omitempty"`
	InstallOn     []fortinet.PackageMember `json:"install_on,omitempty"`
	Devices       []string                 `json:"devices,omitempty"`
	devices       []WebFilterDevice
}

// WebFilterDevice is one device VDOM that receives a profile through a
// policy package, with FortiManager's stored synchronization state.
type WebFilterDevice struct {
	Device           string `json:"device"`
	VDOM             string `json:"vdom,omitempty"`
	Package          string `json:"package"`
	PackageStatus    string `json:"package_status,omitempty"`
	ConfigStatus     string `json:"config_status,omitempty"`
	ConnectionStatus string `json:"connection_status,omitempty"`
}

type WebFilterProfileResult struct {
	Profile             string                   `json:"profile"`
	ADOM                string                   `json:"adom"`
	Source              string                   `json:"source"`
	Manager             string                   `json:"fortimanager_profile"`
	Decision            string                   `json:"decision"`
	Reason              string                   `json:"reason"`
	CategorySource      string                   `json:"category_source,omitempty"`
	EffectiveCategories []CategoryRef            `json:"effective_categories,omitempty"`
	FortiGuardFiltering string                   `json:"fortiguard_filtering"`
	CategoryFilters     []CategoryFilterEvidence `json:"category_filters,omitempty"`
	URLFilter           *URLFilterEvidence       `json:"url_filter,omitempty"`
	URLFilterTable      string                   `json:"url_filter_table,omitempty"`
	LocalRating         *LocalRatingEvidence     `json:"local_rating,omitempty"`
	InspectionMode      string                   `json:"inspection_mode,omitempty"`
	Policies            []WebFilterPolicyUsage   `json:"policies,omitempty"`
	Devices             []WebFilterDevice        `json:"devices,omitempty"`
	Warnings            []string                 `json:"warnings,omitempty"`
}

type WebFilterSummary struct {
	Blocked           []string `json:"blocked"`
	Allowed           []string `json:"allowed"`
	Conditional       []string `json:"conditional"`
	Unknown           []string `json:"unknown"`
	UnusedProfiles    []string `json:"unused_profiles,omitempty"`
	NotOnDevice       []string `json:"not_on_device,omitempty"`
	ProfilesEvaluated int      `json:"profiles_evaluated"`
	PackagesEvaluated int      `json:"packages_evaluated"`
	PoliciesEvaluated int      `json:"policies_evaluated"`
}

type WebFilterCheckOutput struct {
	Query       CheckWebFilterInput      `json:"query"`
	Host        string                   `json:"host,omitempty"`
	Path        string                   `json:"path,omitempty"`
	Categories  []CategoryRef            `json:"categories,omitempty"`
	SnapshotAt  time.Time                `json:"inventory_snapshot_at"`
	Profiles    []WebFilterProfileResult `json:"profiles"`
	Summary     WebFilterSummary         `json:"summary"`
	Errors      []inventory.RefreshError `json:"errors,omitempty"`
	Warnings    []string                 `json:"warnings,omitempty"`
	Limitations []string                 `json:"limitations"`
	// Complete is false when the response budget ended before every ADOM's
	// configuration was read; repeating the check shortly returns the rest,
	// because the reads continue into the cache.
	Complete bool `json:"complete"`
}

// webFilterConfig is one ADOM's (or the global ADOM's) stored web filter
// configuration. Global entries carry no packages or policies.
type webFilterConfig struct {
	created       time.Time
	profiles      []fortinet.WebFilterProfile
	tables        []fortinet.URLFilterTable
	localRatings  []fortinet.LocalRating
	localCategory []fortinet.LocalCategory
	groups        []fortinet.ProfileGroup
	packages      []fortinet.PolicyPackage
	// policies maps policy table (policy, policy6, security-policy,
	// proxy-policy) to package name to policies.
	policies       map[string]map[string][]fortinet.FirewallPolicy
	fmgCategories  map[int]string
	errors         []inventory.RefreshError
	warnings       []string
	packagesFailed bool
	// usagePending marks a per-call view whose policy reads are still
	// running; profile decisions are valid but usage is not known yet.
	usagePending bool
}

// webFilterLoad is one background read of an ADOM's configuration and the
// policies of the packages in scope. Concurrent lookups share it, and its
// results land in the caches even when the caller stopped waiting.
type webFilterLoad struct {
	epoch       uint64
	configReady chan struct{}
	done        chan struct{}
	config      *webFilterConfig
	policies    policySet
}

// policySet holds the policies of the packages in scope, per policy table.
type policySet struct {
	tables   map[string]map[string][]fortinet.FirewallPolicy
	packages []fortinet.PolicyPackage
	failed   bool
	errors   []inventory.RefreshError
	warnings []string
}

// policyTables lists the tables that can apply a web filter profile, in
// reporting order.
var policyTableNames = []string{"policy", "policy6", "security-policy", "proxy-policy"}

func (c *webFilterConfig) policyCount() int {
	count := 0
	for _, packages := range c.policies {
		for _, policies := range packages {
			count += len(policies)
		}
	}
	return count
}

type fortiGateCategoryEntry struct {
	created time.Time
	names   map[int]string
}

type packageStatusEntry struct {
	created time.Time
	status  fortinet.PackageStatus
	found   bool
}

type webFilterCaches struct {
	mu         sync.Mutex
	loads      map[string]*webFilterLoad
	config     map[string]*webFilterConfig
	categories map[string]fortiGateCategoryEntry
	status     map[string]packageStatusEntry
	ratings    map[string]ratingCacheEntry
}

func newWebFilterCaches() *webFilterCaches {
	return &webFilterCaches{loads: make(map[string]*webFilterLoad), config: make(map[string]*webFilterConfig), categories: make(map[string]fortiGateCategoryEntry), status: make(map[string]packageStatusEntry), ratings: make(map[string]ratingCacheEntry)}
}

func (c *webFilterCaches) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = make(map[string]*webFilterConfig)
	c.categories = make(map[string]fortiGateCategoryEntry)
	c.status = make(map[string]packageStatusEntry)
	c.ratings = make(map[string]ratingCacheEntry)
}

// RateURL returns the live FortiGuard category of a URL through the
// FortiManager proxy (see liveRating for the device order).
func (s *Service) RateURL(ctx context.Context, input RateURLInput) (RateURLOutput, error) {
	input.URL = strings.TrimSpace(input.URL)
	input.Profile = strings.TrimSpace(input.Profile)
	input.ADOM = strings.TrimSpace(input.ADOM)
	input.Device = strings.TrimSpace(input.Device)
	input.VDOM = strings.TrimSpace(input.VDOM)
	target, err := parseWebTarget(input.URL)
	if err != nil {
		return RateURLOutput{}, err
	}
	if s.store == nil {
		return RateURLOutput{}, fmt.Errorf("inventory store is not configured")
	}
	manager, err := s.managerForScope(input.Profile, input.ADOM, input.Device)
	if err != nil {
		return RateURLOutput{}, err
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	snapshot := s.store.Snapshot()
	output := RateURLOutput{Query: input, Host: target.Host, Path: target.Path}
	if snapshot.GeneratedAt.IsZero() {
		output.Warnings = append(output.Warnings, inventory.NotReadyMessage(snapshot)+" The device ADOM is resolved from inventory; pass adom meanwhile.")
	}
	output.Rating = s.liveRating(ctx, manager.Name(), snapshot, ratingScope{Device: input.Device, ADOM: input.ADOM, VDOM: input.VDOM}, target, staticCategoryNames())
	var labels []string
	for _, ref := range output.Rating.Categories {
		switch {
		case ref.ID > 0 || strings.EqualFold(ref.Name, "Not Rated") || strings.EqualFold(ref.Name, "Unrated"):
			labels = append(labels, strconv.Itoa(ref.ID))
		case ref.Name != "":
			// check_web_filter also resolves names through the category
			// lists read from the FortiGates.
			labels = append(labels, ref.Name)
		}
	}
	if len(labels) > 0 {
		output.NextStep = fmt.Sprintf("Call check_web_filter with category %q and url %q for each FortiGate that filters the user's traffic.", strings.Join(labels, ","), input.URL)
	}
	return output, nil
}

func staticCategoryNames() map[int]CategoryRef {
	names := make(map[int]CategoryRef)
	for id, category := range fortinet.StaticCategories() {
		names[id] = CategoryRef{ID: id, Name: category.Name, Group: category.Group, NameSource: "static_table"}
	}
	return names
}

// resolveRequestedCategories parses a comma-separated list of category ids
// or names. Names resolve through the static FortiGuard table and every
// category list already read from a FortiGate.
func (s *Service) resolveRequestedCategories(value string) ([]int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	known := make(map[string]int)
	s.webFilter.mu.Lock()
	for _, entry := range s.webFilter.categories {
		for id, name := range entry.names {
			known[strings.ToLower(strings.TrimSpace(name))] = id
		}
	}
	s.webFilter.mu.Unlock()
	var ids []int
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if id, err := strconv.Atoi(part); err == nil {
			if id < 0 || id > 255 {
				return nil, fmt.Errorf("category %d is outside the FortiGuard id range 0-255", id)
			}
			ids = append(ids, id)
			continue
		}
		if category, ok := fortinet.StaticCategoryByName(part); ok {
			ids = append(ids, category.ID)
			continue
		}
		if id, ok := known[strings.ToLower(part)]; ok {
			ids = append(ids, id)
			continue
		}
		return nil, fmt.Errorf("unknown FortiGuard category %q; pass the numeric id returned by rate_url", part)
	}
	return uniqueInts(ids), nil
}

func uniqueInts(values []int) []int {
	seen := make(map[int]bool, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

// CheckWebFilter explains how every web filter profile in scope treats a
// FortiGuard category and, when url is given, the URL's static URL filter
// entries and local rating overrides, and where each profile is applied.
// It reads only FortiManager configuration; get the category with RateURL.
func (s *Service) CheckWebFilter(ctx context.Context, input CheckWebFilterInput) (WebFilterCheckOutput, error) {
	input.Category = strings.TrimSpace(input.Category)
	input.URL = strings.TrimSpace(input.URL)
	input.Profile = strings.TrimSpace(input.Profile)
	input.ADOM = strings.TrimSpace(input.ADOM)
	input.Device = strings.TrimSpace(input.Device)
	input.VDOM = strings.TrimSpace(input.VDOM)
	if input.Category == "" && input.URL == "" {
		return WebFilterCheckOutput{}, fmt.Errorf("category or url is required: get the category with rate_url and pass it, together with the url for URL-specific rules")
	}
	if input.PolicyID < 0 || input.PolicyID > 0 && input.Device == "" {
		return WebFilterCheckOutput{}, fmt.Errorf("policy_id needs device: policy IDs are unique only within the packages of one FortiGate")
	}
	var target webTarget
	if input.URL != "" {
		parsed, err := parseWebTarget(input.URL)
		if err != nil {
			return WebFilterCheckOutput{}, err
		}
		target = parsed
	}
	requestedIDs, err := s.resolveRequestedCategories(input.Category)
	if err != nil {
		return WebFilterCheckOutput{}, err
	}
	if s.store == nil {
		return WebFilterCheckOutput{}, fmt.Errorf("inventory store is not configured")
	}
	manager, err := s.managerForScope(input.Profile, input.ADOM, input.Device)
	if err != nil {
		return WebFilterCheckOutput{}, err
	}
	reader, ok := manager.(fortinet.WebFilterReader)
	if !ok {
		return WebFilterCheckOutput{}, fmt.Errorf("FortiManager profile %q does not support web filter reads", manager.Name())
	}
	// Answer within the request timeout. Reads that take longer continue in
	// background load jobs and fill the caches for the next check.
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	snapshot := s.store.Snapshot()
	output := WebFilterCheckOutput{
		Query:      input,
		Host:       target.Host,
		Path:       target.Path,
		SnapshotAt: snapshot.GeneratedAt,
		Profiles:   []WebFilterProfileResult{},
		Limitations: []string{
			"Decisions come from configuration stored in FortiManager; package_status and config_status show FortiManager's stored synchronization state, not a live test on each FortiGate.",
			"For HTTPS, category and URL matching apply to the server name unless the policy's SSL/SSH inspection profile performs deep inspection; path-based rules need deep inspection.",
			"Quotas, override permissions, authentication, schedules, DNS filter, and application control are not evaluated.",
		},
	}
	if snapshot.GeneratedAt.IsZero() {
		output.Warnings = append(output.Warnings, inventory.NotReadyMessage(snapshot)+" Profile decisions are still evaluated; device assignment needs inventory.")
	}
	if input.URL == "" {
		output.Warnings = append(output.Warnings, "No url given: static URL filter entries and FortiGuard local rating overrides, which match the URL itself, were not evaluated. Pass url for the complete decision on a concrete site.")
	}
	if len(requestedIDs) == 0 {
		output.Warnings = append(output.Warnings, "No category given: category actions are reported as unknown unless a URL filter entry or local rating override decides. Get the category with rate_url.")
	}
	adoms, err := s.webFilterADOMs(manager, snapshot, input.ADOM)
	if err != nil {
		return output, err
	}
	if input.ADOM != "" && !snapshotHasADOM(snapshot, manager.Name(), input.ADOM) {
		output.Warnings = append(output.Warnings, fmt.Sprintf("ADOM %q is not in the current inventory of profile %q (known: %s); reads may fail if the name is wrong.", input.ADOM, manager.Name(), strings.Join(snapshotADOMs(snapshot, manager.Name()), ", ")))
	}
	if input.Device != "" {
		if device, found := findDeviceByName(snapshot, manager.Name(), input.Device); found {
			adoms = []string{device.ADOM}
		} else {
			output.Warnings = append(output.Warnings, fmt.Sprintf("Device %q is not in the inventory of profile %q; results are not limited to it.", input.Device, manager.Name()))
		}
	}

	names := staticCategoryNames()
	s.webFilter.mu.Lock()
	for _, entry := range s.webFilter.categories {
		for id, name := range entry.names {
			names[id] = CategoryRef{ID: id, Name: name, Group: names[id].Group, NameSource: "fortigate"}
		}
	}
	s.webFilter.mu.Unlock()
	ratingIDs := requestedIDs
	ratingSource := "none"
	if len(requestedIDs) > 0 {
		ratingSource = "requested_category"
	}
	for _, id := range requestedIDs {
		output.Categories = append(output.Categories, resolveCategory(id, names))
	}

	// With a device, only the packages assigned to it are read.
	var packageScope []string
	if input.Device != "" {
		if device, found := findDeviceByName(snapshot, manager.Name(), input.Device); found && len(device.Packages) > 0 {
			packageScope = append([]string(nil), device.Packages...)
			sort.Strings(packageScope)
		}
	}
	loads := make([]*webFilterLoad, len(adoms))
	for index, adom := range adoms {
		loads[index] = s.webFilterLoadFor(reader, manager, adom, packageScope, snapshot.GeneratedAt)
	}
	for _, load := range loads {
		select {
		case <-load.done:
		case <-ctx.Done():
		}
	}
	output.Complete = true

	var global *webFilterConfig
	loadGlobal := func() *webFilterConfig {
		if global == nil {
			global = s.globalWebFilterConfig(ctx, reader, manager.Name())
			appendUniqueStrings(&output.Warnings, global.warnings...)
			output.Errors = append(output.Errors, global.errors...)
		}
		return global
	}

	for index, adom := range adoms {
		config, ready := loads[index].view()
		if !ready {
			output.Complete = false
			output.Warnings = append(output.Warnings, fmt.Sprintf("Web filter configuration of ADOM %s is still being read from FortiManager; repeat the lookup shortly, the reads continue in the background.", adom))
			continue
		}
		output.Errors = append(output.Errors, config.errors...)
		appendUniqueStrings(&output.Warnings, config.warnings...)
		output.Summary.PackagesEvaluated += len(config.packages)
		switch {
		case config.usagePending:
			output.Complete = false
			output.Warnings = append(output.Warnings, fmt.Sprintf("Policy usage in ADOM %s is still being read; profile decisions are complete, but policies and devices are missing. Repeat the lookup shortly for them.", adom))
		case config.packagesFailed:
			output.Warnings = append(output.Warnings, fmt.Sprintf("Policy usage in ADOM %s could not be verified completely because package or policy reads failed; see errors.", adom))
		}
		output.Summary.PoliciesEvaluated += config.policyCount()
		adomNames := cloneCategoryNames(names)
		for id, name := range config.fmgCategories {
			adomNames[id] = CategoryRef{ID: id, Name: name, Group: adomNames[id].Group, NameSource: "fortimanager"}
		}
		for _, local := range config.localCategory {
			if local.ID != 0 {
				adomNames[local.ID] = CategoryRef{ID: local.ID, Name: local.Description, Group: "Local Categories", NameSource: "local_category"}
			}
		}

		// Profiles referenced by policies or tables referenced by profiles
		// that the ADOM does not hold come from the global ADOM.
		groups := config.groups
		profiles := make([]fortinet.WebFilterProfile, 0, len(config.profiles))
		sources := make(map[string]string, len(config.profiles))
		for _, profile := range config.profiles {
			profiles = append(profiles, profile)
			sources[profile.Name] = "adom"
		}
		usage := webFilterPolicyUsage(config, groups, snapshot, manager.Name(), adom)
		missingProfiles := make([]string, 0)
		for name := range usage {
			if _, known := sources[name]; !known {
				missingProfiles = append(missingProfiles, name)
			}
		}
		if hasUnresolvedGroups(config) {
			globalConfig := loadGlobal()
			groups = append(append([]fortinet.ProfileGroup(nil), config.groups...), globalConfig.groups...)
			usage = webFilterPolicyUsage(config, groups, snapshot, manager.Name(), adom)
			missingProfiles = missingProfiles[:0]
			for name := range usage {
				if _, known := sources[name]; !known {
					missingProfiles = append(missingProfiles, name)
				}
			}
		}
		sort.Strings(missingProfiles)
		tables := config.tables
		if len(missingProfiles) > 0 || profilesNeedGlobalTables(profiles, config.tables) {
			globalConfig := loadGlobal()
			for _, name := range missingProfiles {
				for _, profile := range globalConfig.profiles {
					if profile.Name == name {
						profiles = append(profiles, profile)
						sources[name] = "global"
					}
				}
				if sources[name] == "" {
					output.Warnings = append(output.Warnings, fmt.Sprintf("Web filter profile %q is referenced by policies in ADOM %s but was found neither in the ADOM nor in the global ADOM.", name, adom))
				}
			}
			tables = append(append([]fortinet.URLFilterTable(nil), config.tables...), globalConfig.tables...)
		}

		for _, profile := range profiles {
			result := evaluateWebFilterProfile(profile, tables, config, target, ratingIDs, ratingSource, adomNames)
			result.ADOM = adom
			result.Manager = manager.Name()
			result.Source = sources[profile.Name]
			label := profile.Name + " (" + adom + ")"
			policies := usage[profile.Name]
			if input.Device != "" && !config.usagePending {
				scoped, unknownScope := scopeUsageToDevice(policies, input.Device, input.VDOM)
				if len(scoped) == 0 {
					// Only the device's packages were read, so a profile without
					// a policy there is "not on this device"; whether other
					// devices use it is not known from this lookup.
					if !config.packagesFailed {
						output.Summary.NotOnDevice = append(output.Summary.NotOnDevice, label)
					}
					continue
				}
				if unknownScope {
					result.Warnings = append(result.Warnings, "Some policies have no resolved device assignment in inventory; they are kept although they may not be installed on the requested device.")
				}
				policies = scoped
			}
			if input.PolicyID > 0 {
				// Only the profile the named policy applies is relevant.
				if config.usagePending {
					continue
				}
				var kept []WebFilterPolicyUsage
				for _, usage := range policies {
					if usage.PolicyID == input.PolicyID {
						kept = append(kept, usage)
					}
				}
				if len(kept) == 0 {
					continue
				}
				policies = kept
			}
			result.Policies = policies
			result.Devices = usageDeviceUnion(policies, input.Device, input.VDOM)
			// Unused profiles are listed once in the summary rather than with a
			// warning on each profile.
			if len(policies) == 0 && !config.packagesFailed && !config.usagePending {
				output.Summary.UnusedProfiles = append(output.Summary.UnusedProfiles, label)
			}
			output.Profiles = append(output.Profiles, result)
		}
		if ctx.Err() == nil {
			s.attachPackageStatus(ctx, manager, adom, output.Profiles, &output.Warnings)
		}
	}

	output.Summary.ProfilesEvaluated = len(output.Profiles)
	output.Summary.Blocked, output.Summary.Allowed, output.Summary.Conditional, output.Summary.Unknown = []string{}, []string{}, []string{}, []string{}
	for _, result := range output.Profiles {
		label := result.Profile + " (" + result.ADOM + ")"
		switch result.Decision {
		case "blocked":
			output.Summary.Blocked = append(output.Summary.Blocked, label)
		case "allowed", "monitored", "exempt":
			output.Summary.Allowed = append(output.Summary.Allowed, label)
		case "warning", "authenticate":
			output.Summary.Conditional = append(output.Summary.Conditional, label)
		default:
			output.Summary.Unknown = append(output.Summary.Unknown, label)
		}
	}
	if len(output.Profiles) == 0 && input.PolicyID > 0 && output.Complete {
		output.Warnings = append(output.Warnings, fmt.Sprintf("Policy %d on %s applies no web filter profile in the packages read (no web filter profile, UTM or the policy disabled, or the policy is not in this device's packages); web filtering does not act on traffic of this policy unless live configuration differs.", input.PolicyID, input.Device))
	} else if len(output.Profiles) == 0 {
		if input.Device != "" {
			output.Warnings = append(output.Warnings, fmt.Sprintf("No web filter profile is applied by an enabled policy on %s; web filtering does not act on this traffic there unless live configuration differs.", input.Device))
		} else {
			output.Warnings = append(output.Warnings, "No web filter profiles were read in the selected scope; check errors and the ADOM selection.")
		}
	}
	return output, nil
}

func findDeviceByName(snapshot inventory.Snapshot, profile, name string) (fortinet.Device, bool) {
	for _, device := range snapshot.Devices {
		if device.Profile == profile && device.Name == name {
			return device, true
		}
	}
	return fortinet.Device{}, false
}

func hasUnresolvedGroups(config *webFilterConfig) bool {
	known := make(map[string]bool, len(config.groups))
	for _, group := range config.groups {
		known[group.Name] = true
	}
	for _, packages := range config.policies {
		for _, policies := range packages {
			for _, policy := range policies {
				if strings.EqualFold(policy.ProfileType, "group") && policy.ProfileGroup != "" && !known[policy.ProfileGroup] {
					return true
				}
			}
		}
	}
	return false
}

func profilesNeedGlobalTables(profiles []fortinet.WebFilterProfile, tables []fortinet.URLFilterTable) bool {
	for _, profile := range profiles {
		if profile.URLFilterTable != "" && findURLFilterTable(tables, profile.URLFilterTable) == nil {
			return true
		}
	}
	return false
}

// scopeUsageToDevice keeps policies installed on device (and vdom when set).
// Policies without any resolved device are kept and reported as unknown.
func scopeUsageToDevice(policies []WebFilterPolicyUsage, device, vdom string) ([]WebFilterPolicyUsage, bool) {
	var scoped []WebFilterPolicyUsage
	unknown := false
	for _, policy := range policies {
		if len(policy.devices) == 0 {
			scoped = append(scoped, policy)
			unknown = true
			continue
		}
		for _, target := range policy.devices {
			if target.Device == device && (vdom == "" || target.VDOM == "" || target.VDOM == vdom) {
				scoped = append(scoped, policy)
				break
			}
		}
	}
	return scoped, unknown
}

func usageDeviceUnion(policies []WebFilterPolicyUsage, device, vdom string) []WebFilterDevice {
	seen := make(map[string]bool)
	var result []WebFilterDevice
	for _, policy := range policies {
		for _, target := range policy.devices {
			if device != "" && (target.Device != device || (vdom != "" && target.VDOM != "" && target.VDOM != vdom)) {
				continue
			}
			key := target.Device + "/" + target.VDOM + "/" + target.Package
			if seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, target)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Device != result[j].Device {
			return result[i].Device < result[j].Device
		}
		return result[i].VDOM < result[j].VDOM
	})
	return result
}

// attachPackageStatus fills FortiManager's stored package installation state
// for the reported devices of one ADOM, reading at most
// maxPackageStatusReads device VDOMs and caching results.
func (s *Service) attachPackageStatus(ctx context.Context, manager fortinet.Manager, adom string, results []WebFilterProfileResult, warnings *[]string) {
	reader, ok := manager.(fortinet.PackageStatusReader)
	if !ok {
		return
	}
	wanted := make(map[string]fortinet.PackageMember)
	for _, result := range results {
		if result.ADOM != adom {
			continue
		}
		for _, device := range result.Devices {
			vdom := routeVDOM(device.VDOM)
			wanted[device.Device+"/"+vdom] = fortinet.PackageMember{Device: device.Device, VDOM: vdom}
		}
	}
	if len(wanted) == 0 {
		return
	}
	epoch := s.cacheEpoch.Load()
	prefix := manager.Name() + "\x00" + adom + "\x00"
	statuses := make(map[string]fortinet.PackageStatus, len(wanted))
	missing := make([]fortinet.PackageMember, 0, len(wanted))
	keys := make([]string, 0, len(wanted))
	for key := range wanted {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	s.webFilter.mu.Lock()
	for _, key := range keys {
		if entry, cached := s.webFilter.status[prefix+key]; cached && time.Since(entry.created) < webFilterConfigTTL {
			if entry.found {
				statuses[key] = entry.status
			}
			continue
		}
		missing = append(missing, wanted[key])
	}
	s.webFilter.mu.Unlock()
	if len(missing) > maxPackageStatusReads {
		*warnings = append(*warnings, fmt.Sprintf("Package status was read for %d of %d device VDOMs in ADOM %s; scope the lookup with device for complete status.", maxPackageStatusReads, len(missing), adom))
		missing = missing[:maxPackageStatusReads]
	}
	if len(missing) > 0 {
		memberKey := make([]string, len(missing))
		for i, member := range missing {
			memberKey[i] = member.Device + "/" + member.VDOM
		}
		shared, flightErr := s.sharedRead(ctx, "pkgstatus\x00"+prefix+strings.Join(memberKey, ","), func() (any, error) {
			return reader.PackageStatusBatch(ctx, adom, missing)
		})
		var read map[string]fortinet.PackageStatus
		err := flightErr
		if flightErr == nil {
			read, _ = shared.(map[string]fortinet.PackageStatus)
		}
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("Package installation status in ADOM %s unavailable: %v; config_status from inventory is shown instead.", adom, err))
		}
		now := time.Now()
		s.webFilter.mu.Lock()
		if s.cacheWriteAllowed(epoch) && err == nil {
			evictOlderThan(s.webFilter.status, webFilterConfigTTL, func(entry packageStatusEntry) time.Time { return entry.created })
		}
		for _, member := range missing {
			key := member.Device + "/" + member.VDOM
			status, found := read[key]
			if found {
				statuses[key] = status
			}
			if err == nil && s.cacheWriteAllowed(epoch) {
				s.webFilter.status[prefix+key] = packageStatusEntry{created: now, status: status, found: found}
			}
		}
		s.webFilter.mu.Unlock()
	}
	for index := range results {
		if results[index].ADOM != adom {
			continue
		}
		for deviceIndex := range results[index].Devices {
			device := &results[index].Devices[deviceIndex]
			status, found := statuses[device.Device+"/"+routeVDOM(device.VDOM)]
			if !found {
				continue
			}
			if status.Package == "" || status.Package == device.Package || strings.HasSuffix(device.Package, "/"+status.Package) {
				device.PackageStatus = status.Status
			} else {
				device.PackageStatus = fmt.Sprintf("%s (installed package %s)", status.Status, status.Package)
			}
		}
	}
}

func snapshotHasADOM(snapshot inventory.Snapshot, profile, adom string) bool {
	for _, record := range snapshot.ADOMs {
		if record.Profile == profile && record.ADOM.Name == adom {
			return true
		}
	}
	return false
}

func snapshotADOMs(snapshot inventory.Snapshot, profile string) []string {
	names := make([]string, 0)
	for _, record := range snapshot.ADOMs {
		if record.Profile == profile {
			names = append(names, record.ADOM.Name)
		}
	}
	if len(names) == 0 {
		return []string{"none"}
	}
	return names
}

func (s *Service) webFilterADOMs(manager fortinet.Manager, snapshot inventory.Snapshot, requested string) ([]string, error) {
	if requested != "" {
		if err := s.validateManagerADOM(manager, requested); err != nil {
			return nil, err
		}
		return []string{requested}, nil
	}
	adoms := make([]string, 0)
	for _, record := range snapshot.ADOMs {
		if record.Profile == manager.Name() && s.profileAllowsADOM(manager.Name(), record.ADOM.Name) {
			adoms = append(adoms, record.ADOM.Name)
		}
	}
	if len(adoms) == 0 {
		for _, configured := range s.cfg.Profiles {
			if configured.Name == manager.Name() {
				adoms = append(adoms, configured.ADOMs...)
			}
		}
	}
	adoms = uniqueStrings(adoms)
	if len(adoms) == 0 {
		return nil, fmt.Errorf("no ADOM is known for FortiManager profile %q; specify adom or run refresh_inventory", manager.Name())
	}
	return adoms, nil
}

// liveRating obtains the FortiGuard category through the FortiManager
// proxy from the configured rating FortiGate (rating.device) or, when none
// is configured or it cannot answer, from the FortiGate given in the
// request. The agent chooses that device by tracing the user's traffic
// (SYSTEM.md); the tool never picks an arbitrary device.
func (s *Service) liveRating(ctx context.Context, profile string, snapshot inventory.Snapshot, input ratingScope, target webTarget, names map[int]CategoryRef) RatingEvidence {
	evidence := RatingEvidence{Source: "none", Profile: profile}
	// FortiGuard rates host and path; the scheme and a bare trailing slash
	// only change the request, not the rating.
	rateTarget := strings.TrimSuffix(target.Full, "/")
	// The category is global, so a recent rating of the same URL answers
	// whichever FortiGate the caller named.
	epoch := s.cacheEpoch.Load()
	cacheKey := profile + "\x00" + strings.ToLower(rateTarget)
	s.webFilter.mu.Lock()
	cached, hit := s.webFilter.ratings[cacheKey]
	s.webFilter.mu.Unlock()
	if hit && time.Since(cached.created) < ratingCacheTTL {
		reused := cached.evidence
		reused.Cached = true
		return reused
	}
	choices := s.ratingDeviceChoices(profile, snapshot, input)
	if len(choices) == 0 {
		evidence.Error = "No FortiGate is selected for the FortiGuard rating: pass device (the FortiGate the user's traffic to this URL passes, found by tracing the source as described in the investigation instructions) or configure rating.device."
		return evidence
	}
	var lastErr error
	for _, choice := range choices {
		label := choice.profile + ":" + choice.adom + "/" + choice.device
		evidence.Attempts = append(evidence.Attempts, label)
		if choice.skip != "" {
			evidence.AttemptErrors = append(evidence.AttemptErrors, label+": "+choice.skip)
			continue
		}
		proxy, account, err := s.ratingProxyFor(choice.profile)
		if err != nil {
			lastErr = err
			evidence.AttemptErrors = append(evidence.AttemptErrors, label+": "+err.Error())
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, ratingAttemptTimeout)
		rating, err := proxy.LookupURLRating(attemptCtx, choice.adom, choice.device, choice.vdom, rateTarget)
		timedOut := attemptCtx.Err() != nil && ctx.Err() == nil
		cancel()
		if err != nil {
			lastErr = err
			reason := shortRatingReason(err)
			if timedOut || fortinet.DescribeError(err).Kind == fortinet.ErrorKindTimeout {
				reason = fmt.Sprintf("no answer within %s: the FortiGate did not complete the FortiGuard lookup; check its FortiGuard connectivity and web filter license (proxy GET /api/v2/monitor/system/fortiguard/server-info and /api/v2/monitor/license/status)", ratingAttemptTimeout)
				lastErr = fmt.Errorf("FortiGuard rating via %s timed out: %s", label, reason)
			}
			evidence.AttemptErrors = append(evidence.AttemptErrors, label+" ("+account+"): "+reason)
			if ctx.Err() != nil {
				break
			}
			continue
		}
		evidence.Source, evidence.Selection, evidence.Account = "live_fortigate", choice.selection, account
		evidence.Profile, evidence.ADOM, evidence.Device, evidence.VDOM, evidence.Resource = choice.profile, choice.adom, choice.device, choice.vdom, rating.Resource
		key := choice.profile + "/" + choice.adom + "/" + choice.device
		adom, device, vdom := choice.adom, choice.device, choice.vdom
		namesCtx, cancelNames := context.WithTimeout(ctx, ratingAttemptTimeout)
		s.applyRating(&evidence, rating, s.cachedCategoryNames(namesCtx, key, func(ctx context.Context) (map[int]string, error) {
			return proxy.ListFortiGateCategories(ctx, adom, device, vdom)
		}), names)
		cancelNames()
		evidence.RatedAt = time.Now()
		if len(evidence.Categories) > 0 {
			s.webFilter.mu.Lock()
			if s.cacheWriteAllowed(epoch) {
				evictOlderThan(s.webFilter.ratings, ratingCacheTTL, func(entry ratingCacheEntry) time.Time { return entry.created })
				s.webFilter.ratings[cacheKey] = ratingCacheEntry{created: evidence.RatedAt, evidence: evidence}
			}
			s.webFilter.mu.Unlock()
		}
		return evidence
	}
	if lastErr != nil {
		info := fortinet.DescribeError(lastErr)
		evidence.Error = info.Message
		if info.Hint != "" {
			evidence.Error += " Hint: " + info.Hint
		}
		evidence.ErrorDetails = &info
	} else {
		evidence.Error = "No selected rating FortiGate could answer; see attempt_errors."
	}
	return evidence
}

type ratingChoice struct {
	profile, adom, device, vdom string
	selection                   string
	skip                        string
}

// ratingDeviceChoices returns the configured rating device first and the
// requested device second. Offline or unknown devices are kept with a skip
// reason so the result explains why they were not asked.
func (s *Service) ratingDeviceChoices(profile string, snapshot inventory.Snapshot, input ratingScope) []ratingChoice {
	var choices []ratingChoice
	add := func(choiceProfile, name, adom, vdom, selection string) {
		if name == "" {
			return
		}
		for _, existing := range choices {
			if existing.profile == choiceProfile && existing.device == name {
				return
			}
		}
		device, found := findDeviceByName(snapshot, choiceProfile, name)
		if adom == "" && found {
			adom = device.ADOM
		}
		if vdom == "" {
			vdom = "root"
		}
		choice := ratingChoice{profile: choiceProfile, adom: adom, device: name, vdom: vdom, selection: selection}
		switch {
		case adom == "":
			choice.skip = fmt.Sprintf("not in the inventory of profile %q; set the ADOM or check the device name", choiceProfile)
		case found:
			if unavailable, reason := fortinet.DeviceUnavailable(device); unavailable {
				choice.skip = "offline (" + reason + ")"
			}
		}
		choices = append(choices, choice)
	}
	rating := s.cfg.Rating
	ratingProfile := rating.FortiManagerProfile
	if ratingProfile == "" {
		ratingProfile = profile
	}
	add(ratingProfile, rating.Device, rating.ADOM, rating.VDOM, "configured rating device")
	add(profile, input.Device, input.ADOM, input.VDOM, "requested device")
	return choices
}

func (s *Service) applyRating(evidence *RatingEvidence, rating fortinet.URLRating, liveNames map[int]string, names map[int]CategoryRef) {
	for id, name := range liveNames {
		names[id] = CategoryRef{ID: id, Name: name, Group: names[id].Group, NameSource: "fortigate"}
	}
	for _, id := range rating.CategoryIDs {
		evidence.Categories = append(evidence.Categories, resolveCategory(id, names))
	}
	if len(rating.CategoryIDs) == 0 {
		// FortiOS answered with names only: resolve them through the
		// FortiGate's own category list first, which also knows categories
		// newer than the static table.
		byName := make(map[string]int, len(names))
		for id, ref := range names {
			byName[strings.ToLower(ref.Name)] = id
		}
		for _, name := range rating.CategoryNames {
			if id, ok := byName[strings.ToLower(strings.TrimSpace(name))]; ok {
				evidence.Categories = append(evidence.Categories, resolveCategory(id, names))
			} else if category, ok := fortinet.StaticCategoryByName(name); ok {
				evidence.Categories = append(evidence.Categories, resolveCategory(category.ID, names))
			} else {
				evidence.Categories = append(evidence.Categories, CategoryRef{Name: name, NameSource: "fortigate"})
			}
		}
	}
}

// cachedCategoryNames caches a FortiGate category catalogue per source.
func (s *Service) cachedCategoryNames(ctx context.Context, key string, fetch func(context.Context) (map[int]string, error)) map[int]string {
	epoch := s.cacheEpoch.Load()
	s.webFilter.mu.Lock()
	entry, ok := s.webFilter.categories[key]
	s.webFilter.mu.Unlock()
	if ok && time.Since(entry.created) < fortiGateCategoryTTL {
		return entry.names
	}
	names, err := fetch(ctx)
	if err != nil {
		return nil
	}
	s.webFilter.mu.Lock()
	defer s.webFilter.mu.Unlock()
	if !s.cacheWriteAllowed(epoch) {
		return names
	}
	evictOlderThan(s.webFilter.categories, fortiGateCategoryTTL, func(entry fortiGateCategoryEntry) time.Time { return entry.created })
	s.webFilter.categories[key] = fortiGateCategoryEntry{created: time.Now(), names: names}
	return names
}

func shortRatingReason(err error) string {
	info := fortinet.DescribeError(err)
	reason := string(info.Kind)
	switch {
	case info.FortiGateStatus != 0:
		reason = fmt.Sprintf("FortiGate HTTP %d (%s)", info.FortiGateStatus, info.Kind)
	case info.Code != 0:
		reason = fmt.Sprintf("FortiManager code %d (%s)", info.Code, info.Kind)
	case info.HTTPStatus != 0:
		reason = fmt.Sprintf("HTTP %d (%s)", info.HTTPStatus, info.Kind)
	case info.Kind == fortinet.ErrorKindResponse:
		reason = "FortiGate answered without a recognised category (invalid_response); the response is quoted in error"
	}
	if reason == "" {
		reason = err.Error()
	}
	return reason
}

// webFilterLoadFor returns the running or a new background load of an ADOM's
// web filter configuration and the policies of packageScope (all packages
// when empty). The load is bounded by the refresh timeout, independent of
// the caller, and serves concurrent lookups of the same scope.
func (s *Service) webFilterLoadFor(reader fortinet.WebFilterReader, manager fortinet.Manager, adom string, packageScope []string, snapshotAt time.Time) *webFilterLoad {
	key := manager.Name() + "\x00" + adom + "\x00" + strings.Join(packageScope, "\x01")
	epoch := s.cacheEpoch.Load()
	s.webFilter.mu.Lock()
	if load, running := s.webFilter.loads[key]; running && load.epoch == epoch {
		s.webFilter.mu.Unlock()
		return load
	}
	load := &webFilterLoad{epoch: epoch, configReady: make(chan struct{}), done: make(chan struct{})}
	s.webFilter.loads[key] = load
	s.webFilter.mu.Unlock()

	s.goBackground(func() {
		configClosed := false
		defer func() {
			if recovered := recover(); recovered != nil {
				if load.config == nil {
					load.config = &webFilterConfig{warnings: []string{fmt.Sprintf("web filter configuration read of ADOM %s failed: %v", adom, recovered)}}
				}
				load.policies = policySet{failed: true, warnings: []string{fmt.Sprintf("policy read of ADOM %s failed: %v", adom, recovered)}}
			}
			if !configClosed {
				close(load.configReady)
			}
			close(load.done)
			s.webFilter.mu.Lock()
			if current := s.webFilter.loads[key]; current == load {
				delete(s.webFilter.loads, key)
			}
			s.webFilter.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.RefreshTimeoutDuration())
		defer cancel()
		// The reads run one after another: the account's request lane is
		// serial anyway, and queueing them all at once would make every
		// other tool call wait behind the whole load.
		ctx, stats := fortinet.WithRequestStats(ctx)
		started := time.Now()
		load.config = s.webFilterConfigFor(ctx, reader, manager, adom)
		objectsDone := time.Since(started)
		close(load.configReady)
		configClosed = true
		load.policies = s.loadPolicySet(ctx, manager, adom, scopePackages(load.config.packages, packageScope), snapshotAt)
		requests := stats.Snapshot()
		policies := 0
		for _, packages := range load.policies.tables {
			for _, list := range packages {
				policies += len(list)
			}
		}
		slog.Info("web filter configuration loaded", "profile", manager.Name(), "adom", adom, "packages", len(load.policies.packages), "policies", policies,
			"errors", len(load.config.errors)+len(load.policies.errors), "duration", time.Since(started).Round(time.Millisecond), "objects_duration", objectsDone.Round(time.Millisecond),
			"fortinet_requests", requests.Requests, "lane_wait", requests.LaneWait.Round(time.Millisecond), "slowest_resource", requests.SlowestResource)
	})
	return load
}

// view returns a per-call copy of the loaded configuration: complete when
// the load finished, with pending usage when only the objects are read, and
// ready=false when not even the objects are available yet.
func (l *webFilterLoad) view() (*webFilterConfig, bool) {
	select {
	case <-l.done:
		view := *l.config
		view.packages = l.policies.packages
		view.policies = l.policies.tables
		view.packagesFailed = view.packagesFailed || l.policies.failed
		view.errors = append(append([]inventory.RefreshError(nil), view.errors...), l.policies.errors...)
		view.warnings = append(append([]string(nil), view.warnings...), l.policies.warnings...)
		return &view, true
	default:
	}
	select {
	case <-l.configReady:
		view := *l.config
		view.packages = nil
		view.policies = nil
		view.usagePending = true
		return &view, true
	default:
		return nil, false
	}
}

// scopePackages keeps the packages named in scope. An empty scope, or a
// scope that matches none of the ADOM's packages, reads all packages.
func scopePackages(packages []fortinet.PolicyPackage, scope []string) []fortinet.PolicyPackage {
	if len(scope) == 0 {
		return packages
	}
	var scoped []fortinet.PolicyPackage
	for _, pkg := range packages {
		if containsString(scope, pkg.Name) {
			scoped = append(scoped, pkg)
		}
	}
	if len(scoped) == 0 {
		return packages
	}
	return scoped
}

// webFilterConfigFor reads (or returns cached) web filter objects, profile
// groups and the package list of one ADOM. The objects share the /pm/config
// prefix and are read in one multiplexed request; the package list
// (/pm/pkg) is a second request. Policies are read separately so that a
// lookup for one device reads only that device's packages.
func (s *Service) webFilterConfigFor(ctx context.Context, reader fortinet.WebFilterReader, manager fortinet.Manager, adom string) *webFilterConfig {
	epoch := s.cacheEpoch.Load()
	key := manager.Name() + "\x00" + adom
	s.webFilter.mu.Lock()
	entry, ok := s.webFilter.config[key]
	s.webFilter.mu.Unlock()
	if ok && time.Since(entry.created) < webFilterConfigTTL {
		return entry
	}
	value, _ := s.sharedRead(ctx, "wf-config\x00"+key, func() (any, error) {
		s.webFilter.mu.Lock()
		cached, hit := s.webFilter.config[key]
		s.webFilter.mu.Unlock()
		if hit && time.Since(cached.created) < webFilterConfigTTL {
			return cached, nil
		}
		return s.readWebFilterConfig(ctx, reader, manager, adom, epoch, key), nil
	})
	if config, ok := value.(*webFilterConfig); ok && config != nil {
		return config
	}
	return &webFilterConfig{warnings: []string{fmt.Sprintf("%s/%s web filter configuration was not read", manager.Name(), adom)}}
}

func (s *Service) readWebFilterConfig(ctx context.Context, reader fortinet.WebFilterReader, manager fortinet.Manager, adom string, epoch uint64, key string) *webFilterConfig {
	config := &webFilterConfig{created: time.Now()}
	stageErrors := make(map[string]error)
	if objectReader, ok := reader.(fortinet.WebFilterObjectReader); ok {
		objects := objectReader.ReadWebFilterObjects(ctx, adom)
		config.profiles, config.tables, config.localRatings = objects.Profiles, objects.URLFilterTables, objects.LocalRatings
		config.localCategory, config.groups, config.fmgCategories = objects.LocalCategories, objects.ProfileGroups, objects.Categories
		maps.Copy(stageErrors, objects.Errors)
	} else {
		var err error
		if config.profiles, err = reader.ListWebFilterProfiles(ctx, adom); err != nil {
			stageErrors["list_webfilter_profiles"] = err
		}
		if config.tables, err = reader.ListURLFilterTables(ctx, adom); err != nil {
			stageErrors["list_urlfilter_tables"] = err
		}
		if config.localRatings, err = reader.ListLocalRatings(ctx, adom); err != nil {
			stageErrors["list_local_ratings"] = err
		}
		if config.localCategory, err = reader.ListLocalCategories(ctx, adom); err != nil {
			stageErrors["list_local_categories"] = err
		}
		if config.groups, err = reader.ListProfileGroups(ctx, adom); err != nil {
			stageErrors["list_profile_groups"] = err
		}
		if config.fmgCategories, err = reader.ListFortiGuardCategories(ctx, adom); err != nil {
			stageErrors["list_fortiguard_categories"] = err
		}
	}
	var packagesErr error
	if listed, known := s.snapshotPackages(manager.Name(), adom); known {
		config.packages = listed
	} else if config.packages, packagesErr = manager.ListPolicyPackages(ctx, adom); packagesErr != nil {
		stageErrors["list_policy_packages"] = packagesErr
		config.packagesFailed = true
	}
	for _, stage := range []string{"list_webfilter_profiles", "list_urlfilter_tables", "list_local_ratings", "list_local_categories", "list_profile_groups", "list_policy_packages"} {
		err := stageErrors[stage]
		if err == nil {
			continue
		}
		// The FortiGuard category catalogue is optional: names also come from
		// the static table and the FortiGates.
		config.errors = append(config.errors, serviceRefreshError(manager.Name(), adom, "", "", stage, err))
		config.warnings = append(config.warnings, fmt.Sprintf("%s/%s %s: %v", manager.Name(), adom, stage, err))
	}
	// Cache only complete reads so a transient failure is retried next time.
	if len(config.errors) == 0 {
		s.webFilter.mu.Lock()
		if s.cacheWriteAllowed(epoch) {
			evictOlderThan(s.webFilter.config, webFilterConfigTTL, func(entry *webFilterConfig) time.Time { return entry.created })
			s.webFilter.config[key] = config
		}
		s.webFilter.mu.Unlock()
	}
	return config
}

// loadPolicySet reads the policy tables of the given packages through the
// shared policy cache, one multiplexed request per package. Firewall
// policies are required; the legacy IPv6, NGFW security and explicit proxy
// tables are optional and often absent (cached as empty).
func (s *Service) loadPolicySet(ctx context.Context, manager fortinet.Manager, adom string, packages []fortinet.PolicyPackage, snapshotAt time.Time) policySet {
	set := policySet{tables: make(map[string]map[string][]fortinet.FirewallPolicy), packages: packages}
	for _, pkg := range packages {
		if ctx.Err() != nil {
			set.failed = true
			set.errors = append(set.errors, serviceRefreshError(manager.Name(), adom, "", pkg.Name, "list_policies", ctx.Err()))
			continue
		}
		tables, errs := s.packagePolicies(ctx, manager, adom, pkg.Name, policyTableNames, snapshotAt)
		for _, table := range policyTableNames {
			if err := errs[table]; err != nil {
				if table != "policy" {
					// Optional tables that failed for another reason than
					// absence warn without failing the ADOM.
					set.warnings = append(set.warnings, fmt.Sprintf("%s/%s package %s %s table: %v", manager.Name(), adom, pkg.Name, table, err))
					continue
				}
				set.failed = true
				set.errors = append(set.errors, serviceRefreshError(manager.Name(), adom, "", pkg.Name, "list_policies", err))
				set.warnings = append(set.warnings, fmt.Sprintf("%s/%s package %s policies: %v", manager.Name(), adom, pkg.Name, err))
				continue
			}
			if set.tables[table] == nil {
				set.tables[table] = make(map[string][]fortinet.FirewallPolicy)
			}
			set.tables[table][pkg.Name] = tables[table]
		}
	}
	return set
}

// globalWebFilterConfig reads shared web filter objects from the global
// ADOM. Failures (often a permission boundary) are cached like successes so
// a denied read is not repeated on every lookup.
func (s *Service) globalWebFilterConfig(ctx context.Context, reader fortinet.WebFilterReader, managerName string) *webFilterConfig {
	epoch := s.cacheEpoch.Load()
	key := managerName + "\x00\x00global"
	s.webFilter.mu.Lock()
	entry, ok := s.webFilter.config[key]
	s.webFilter.mu.Unlock()
	if ok && time.Since(entry.created) < webFilterConfigTTL {
		return entry
	}
	config := &webFilterConfig{created: time.Now()}
	var failures []string
	if objectReader, ok := reader.(fortinet.WebFilterObjectReader); ok {
		// One multiplexed request for the three global tables.
		objects := objectReader.ReadWebFilterObjects(ctx, "")
		config.profiles, config.tables, config.groups = objects.Profiles, objects.URLFilterTables, objects.ProfileGroups
		for _, stage := range []string{"list_webfilter_profiles", "list_urlfilter_tables", "list_profile_groups"} {
			if err := objects.Errors[stage]; err != nil {
				failures = append(failures, err.Error())
			}
		}
	} else {
		var err error
		if config.profiles, err = reader.ListWebFilterProfiles(ctx, ""); err != nil {
			failures = append(failures, err.Error())
		}
		if config.tables, err = reader.ListURLFilterTables(ctx, ""); err != nil {
			failures = append(failures, err.Error())
		}
		if config.groups, err = reader.ListProfileGroups(ctx, ""); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		config.warnings = append(config.warnings, fmt.Sprintf("Global ADOM web filter objects of %s could not be read completely (%s); profiles or tables defined only there are unresolved.", managerName, strings.Join(failures, "; ")))
	}
	if ctx.Err() == nil {
		s.webFilter.mu.Lock()
		if s.cacheWriteAllowed(epoch) {
			s.webFilter.config[key] = config
		}
		s.webFilter.mu.Unlock()
	}
	return config
}

// webFilterPolicyUsage maps profile name to the enabled policies that apply
// it directly or through a security profile group, with the device VDOMs
// each policy reaches through package scope or its own install-on list.
func webFilterPolicyUsage(config *webFilterConfig, groups []fortinet.ProfileGroup, snapshot inventory.Snapshot, managerName, adom string) map[string][]WebFilterPolicyUsage {
	groupProfile := make(map[string]string, len(groups))
	for _, group := range groups {
		if _, exists := groupProfile[group.Name]; !exists {
			groupProfile[group.Name] = group.WebFilterProfile
		}
	}
	type packageDevice struct {
		device fortinet.Device
		vdom   string
	}
	byPackage := make(map[string][]packageDevice)
	for _, device := range snapshot.Devices {
		if device.Profile != managerName || device.ADOM != adom {
			continue
		}
		for _, target := range device.PackageTargets {
			byPackage[target.Package] = append(byPackage[target.Package], packageDevice{device: device, vdom: target.VDOM})
		}
	}
	usage := make(map[string][]WebFilterPolicyUsage)
	add := func(packageName, table string, policies []fortinet.FirewallPolicy) {
		for _, policy := range policies {
			if strings.EqualFold(policy.Status, "disable") || strings.EqualFold(policy.UTMStatus, "disable") {
				continue
			}
			if policy.UTMStatus == "" && policy.WebFilterProfile == "" && policy.ProfileGroup == "" {
				continue
			}
			profile, via := "", ""
			if strings.EqualFold(policy.ProfileType, "group") && policy.ProfileGroup != "" {
				profile, via = groupProfile[policy.ProfileGroup], "profile-group:"+policy.ProfileGroup
			} else if policy.WebFilterProfile != "" {
				profile, via = policy.WebFilterProfile, "webfilter-profile"
			}
			if profile == "" {
				continue
			}
			entry := WebFilterPolicyUsage{
				Package: packageName, Table: table, PolicyID: policy.PolicyID, Name: policy.Name,
				Action: policy.Action, Via: via, SSLSSHProfile: policy.SSLSSHProfile, InstallOn: policy.Scope,
			}
			for _, candidate := range byPackage[packageName] {
				if len(policy.Scope) > 0 && !policyScopeIncludes(policy.Scope, candidate.device, candidate.vdom) {
					continue
				}
				entry.devices = append(entry.devices, WebFilterDevice{
					Device: candidate.device.Name, VDOM: candidate.vdom, Package: packageName,
					ConfigStatus: candidate.device.ConfigStatus, ConnectionStatus: candidate.device.ConnectionStatus,
				})
				label := candidate.device.Name
				if candidate.vdom != "" {
					label += "/" + candidate.vdom
				}
				entry.Devices = append(entry.Devices, label)
			}
			usage[profile] = append(usage[profile], entry)
		}
	}
	names := make(map[string]struct{})
	for _, packages := range config.policies {
		for name := range packages {
			names[name] = struct{}{}
		}
	}
	packageNames := make([]string, 0, len(names))
	for name := range names {
		packageNames = append(packageNames, name)
	}
	sort.Strings(packageNames)
	for _, name := range packageNames {
		for _, table := range policyTableNames {
			add(name, table, config.policies[table][name])
		}
	}
	return usage
}

func policyScopeIncludes(scope []fortinet.PackageMember, device fortinet.Device, vdom string) bool {
	for _, member := range scope {
		if member.Device != device.Name && !containsString(device.Groups, member.Device) {
			continue
		}
		if member.VDOM == "" || vdom == "" || member.VDOM == vdom {
			return true
		}
	}
	return false
}

// exemptsFortiGuard reports whether a URL filter exempt action skips
// FortiGuard category filtering. An empty list is the FortiOS default,
// which includes fortiguard.
func exemptsFortiGuard(exempt []string) bool {
	if len(exempt) == 0 {
		return true
	}
	return containsFold(exempt, "fortiguard") || containsFold(exempt, "all")
}

func evaluateWebFilterProfile(profile fortinet.WebFilterProfile, tables []fortinet.URLFilterTable, config *webFilterConfig, target webTarget, ratingIDs []int, ratingSource string, names map[int]CategoryRef) WebFilterProfileResult {
	result := WebFilterProfileResult{
		Profile:             profile.Name,
		Decision:            "unknown",
		FortiGuardFiltering: "enabled",
		InspectionMode:      firstNonEmpty(profile.InspectionMode, profile.FeatureSet),
		URLFilterTable:      profile.URLFilterTable,
	}
	if profile.FortiGuardDisabled {
		result.FortiGuardFiltering = "disabled"
	}

	hasURL := target.Host != ""
	// 1. Static URL filter entries run before FortiGuard category filtering.
	if profile.URLFilterTable != "" && hasURL {
		table := findURLFilterTable(tables, profile.URLFilterTable)
		if table == nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("URL filter table %q referenced by the profile was not found in the ADOM or the global ADOM; static URL entries could not be evaluated.", profile.URLFilterTable))
		} else {
			result.URLFilterTable = table.Name
			entries := append([]fortinet.URLFilterEntry(nil), table.Entries...)
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
			for _, entry := range entries {
				match := matchURLFilterEntry(entry, target)
				if match.Unresolved {
					result.Warnings = append(result.Warnings, "URL filter: "+match.Note)
					continue
				}
				if !match.Matched {
					continue
				}
				entryType := firstNonEmpty(entry.Type, "simple")
				result.URLFilter = &URLFilterEvidence{Table: table.Name, EntryID: entry.ID, Pattern: entry.URL, Type: entryType, Action: entry.Action, Exempt: entry.Exempt}
				switch entry.Action {
				case "block":
					result.Decision = "blocked"
					result.Reason = fmt.Sprintf("Static URL filter table %q entry %d (%s %q) blocks the URL before FortiGuard category filtering.", table.Name, entry.ID, entryType, entry.URL)
					return result
				case "exempt":
					if exemptsFortiGuard(entry.Exempt) {
						result.Decision = "exempt"
						result.Reason = fmt.Sprintf("Static URL filter table %q entry %d (%s %q) exempts the URL from FortiGuard category filtering and the listed scans.", table.Name, entry.ID, entryType, entry.URL)
						return result
					}
					result.Warnings = append(result.Warnings, fmt.Sprintf("Static URL filter entry %d exempts only %s; FortiGuard category filtering still applies.", entry.ID, strings.Join(entry.Exempt, ", ")))
				case "allow", "pass":
					result.Warnings = append(result.Warnings, fmt.Sprintf("Static URL filter entry %d allows the URL, but FortiOS still applies FortiGuard category filtering after an Allow action.", entry.ID))
				case "monitor":
					result.Warnings = append(result.Warnings, fmt.Sprintf("Static URL filter entry %d monitors (logs) the URL; FortiGuard category filtering still applies.", entry.ID))
				default:
					result.Warnings = append(result.Warnings, fmt.Sprintf("Static URL filter entry %d has unrecognized action %q.", entry.ID, entry.Action))
				}
				break
			}
		}
	}

	// 2. Effective category: a stored local rating override wins over the
	// live FortiGuard rating.
	effective := append([]int(nil), ratingIDs...)
	result.CategorySource = ratingSource
	if len(ratingIDs) == 0 {
		result.CategorySource = "none"
	}
	for _, local := range config.localRatings {
		if !hasURL || local.Status == "disable" || !matchSimpleURL(local.URL, target) {
			continue
		}
		ids := make([]int, 0, len(local.Rating))
		refs := make([]CategoryRef, 0, len(local.Rating))
		for _, value := range local.Rating {
			if id, ok := fortinet.ParseCategoryReference(value); ok {
				ids = append(ids, id)
				refs = append(refs, resolveCategory(id, names))
				continue
			}
			if id, ok := localCategoryByName(config.localCategory, value); ok {
				ids = append(ids, id)
				refs = append(refs, resolveCategory(id, names))
				continue
			}
			refs = append(refs, CategoryRef{Name: value, NameSource: "unresolved"})
		}
		result.LocalRating = &LocalRatingEvidence{URL: local.URL, Categories: refs}
		if len(ids) > 0 {
			effective = ids
			result.CategorySource = "local_rating_override"
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Local rating override %q matches but its category %v could not be resolved.", local.URL, local.Rating))
		}
		break
	}
	for _, id := range effective {
		result.EffectiveCategories = append(result.EffectiveCategories, resolveCategory(id, names))
	}

	if profile.FortiGuardDisabled {
		result.Decision = "allowed"
		result.Reason = "FortiGuard category filtering is disabled in this profile (ftgd-disable); only static URL filter entries apply, and none blocked the URL."
		return result
	}
	if len(effective) == 0 {
		result.Decision = "unknown"
		result.Reason = "No category is known (none given and no local rating override matched), so the category action cannot be determined; get it with rate_url."
		return result
	}

	// 3. Category actions. For each category the first filter entry that
	// names it (directly or through its category group) applies; a missing
	// entry means allow. Across several categories the strictest action wins.
	rank := map[string]int{"block": 4, "warning": 3, "authenticate": 2, "monitor": 1, "allow": 0}
	worst, worstAction := -1, "allow"
	for _, id := range effective {
		var applied *CategoryFilterEvidence
		for _, filter := range profile.Filters {
			token := strings.ToLower(strings.TrimSpace(filter.Category))
			viaGroup := ""
			if members, isGroup := fortinet.CategoryGroupMembers(token); isGroup {
				if !containsInt(members, id) {
					continue
				}
				viaGroup = token
			} else if strings.HasPrefix(token, "g") && len(token) == 3 {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Category group %q in filter entry %d is unknown to this server; verify its members on the FortiGate.", filter.Category, filter.ID))
				continue
			} else if filterID, ok := fortinet.ParseCategoryReference(filter.Category); !ok || filterID != id {
				continue
			}
			action := filter.Action
			if action == "" {
				action = "allow"
			}
			applied = &CategoryFilterEvidence{EntryID: filter.ID, Category: categoryLabel(id, names), Action: action, ViaGroup: viaGroup}
			break
		}
		if applied == nil {
			applied = &CategoryFilterEvidence{Category: categoryLabel(id, names), Action: "allow", Implicit: true}
		}
		result.CategoryFilters = append(result.CategoryFilters, *applied)
		if rank[applied.Action] > worst {
			worst, worstAction = rank[applied.Action], applied.Action
		}
	}
	switch worstAction {
	case "block":
		result.Decision = "blocked"
		result.Reason = "A FortiGuard category filter entry blocks the URL's category."
	case "warning":
		result.Decision = "warning"
		result.Reason = "The category action is warning: the user sees a warning page and may proceed."
	case "authenticate":
		result.Decision = "authenticate"
		result.Reason = "The category action is authenticate: access requires user authentication in the configured groups."
	case "monitor":
		result.Decision = "monitored"
		result.Reason = "The category action is monitor: the URL is allowed and logged."
	default:
		result.Decision = "allowed"
		result.Reason = "No category filter entry blocks the URL's category; FortiOS treats a missing entry as allow."
	}
	if result.URLFilter != nil && result.URLFilter.Action != "block" {
		result.Reason += fmt.Sprintf(" A static URL filter entry (%s) matched first but does not override category filtering.", result.URLFilter.Action)
	}
	return result
}

func findURLFilterTable(tables []fortinet.URLFilterTable, reference string) *fortinet.URLFilterTable {
	reference = strings.TrimSpace(reference)
	for index := range tables {
		if tables[index].Name == reference {
			return &tables[index]
		}
	}
	if id, err := strconv.Atoi(reference); err == nil {
		for index := range tables {
			if tables[index].ID == id {
				return &tables[index]
			}
		}
	}
	return nil
}

func localCategoryByName(categories []fortinet.LocalCategory, name string) (int, bool) {
	wanted := strings.ToLower(strings.TrimSpace(name))
	for _, category := range categories {
		if strings.ToLower(strings.TrimSpace(category.Description)) == wanted {
			return category.ID, true
		}
	}
	return 0, false
}

func resolveCategory(id int, names map[int]CategoryRef) CategoryRef {
	if ref, ok := names[id]; ok {
		ref.ID = id
		return ref
	}
	return CategoryRef{ID: id, NameSource: "unknown"}
}

func categoryLabel(id int, names map[int]CategoryRef) string {
	ref := resolveCategory(id, names)
	if ref.Name == "" {
		return strconv.Itoa(id)
	}
	return fmt.Sprintf("%d (%s)", id, ref.Name)
}

func categoryIDs(refs []CategoryRef) []int {
	ids := make([]int, 0, len(refs))
	for _, ref := range refs {
		if ref.ID > 0 || strings.EqualFold(ref.Name, "Not Rated") || strings.EqualFold(ref.Name, "Unrated") {
			ids = append(ids, ref.ID)
		}
	}
	return ids
}

func cloneCategoryNames(names map[int]CategoryRef) map[int]CategoryRef {
	clone := make(map[int]CategoryRef, len(names))
	maps.Copy(clone, names)
	return clone
}

func containsInt(values []int, wanted int) bool {
	return slices.Contains(values, wanted)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func appendUniqueStrings(target *[]string, values ...string) {
	for _, value := range values {
		if value == "" || containsString(*target, value) {
			continue
		}
		*target = append(*target, value)
	}
}

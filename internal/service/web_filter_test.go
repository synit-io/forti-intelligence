package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

type webFilterManager struct {
	*fakeManager
	profiles       []fortinet.WebFilterProfile
	tables         []fortinet.URLFilterTable
	localRatings   []fortinet.LocalRating
	localCats      []fortinet.LocalCategory
	groups         []fortinet.ProfileGroup
	globalProfiles []fortinet.WebFilterProfile
	policies6      map[string][]fortinet.FirewallPolicy
	statuses       map[string]fortinet.PackageStatus
	rating         fortinet.URLRating
	ratingErr      error
	ratingCalls    int
	ratingDevices  []string
	profileReads   int
	globalReads    int
	statusReads    int
}

func (m *webFilterManager) ListWebFilterProfiles(_ context.Context, adom string) ([]fortinet.WebFilterProfile, error) {
	if adom == "" {
		m.globalReads++
		return m.globalProfiles, nil
	}
	m.profileReads++
	return m.profiles, nil
}
func (m *webFilterManager) ListURLFilterTables(_ context.Context, adom string) ([]fortinet.URLFilterTable, error) {
	if adom == "" {
		return nil, nil
	}
	return m.tables, nil
}
func (m *webFilterManager) ListLocalRatings(context.Context, string) ([]fortinet.LocalRating, error) {
	return m.localRatings, nil
}
func (m *webFilterManager) ListLocalCategories(context.Context, string) ([]fortinet.LocalCategory, error) {
	return m.localCats, nil
}
func (m *webFilterManager) ListProfileGroups(_ context.Context, adom string) ([]fortinet.ProfileGroup, error) {
	if adom == "" {
		return nil, nil
	}
	return m.groups, nil
}
func (m *webFilterManager) ListFortiGuardCategories(context.Context, string) (map[int]string, error) {
	return nil, errors.New("not supported")
}
func (m *webFilterManager) ListFortiGateCategories(context.Context, string, string, string) (map[int]string, error) {
	return map[int]string{52: "Information Technology", 37: "Social Networking"}, nil
}
func (m *webFilterManager) ListIPv6Policies(_ context.Context, adom, pkg string) ([]fortinet.FirewallPolicy, error) {
	policies, ok := m.policies6[adom+"/"+pkg]
	if !ok {
		return nil, errors.New("fmg API result: code -3: Object does not exist")
	}
	return policies, nil
}
func (m *webFilterManager) PackageStatusBatch(_ context.Context, _ string, targets []fortinet.PackageMember) (map[string]fortinet.PackageStatus, error) {
	m.statusReads++
	result := make(map[string]fortinet.PackageStatus)
	for _, target := range targets {
		if status, ok := m.statuses[target.Device+"/"+target.VDOM]; ok {
			result[target.Device+"/"+target.VDOM] = status
		}
	}
	return result, nil
}
func (m *webFilterManager) LookupURLRating(_ context.Context, _, device, _, target string) (fortinet.URLRating, error) {
	m.ratingCalls++
	m.ratingDevices = append(m.ratingDevices, device)
	if m.ratingErr != nil {
		return fortinet.URLRating{}, m.ratingErr
	}
	rating := m.rating
	rating.URL = target
	return rating, nil
}

func newWebFilterService(t *testing.T) (*Service, *webFilterManager) {
	t.Helper()
	base := &fakeManager{
		name:  "fmg-a",
		adoms: []fortinet.ADOM{{Name: "test-adom-primary"}},
		devices: map[string][]fortinet.Device{"test-adom-primary": {
			{Name: "edge-down", ADOM: "test-adom-primary", Profile: "fmg-a", ConnectionStatus: "down", VDOMs: []string{"root"}},
			{Name: "edge-1", ADOM: "test-adom-primary", Profile: "fmg-a", ConnectionStatus: "up", ConfigStatus: "insync", VDOMs: []string{"root"}},
			{Name: "edge-2", ADOM: "test-adom-primary", Profile: "fmg-a", ConnectionStatus: "up", ConfigStatus: "modified", VDOMs: []string{"root"}},
		}},
		packages: map[string][]fortinet.PolicyPackage{"test-adom-primary": {
			{Name: "default", Members: []fortinet.PackageMember{{Device: "edge-1", VDOM: "root"}}},
			{Name: "branch", Members: []fortinet.PackageMember{{Device: "edge-2", VDOM: "root"}}},
		}},
		policies: map[string][]fortinet.FirewallPolicy{
			"test-adom-primary/default": {
				{PolicyID: 10, Name: "staff", Status: "enable", Action: "accept", UTMStatus: "enable", ProfileType: "single", WebFilterProfile: "corp-web", SSLSSHProfile: "certificate-inspection"},
				{PolicyID: 11, Name: "guests", Status: "enable", Action: "accept", UTMStatus: "enable", ProfileType: "group", ProfileGroup: "grp-a", Scope: []fortinet.PackageMember{{Device: "edge-1", VDOM: "root"}}},
				{PolicyID: 12, Name: "old", Status: "disable", UTMStatus: "enable", ProfileType: "single", WebFilterProfile: "unused-web"},
				{PolicyID: 13, Name: "exempt", Status: "enable", UTMStatus: "enable", ProfileType: "single", WebFilterProfile: "exempt-web"},
				{PolicyID: 14, Name: "partial-exempt", Status: "enable", UTMStatus: "enable", ProfileType: "single", WebFilterProfile: "exempt-av-web"},
			},
			"test-adom-primary/branch": {
				{PolicyID: 20, Name: "branch-users", Status: "enable", Action: "accept", UTMStatus: "enable", ProfileType: "single", WebFilterProfile: "global-web"},
			},
		},
	}
	manager := &webFilterManager{
		fakeManager: base,
		profiles: []fortinet.WebFilterProfile{
			{Name: "corp-web", InspectionMode: "flow-based", URLFilterTable: "corp-urls", Filters: []fortinet.CategoryFilter{{ID: 1, Category: "37", Action: "block"}, {ID: 2, Category: "52", Action: "monitor"}}},
			{Name: "strict-web", Filters: []fortinet.CategoryFilter{{ID: 1, Category: "52", Action: "block"}}},
			{Name: "exempt-web", URLFilterTable: "3"},
			{Name: "exempt-av-web", URLFilterTable: "av-only"},
			{Name: "unused-web"},
		},
		globalProfiles: []fortinet.WebFilterProfile{{Name: "global-web", Filters: []fortinet.CategoryFilter{{ID: 1, Category: "g07", Action: "block"}}}},
		tables: []fortinet.URLFilterTable{
			{ID: 1, Name: "corp-urls", Entries: []fortinet.URLFilterEntry{
				{ID: 1, URL: "intranet.example.com", Type: "simple", Action: "allow", Status: "enable"},
				{ID: 2, URL: "*.blocked.example", Type: "wildcard", Action: "block", Status: "enable"},
				{ID: 3, URL: "^bad\\.", Type: "regex", Action: "block", Status: "enable"},
				{ID: 4, URL: "disabled.example", Type: "simple", Action: "block", Status: "disable"},
			}},
			{ID: 3, Name: "exempt-urls", Entries: []fortinet.URLFilterEntry{{ID: 1, URL: "example.com", Type: "simple", Action: "exempt", Status: "enable", Exempt: []string{"fortiguard"}}}},
			{ID: 4, Name: "av-only", Entries: []fortinet.URLFilterEntry{{ID: 1, URL: "example.com", Type: "simple", Action: "exempt", Status: "enable", Exempt: []string{"av", "dlp"}}}},
		},
		localRatings: []fortinet.LocalRating{{URL: "intranet.example.com", Rating: []string{"140"}, Status: "enable"}},
		localCats:    []fortinet.LocalCategory{{ID: 140, Description: "Intranet", Status: "enable"}},
		groups:       []fortinet.ProfileGroup{{Name: "grp-a", WebFilterProfile: "strict-web"}},
		policies6: map[string][]fortinet.FirewallPolicy{"test-adom-primary/default": {
			{PolicyID: 30, Name: "staff-v6", Status: "enable", Action: "accept", UTMStatus: "enable", ProfileType: "single", WebFilterProfile: "corp-web"},
		}},
		statuses: map[string]fortinet.PackageStatus{
			"edge-1/root": {Device: "edge-1", VDOM: "root", Package: "default", Status: "installed"},
			"edge-2/root": {Device: "edge-2", VDOM: "root", Package: "branch", Status: "modified"},
		},
		rating: fortinet.URLRating{CategoryIDs: []int{52}, Resource: "/api/v2/monitor/utm/rating-lookup/select"},
	}
	cfg := config.Default()
	cfg.Profiles = []config.ProfileConfig{{Name: "fmg-a", Product: config.ProductFortiManager, URL: "https://fmg.invalid", Username: "u", Password: "p", Default: true}}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": manager}, 0, 1)
	store.Refresh(context.Background())
	return New(cfg, store, map[string]fortinet.Manager{"fmg-a": manager}, nil), manager
}

func profileResult(t *testing.T, output WebFilterCheckOutput, name string) WebFilterProfileResult {
	t.Helper()
	for _, result := range output.Profiles {
		if result.Profile == name {
			return result
		}
	}
	t.Fatalf("profile %s missing from %#v", name, output.Profiles)
	return WebFilterProfileResult{}
}

func TestCheckWebFilterMapsPoliciesForCategoryAndURL(t *testing.T) {
	app, manager := newWebFilterService(t)
	output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "https://www.example.com/path"})
	if err != nil {
		t.Fatalf("CheckWebFilter() error = %v", err)
	}
	if output.Host != "www.example.com" || output.Path != "/path" {
		t.Fatalf("target = %q %q", output.Host, output.Path)
	}
	if len(output.Categories) != 1 || output.Categories[0].ID != 52 || output.Categories[0].Name != "Information Technology" || manager.ratingCalls != 0 {
		t.Fatalf("categories = %#v rating calls = %d", output.Categories, manager.ratingCalls)
	}
	corp := profileResult(t, output, "corp-web")
	if corp.Decision != "monitored" || len(corp.CategoryFilters) != 1 || corp.CategoryFilters[0].Action != "monitor" || corp.CategorySource != "requested_category" || corp.Source != "adom" {
		t.Fatalf("corp-web = %#v", corp)
	}
	if len(corp.Policies) != 2 || corp.Policies[0].PolicyID != 10 || corp.Policies[0].Table != "policy" || corp.Policies[1].PolicyID != 30 || corp.Policies[1].Table != "policy6" || corp.Policies[0].Devices[0] != "edge-1/root" {
		t.Fatalf("corp-web policies = %#v", corp.Policies)
	}
	if len(corp.Devices) != 1 || corp.Devices[0].Device != "edge-1" || corp.Devices[0].PackageStatus != "installed" || corp.Devices[0].ConfigStatus != "insync" || corp.Devices[0].ConnectionStatus != "up" {
		t.Fatalf("corp-web devices = %#v", corp.Devices)
	}
	strict := profileResult(t, output, "strict-web")
	if strict.Decision != "blocked" || len(strict.Policies) != 1 || strict.Policies[0].Via != "profile-group:grp-a" || len(strict.Policies[0].InstallOn) != 1 {
		t.Fatalf("strict-web = %#v", strict)
	}
	global := profileResult(t, output, "global-web")
	if global.Source != "global" || global.Decision != "blocked" || global.CategoryFilters[0].ViaGroup != "g07" || len(global.Devices) != 1 || global.Devices[0].Device != "edge-2" || global.Devices[0].PackageStatus != "modified" {
		t.Fatalf("global-web = %#v", global)
	}
	exempt := profileResult(t, output, "exempt-web")
	if exempt.Decision != "exempt" || exempt.URLFilter == nil || exempt.URLFilter.Table != "exempt-urls" || exempt.URLFilterTable != "exempt-urls" {
		t.Fatalf("exempt-web = %#v", exempt)
	}
	partial := profileResult(t, output, "exempt-av-web")
	if partial.Decision != "allowed" || partial.URLFilter == nil || partial.URLFilter.Action != "exempt" || !strings.Contains(strings.Join(partial.Warnings, " "), "exempts only av, dlp") || !partial.CategoryFilters[0].Implicit {
		t.Fatalf("exempt-av-web = %#v", partial)
	}
	unused := profileResult(t, output, "unused-web")
	if unused.Decision != "allowed" || len(unused.Policies) != 0 || len(unused.Warnings) != 0 {
		t.Fatalf("unused-web = %#v", unused)
	}
	if strings.Join(output.Summary.Blocked, ",") != "strict-web (test-adom-primary),global-web (test-adom-primary)" || len(output.Summary.Allowed) != 4 || strings.Join(output.Summary.UnusedProfiles, ",") != "unused-web (test-adom-primary)" {
		t.Fatalf("summary = %#v", output.Summary)
	}
	if output.Summary.PoliciesEvaluated != 7 || output.Summary.PackagesEvaluated != 2 || output.Summary.ProfilesEvaluated != 6 {
		t.Fatalf("summary counts = %#v", output.Summary)
	}

	// Configuration, global objects and package status are cached; the
	// rating is fresh per lookup.
	if _, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "www.example.com"}); err != nil {
		t.Fatal(err)
	}
	if manager.ratingCalls != 0 || manager.profileReads != 1 || manager.globalReads != 1 || manager.statusReads != 1 {
		t.Fatalf("reads rating=%d profiles=%d global=%d status=%d", manager.ratingCalls, manager.profileReads, manager.globalReads, manager.statusReads)
	}
	if _, err := app.RefreshInventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "www.example.com"}); err != nil {
		t.Fatal(err)
	}
	if manager.profileReads != 2 || manager.statusReads != 2 {
		t.Fatalf("refresh_inventory must drop cached web filter reads: profiles=%d status=%d", manager.profileReads, manager.statusReads)
	}
}

func TestCheckWebFilterScopesResultsToDevice(t *testing.T) {
	app, manager := newWebFilterService(t)
	output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "www.example.com", Device: "edge-2"})
	if err != nil {
		t.Fatalf("CheckWebFilter() error = %v", err)
	}
	if manager.ratingCalls != 0 {
		t.Fatalf("check_web_filter must not rate: %d calls", manager.ratingCalls)
	}
	if len(output.Profiles) != 1 || output.Profiles[0].Profile != "global-web" || output.Profiles[0].Decision != "blocked" {
		t.Fatalf("profiles = %#v", output.Profiles)
	}
	// Only edge-2's package (branch) is read; every other profile is not on
	// this device, and "unused" cannot be decided from a device lookup.
	if strings.Join(output.Summary.NotOnDevice, ",") != "corp-web (test-adom-primary),strict-web (test-adom-primary),exempt-web (test-adom-primary),exempt-av-web (test-adom-primary),unused-web (test-adom-primary)" || len(output.Summary.UnusedProfiles) != 0 || strings.Join(output.Summary.Blocked, ",") != "global-web (test-adom-primary)" || output.Summary.PackagesEvaluated != 1 || !output.Complete {
		t.Fatalf("summary = %#v", output.Summary)
	}
}

func TestCheckWebFilterAppliesLocalRatingOverrideAndAllowEntry(t *testing.T) {
	app, _ := newWebFilterService(t)
	output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "intranet.example.com/portal", ADOM: "test-adom-primary"})
	if err != nil {
		t.Fatalf("CheckWebFilter() error = %v", err)
	}
	corp := profileResult(t, output, "corp-web")
	if corp.Decision != "allowed" || corp.CategorySource != "local_rating_override" || corp.LocalRating == nil || corp.LocalRating.Categories[0].Name != "Intranet" {
		t.Fatalf("corp-web = %#v", corp)
	}
	if corp.URLFilter == nil || corp.URLFilter.Action != "allow" || !strings.Contains(strings.Join(corp.Warnings, " "), "still applies") || !corp.CategoryFilters[0].Implicit {
		t.Fatalf("corp-web evidence = %#v", corp)
	}
	strict := profileResult(t, output, "strict-web")
	if strict.Decision != "allowed" || strict.CategorySource != "local_rating_override" {
		t.Fatalf("strict-web = %#v", strict)
	}
}

func TestCheckWebFilterStaticEntriesBlockBeforeCategories(t *testing.T) {
	app, _ := newWebFilterService(t)
	for _, target := range []string{"http://x.blocked.example/", "bad.example.org"} {
		output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: target})
		if err != nil {
			t.Fatalf("CheckWebFilter(%s) error = %v", target, err)
		}
		corp := profileResult(t, output, "corp-web")
		if corp.Decision != "blocked" || corp.URLFilter == nil || corp.URLFilter.Action != "block" || len(corp.CategoryFilters) != 0 {
			t.Fatalf("corp-web for %s = %#v", target, corp)
		}
	}
	output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "disabled.example"})
	if err != nil {
		t.Fatal(err)
	}
	if corp := profileResult(t, output, "corp-web"); corp.URLFilter != nil {
		t.Fatalf("disabled entry must not match: %#v", corp)
	}
}

func TestCheckWebFilterCategoryInputs(t *testing.T) {
	app, manager := newWebFilterService(t)
	for _, category := range []string{"37", "Social Networking", " social networking , 37 "} {
		output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: category, URL: "social.example"})
		if err != nil {
			t.Fatalf("CheckWebFilter(%q) error = %v", category, err)
		}
		if corp := profileResult(t, output, "corp-web"); corp.Decision != "blocked" || corp.CategorySource != "requested_category" || len(output.Categories) != 1 || output.Categories[0].ID != 37 {
			t.Fatalf("category %q: corp-web = %#v categories = %#v", category, corp, output.Categories)
		}
	}
	// Category only: URL-specific rules are skipped and said so.
	output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52"})
	if err != nil {
		t.Fatal(err)
	}
	if exempt := profileResult(t, output, "exempt-web"); exempt.Decision != "allowed" || exempt.URLFilter != nil {
		t.Fatalf("category-only exempt-web = %#v", exempt)
	}
	if !strings.Contains(strings.Join(output.Warnings, " "), "No url given") {
		t.Fatalf("warnings = %v", output.Warnings)
	}
	// URL only: category actions are unknown, URL rules still decide.
	output, err = app.CheckWebFilter(context.Background(), CheckWebFilterInput{URL: "unknown.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if corp := profileResult(t, output, "corp-web"); corp.Decision != "unknown" {
		t.Fatalf("corp-web = %#v", corp)
	}
	if exempt := profileResult(t, output, "exempt-web"); exempt.Decision != "exempt" {
		t.Fatalf("exempt-web = %#v", exempt)
	}
	if len(output.Summary.Unknown) != 5 || !strings.Contains(strings.Join(output.Warnings, " "), "No category given") || manager.ratingCalls != 0 {
		t.Fatalf("summary = %#v warnings = %v", output.Summary, output.Warnings)
	}
}

func TestRateURLReportsFailedRating(t *testing.T) {
	app, manager := newWebFilterService(t)
	manager.ratingErr = errors.New("fmg API result: code -11: No permission for the resource")
	app.cfg.Rating.Device = "edge-1"
	output, err := app.RateURL(context.Background(), RateURLInput{URL: "unknown.example.com"})
	if err != nil {
		t.Fatalf("RateURL() error = %v", err)
	}
	if output.Rating.Source != "none" || output.Rating.Error == "" || output.Rating.ErrorDetails == nil || len(output.Rating.Attempts) != 1 || output.NextStep != "" {
		t.Fatalf("rating = %#v next = %q", output.Rating, output.NextStep)
	}
}

func TestWebFilterToolsRejectInvalidInput(t *testing.T) {
	app, _ := newWebFilterService(t)
	for _, input := range []CheckWebFilterInput{{}, {URL: "not a url"}, {Category: "Nonexistent Category"}, {Category: "300"}} {
		if _, err := app.CheckWebFilter(context.Background(), input); err == nil {
			t.Fatalf("CheckWebFilter(%#v) error = nil", input)
		}
	}
	for _, input := range []RateURLInput{{URL: ""}, {URL: "not a url"}} {
		if _, err := app.RateURL(context.Background(), input); err == nil {
			t.Fatalf("RateURL(%#v) error = nil", input)
		}
	}
	if _, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", Profile: "nope"}); err == nil || !strings.Contains(err.Error(), "fmg-a") {
		t.Fatalf("unknown profile error = %v, want configured profile names", err)
	}
	output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", Profile: "fmg-a", ADOM: "test-adom-missing"})
	if err != nil || !strings.Contains(strings.Join(output.Warnings, " "), `ADOM "test-adom-missing" is not in the current inventory`) {
		t.Fatalf("unknown ADOM: err=%v warnings=%v", err, output.Warnings)
	}
}

func TestURLPatternMatching(t *testing.T) {
	target, err := parseWebTarget("HTTPS://Www.Example.com:8443/Docs/index.html?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "www.example.com" || target.Path != "/Docs/index.html?x=1" {
		t.Fatalf("target = %#v", target)
	}
	cases := []struct {
		pattern string
		want    bool
	}{
		{"example.com", true},
		{"www.example.com/docs", true},
		{"https://example.com/", true},
		{"other.com", false},
		{"ample.com", false},
		{"www.example.com/admin", false},
	}
	for _, testCase := range cases {
		if got := matchSimpleURL(testCase.pattern, target); got != testCase.want {
			t.Errorf("matchSimpleURL(%q) = %v, want %v", testCase.pattern, got, testCase.want)
		}
	}
	wildcard := func(pattern string, host string) bool {
		expression, err := wildcardToRegexp(pattern)
		if err != nil {
			t.Fatal(err)
		}
		return expression.MatchString(host)
	}
	if !wildcard("*.fortinet.com", "support.fortinet.com") || !wildcard("*.fortinet.com", "fortinet.com") || wildcard("*.fortinet.com", "fortinet.community") {
		t.Fatal("wildcard base-domain semantics wrong")
	}
	if match := matchURLFilterEntry(fortinet.URLFilterEntry{ID: 9, URL: "(unclosed", Type: "regex", Status: "enable"}, target); !match.Unresolved || match.Matched {
		t.Fatalf("invalid regex = %#v, want unresolved", match)
	}
	if match := matchURLFilterEntry(fortinet.URLFilterEntry{ID: 8, URL: "example.com", Type: "simple", Status: "enable", ReferrerHost: "portal.example.com"}, target); !match.Unresolved || !strings.Contains(match.Note, "referrer") {
		t.Fatalf("referrer entry = %#v, want unresolved note", match)
	}
}

// fakeRatingProxy is a dedicated FortiManager rating account.
type fakeRatingProxy struct {
	devices []string
}

func (p *fakeRatingProxy) LookupURLRating(_ context.Context, _, device, _, target string) (fortinet.URLRating, error) {
	p.devices = append(p.devices, device)
	return fortinet.URLRating{URL: target, CategoryIDs: []int{36}, Resource: "/api/v2/monitor/utm/rating-lookup/select"}, nil
}
func (p *fakeRatingProxy) ListFortiGateCategories(context.Context, string, string, string) (map[int]string, error) {
	return map[int]string{36: "News and Media"}, nil
}

func TestRateURLPrefersConfiguredRatingDevice(t *testing.T) {
	app, manager := newWebFilterService(t)
	app.cfg.Rating.Device = "edge-2"
	output, err := app.RateURL(context.Background(), RateURLInput{URL: "https://www.heise.de/", Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(manager.ratingDevices, ",") != "edge-2" || output.Rating.Device != "edge-2" || output.Rating.Selection != "configured rating device" || output.Rating.Account != "profile account" {
		t.Fatalf("rating = %#v devices = %v", output.Rating, manager.ratingDevices)
	}
	if output.Host != "www.heise.de" || !strings.Contains(output.NextStep, `category "52"`) || !strings.Contains(output.NextStep, "check_web_filter") {
		t.Fatalf("host = %q next = %q", output.Host, output.NextStep)
	}
}

// A category the static table does not know arrives as a name; the
// FortiGate's category list resolves it, and "Unrated" maps to category 0.
func TestRateURLResolvesNamedCategories(t *testing.T) {
	app, manager := newWebFilterService(t)
	manager.rating = fortinet.URLRating{CategoryNames: []string{"Social Networking"}}
	output, err := app.RateURL(context.Background(), RateURLInput{URL: "jacob-tks.com", Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Rating.Categories) != 1 || output.Rating.Categories[0].ID != 37 || !strings.Contains(output.NextStep, `category "37"`) {
		t.Fatalf("categories = %#v next = %q", output.Rating.Categories, output.NextStep)
	}
	manager.rating = fortinet.URLRating{CategoryNames: []string{"Brand New Category"}}
	output, _ = app.RateURL(context.Background(), RateURLInput{URL: "brand-new.example", Device: "edge-1"})
	if len(output.Rating.Categories) != 1 || output.Rating.Categories[0].Name != "Brand New Category" || !strings.Contains(output.NextStep, `category "Brand New Category"`) {
		t.Fatalf("unknown name: categories = %#v next = %q", output.Rating.Categories, output.NextStep)
	}
	manager.rating = fortinet.URLRating{CategoryNames: []string{"Unrated"}}
	output, _ = app.RateURL(context.Background(), RateURLInput{URL: "unrated.example", Device: "edge-1"})
	if len(output.Rating.Categories) != 1 || output.Rating.Categories[0].ID != 0 || !strings.Contains(output.NextStep, `category "0"`) {
		t.Fatalf("unrated: categories = %#v next = %q", output.Rating.Categories, output.NextStep)
	}
}

func TestRateURLFallsBackFromConfiguredToRequestedDevice(t *testing.T) {
	app, manager := newWebFilterService(t)
	app.cfg.Rating.Device = "edge-down"
	output, err := app.RateURL(context.Background(), RateURLInput{URL: "www.heise.de", Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if output.Rating.Device != "edge-1" || output.Rating.Selection != "requested device" || strings.Join(manager.ratingDevices, ",") != "edge-1" || !strings.Contains(strings.Join(output.Rating.AttemptErrors, " "), "edge-down: offline") {
		t.Fatalf("rating = %#v devices = %v", output.Rating, manager.ratingDevices)
	}
}

func TestRateURLNeverPicksAnArbitraryDevice(t *testing.T) {
	app, manager := newWebFilterService(t)
	output, err := app.RateURL(context.Background(), RateURLInput{URL: "www.heise.de"})
	if err != nil {
		t.Fatal(err)
	}
	if manager.ratingCalls != 0 || output.Rating.Source != "none" || !strings.Contains(output.Rating.Error, "pass device") || len(output.Rating.Attempts) != 0 {
		t.Fatalf("rating = %#v calls = %d", output.Rating, manager.ratingCalls)
	}
}

func TestRateURLUsesDedicatedRatingAccount(t *testing.T) {
	app, manager := newWebFilterService(t)
	proxy := &fakeRatingProxy{}
	app.SetRatingClient("fmg-a", proxy)
	output, err := app.RateURL(context.Background(), RateURLInput{URL: "www.heise.de", Device: "edge-2"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(proxy.devices, ",") != "edge-2" || manager.ratingCalls != 0 || output.Rating.Account != "dedicated rating account" || len(output.Rating.Categories) != 1 || output.Rating.Categories[0].Name != "News and Media" {
		t.Fatalf("rating = %#v proxy = %v manager calls = %d", output.Rating, proxy.devices, manager.ratingCalls)
	}
}

func TestCheckWebFilterReadsSecurityAndProxyPolicies(t *testing.T) {
	app, manager := newWebFilterService(t)
	tables := &tableManager{webFilterManager: manager, extra: map[string][]fortinet.FirewallPolicy{
		"security-policy/test-adom-primary/default": {{PolicyID: 40, Name: "ngfw-staff", Status: "enable", Action: "accept", WebFilterProfile: "unused-web"}},
		"proxy-policy/test-adom-primary/default":    {{PolicyID: 50, Name: "explicit-proxy", Status: "enable", Action: "accept", UTMStatus: "enable", WebFilterProfile: "strict-web"}},
	}}
	cfg := app.cfg
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": tables}, 0, 1)
	store.Refresh(context.Background())
	app = New(cfg, store, map[string]fortinet.Manager{"fmg-a": tables}, nil)
	output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	unused := profileResult(t, output, "unused-web")
	if len(unused.Policies) != 1 || unused.Policies[0].Table != "security-policy" || strings.Contains(strings.Join(output.Summary.UnusedProfiles, ","), "unused-web") {
		t.Fatalf("unused-web = %#v summary = %#v", unused.Policies, output.Summary)
	}
	strict := profileResult(t, output, "strict-web")
	found := false
	for _, policy := range strict.Policies {
		if policy.Table == "proxy-policy" && policy.PolicyID == 50 {
			found = true
		}
	}
	if !found {
		t.Fatalf("strict-web policies = %#v, want proxy-policy 50", strict.Policies)
	}
	if output.Summary.PoliciesEvaluated != 9 {
		t.Fatalf("policies evaluated = %d, want 7 firewall + 2 extra", output.Summary.PoliciesEvaluated)
	}
}

type tableManager struct {
	*webFilterManager
	extra map[string][]fortinet.FirewallPolicy
}

func (m *tableManager) ListPolicyTable(_ context.Context, adom, pkg, table string) ([]fortinet.FirewallPolicy, error) {
	policies, ok := m.extra[table+"/"+adom+"/"+pkg]
	if !ok {
		return nil, errors.New("fmg API result: code -3: Object does not exist")
	}
	return policies, nil
}

// silentRatingProxy never answers for the listed devices, like a FortiGate
// that cannot reach FortiGuard.
type silentRatingProxy struct {
	silent  map[string]bool
	devices []string
}

func (p *silentRatingProxy) LookupURLRating(ctx context.Context, _, device, _, target string) (fortinet.URLRating, error) {
	p.devices = append(p.devices, device)
	if p.silent[device] {
		<-ctx.Done()
		return fortinet.URLRating{}, ctx.Err()
	}
	return fortinet.URLRating{URL: target, CategoryIDs: []int{52}}, nil
}
func (p *silentRatingProxy) ListFortiGateCategories(context.Context, string, string, string) (map[int]string, error) {
	return nil, errors.New("not needed")
}

func TestRateURLBoundsSilentRatingFortiGate(t *testing.T) {
	previous := ratingAttemptTimeout
	ratingAttemptTimeout = 100 * time.Millisecond
	defer func() { ratingAttemptTimeout = previous }()

	app, _ := newWebFilterService(t)
	app.cfg.Rating.Device = "edge-2"
	proxy := &silentRatingProxy{silent: map[string]bool{"edge-2": true}}
	app.SetRatingClient("fmg-a", proxy)
	started := time.Now()
	output, err := app.RateURL(context.Background(), RateURLInput{URL: "www.heise.de", Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("lookup took %v; a silent rating FortiGate must be bounded", elapsed)
	}
	if strings.Join(proxy.devices, ",") != "edge-2,edge-1" || output.Rating.Device != "edge-1" || !strings.Contains(strings.Join(output.Rating.AttemptErrors, " "), "edge-2 (dedicated rating account): no answer within 100ms") {
		t.Fatalf("rating = %#v devices = %v", output.Rating, proxy.devices)
	}

	// Both devices silent: a recent rating of the same URL still answers
	// from the rating cache without asking any FortiGate.
	proxy.silent["edge-1"] = true
	proxy.devices = nil
	output, err = app.RateURL(context.Background(), RateURLInput{URL: "www.heise.de", Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !output.Rating.Cached || output.Rating.Device != "edge-1" || len(proxy.devices) != 0 || len(output.Rating.Categories) != 1 {
		t.Fatalf("rating = %#v devices = %v, want the cached rating", output.Rating, proxy.devices)
	}
	// An unrated URL with both devices silent: the tool answers with the reason.
	output, err = app.RateURL(context.Background(), RateURLInput{URL: "www.example.org", Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if output.Rating.Source != "none" || output.Rating.Cached || !strings.Contains(output.Rating.Error, "timed out") {
		t.Fatalf("rating = %#v", output.Rating)
	}
}

// countingPolicyManager counts package policy reads and can slow them down.
type countingPolicyManager struct {
	*webFilterManager
	mu    sync.Mutex
	reads map[string]int
	delay time.Duration
}

func (m *countingPolicyManager) ListPolicies(ctx context.Context, adom, pkg string) ([]fortinet.FirewallPolicy, error) {
	m.mu.Lock()
	m.reads[pkg]++
	m.mu.Unlock()
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.webFilterManager.ListPolicies(ctx, adom, pkg)
}

func (m *countingPolicyManager) readCount(pkg string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reads[pkg]
}

func newCountingWebFilterService(t *testing.T, delay time.Duration) (*Service, *countingPolicyManager) {
	t.Helper()
	base, manager := newWebFilterService(t)
	counting := &countingPolicyManager{webFilterManager: manager, reads: map[string]int{}, delay: delay}
	store := inventory.NewStore(map[string]fortinet.Manager{"fmg-a": counting}, 0, 1)
	store.Refresh(context.Background())
	return New(base.cfg, store, map[string]fortinet.Manager{"fmg-a": counting}, nil), counting
}

func TestCheckWebFilterReadsOnlyTheDevicesPackages(t *testing.T) {
	app, manager := newCountingWebFilterService(t, 0)
	output, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "www.example.com", Device: "edge-2"})
	if err != nil {
		t.Fatal(err)
	}
	if manager.readCount("branch") != 1 || manager.readCount("default") != 0 || output.Summary.PackagesEvaluated != 1 || !output.Complete {
		t.Fatalf("reads branch=%d default=%d packages=%d complete=%v", manager.readCount("branch"), manager.readCount("default"), output.Summary.PackagesEvaluated, output.Complete)
	}
}

func TestCheckWebFilterAnswersWithinBudgetAndCompletesFromCache(t *testing.T) {
	app, manager := newCountingWebFilterService(t, 400*time.Millisecond)
	app.timeout = 150 * time.Millisecond
	started := time.Now()
	first, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 350*time.Millisecond {
		t.Fatalf("first lookup took %v, want an answer within the budget", elapsed)
	}
	if first.Complete || !strings.Contains(strings.Join(first.Warnings, " "), "still being read") || len(first.Profiles) == 0 {
		t.Fatalf("first lookup complete=%v warnings=%v profiles=%d", first.Complete, first.Warnings, len(first.Profiles))
	}
	if corp := profileResult(t, first, "corp-web"); corp.Decision != "monitored" || len(corp.Policies) != 0 {
		t.Fatalf("pending corp-web = %#v", corp)
	}
	if len(first.Summary.UnusedProfiles) != 0 {
		t.Fatalf("pending usage must not report unused profiles: %v", first.Summary.UnusedProfiles)
	}

	// The background load finishes into the cache; the next lookup is complete.
	deadline := time.Now().Add(3 * time.Second)
	for {
		app.webFilter.mu.Lock()
		running := len(app.webFilter.loads)
		app.webFilter.mu.Unlock()
		if running == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	reads := manager.readCount("default")
	app.timeout = 2 * time.Second
	second, err := app.CheckWebFilter(context.Background(), CheckWebFilterInput{Category: "52", URL: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Complete || manager.readCount("default") != reads {
		t.Fatalf("second lookup complete=%v policy reads %d -> %d (want cached)", second.Complete, reads, manager.readCount("default"))
	}
	if corp := profileResult(t, second, "corp-web"); len(corp.Policies) != 2 {
		t.Fatalf("completed corp-web policies = %#v", corp.Policies)
	}
}

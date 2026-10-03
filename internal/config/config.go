package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ProductFortiManager  = "fortimanager"
	ProductFortiAnalyzer = "fortianalyzer"
)

// Config is the complete process configuration. Secrets should normally be
// supplied through environment substitutions in the YAML file.
type Config struct {
	Server   ServerConfig    `yaml:"server"`
	Profiles []ProfileConfig `yaml:"profiles"`
	Rating   RatingConfig    `yaml:"rating"`
}

// RatingConfig controls FortiGuard URL ratings for rate_url. The
// rating is always requested from a managed FortiGate through the
// FortiManager proxy. Device names a dedicated rating FortiGate; without it
// the tool rates through the FortiGate given in the request. The proxy POST
// that FortiOS 7.4 requires needs JSON API Read-Write on FortiManager, so a
// dedicated rating account can be configured instead of widening the
// profile's own account.
type RatingConfig struct {
	Device              string `yaml:"device,omitempty"`
	ADOM                string `yaml:"adom,omitempty"`
	VDOM                string `yaml:"vdom,omitempty"`
	FortiManagerProfile string `yaml:"fortimanager_profile,omitempty"`
	APIKey              string `yaml:"api_key,omitempty"`
	Username            string `yaml:"username,omitempty"`
	Password            string `yaml:"password,omitempty"`
	// LegacyFortiGate catches the removed direct-FortiGate option so an old
	// configuration fails loudly instead of being ignored.
	LegacyFortiGate any `yaml:"fortigate,omitempty"`
}

// HasDedicatedCredentials reports whether rating uses its own account.
func (r RatingConfig) HasDedicatedCredentials() bool {
	return strings.TrimSpace(r.APIKey) != "" || strings.TrimSpace(r.Username) != ""
}

// RatingProfile derives the connection for the dedicated rating account: the
// FortiManager profile's URL, TLS and ADOM scope with the rating credentials.
func (c Config) RatingProfile() (ProfileConfig, error) {
	base, err := c.Profile(c.Rating.FortiManagerProfile, ProductFortiManager)
	if err != nil {
		return ProfileConfig{}, fmt.Errorf("rating.fortimanager_profile: %w", err)
	}
	profile := base
	profile.Name = base.Name + "/rating"
	profile.APIKey = strings.TrimSpace(c.Rating.APIKey)
	profile.Username = strings.TrimSpace(c.Rating.Username)
	profile.Password = c.Rating.Password
	profile.Default = false
	return profile, nil
}

type ServerConfig struct {
	ListenAddress      string `yaml:"listen_address"`
	MCPPath            string `yaml:"mcp_path"`
	HTTPBearerToken    string `yaml:"http_bearer_token"`
	HTTPTrustedProxy   bool   `yaml:"http_trusted_proxy"`
	RefreshInterval    string `yaml:"refresh_interval"`
	RefreshTimeout     string `yaml:"refresh_timeout"`
	RequestTimeout     string `yaml:"request_timeout"`
	MaxConcurrentCalls int    `yaml:"max_concurrent_calls"`
	// MaxResultBytes caps one tool result. A larger answer is replaced by an
	// error that says how to narrow the request, so an agent never receives
	// megabytes it cannot read. 0 means the default.
	MaxResultBytes int `yaml:"max_result_bytes"`
	// PrefetchCachedPolicies re-reads policy tables that a tool already
	// cached, after each background inventory refresh, so the next lookup
	// hits the new snapshot. It does not read packages nobody has asked for.
	PrefetchCachedPolicies bool `yaml:"prefetch_cached_policies"`
}

// DefaultMaxResultBytes is the default tool result cap (512 KiB, roughly
// 130k tokens).
const DefaultMaxResultBytes = 512 << 10

type ProfileConfig struct {
	Name               string            `yaml:"name"`
	Product            string            `yaml:"product"`
	ADOMs              []string          `yaml:"adoms,omitempty"`
	URL                string            `yaml:"url"`
	Username           string            `yaml:"username"`
	Password           string            `yaml:"password"`
	APIKey             string            `yaml:"api_key"`
	InsecureSkipVerify bool              `yaml:"insecure_skip_verify"`
	AllowInsecureHTTP  bool              `yaml:"allow_insecure_http"`
	CAFile             string            `yaml:"ca_file"`
	Headers            map[string]string `yaml:"headers"`
	// Timezone is the IANA zone the appliance uses to interpret wall-clock
	// values such as FortiAnalyzer Log View time ranges. Empty keeps the
	// caller's zone and adds a warning to results.
	Timezone string `yaml:"timezone"`
	Default  bool   `yaml:"default"`
}

// Location returns the configured appliance time zone, or nil when unset.
func (p ProfileConfig) Location() *time.Location {
	if strings.TrimSpace(p.Timezone) == "" {
		return nil
	}
	location, err := time.LoadLocation(strings.TrimSpace(p.Timezone))
	if err != nil {
		return nil
	}
	return location
}

// AllowsADOM reports whether profile may access adom. Empty ADOMs means no
// allowlist, preserving current behavior for profiles without configuration.
func (p ProfileConfig) AllowsADOM(adom string) bool {
	if len(p.ADOMs) == 0 {
		return true
	}
	adom = strings.TrimSpace(adom)
	for _, allowed := range p.ADOMs {
		if strings.TrimSpace(allowed) == adom {
			return true
		}
	}
	return false
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			ListenAddress:      "127.0.0.1:8080",
			MCPPath:            "/mcp",
			RefreshInterval:    "1h",
			RefreshTimeout:     "2m",
			RequestTimeout:     "30s",
			MaxConcurrentCalls: 8,
			MaxResultBytes:     DefaultMaxResultBytes,
		},
	}
}

// tryConfigPath expands ~ and checks if the file exists.
// Returns the expanded path if readable, empty string otherwise.
func tryConfigPath(path string) string {
	expanded := os.ExpandEnv(path)
	if strings.HasPrefix(expanded, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		expanded = home + expanded[1:]
	}
	if _, err := os.Stat(expanded); err == nil {
		return expanded
	}
	return ""
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = os.Getenv("FORTI_INTELLIGENCE_CONFIG")
	}
	if path == "" {
		// Try XDG locations
		path = tryConfigPath("~/.config/forti-intelligence/config.yaml")
	}
	if path == "" {
		path = tryConfigPath("/etc/forti-intelligence/config.yaml")
	}
	if path == "" {
		return cfg, nil
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	contents = []byte(os.ExpandEnv(string(contents)))
	if err := yaml.Unmarshal(contents, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		return Config{}, fmt.Errorf("validate config %q: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) normalizeAndValidate() error {
	defaults := Default().Server
	if c.Server.ListenAddress == "" {
		c.Server.ListenAddress = defaults.ListenAddress
	}
	if c.Server.MCPPath == "" {
		c.Server.MCPPath = defaults.MCPPath
	}
	if !strings.HasPrefix(c.Server.MCPPath, "/") {
		c.Server.MCPPath = "/" + c.Server.MCPPath
	}
	if c.Server.RefreshInterval == "" {
		c.Server.RefreshInterval = defaults.RefreshInterval
	}
	if c.Server.RequestTimeout == "" {
		c.Server.RequestTimeout = defaults.RequestTimeout
	}
	if c.Server.RefreshTimeout == "" {
		c.Server.RefreshTimeout = defaults.RefreshTimeout
	}
	if c.Server.MaxConcurrentCalls < 1 {
		return fmt.Errorf("server.max_concurrent_calls must be at least 1, got %d", c.Server.MaxConcurrentCalls)
	}
	if c.Server.MaxResultBytes == 0 {
		c.Server.MaxResultBytes = DefaultMaxResultBytes
	}
	if c.Server.MaxResultBytes < 64<<10 {
		return fmt.Errorf("max_result_bytes must be at least 65536 (64 KiB), got %d", c.Server.MaxResultBytes)
	}
	if duration, err := time.ParseDuration(c.Server.RefreshInterval); err != nil || duration <= 0 {
		if err == nil {
			err = fmt.Errorf("must be greater than zero")
		}
		return fmt.Errorf("refresh_interval: %w", err)
	}
	if duration, err := time.ParseDuration(c.Server.RequestTimeout); err != nil || duration <= 0 {
		if err == nil {
			err = fmt.Errorf("must be greater than zero")
		}
		return fmt.Errorf("request_timeout: %w", err)
	}
	if duration, err := time.ParseDuration(c.Server.RefreshTimeout); err != nil || duration <= 0 {
		if err == nil {
			err = fmt.Errorf("must be greater than zero")
		}
		return fmt.Errorf("refresh_timeout: %w", err)
	}

	if err := c.validateRating(); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(c.Profiles))
	defaultByProduct := make(map[string]string, 2)
	for i := range c.Profiles {
		p := &c.Profiles[i]
		p.Product = strings.ToLower(strings.TrimSpace(p.Product))
		p.Name = strings.TrimSpace(p.Name)
		p.URL = strings.TrimRight(strings.TrimSpace(p.URL), "/")
		if len(p.ADOMs) > 0 {
			adoms := make([]string, 0, len(p.ADOMs))
			seenADOMs := make(map[string]struct{}, len(p.ADOMs))
			for adomIndex, adom := range p.ADOMs {
				adom = strings.TrimSpace(adom)
				if adom == "" {
					return fmt.Errorf("profiles[%q].adoms[%d] must not be empty", p.Name, adomIndex)
				}
				if _, exists := seenADOMs[adom]; exists {
					continue
				}
				seenADOMs[adom] = struct{}{}
				adoms = append(adoms, adom)
			}
			p.ADOMs = adoms
		}
		if p.Name == "" {
			return fmt.Errorf("profiles[%d].name is required", i)
		}
		if _, ok := seen[p.Name]; ok {
			return fmt.Errorf("duplicate profile name %q", p.Name)
		}
		seen[p.Name] = struct{}{}
		if p.Product != ProductFortiManager && p.Product != ProductFortiAnalyzer {
			return fmt.Errorf("profiles[%q].product must be %q or %q", p.Name, ProductFortiManager, ProductFortiAnalyzer)
		}
		if p.URL == "" {
			return fmt.Errorf("profiles[%q].url is required", p.Name)
		}
		parsedURL, parseErr := url.Parse(p.URL)
		if parseErr != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			return fmt.Errorf("profiles[%q].url must include a scheme and host", p.Name)
		}
		if parsedURL.User != nil {
			return fmt.Errorf("profiles[%q].url must not embed credentials; use username/password or api_key fields", p.Name)
		}
		if parsedURL.Scheme != "https" && !(parsedURL.Scheme == "http" && p.AllowInsecureHTTP) {
			return fmt.Errorf("profiles[%q].url must use https; set allow_insecure_http only for controlled tests or labs", p.Name)
		}
		if p.Username == "" && p.APIKey == "" {
			return fmt.Errorf("profiles[%q] needs username/password or api_key", p.Name)
		}
		if p.APIKey == "" && p.Password == "" {
			return fmt.Errorf("profiles[%q].password is required when api_key is not set", p.Name)
		}
		p.Timezone = strings.TrimSpace(p.Timezone)
		if p.Timezone != "" {
			if _, err := time.LoadLocation(p.Timezone); err != nil {
				return fmt.Errorf("profiles[%q].timezone %q is not a valid IANA zone (example: Europe/Berlin)", p.Name, p.Timezone)
			}
		}
		if p.Default {
			if previous, exists := defaultByProduct[p.Product]; exists {
				return fmt.Errorf("profiles %q and %q are both default %s profiles", previous, p.Name, p.Product)
			}
			defaultByProduct[p.Product] = p.Name
		}
	}
	return nil
}

func (c *Config) validateRating() error {
	rating := &c.Rating
	if rating.LegacyFortiGate != nil {
		return fmt.Errorf("rating.fortigate (direct FortiGate connection) was removed: ratings go through FortiManager. Use rating.device for a dedicated rating FortiGate and optionally rating.api_key for a dedicated FortiManager rating account")
	}
	rating.Device = strings.TrimSpace(rating.Device)
	rating.ADOM = strings.TrimSpace(rating.ADOM)
	rating.VDOM = strings.TrimSpace(rating.VDOM)
	rating.FortiManagerProfile = strings.TrimSpace(rating.FortiManagerProfile)
	rating.APIKey = strings.TrimSpace(rating.APIKey)
	rating.Username = strings.TrimSpace(rating.Username)
	if rating.FortiManagerProfile != "" {
		found := false
		for _, profile := range c.Profiles {
			if strings.TrimSpace(profile.Name) == rating.FortiManagerProfile && strings.EqualFold(strings.TrimSpace(profile.Product), ProductFortiManager) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("rating.fortimanager_profile %q is not a configured FortiManager profile", rating.FortiManagerProfile)
		}
	}
	if rating.Username != "" && rating.Password == "" {
		return fmt.Errorf("rating.password is required when rating.username is set")
	}
	if rating.APIKey != "" && rating.Username != "" {
		return fmt.Errorf("rating: use either api_key or username/password for the dedicated rating account, not both")
	}
	if rating.HasDedicatedCredentials() {
		// A dedicated account with the profile's own key is not dedicated:
		// it usually means the rating key was also put into the profile, and
		// then inventory runs with the rating administrator's permissions.
		for _, profile := range c.Profiles {
			if !strings.EqualFold(strings.TrimSpace(profile.Product), ProductFortiManager) {
				continue
			}
			if rating.FortiManagerProfile != "" && strings.TrimSpace(profile.Name) != rating.FortiManagerProfile {
				continue
			}
			if (rating.APIKey != "" && rating.APIKey == strings.TrimSpace(profile.APIKey)) || (rating.Username != "" && rating.Username == strings.TrimSpace(profile.Username)) {
				return fmt.Errorf("rating credentials are the same as those of profile %q: use a separate rating administrator's key, or remove rating.api_key/username to reuse the profile account", profile.Name)
			}
		}
	}
	if rating.HasDedicatedCredentials() && rating.FortiManagerProfile == "" {
		fortiManagers := 0
		for _, profile := range c.Profiles {
			if strings.EqualFold(strings.TrimSpace(profile.Product), ProductFortiManager) {
				fortiManagers++
			}
		}
		if fortiManagers == 0 {
			return fmt.Errorf("rating credentials need a FortiManager profile; none is configured")
		}
	}
	return nil
}

// ValidateHTTPExposure prevents an HTTP MCP listener from being exposed on a
// non-loopback address without either bearer authentication or an explicitly
// trusted authenticating reverse proxy.
func ValidateHTTPExposure(transport, address, bearerToken string, trustedProxy bool) error {
	transport = strings.ToLower(strings.TrimSpace(transport))
	if transport != "http" && transport != "streamable-http" && transport != "streamable_http" {
		return nil
	}
	if isLoopbackListenAddress(address) || strings.TrimSpace(bearerToken) != "" || trustedProxy {
		return nil
	}
	return fmt.Errorf("HTTP MCP listener %q is non-loopback without a bearer token; configure http_bearer_token or explicitly set http_trusted_proxy", address)
}

func isLoopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		host = strings.TrimSpace(address)
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c Config) RefreshIntervalDuration() time.Duration {
	d, err := time.ParseDuration(c.Server.RefreshInterval)
	if err != nil {
		return time.Hour
	}
	return d
}

func (c Config) RequestTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(c.Server.RequestTimeout)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

// RequestTimeoutDuration returns the configured request timeout as a duration.
// This is a helper on ServerConfig to match the pattern used by Config.
func (s ServerConfig) RequestTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(s.RequestTimeout)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

func (c Config) RefreshTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(c.Server.RefreshTimeout)
	if err != nil {
		return 2 * time.Minute
	}
	return d
}

func (c Config) Profile(name, product string) (ProfileConfig, error) {
	product = strings.ToLower(strings.TrimSpace(product))
	if name != "" {
		for _, p := range c.Profiles {
			if p.Name == name {
				if product != "" && p.Product != product {
					return ProfileConfig{}, fmt.Errorf("profile %q is %s, not %s", name, p.Product, product)
				}
				return p, nil
			}
		}
		return ProfileConfig{}, fmt.Errorf("profile %q not found", name)
	}
	for _, p := range c.Profiles {
		if p.Product == product && p.Default {
			return p, nil
		}
	}
	for _, p := range c.Profiles {
		if p.Product == product {
			return p, nil
		}
	}
	return ProfileConfig{}, fmt.Errorf("no %s profile configured", product)
}

func (c Config) Validate() error {
	clone := c
	if err := clone.normalizeAndValidate(); err != nil {
		return err
	}
	return nil
}

var ErrNoProfiles = errors.New("no FortiManager or FortiAnalyzer profiles configured")

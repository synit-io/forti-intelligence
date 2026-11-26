package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaultRefreshIntervalIsHourly(t *testing.T) {
	cfg := Default()
	if cfg.Server.RefreshInterval != "1h" || cfg.RefreshIntervalDuration() != time.Hour {
		t.Fatalf("refresh interval = %q (%v), want 1h", cfg.Server.RefreshInterval, cfg.RefreshIntervalDuration())
	}
}

func TestAuditSyslogConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.yaml")
	for _, tc := range []struct {
		target, caFile string
		valid          bool
	}{
		{"tcp://logs.example.net:514", "", true},
		{"tls://[::1]:6514", "", true},
		{"logs.example.net:6514", "", false},
		{"udp://logs.example.net:514", "", false},
		{"tls://:6514", "", false},
		{"tls://logs.example.net", "", false},
		{"tls://logs.example.net:65536", "", false},
		{"tls://user:secret@logs.example.net:6514", "", false},
		{"tls://logs.example.net:6514/path", "", false},
		{"tls://logs.example.net:6514?x=1", "", false},
		{"tcp://logs.example.net:514", "private.pem", false},
		{"", "private.pem", false},
	} {
		t.Run(tc.target+" "+tc.caFile, func(t *testing.T) {
			contents := "server:\n  audit:\n    syslog:\n      target: \"" + tc.target + "\"\n      ca_file: \"" + tc.caFile + "\"\n"
			if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, Load error=%v", tc.valid, err)
			}
			if tc.valid && cfg.Server.Audit.Syslog.Target != tc.target {
				t.Fatalf("target = %q, want %q", cfg.Server.Audit.Syslog.Target, tc.target)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatalf("configuration error exposed a credential: %v", err)
			}
		})
	}
	for _, settings := range []string{
		"      targte: tls://logs.example.net:6514",
		"      target: tls://logs.example.net:6514\n      ca_file: " + path + ".missing",
		"      target: tls://logs.example.net:6514\n      ca_file: " + path,
	} {
		if err := os.WriteFile(path, []byte("server:\n  audit:\n    syslog:\n"+settings+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted invalid settings: %s", settings)
		}
	}
}

func TestAuditSyslogSuppressHTTPStdout(t *testing.T) {
	for _, tc := range []struct {
		name, settings, wantError string
		wantSuppression           bool
	}{
		{name: "omitted", settings: `target: tcp://logs.example.net:514`},
		{name: "false without a target", settings: `suppress_http_stdout: false`},
		{name: "true with a target", settings: `target: tls://logs.example.net:6514, suppress_http_stdout: true`, wantSuppression: true},
		{name: "true without a target", settings: `suppress_http_stdout: true`, wantError: "suppress_http_stdout requires server.audit.syslog.target"},
		{name: "true with a blank target", settings: `target: "  ", suppress_http_stdout: true`, wantError: "suppress_http_stdout requires server.audit.syslog.target"},
		{name: "true with an invalid target", settings: `target: udp://logs.example.net:514, suppress_http_stdout: true`, wantError: "server.audit.syslog.target must be"},
		{name: "wrong type", settings: `suppress_http_stdout: never`, wantError: "server.audit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.yaml")
			contents := "server:\n  audit:\n    syslog: {" + tc.settings + "}\n"
			if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("Load() error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Server.Audit.Syslog.SuppressHTTPStdout; got != tc.wantSuppression {
				t.Fatalf("suppress_http_stdout = %v, want %v", got, tc.wantSuppression)
			}
		})
	}
}

func TestLoadSelectsIndependentNamedProfiles(t *testing.T) {
	t.Setenv("FMG_USER", "fmg-reader")
	t.Setenv("FMG_PASS", "fmg-secret")
	t.Setenv("FAZ_USER", "faz-reader")
	t.Setenv("FAZ_PASS", "faz-secret")

	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
server:
  refresh_interval: 1m
profiles:
  - name: fmg-primary
    product: fortimanager
    url: https://fmg.example.invalid
    username: ${FMG_USER}
    password: ${FMG_PASS}
    default: true
  - name: faz-primary
    product: fortianalyzer
    url: https://faz.example.invalid
    username: ${FAZ_USER}
    password: ${FAZ_PASS}
    default: true
  - name: fmg-secondary
    product: fortimanager
    url: https://fmg-secondary.example.invalid
    username: backup
    password: backup-secret
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	fmg, err := cfg.Profile("", ProductFortiManager)
	if err != nil || fmg.Name != "fmg-primary" || fmg.Username != "fmg-reader" || fmg.Password != "fmg-secret" {
		t.Fatalf("default FMG profile = %#v, %v", fmg, err)
	}
	faz, err := cfg.Profile("", ProductFortiAnalyzer)
	if err != nil || faz.Name != "faz-primary" || faz.Username != "faz-reader" || faz.Password != "faz-secret" {
		t.Fatalf("default FAZ profile = %#v, %v", faz, err)
	}
	secondary, err := cfg.Profile("fmg-secondary", ProductFortiManager)
	if err != nil || secondary.Username != "backup" {
		t.Fatalf("named secondary profile = %#v, %v", secondary, err)
	}
}

func TestLoadNormalizesProfileADOMAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
profiles:
  - name: fmg
    product: fortimanager
    url: https://fmg.example.invalid
    api_key: api-key
    adoms: [" test-adom-primary ", test-adom-primary, test-adom-customer-a]
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := cfg.Profiles[0].ADOMs, []string{"test-adom-primary", "test-adom-customer-a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("profile ADOMs = %#v, want %#v", got, want)
	}
}

func TestValidateRejectsInsecureProfileURLUnlessExplicitlyAllowed(t *testing.T) {
	cfg := Default()
	cfg.Profiles = []ProfileConfig{{
		Name: "fmg", Product: ProductFortiManager, URL: "http://fmg.example.invalid", Username: "u", Password: "p",
	}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "allow_insecure_http") {
		t.Fatalf("Validate() error = %v, want explicit insecure HTTP error", err)
	}
	cfg.Profiles[0].AllowInsecureHTTP = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with lab override error = %v", err)
	}
}

func TestValidateAcceptsAPIKeyWithoutUsername(t *testing.T) {
	cfg := Default()
	cfg.Profiles = []ProfileConfig{{
		Name: "fmg", Product: ProductFortiManager, URL: "https://fmg.example.invalid", APIKey: "api-key",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want API-key-only profile to be valid", err)
	}
}

func TestValidateRejectsMultipleDefaultsPerProduct(t *testing.T) {
	cfg := Default()
	cfg.Profiles = []ProfileConfig{
		{Name: "fmg-a", Product: ProductFortiManager, URL: "https://a.example.invalid", Username: "u", Password: "p", Default: true},
		{Name: "fmg-b", Product: ProductFortiManager, URL: "https://b.example.invalid", Username: "u", Password: "p", Default: true},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "both default") {
		t.Fatalf("Validate() error = %v, want duplicate default error", err)
	}
}

func TestValidateHTTPExposure(t *testing.T) {
	tests := []struct {
		name    string
		address string
		token   string
		proxy   bool
		wantErr bool
	}{
		{name: "loopback without token", address: "127.0.0.1:8080"},
		{name: "remote with token", address: "0.0.0.0:8080", token: "secret"},
		{name: "remote trusted proxy", address: "0.0.0.0:8080", proxy: true},
		{name: "remote unauthenticated", address: "0.0.0.0:8080", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateHTTPExposure("http", test.address, test.token, test.proxy)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateHTTPExposure() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestToolConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, yaml  string
		rateEnabled bool
		wantError   bool
	}{
		{"default", "server: {}", true, false},
		{"disabled", "server:\n  tools:\n    rate_url: false\n    inventory_status: true", false, false},
		{"legacy YAML", "defaults: &defaults {rate_url: off, inventory_status: on}\nserver:\n  tools:\n    <<: *defaults", false, false},
		{"duplicate", "server:\n  tools:\n    rate_url: false\n    rate_url: true", false, true},
		{"unknown", "server:\n  tools:\n    rate_urll: false", false, true},
		{"wrong type", "server:\n  tools:\n    rate_url: disabled", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err != nil) != tc.wantError {
				t.Fatalf("Load() error = %v", err)
			}
			if err != nil {
				return
			}
			if cfg.Server.ToolEnabled("rate_url") != tc.rateEnabled {
				t.Fatal("wrong rate_url availability")
			}
			if !cfg.Server.ToolEnabled("inventory_status") {
				t.Fatal("inventory_status must stay enabled")
			}
		})
	}
}

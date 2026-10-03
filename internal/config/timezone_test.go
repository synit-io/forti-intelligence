package config

import (
	"strings"
	"testing"
)

func TestProfileTimezoneIsValidatedAndResolved(t *testing.T) {
	cfg := Default()
	cfg.Profiles = []ProfileConfig{{Name: "faz", Product: ProductFortiAnalyzer, URL: "https://faz.invalid", APIKey: "k", Timezone: " Europe/Berlin "}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if location := cfg.Profiles[0].Location(); location == nil || location.String() != "Europe/Berlin" {
		t.Fatalf("Location() = %v", location)
	}
	cfg.Profiles[0].Timezone = "Mars/Olympus"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "timezone") {
		t.Fatalf("Validate() error = %v, want timezone rejection", err)
	}
	if location := (ProfileConfig{}).Location(); location != nil {
		t.Fatalf("empty timezone Location() = %v, want nil", location)
	}
}

func TestRatingConfigValidation(t *testing.T) {
	base := func() Config {
		cfg := Default()
		cfg.Profiles = []ProfileConfig{
			{Name: "fmg", Product: ProductFortiManager, URL: "https://fmg.invalid", APIKey: "read-only", ADOMs: []string{"test-adom-secondary"}, Default: true},
			{Name: "faz", Product: ProductFortiAnalyzer, URL: "https://faz.invalid", APIKey: "k"},
		}
		return cfg
	}
	cfg := base()
	cfg.Rating = RatingConfig{Device: " test-device-rating ", ADOM: "test-adom-secondary", APIKey: "rating-key"}
	if err := cfg.normalizeAndValidate(); err != nil {
		t.Fatalf("valid rating config rejected: %v", err)
	}
	if cfg.Rating.Device != "test-device-rating" || !cfg.Rating.HasDedicatedCredentials() {
		t.Fatalf("normalized = %#v", cfg.Rating)
	}
	profile, err := cfg.RatingProfile()
	if err != nil || profile.Name != "fmg/rating" || profile.APIKey != "rating-key" || profile.URL != "https://fmg.invalid" || len(profile.ADOMs) != 1 || profile.Default {
		t.Fatalf("rating profile = %#v err = %v", profile, err)
	}
	for name, mutate := range map[string]func(*Config){
		"legacy direct fortigate":   func(c *Config) { c.Rating.LegacyFortiGate = map[string]any{"url": "https://fgt"} },
		"wrong profile":             func(c *Config) { c.Rating.FortiManagerProfile = "faz" },
		"username without password": func(c *Config) { c.Rating.Username = "rater" },
		"key and username":          func(c *Config) { c.Rating.APIKey, c.Rating.Username, c.Rating.Password = "k", "u", "p" },
	} {
		cfg := base()
		mutate(&cfg)
		if err := cfg.normalizeAndValidate(); err == nil || !strings.Contains(err.Error(), "rating") {
			t.Errorf("%s: error = %v, want rating validation error", name, err)
		}
	}
	if (RatingConfig{}).HasDedicatedCredentials() {
		t.Fatal("empty rating config reports dedicated credentials")
	}
}

package service

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

// webTarget is the normalized form of the URL under evaluation: lower-case
// host without port, the request path, and host+path for pattern matching.
type webTarget struct {
	Host string
	Path string
	Full string
}

func parseWebTarget(raw string) (webTarget, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return webTarget{}, fmt.Errorf("url is required")
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return webTarget{}, fmt.Errorf("invalid url %q; use a hostname or a full address such as https://www.example.com/path", raw)
	}
	host := strings.ToLower(parsed.Hostname())
	if net.ParseIP(host) == nil {
		if err := validateDestinationHostname(strings.TrimSuffix(host, ".")); err != nil {
			return webTarget{}, fmt.Errorf("invalid url %q: %w", raw, err)
		}
	}
	path := parsed.EscapedPath()
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	if path == "/" {
		path = ""
	}
	return webTarget{Host: host, Path: path, Full: host + path}, nil
}

// splitURLPattern removes a scheme and separates host and path parts of a
// FortiOS URL pattern. Patterns are matched case-insensitively.
func splitURLPattern(pattern string) (host, path string) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if index := strings.Index(pattern, "://"); index >= 0 {
		pattern = pattern[index+3:]
	}
	host, path, _ = strings.Cut(pattern, "/")
	if path != "" {
		path = "/" + path
	}
	return strings.TrimSuffix(host, "."), path
}

// matchSimpleURL follows the FortiOS "simple" semantics: the host matches
// exactly or as a subdomain, and a pattern path must appear in the request
// path. A pattern without a path matches every path on that host.
func matchSimpleURL(pattern string, target webTarget) bool {
	host, path := splitURLPattern(pattern)
	if host == "" {
		return false
	}
	host = strings.TrimPrefix(host, "*.")
	if target.Host != host && !strings.HasSuffix(target.Host, "."+host) {
		return false
	}
	if path == "" {
		return true
	}
	return strings.Contains(strings.ToLower(target.Path), strings.TrimSuffix(path, "/"))
}

func wildcardToRegexp(pattern string) (*regexp.Regexp, error) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if index := strings.Index(pattern, "://"); index >= 0 {
		pattern = pattern[index+3:]
	}
	var builder strings.Builder
	builder.WriteString("(?i)")
	if strings.HasPrefix(pattern, "*.") {
		// FortiOS 6.0.5+: "*.example.com" also matches "example.com".
		builder.WriteString("^(.*\\.)?")
		pattern = strings.TrimPrefix(pattern, "*.")
	}
	if !strings.HasPrefix(builder.String(), "(?i)^") {
		builder.WriteString("^")
	}
	for _, character := range pattern {
		switch character {
		case '*':
			builder.WriteString(".*")
		case '?':
			builder.WriteString(".")
		default:
			builder.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	switch {
	case strings.HasSuffix(pattern, "*"):
		builder.WriteString("$")
	case strings.Contains(pattern, "/"):
		builder.WriteString("$")
	default:
		// A host-only pattern applies to every path on that host.
		builder.WriteString("(/.*)?$")
	}
	return regexp.Compile(builder.String())
}

type urlFilterMatch struct {
	Matched    bool
	Unresolved bool
	Note       string
}

// matchURLFilterEntry reports whether one static URL filter entry applies to
// the target. Unsupported expressions and referrer conditions are reported as
// unresolved instead of being silently ignored.
func matchURLFilterEntry(entry fortinet.URLFilterEntry, target webTarget) urlFilterMatch {
	if entry.Status == "disable" {
		return urlFilterMatch{}
	}
	if strings.TrimSpace(entry.URL) == "" {
		return urlFilterMatch{}
	}
	var matched bool
	switch entry.Type {
	case "", "simple":
		matched = matchSimpleURL(entry.URL, target)
	case "wildcard":
		expression, err := wildcardToRegexp(entry.URL)
		if err != nil {
			return urlFilterMatch{Unresolved: true, Note: fmt.Sprintf("wildcard entry %d %q could not be evaluated: %v", entry.ID, entry.URL, err)}
		}
		matched = expression.MatchString(target.Full)
	case "regex":
		expression, err := regexp.Compile("(?i)" + entry.URL)
		if err != nil {
			return urlFilterMatch{Unresolved: true, Note: fmt.Sprintf("regex entry %d %q uses syntax this evaluator cannot compile (%v); verify on the FortiGate", entry.ID, entry.URL, err)}
		}
		matched = expression.MatchString(target.Full)
	default:
		return urlFilterMatch{Unresolved: true, Note: fmt.Sprintf("entry %d has unsupported type %q", entry.ID, entry.Type)}
	}
	if !matched {
		return urlFilterMatch{}
	}
	if strings.TrimSpace(entry.ReferrerHost) != "" {
		return urlFilterMatch{Unresolved: true, Note: fmt.Sprintf("entry %d %q matches the URL but only applies when the HTTP referrer host is %q; the referrer is unknown here", entry.ID, entry.URL, entry.ReferrerHost)}
	}
	return urlFilterMatch{Matched: true}
}

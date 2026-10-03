package fortinet

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
)

// requestPolicy is the MCP server's own allowlist for JSON-RPC requests. It
// is checked for every request, including batch items, before anything is
// sent, so an account with broader appliance rights still cannot be used to
// change configuration through this server.
type requestPolicy int

const (
	// policyFortiManager: get on any resource; exec only for login, logout
	// and the device proxy (GET reads plus the FortiGuard rating POST).
	policyFortiManager requestPolicy = iota
	// policyFortiManagerRating: the dedicated rating account may only log
	// in and out and send the FortiGuard rating lookup and category reads
	// through the proxy.
	policyFortiManagerRating
	// policyFortiAnalyzer: get on any resource; add only to create a Log
	// View search task; exec only for login and logout.
	policyFortiAnalyzer
)

const (
	ratingLookupResource   = "/api/v2/monitor/utm/rating-lookup/select"
	ratingCategoryResource = "/api/v2/monitor/webfilter/fortiguard-categories"
	maxRatingURLLength     = 2048
)

var logSearchURL = regexp.MustCompile(`^/logview/adom/[^/]+/logsearch$`)

var escapedPathOctet = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

// policyResourcePath checks the decoded path that the appliance will read.
// Nested escapes are ambiguous across proxy layers and are rejected.
func policyResourcePath(resource string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(resource))
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Path == "" {
		return "", fmt.Errorf("invalid resource %q", resource)
	}
	if strings.Contains(parsed.Path, "..") || strings.IndexFunc(resource+parsed.Path, unicode.IsControl) >= 0 || escapedPathOctet.MatchString(parsed.Path) {
		return "", fmt.Errorf("resource %q contains traversal, control characters or nested escapes", resource)
	}
	return path.Clean(parsed.Path), nil
}

func (p requestPolicy) check(method string, params []map[string]any) error {
	if len(params) == 0 {
		return fmt.Errorf("request without parameters")
	}
	for _, param := range params {
		if err := p.checkOne(method, param); err != nil {
			return err
		}
	}
	return nil
}

func (p requestPolicy) checkOne(method string, param map[string]any) error {
	resource := normalizeRPCPath(fmt.Sprint(param["url"]))
	canonical, err := policyResourcePath(resource)
	if err != nil {
		return err
	}
	if method == "exec" && (resource == "/sys/login/user" || resource == "/sys/logout") {
		return nil
	}
	switch p {
	case policyFortiManager:
		switch method {
		case "get":
			if sensitiveResource(resource) || sensitiveResource(canonical) {
				return fmt.Errorf("read of %s is not permitted", resource)
			}
			return nil
		case "exec":
			if resource == "/sys/proxy/json" {
				return checkProxy(param, false)
			}
		}
	case policyFortiManagerRating:
		if method == "exec" && resource == "/sys/proxy/json" {
			return checkProxy(param, true)
		}
	case policyFortiAnalyzer:
		switch method {
		case "get":
			if sensitiveResource(resource) || sensitiveResource(canonical) {
				return fmt.Errorf("read of %s is not permitted", resource)
			}
			return nil
		case "add":
			if logSearchURL.MatchString(resource) {
				return nil
			}
		}
	}
	return fmt.Errorf("method %q on %s is not permitted", method, resource)
}

// checkProxy allows proxied FortiOS GET reads of monitor and cmdb resources,
// and POST only for the FortiGuard rating lookup with a url list and lang.
// ratingOnly further limits GET to the rating and category resources.
func checkProxy(param map[string]any, ratingOnly bool) error {
	data, _ := param["data"].(map[string]any)
	if data == nil {
		return fmt.Errorf("proxy request without data")
	}
	action := strings.ToLower(strings.TrimSpace(fmt.Sprint(data["action"])))
	resource := strings.TrimSpace(fmt.Sprint(data["resource"]))
	path, err := policyResourcePath(resource)
	if err != nil {
		return fmt.Errorf("proxy resource %q is not permitted", resource)
	}
	switch action {
	case "get":
		if sensitiveResource(path) {
			return fmt.Errorf("proxy GET of %s is not permitted", path)
		}
		if ratingOnly {
			if path == ratingLookupResource || path == ratingCategoryResource || path == strings.TrimSuffix(ratingLookupResource, "/select") {
				return nil
			}
			return fmt.Errorf("the rating account may only read %s and %s", ratingLookupResource, ratingCategoryResource)
		}
		if strings.HasPrefix(path, "/api/v2/monitor/") || strings.HasPrefix(path, "/api/v2/cmdb/") {
			return nil
		}
		return fmt.Errorf("proxy GET is limited to /api/v2/monitor/* and /api/v2/cmdb/*, not %s", path)
	case "post":
		if path != ratingLookupResource {
			return fmt.Errorf("proxy POST is limited to %s, not %s", ratingLookupResource, path)
		}
		return checkRatingPayload(data["payload"])
	}
	return fmt.Errorf("proxy action %q is not permitted", action)
}

// sensitiveResource blocks reads of administrator, credential, and private
// key material. Troubleshooting reads do not need those paths, and a URL
// built from a device or object name must not be able to reach them.
func sensitiveResource(resource string) bool {
	lower := strings.ToLower(resource)
	for _, fragment := range []string{
		"/system/admin",
		"/sys/admin",
		"vpn.certificate/local",
		"/certificate/local",
		"private-key",
		"/sys/login",
		"password",
		"api-key",
		"api_key",
	} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

func checkRatingPayload(value any) error {
	payload, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("rating lookup payload must be an object with url and lang")
	}
	for key := range payload {
		if key != "url" && key != "lang" {
			return fmt.Errorf("rating lookup payload field %q is not permitted", key)
		}
	}
	var urls []string
	switch typed := payload["url"].(type) {
	case []string:
		urls = typed
	case []any:
		for _, item := range typed {
			text, isText := item.(string)
			if !isText {
				return fmt.Errorf("rating lookup url entries must be strings")
			}
			urls = append(urls, text)
		}
	}
	if len(urls) != 1 {
		return fmt.Errorf("rating lookup must carry exactly one url")
	}
	if target := urls[0]; target == "" || len(target) > maxRatingURLLength || strings.ContainsAny(target, " \t\r\n\"'<>") {
		return fmt.Errorf("rating lookup url is not a plain host or path")
	}
	if lang, present := payload["lang"]; present {
		if text, isText := lang.(string); !isText || len(text) > 8 {
			return fmt.Errorf("rating lookup lang must be a short language code")
		}
	}
	return nil
}

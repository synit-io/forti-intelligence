package fortinet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
)

type FortiManager struct {
	rpc *rpcClient
	// ratingPostDenied remembers that this account may not send action=post
	// through the proxy (read-only JSON API), so later rating lookups skip it.
	ratingPostDenied atomic.Bool
	// ratingForm remembers which rating request form last succeeded
	// (index+1 into ratingForms; 0 = unknown) so it is tried first.
	ratingForm atomic.Int32
	// ratingBlocked caches the finding that no proxy form can rate URLs for
	// this account (GET rejected by FortiOS, POST refused by FortiManager),
	// so lookups do not repeat known-impossible calls for ratingBlockTTL.
	ratingMu           sync.Mutex
	ratingBlockedUntil time.Time
	ratingBlockedErr   error
	// batchRereadDenied remembers that this FortiManager denies multi-item
	// re-reads of denied items, so they are re-read one by one directly.
	batchRereadDenied atomic.Bool
}

const ratingBlockTTL = 15 * time.Minute

func NewFortiManager(profile config.ProfileConfig) (*FortiManager, error) {
	rpc, err := newRPCClient(profile)
	if err != nil {
		return nil, err
	}
	rpc.policy = policyFortiManager
	return &FortiManager{rpc: rpc}, nil
}

// NewFortiManagerRatingClient connects the dedicated rating account. Its
// request policy permits only login/logout and the proxied FortiGuard
// rating lookup and category read, whatever the account may do on the
// appliance.
func NewFortiManagerRatingClient(profile config.ProfileConfig) (*FortiManager, error) {
	rpc, err := newRPCClient(profile)
	if err != nil {
		return nil, err
	}
	rpc.policy = policyFortiManagerRating
	return &FortiManager{rpc: rpc}, nil
}

// TransientDenials reports reads that FortiManager denied once and allowed
// on the re-check, a sign that another client shares this API credential.
func (c *FortiManager) TransientDenials() int64 {
	return c.rpc.TransientDenials()
}

func (c *FortiManager) Name() string {
	return c.rpc.profile.Name
}

// AllowsADOM exposes profile scope to inventory and service layers. Empty
// profile ADOMs means all ADOMs, preserving backwards compatibility.
func (c *FortiManager) AllowsADOM(adom string) bool {
	return c.rpc.profile.AllowsADOM(adom)
}

func (c *FortiManager) validateADOM(adom string) error {
	adom = strings.TrimSpace(adom)
	if adom == "" {
		return fmt.Errorf("ADOM must not be empty")
	}
	if c.AllowsADOM(adom) {
		return nil
	}
	return fmt.Errorf("ADOM %q is not configured for FortiManager profile %q", adom, c.Name())
}

func (c *FortiManager) validateResourceADOM(resource string) error {
	if adom, ok := resourceADOM(resource); ok {
		return c.validateADOM(adom)
	}
	return nil
}

func (c *FortiManager) ListADOMs(ctx context.Context) ([]ADOM, error) {
	if len(c.rpc.profile.ADOMs) > 0 {
		// An explicit allowlist is authoritative. Do not discover every ADOM
		// first: product/default ADOMs can be visible in /dvmdb/adom while the
		// API administrator has no permission to read their later resources.
		// Returning the configured names guarantees that inventory never fans
		// out into an ADOM the operator deliberately excluded.
		adoms := make([]ADOM, 0, len(c.rpc.profile.ADOMs))
		seen := make(map[string]struct{}, len(c.rpc.profile.ADOMs))
		for _, configured := range c.rpc.profile.ADOMs {
			name := strings.TrimSpace(configured)
			if name == "" {
				continue
			}
			if _, exists := seen[name]; exists {
				continue
			}
			seen[name] = struct{}{}
			adoms = append(adoms, ADOM{Name: name})
		}
		return adoms, nil
	}

	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		// Keep the ADOM discovery request to the documented collection route
		// and let FortiManager return its default metadata. The extra field
		// projection previously included status fields that are not needed for
		// inventory and can make a least-privilege API profile fail before the
		// ADOM list is returned.
		"url": "/dvmdb/adom",
	}})
	if err != nil {
		if isPermissionDenied(err) {
			return nil, fmt.Errorf("list FortiManager ADOMs via /dvmdb/adom: %w; verify the REST API administrator has JSON API Read, system-setting read, adom-switch read, and access to the target ADOMs", err)
		}
		return nil, fmt.Errorf("list FortiManager ADOMs via /dvmdb/adom: %w", err)
	}
	return parseADOMs(result), nil
}

func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "code -11") || strings.Contains(message, "no permission for the resource")
}

func (c *FortiManager) ListDevices(ctx context.Context, adom string) ([]Device, error) {
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		"url": normalizePath("dvmdb", "adom", adom, "device"),
		"fields": []string{
			"name", "hostname", "sn", "ip", "ostype", "os_ver", "platform_str", "status", "conn_status", "conf_status", "vdom",
		},
		"loadsub": 0,
	}})
	if err != nil {
		return nil, fmt.Errorf("list devices in ADOM %q: %w", adom, err)
	}
	devices := parseDevices(result, adom, c.Name())
	managedFortiGates := devices[:0]
	for _, device := range devices {
		if isFortiGateDevice(device) {
			managedFortiGates = append(managedFortiGates, device)
		}
	}
	return managedFortiGates, nil
}

func isFortiGateDevice(device Device) bool {
	product := strings.TrimSpace(device.OSType)
	if product == "" {
		product = strings.TrimSpace(device.Platform)
	}
	if product == "" {
		// Older FMG responses omit ostype; retain device instead of silently
		// dropping a managed FortiGate from inventory.
		return true
	}
	product = strings.ToLower(product)
	return strings.Contains(product, "fortigate") || strings.Contains(product, "fortiwifi")
}

func (c *FortiManager) ListDeviceGroups(ctx context.Context, adom string) ([]DeviceGroup, error) {
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		"url": normalizePath("dvmdb", "adom", adom, "group"),
	}})
	if err != nil {
		return nil, fmt.Errorf("list device groups in ADOM %q: %w", adom, err)
	}
	groups := parseDeviceGroups(result)
	// FortiManager versions may return group metadata without nested
	// members. The object-member table is a documented subresource; read it
	// for every such group in one multiplexed request.
	var pending []int
	var params []map[string]any
	for index := range groups {
		if len(groups[index].Members) > 0 {
			continue
		}
		memberPath, pathErr := normalizePathWithNestedSegment(
			[]string{"dvmdb", "adom", adom, "group"}, groups[index].Name, "object member",
		)
		if pathErr != nil {
			return nil, fmt.Errorf("list members for device group %q in ADOM %q: %w", groups[index].Name, adom, pathErr)
		}
		pending = append(pending, index)
		params = append(params, map[string]any{"url": memberPath})
	}
	if len(params) == 0 {
		return groups, nil
	}
	items, err := c.callBatchWithSingleFallback(ctx, adom, params)
	if err != nil {
		return nil, fmt.Errorf("list device group members in ADOM %q: %w", adom, err)
	}
	for position, index := range pending {
		if position >= len(items) || items[position].Err != nil {
			memberErr := fmt.Errorf("no result returned")
			if position < len(items) {
				memberErr = items[position].Err
			}
			return nil, fmt.Errorf("list members for device group %q in ADOM %q: %w", groups[index].Name, adom, memberErr)
		}
		groups[index].Members = parsePackageMembersResult(items[position].Value)
	}
	return groups, nil
}

func (c *FortiManager) ListPolicyPackages(ctx context.Context, adom string) ([]PolicyPackage, error) {
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{{
		"url":     normalizePath("pm", "pkg", "adom", adom),
		"fields":  []string{"name", "type", "oid", "scope member"},
		"loadsub": 1,
	}})
	if err != nil {
		return nil, fmt.Errorf("list policy packages in ADOM %q: %w", adom, err)
	}
	packages := parsePackages(result)
	// FortiManager returns package scope in the package collection response.
	// Do not probe a per-package "scope member" child URL: several supported
	// firmware versions reject that URL with code -10, and an empty member list
	// already means package scope is unrestricted to the caller.
	return packages, nil
}

// policyReadFields are the attributes the server evaluates on firewall
// policies: interfaces, addresses of both IP families, internet services,
// services, identity, security profiles and per-policy install targets.
var policyReadFields = []string{
	"obj seq", "status", "policyid", "srcintf", "dstintf", "action", "schedule", "service", "users", "groups",
	"logtraffic", "nat", "name", "comments", "vdom", "srcaddr-negate", "dstaddr-negate", "service-negate",
	"utm-status", "profile-type", "profile-group", "webfilter-profile", "inspection-mode", "ssl-ssh-profile",
	"srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "_scope",
	"internet-service", "internet-service-name", "internet-service-src", "internet-service-src-name",
	"internet-service6", "internet-service6-name", "internet-service6-src", "internet-service6-src-name",
}

// legacyIPv6PolicyFields reads the policy6 table of FortiOS 6.2 and older
// ADOMs, whose schema has neither the *6 address columns nor service names.
var legacyIPv6PolicyFields = []string{
	"obj seq", "status", "policyid", "srcintf", "dstintf", "action", "schedule", "service", "users", "groups",
	"logtraffic", "nat", "name", "comments", "vdom", "srcaddr-negate", "dstaddr-negate", "service-negate",
	"utm-status", "profile-type", "profile-group", "webfilter-profile", "inspection-mode", "ssl-ssh-profile",
	"srcaddr", "dstaddr", "_scope", "internet-service", "internet-service-src",
}

// ListPolicies reads a package's firewall/policy table. Since FortiOS 6.4 it
// holds IPv4 and IPv6 policies (SourceAddresses6/DestinationAddresses6).
func (c *FortiManager) ListPolicies(ctx context.Context, adom, packageName string) ([]FirewallPolicy, error) {
	return c.listPolicies(ctx, adom, packageName, "policy", policyReadFields, true)
}

// ListPolicyTable reads security-policy or proxy-policy entries of a
// package without a field projection, because the tables differ in fields
// across releases.
func (c *FortiManager) ListPolicyTable(ctx context.Context, adom, packageName, table string) ([]FirewallPolicy, error) {
	if table != "security-policy" && table != "proxy-policy" {
		return nil, fmt.Errorf("unsupported policy table %q", table)
	}
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	policyPath, err := normalizePathWithNestedSegment([]string{"pm", "config", "adom", adom, "pkg"}, packageName, "firewall", table)
	if err != nil {
		return nil, fmt.Errorf("list %s in ADOM %q package %q: %w", table, adom, packageName, err)
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{{"url": policyPath, "loadsub": 0}})
	if err != nil {
		return nil, fmt.Errorf("list %s in ADOM %q package %q: %w", table, adom, packageName, err)
	}
	return parsePolicies(result), nil
}

// ListIPv6Policies reads the legacy IPv6 policy table (policy6) of FortiOS
// 6.2 and older ADOMs. FortiOS 6.4 merged IPv6 policies into firewall/policy
// (see ListPolicies), so newer ADOMs answer not found or invalid, which
// callers treat as "no legacy table". The error keeps its kind for that.
func (c *FortiManager) ListIPv6Policies(ctx context.Context, adom, packageName string) ([]FirewallPolicy, error) {
	policies, err := c.listPolicies(ctx, adom, packageName, "policy6", legacyIPv6PolicyFields, false)
	if err != nil {
		return nil, err
	}
	return NormalizeLegacyIPv6Policies(policies), nil
}

// NormalizeLegacyIPv6Policies moves the addresses and internet services of
// legacy policy6 entries, which FortiOS keeps in the IPv4 column names, to
// the IPv6 fields. It changes the given slice in place and returns it.
func NormalizeLegacyIPv6Policies(policies []FirewallPolicy) []FirewallPolicy {
	for index := range policies {
		policy := &policies[index]
		if len(policy.SourceAddresses6) == 0 {
			policy.SourceAddresses6, policy.SourceAddresses = policy.SourceAddresses, nil
		}
		if len(policy.DestinationAddresses6) == 0 {
			policy.DestinationAddresses6, policy.DestinationAddresses = policy.DestinationAddresses, nil
		}
		policy.SourceInternetService6 = policy.SourceInternetService6 || policy.SourceInternetService
		policy.DestinationInternetService6 = policy.DestinationInternetService6 || policy.DestinationInternetService
		policy.SourceInternetService, policy.DestinationInternetService = false, false
	}
	return policies
}

func (c *FortiManager) policyTablePath(adom, packageName, table string) (string, error) {
	return normalizePathWithNestedSegment([]string{"pm", "config", "adom", adom, "pkg"}, packageName, "firewall", table)
}

// listPolicies reads one policy table with a field projection. Releases
// whose schema lacks a requested field reject the projection;
// retryWithoutFields then reads full records, which carry the same
// attributes.
func (c *FortiManager) listPolicies(ctx context.Context, adom, packageName, policyType string, fields []string, retryWithoutFields bool) ([]FirewallPolicy, error) {
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	policyPath, err := c.policyTablePath(adom, packageName, policyType)
	if err != nil {
		return nil, fmt.Errorf("list %s policies in ADOM %q package %q: %w", policyType, adom, packageName, err)
	}
	param := map[string]any{"url": policyPath, "loadsub": 1}
	if len(fields) > 0 {
		param["fields"] = fields
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{param})
	if err != nil && retryWithoutFields && len(fields) > 0 && DescribeError(err).Kind == ErrorKindInvalid && ctx.Err() == nil {
		result, err = c.rpc.call(ctx, "get", []map[string]any{{"url": policyPath, "loadsub": 1}})
	}
	if err != nil {
		return nil, fmt.Errorf("list %s policies in ADOM %q package %q: %w", policyType, adom, packageName, err)
	}
	return parsePolicies(result), nil
}

// PolicyTableRead is one policy table of a package read.
type PolicyTableRead struct {
	Policies []FirewallPolicy
	Err      error
}

// ListPackagePolicyTables reads several policy tables of one package in one
// multiplexed request: policy (IPv4 and consolidated IPv6), policy6 (legacy
// IPv6), security-policy (NGFW policy-based mode) and proxy-policy
// (explicit proxy). Absent tables come back with a not-found or invalid
// error per table.
func (c *FortiManager) ListPackagePolicyTables(ctx context.Context, adom, packageName string, tables []string) map[string]PolicyTableRead {
	results := make(map[string]PolicyTableRead, len(tables))
	if err := c.validateADOM(adom); err != nil {
		for _, table := range tables {
			results[table] = PolicyTableRead{Err: err}
		}
		return results
	}
	params := make([]map[string]any, 0, len(tables))
	names := make([]string, 0, len(tables))
	for _, table := range tables {
		policyPath, err := c.policyTablePath(adom, packageName, table)
		if err != nil {
			results[table] = PolicyTableRead{Err: fmt.Errorf("list %s in ADOM %q package %q: %w", table, adom, packageName, err)}
			continue
		}
		param := map[string]any{"url": policyPath, "loadsub": 1}
		switch table {
		case "policy":
			param["fields"] = policyReadFields
		case "policy6":
			param["fields"] = legacyIPv6PolicyFields
		default:
			// security-policy and proxy-policy differ in fields across
			// releases; read them without a projection.
			param["loadsub"] = 0
		}
		params = append(params, param)
		names = append(names, table)
	}
	if len(params) == 0 {
		return results
	}
	items, err := c.callBatchReads(ctx, adom, params, false)
	for index, table := range names {
		var value any
		itemErr := err
		if itemErr == nil {
			if index < len(items) {
				value, itemErr = items[index].Value, items[index].Err
			} else {
				itemErr = newRPCFailure(ErrorInfo{Kind: ErrorKindResponse, Message: "FortiManager returned no batch item", Resource: params[index]["url"].(string)}, nil)
			}
		}
		if itemErr != nil && table == "policy" && DescribeError(itemErr).Kind == ErrorKindInvalid && ctx.Err() == nil {
			// The policy table always exists; an invalid answer means this
			// release rejected the field projection. Read full records.
			policies, fullErr := c.listPolicies(ctx, adom, packageName, "policy", nil, false)
			results[table] = PolicyTableRead{Policies: policies, Err: fullErr}
			continue
		}
		if itemErr != nil {
			results[table] = PolicyTableRead{Err: fmt.Errorf("list %s in ADOM %q package %q: %w", table, adom, packageName, itemErr)}
			continue
		}
		policies := parsePolicies(value)
		if table == "policy6" {
			policies = NormalizeLegacyIPv6Policies(policies)
		}
		results[table] = PolicyTableRead{Policies: policies}
	}
	return results
}

func (c *FortiManager) ListAddresses(ctx context.Context, adom string) ([]AddressObject, error) {
	return c.listAddressTypes(ctx, adom, []string{"address", "address6", "addrgrp", "addrgrp6", "vip", "vip6", "vipgrp", "vipgrp6"})
}

// ListAddressesForFamily reads only the object tables of one IP family, which
// halves the FortiManager reads a single-family policy lookup needs.
func (c *FortiManager) ListAddressesForFamily(ctx context.Context, adom string, ipv6 bool) ([]AddressObject, error) {
	if ipv6 {
		return c.listAddressTypes(ctx, adom, []string{"address6", "addrgrp6", "vip6", "vipgrp6"})
	}
	return c.listAddressTypes(ctx, adom, []string{"address", "addrgrp", "vip", "vipgrp"})
}

func addressTables(ipv6 bool) []string {
	if ipv6 {
		return []string{"firewall/address6", "firewall/addrgrp6", "firewall/vip6", "firewall/vipgrp6"}
	}
	return []string{"firewall/address", "firewall/addrgrp", "firewall/vip", "firewall/vipgrp"}
}

var serviceTables = []string{"firewall/service/custom", "firewall/service/group"}

func (c *FortiManager) listAddressTypes(ctx context.Context, adom string, objectTypes []string) ([]AddressObject, error) {
	tables := make([]string, 0, len(objectTypes))
	for _, objectType := range objectTypes {
		tables = append(tables, "firewall/"+objectType)
	}
	objects, err := c.ListPolicyObjects(ctx, adom, tables)
	if err != nil {
		return nil, err
	}
	return objects.Addresses, objects.TableError("address objects", adom)
}

func (c *FortiManager) ListServices(ctx context.Context, adom string) ([]ServiceObject, error) {
	objects, err := c.ListPolicyObjects(ctx, adom, serviceTables)
	if err != nil {
		return nil, err
	}
	return objects.Services, objects.TableError("service objects", adom)
}

// AddressTables and ServiceTables name the object tables ListPolicyObjects
// reads for policy evaluation.
func AddressTables(ipv6 bool) []string { return addressTables(ipv6) }
func ServiceTables() []string          { return append([]string(nil), serviceTables...) }

// PolicyObjects holds address and service objects of one ADOM read in one
// multiplexed request. Errors keys failed tables by object path.
type PolicyObjects struct {
	Addresses []AddressObject
	Services  []ServiceObject
	Errors    map[string]error
}

// TableError summarises failed tables as one partial-result error, or nil.
func (o PolicyObjects) TableError(label, adom string) error {
	if len(o.Errors) == 0 {
		return nil
	}
	tables := make([]string, 0, len(o.Errors))
	for table := range o.Errors {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	parts := make([]string, 0, len(tables))
	var first error
	for _, table := range tables {
		if first == nil {
			first = o.Errors[table]
		}
		parts = append(parts, fmt.Sprintf("%s: %v", table, o.Errors[table]))
	}
	// Wrap the first failure so its kind (permission, timeout, ...) stays
	// visible to DescribeError.
	return fmt.Errorf("list %s in ADOM %q (partial result): %s: %w", label, adom, strings.Join(parts, "; "), first)
}

// ListPolicyObjects reads the given firewall object tables (paths after
// /obj/, for example firewall/address or firewall/service/custom) of one
// ADOM in one multiplexed request; they share the /pm/config prefix.
func (c *FortiManager) ListPolicyObjects(ctx context.Context, adom string, tables []string) (PolicyObjects, error) {
	objects := PolicyObjects{Errors: make(map[string]error)}
	if err := c.validateADOM(adom); err != nil {
		return objects, err
	}
	params := make([]map[string]any, 0, len(tables))
	for _, table := range tables {
		params = append(params, map[string]any{
			"url":     normalizePath(append([]string{"pm", "config", "adom", adom, "obj"}, strings.Split(table, "/")...)...),
			"loadsub": 1,
		})
	}
	items, err := c.callBatchReads(ctx, adom, params, true)
	for index, table := range tables {
		itemErr := err
		var value any
		if itemErr == nil {
			if index < len(items) {
				value, itemErr = items[index].Value, items[index].Err
			} else {
				itemErr = newRPCFailure(ErrorInfo{Kind: ErrorKindResponse, Message: "FortiManager returned no batch item", Resource: params[index]["url"].(string)}, nil)
			}
		}
		if itemErr != nil {
			objects.Errors[table] = itemErr
			continue
		}
		if strings.HasPrefix(table, "firewall/service/") {
			objects.Services = append(objects.Services, parseServices(value)...)
		} else {
			objects.Addresses = append(objects.Addresses, parseAddresses(value)...)
		}
	}
	return objects, nil
}

func (c *FortiManager) ListInterfaces(ctx context.Context, adom, device string) ([]Interface, error) {
	results, err := c.ListInterfacesBatch(ctx, adom, []string{device})
	if err != nil {
		return nil, err
	}
	result, ok := results[device]
	if !ok {
		return nil, fmt.Errorf("list interfaces for %s/%s: no batch result returned", adom, device)
	}
	if result.InterfaceError != nil {
		return nil, result.InterfaceError
	}
	if result.ZoneError != nil {
		return result.Interfaces, result.ZoneError
	}
	return result.Interfaces, nil
}

var interfaceReadFields = []string{
	"name", "alias", "type", "ip", "ipv6", "vdom", "status", "role", "interface", "secondaryip",
}

func (c *FortiManager) ListInterfacesBatch(ctx context.Context, adom string, devices []string) (map[string]InterfaceBatchResult, error) {
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	names := uniqueNonEmptyStrings(devices)
	results := make(map[string]InterfaceBatchResult, len(names))
	if len(names) == 0 {
		return results, nil
	}

	// The request lane already serializes every request of this account.
	// Batch first to reduce HTTP overhead, then verify rejected multi-param
	// reads individually. Code -11 alone does not establish overload.

	interfaceParams := make([]map[string]any, 0, len(names))
	for _, device := range names {
		interfaceParams = append(interfaceParams, map[string]any{
			"url":     normalizePath("pm", "config", "device", device, "global", "system", "interface"),
			"fields":  interfaceReadFields,
			"loadsub": 1,
		})
	}
	interfaceItems, err := c.callBatchWithSingleFallback(ctx, adom, interfaceParams)
	if err != nil {
		return nil, fmt.Errorf("list interfaces in ADOM %q for %d devices: %w", adom, len(names), err)
	}
	for index, device := range names {
		if index >= len(interfaceItems) {
			results[device] = InterfaceBatchResult{InterfaceError: newRPCFailure(ErrorInfo{
				Kind:     ErrorKindResponse,
				Message:  fmt.Sprintf("list interfaces for %s/%s: FortiManager returned no batch item", adom, device),
				Resource: interfaceParams[index]["url"].(string),
				Hint:     "FortiManager returned fewer results than requested; check the appliance API response and version.",
			}, nil)}
			continue
		}
		item := interfaceItems[index]
		if item.Err != nil {
			itemErr := item.Err
			if DescribeError(itemErr).Kind == ErrorKindPermission {
				itemErr = errorWithHint(itemErr, "The API administrator cannot read this device's database (code -11 on /pm/config/device/...). Grant Device Manager read permission and confirm the ADOM/device assignment for that account; inventory keeps last-known-good interfaces meanwhile, so ownership and interface-based lookups for this device are incomplete.")
			}
			results[device] = InterfaceBatchResult{InterfaceError: fmt.Errorf("list interfaces for %s/%s: %w", adom, device, itemErr)}
			continue
		}
		results[device] = InterfaceBatchResult{Interfaces: parseInterfaces(item.Value)}
	}

	zoneParams := make([]map[string]any, 0, len(names))
	zoneDevices := make([]string, 0, len(names))
	zoneVDOMs := make([]string, 0, len(names))
	for _, device := range names {
		if results[device].InterfaceError != nil {
			continue
		}
		var vdoms []string
		for _, iface := range results[device].Interfaces {
			vdom := iface.VDOM
			if vdom == "" {
				vdom = "root"
			}
			vdoms = append(vdoms, vdom)
		}
		for _, vdom := range uniqueNonEmptyStrings(vdoms) {
			zoneDevices = append(zoneDevices, device)
			zoneVDOMs = append(zoneVDOMs, vdom)
			zoneParams = append(zoneParams, map[string]any{
				"url":     normalizePath("pm", "config", "device", device, "vdom", vdom, "system", "zone"),
				"loadsub": 1,
			})
		}
	}
	if len(zoneParams) == 0 {
		return results, nil
	}
	zoneItems, zoneErr := c.callBatchWithSingleFallback(ctx, adom, zoneParams)
	if zoneErr != nil {
		for _, device := range zoneDevices {
			results[device] = withZoneError(results[device], fmt.Errorf("list interface zones for %s/%s: %w", adom, device, zoneErr))
		}
		return results, nil
	}
	for index, device := range zoneDevices {
		if index >= len(zoneItems) {
			results[device] = withZoneError(results[device], newRPCFailure(ErrorInfo{
				Kind:     ErrorKindResponse,
				Message:  fmt.Sprintf("list interface zones for %s/%s: FortiManager returned no batch item", adom, device),
				Resource: zoneParams[index]["url"].(string),
				Hint:     "FortiManager returned fewer results than requested; check the appliance API response and version.",
			}, nil))
			continue
		}
		item := zoneItems[index]
		if item.Err != nil {
			results[device] = withZoneError(results[device], fmt.Errorf("list interface zones for %s/%s: %w", adom, device, item.Err))
			continue
		}
		for _, membership := range parseInterfaceZones(item.Value) {
			for i := range results[device].Interfaces {
				iface := &results[device].Interfaces[i]
				vdom := iface.VDOM
				if vdom == "" {
					vdom = "root"
				}
				if vdom == zoneVDOMs[index] && iface.Name == membership.Interface {
					iface.Zone = membership.Zone
				}
			}
		}
	}
	return results, nil
}

const devicePermissionHint = "The API administrator cannot read this device's database (code -11 on /pm/config/device/...). Grant Device Manager read permission and confirm the ADOM/device assignment for that account."

// ListRoutesBatch reads the routing configuration of each device VDOM from
// the FortiManager device database: router/static (and static6 when
// requested), router/policy (and policy6), and system/sdwan. Results are
// keyed by device; per-table failures are reported in Err and never abort the
// other devices. Missing policy-route or SD-WAN tables mean "not configured".
func (c *FortiManager) ListRoutesBatch(ctx context.Context, adom string, targets []RouteTarget) (map[string]RouteBatchResult, error) {
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	results := make(map[string]RouteBatchResult, len(targets))
	if len(targets) == 0 {
		return results, nil
	}

	type routeRead struct {
		device, vdom, family, table string
	}
	reads := make([]routeRead, 0, len(targets)*4)
	params := make([]map[string]any, 0, len(targets)*4)
	add := func(device, vdom, family, table string, path ...string) {
		reads = append(reads, routeRead{device, vdom, family, table})
		param := map[string]any{"url": normalizePath(append([]string{"pm", "config", "device", device, "vdom", vdom}, path...)...)}
		if table == "sdwan" {
			param["loadsub"] = 1
		}
		params = append(params, param)
	}
	for _, target := range targets {
		device, vdom := strings.TrimSpace(target.Device), strings.TrimSpace(target.VDOM)
		if device == "" {
			continue
		}
		if vdom == "" {
			vdom = "root"
		}
		// Every device result starts complete; failed reads clear their flag.
		results[device] = RouteBatchResult{StaticOK: true, PolicyOK: true, SDWANOK: true}
		add(device, vdom, "ipv4", "static", "router", "static")
		add(device, vdom, "ipv4", "policy", "router", "policy")
		add(device, vdom, "", "sdwan", "system", "sdwan")
		if target.IPv6 {
			add(device, vdom, "ipv6", "static", "router", "static6")
			add(device, vdom, "ipv6", "policy", "router", "policy6")
		}
	}
	items, err := c.callBatchWithSingleFallback(ctx, adom, params)
	if err != nil {
		return nil, fmt.Errorf("list routing tables in ADOM %q for %d device VDOMs: %w", adom, len(targets), err)
	}
	for index, read := range reads {
		result := results[read.device]
		var itemErr error
		var value any
		if index >= len(items) {
			itemErr = newRPCFailure(ErrorInfo{Kind: ErrorKindResponse, Message: "FortiManager returned no batch item", Resource: params[index]["url"].(string)}, nil)
		} else {
			value, itemErr = items[index].Value, items[index].Err
		}
		if itemErr != nil && read.table != "static" {
			// Devices without policy routes or SD-WAN return not-found or
			// invalid-path for those tables; that is absence, not failure.
			if kind := DescribeError(itemErr).Kind; kind == ErrorKindNotFound || kind == ErrorKindInvalid {
				itemErr, value = nil, nil
			}
		}
		if itemErr != nil {
			if DescribeError(itemErr).Kind == ErrorKindPermission {
				itemErr = errorWithHint(itemErr, devicePermissionHint+" Configured routing for this device is unavailable until then.")
			}
			result.Err = errors.Join(result.Err, fmt.Errorf("list %s %s for %s/%s vdom %s: %w", read.family, read.table, adom, read.device, read.vdom, itemErr))
			switch read.table {
			case "static":
				result.StaticOK = false
			case "policy":
				result.PolicyOK = false
			case "sdwan":
				result.SDWANOK = false
			}
			results[read.device] = result
			continue
		}
		switch read.table {
		case "static":
			result.Routes = append(result.Routes, parseRoutes(value, read.family, read.vdom)...)
		case "policy":
			result.PolicyRoutes = append(result.PolicyRoutes, parsePolicyRoutes(value, read.family, read.vdom)...)
		case "sdwan":
			if value != nil {
				if config, enabled := parseSDWAN(value, read.vdom); enabled {
					result.SDWAN = append(result.SDWAN, config)
				}
			}
		}
		results[read.device] = result
	}
	return results, nil
}

// PackageStatusBatch reads FortiManager's stored package installation state
// for each device VDOM (/pm/config/adom/<adom>/_package/status/<dev>/<vdom>).
// The result is keyed "device/vdom"; unreadable targets are omitted.
func (c *FortiManager) PackageStatusBatch(ctx context.Context, adom string, targets []PackageMember) (map[string]PackageStatus, error) {
	if err := c.validateADOM(adom); err != nil {
		return nil, err
	}
	results := make(map[string]PackageStatus, len(targets))
	params := make([]map[string]any, 0, len(targets))
	keys := make([]PackageMember, 0, len(targets))
	for _, target := range targets {
		if strings.TrimSpace(target.Device) == "" {
			continue
		}
		vdom := target.VDOM
		if vdom == "" {
			vdom = "root"
		}
		keys = append(keys, PackageMember{Device: target.Device, VDOM: vdom})
		params = append(params, map[string]any{"url": normalizePath("pm", "config", "adom", adom, "_package", "status", target.Device, vdom)})
	}
	if len(params) == 0 {
		return results, nil
	}
	items, err := c.callBatchWithSingleFallback(ctx, adom, params)
	if err != nil {
		return nil, fmt.Errorf("read package status in ADOM %q: %w", adom, err)
	}
	var firstErr error
	for index, key := range keys {
		if index >= len(items) || items[index].Err != nil {
			if index < len(items) && firstErr == nil {
				firstErr = items[index].Err
			}
			continue
		}
		if status, ok := parsePackageStatus(items[index].Value, key.Device, key.VDOM); ok {
			results[key.Device+"/"+key.VDOM] = status
		}
	}
	if len(results) == 0 && firstErr != nil {
		return nil, fmt.Errorf("read package status in ADOM %q: %w", adom, firstErr)
	}
	return results, nil
}

// callBatchWithSingleFallback reads params in envelopes of at most eight
// and re-reads rejected items individually. See callBatchReads.
func (c *FortiManager) callBatchWithSingleFallback(ctx context.Context, adom string, params []map[string]any) ([]rpcBatchItem, error) {
	return c.callBatchReads(ctx, adom, params, true)
}

// maxBatchItems bounds one multiplexed request. Device batching alone does
// not bound zone requests (each device can contribute many VDOMs), so every
// read stage is split here.
const maxBatchItems = 8

// callBatchReads reads params in envelopes of at most maxBatchItems.
//
//   - adom is the ADOM that owns the devices of ADOM-less paths such as
//     /pm/config/device/<dev>/.... FortiManager was observed to deny device
//     database reads that follow a request for a different ADOM and to allow
//     the same read moments later, so denied items are re-read after an
//     ADOM-aligned read, and a denial is only final after that. The lane is
//     held from the pause through the re-read, so no other request can slip
//     in between and cause another spurious denial.
//   - A whole envelope that timed out or returned an unusable (for example
//     oversized) answer is split into single reads while the caller's
//     deadline allows.
//   - rereadInvalid re-reads items answered as invalid one by one; callers
//     that read optional tables pass false, because invalid there means
//     "table absent".
//
// Successful items are never repeated.
func (c *FortiManager) callBatchReads(ctx context.Context, adom string, params []map[string]any, rereadInvalid bool) ([]rpcBatchItem, error) {
	if len(params) > maxBatchItems {
		items := make([]rpcBatchItem, 0, len(params))
		for start := 0; start < len(params); start += maxBatchItems {
			end := min(start+maxBatchItems, len(params))
			chunk, err := c.callBatchReads(ctx, adom, params[start:end], rereadInvalid)
			if err != nil {
				// Preserve successful earlier chunks and identify failed resources.
				chunk = make([]rpcBatchItem, end-start)
				for i := range chunk {
					chunk[i].Err = fmt.Errorf("read %s: %w", firstRPCResource(params[start+i:start+i+1]), err)
				}
			}
			items = append(items, chunk...)
		}
		return items, nil
	}
	items, err := c.rpc.callBatch(ctx, "get", params)
	if err != nil {
		kind := DescribeError(err).Kind
		switch {
		case kind == ErrorKindPermission:
			items = make([]rpcBatchItem, len(params))
			all := make([]int, len(params))
			for index := range params {
				items[index].Err = err
				all[index] = index
			}
			c.rereadDenied(ctx, adom, params, all, items)
			return items, nil
		case len(params) > 1 && ctx.Err() == nil && (kind == ErrorKindInvalid || kind == ErrorKindTimeout || kind == ErrorKindResponse):
			// The envelope as a whole failed: read the items one by one so a
			// single slow, oversized or rejected table cannot fail the rest.
			return c.callSingleReadItems(ctx, params), nil
		default:
			return nil, err
		}
	}
	var denied []int
	for index := range params {
		if index >= len(items) {
			items = append(items, rpcBatchItem{Err: newRPCFailure(ErrorInfo{Kind: ErrorKindResponse, Message: "FortiManager returned no batch item", Resource: firstRPCResource(params[index : index+1])}, nil)})
		}
		itemErr := items[index].Err
		if itemErr == nil {
			continue
		}
		switch DescribeError(itemErr).Kind {
		case ErrorKindPermission:
			denied = append(denied, index)
		case ErrorKindInvalid:
			if rereadInvalid && len(params) > 1 {
				value, singleErr := c.rpc.callWith(ctx, "get", []map[string]any{params[index]}, false)
				items[index] = rpcBatchItem{Value: value, Err: singleErr}
			}
		}
	}
	if len(denied) > 0 {
		c.rereadDenied(ctx, adom, params, denied, items)
	}
	return items, nil
}

// rereadDenied re-reads the denied items after aligning FortiManager's ADOM
// context, in one request when several were denied. The lane stays held
// from the pause through the re-read.
func (c *FortiManager) rereadDenied(ctx context.Context, adom string, params []map[string]any, denied []int, items []rpcBatchItem) {
	_ = c.rpc.withLaneHeld(ctx, func(ctx context.Context) error {
		c.alignADOMContext(ctx, adom)
		reread := make([]map[string]any, 0, len(denied))
		for _, index := range denied {
			reread = append(reread, params[index])
		}
		var results []rpcBatchItem
		if len(reread) > 1 && !c.batchRereadDenied.Load() {
			if batch, err := c.rpc.callBatchOnce(ctx, "get", reread); err == nil && len(batch) == len(reread) {
				results = batch
			}
		}
		if results != nil {
			// Items denied again in the combined re-read are read one by one:
			// some releases deny multi-item device reads altogether. When
			// every item was denied again, remember that and read singly
			// from the start next time.
			var again []int
			for position := range results {
				if results[position].Err != nil && DescribeError(results[position].Err).Kind == ErrorKindPermission {
					again = append(again, position)
				}
			}
			if len(again) == len(results) {
				c.batchRereadDenied.Store(true)
			}
			for _, position := range again {
				value, err := c.rpc.callWith(ctx, "get", []map[string]any{reread[position]}, false)
				results[position] = rpcBatchItem{Value: value, Err: err}
			}
		} else {
			results = c.callSingleReadItems(ctx, reread)
		}
		for position, index := range denied {
			result := results[position]
			if result.Err == nil {
				c.rpc.transientDenials.Add(1)
			} else if DescribeError(result.Err).Kind == ErrorKindPermission {
				result.Err = errorWithHint(result.Err, "FortiManager denied this read twice, including after an ADOM-aligned re-read, so the administrator profile lacks read permission for it. Grant the read permission (Device Manager for device database paths) and the ADOM/device assignment to this API account.")
			}
			items[index] = result
		}
		return nil
	})
}

// alignADOMContext pauses and then issues a small read scoped to adom, so a
// following ADOM-less device read is evaluated in the device's ADOM. The
// result is ignored; the read uses the device list inventory already needs.
func (c *FortiManager) alignADOMContext(ctx context.Context, adom string) {
	if sleepContext(ctx, permissionRecheckDelay) != nil || strings.TrimSpace(adom) == "" {
		return
	}
	_, _ = c.rpc.callWith(ctx, "get", []map[string]any{{
		"url":     normalizePath("dvmdb", "adom", adom, "device"),
		"fields":  []string{"name"},
		"loadsub": 0,
	}}, false)
}

func (c *FortiManager) callSingleReadItems(ctx context.Context, params []map[string]any) []rpcBatchItem {
	items := make([]rpcBatchItem, len(params))
	for index, param := range params {
		value, err := c.rpc.callWith(ctx, "get", []map[string]any{param}, false)
		items[index] = rpcBatchItem{Value: value, Err: err}
	}
	return items
}

func withZoneError(result InterfaceBatchResult, err error) InterfaceBatchResult {
	result.ZoneError = errors.Join(result.ZoneError, err)
	return result
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
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

func (c *FortiManager) ProxyGet(ctx context.Context, adom, device, vdom, resource string) (ProxyResult, error) {
	return c.proxyCall(ctx, adom, device, vdom, "get", resource, nil)
}

// PolicyLookupTimeoutSeconds bounds how long FortiManager waits for a
// FortiGate's policy-lookup answer; a slow device then fails fast instead of
// holding the request lane for FortiManager's 60 s default.
const PolicyLookupTimeoutSeconds = 10

// ProxyGetTimeout sends a live FortiGate read and asks FortiManager to give
// up on the FortiGate after timeoutSeconds.
func (c *FortiManager) ProxyGetTimeout(ctx context.Context, adom, device, vdom, resource string, timeoutSeconds int) (ProxyResult, error) {
	return c.proxyCallTimeout(ctx, adom, device, vdom, "get", resource, nil, timeoutSeconds)
}

// proxyPostAllowed permits exactly one POST resource: the read-only
// FortiGuard rating lookup, whose FortiOS 7.4 API requires a request body.
func proxyPostAllowed(resource string) bool {
	return strings.SplitN(normalizeRPCPath(resource), "?", 2)[0] == ratingLookupResource
}

func (c *FortiManager) proxyCall(ctx context.Context, adom, device, vdom, action, resource string, payload map[string]any) (ProxyResult, error) {
	return c.proxyCallTimeout(ctx, adom, device, vdom, action, resource, payload, 0)
}

// proxyCallTimeout sends one proxied FortiOS request. timeoutSeconds > 0
// asks FortiManager to give up on the FortiGate after that many seconds
// instead of its 60s default.
func (c *FortiManager) proxyCallTimeout(ctx context.Context, adom, device, vdom, action, resource string, payload map[string]any, timeoutSeconds int) (ProxyResult, error) {
	if err := c.validateADOM(adom); err != nil {
		return ProxyResult{}, err
	}
	if strings.TrimSpace(device) == "" {
		return ProxyResult{}, fmt.Errorf("device is required for a live FortiGate read in ADOM %q", adom)
	}
	if action != "get" && !proxyPostAllowed(resource) {
		return ProxyResult{}, fmt.Errorf("proxy action %q is not permitted for %s; only read-only monitor lookups may use a request body", action, resource)
	}
	resource = normalizeRPCPath(resource)
	if vdom != "" {
		parsed, err := url.Parse(resource)
		if err != nil {
			return ProxyResult{}, fmt.Errorf("invalid proxy resource: %w", err)
		}
		query := parsed.Query()
		query.Set("vdom", vdom)
		parsed.RawQuery = query.Encode()
		resource = parsed.String()
	}
	data := map[string]any{
		"action":   action,
		"resource": resource,
		"target":   []string{"adom/" + url.PathEscape(adom) + "/device/" + url.PathEscape(device)},
	}
	if payload != nil {
		data["payload"] = payload
	}
	if timeoutSeconds > 0 {
		data["timeout"] = timeoutSeconds
	}
	result, err := c.rpc.call(ctx, "exec", []map[string]any{{
		"url":  "/sys/proxy/json",
		"data": data,
	}})
	if err != nil {
		info := DescribeError(err)
		if info.Kind == ErrorKindPermission && strings.TrimPrefix(info.Resource, "/") == "sys/proxy/json" {
			info.Hint = "This live FortiGate read uses JSON-RPC exec /sys/proxy/json with action=" + action + ", not a FortiManager database get. Verify the same account can execute this proxy request and access the target ADOM/device; inspect JSON API/rpc-permit and administrator-profile permissions. Database read success does not establish proxy access. An administrator must review any permission change; retrying a persistent denial will not fix it."
			err = newRPCFailure(info, err)
		}
		return ProxyResult{}, fmt.Errorf("proxy %s through %s/%s: %w", resource, adom, device, err)
	}
	return ProxyResult{
		ADOM:     adom,
		Device:   device,
		VDOM:     vdom,
		Resource: resource,
		Data:     dataFromResult(result),
		Raw:      result,
	}, nil
}

func (c *FortiManager) PolicyLookup(ctx context.Context, adom, device, vdom string, request PolicyLookupRequest) (ProxyResult, error) {
	values := url.Values{}
	values.Set("srcintf", request.SourceInterface)
	values.Set("sourceip", request.SourceIP)
	values.Set("dest", request.DestinationIP)
	values.Set("destport", strconv.Itoa(request.DestinationPort))
	values.Set("policy_type", "policy")
	sourceIP := net.ParseIP(strings.TrimSpace(request.SourceIP))
	values.Set("ipv6", strconv.FormatBool(sourceIP != nil && sourceIP.To4() == nil))
	if vdom != "" {
		values.Set("vdom", vdom)
	}
	if request.SourcePort > 0 {
		values.Set("sourceport", strconv.Itoa(request.SourcePort))
	}
	protocol, err := protocolNumber(request.Protocol)
	if err != nil {
		return ProxyResult{}, err
	}
	values.Set("protocol", strconv.Itoa(protocol))
	resource := "/api/v2/monitor/firewall/policy-lookup/?" + values.Encode()
	return c.proxyCallTimeout(ctx, adom, device, vdom, "get", resource, nil, PolicyLookupTimeoutSeconds)
}

func (c *FortiManager) Read(ctx context.Context, resource string, data map[string]any) (any, error) {
	if err := c.validateResourceADOM(resource); err != nil {
		return nil, err
	}
	param := map[string]any{"url": normalizeRPCPath(resource)}
	for key, value := range data {
		if key != "url" {
			param[key] = value
		}
	}
	result, err := c.rpc.call(ctx, "get", []map[string]any{param})
	if err != nil {
		return nil, fmt.Errorf("FortiManager read %s: %w", resource, err)
	}
	return dataFromResult(result), nil
}

func (c *FortiManager) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.rpc.logout(ctx)
}

func protocolNumber(protocol string) (int, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return 6, nil
	}
	if number, err := strconv.Atoi(protocol); err == nil && number > 0 && number <= 255 {
		return number, nil
	}
	switch protocol {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "sctp":
		return 132, nil
	case "icmp":
		return 1, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", protocol)
	}
}

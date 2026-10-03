package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

// flightGroup deduplicates concurrent cold reads: callers that ask for the
// same key while a read runs wait for its result instead of queueing the
// same FortiManager requests again behind it on the serial lane.
type flightGroup struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	done  chan struct{}
	value any
	err   error
}

// sharedRead separates callers across refresh_inventory generations. A read
// already in flight may finish for its original callers, but a later caller
// must not join it after the caches were invalidated.
func (s *Service) sharedRead(ctx context.Context, key string, read func() (any, error)) (any, error) {
	return s.flights.do(ctx, strconv.FormatUint(s.cacheEpoch.Load(), 10)+"\x00"+key, read)
}

// do runs fn once per key at a time. A waiter whose shared read was cut
// short by the leader's own deadline or cancellation reads for itself.
func (g *flightGroup) do(ctx context.Context, key string, fn func() (any, error)) (any, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*flightCall)
	}
	if call, ok := g.calls[key]; ok {
		g.mu.Unlock()
		select {
		case <-call.done:
			if call.err != nil && ctx.Err() == nil && isContextError(call.err) {
				return fn()
			}
			return call.value, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &flightCall{done: make(chan struct{})}
	g.calls[key] = call
	g.mu.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			call.err = fmt.Errorf("read failed: %v", recovered)
			g.finish(key, call)
			panic(recovered)
		}
		g.finish(key, call)
	}()
	call.value, call.err = fn()
	return call.value, call.err
}

func (g *flightGroup) finish(key string, call *flightCall) {
	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	close(call.done)
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// absentTable reports FortiManager's answer for a table that does not exist
// in the ADOM's schema (not found or invalid path).
func absentTable(err error) bool {
	kind := fortinet.DescribeError(err).Kind
	return kind == fortinet.ErrorKindNotFound || kind == fortinet.ErrorKindInvalid
}

// optionalPolicyTable names package tables that may be absent: the legacy
// IPv6 table on FortiOS 6.4+ ADOMs, and the NGFW security and explicit
// proxy tables where those modes are not used. firewall/policy always
// exists, so a failure to read it is always an error.
func optionalPolicyTable(table string) bool {
	return table != "policy"
}

func policyTableKey(managerName, adom, pkg, table string) string {
	return managerName + "\x00" + adom + "\x00" + pkg + "\x00" + table
}

// policyEntryFresh reports whether a cached policy table still matches the
// package. A known package oid survives a new inventory timestamp. Without
// an oid, the table is tied to the snapshot that produced it.
func policyEntryFresh(entry policyCacheEntry, oid int64, snapshotAt time.Time) bool {
	if time.Since(entry.created) >= objectCacheTTL {
		return false
	}
	if oid != 0 && entry.packageOID == oid {
		return true
	}
	return oid == 0 && entry.inventoryAt.Equal(snapshotAt)
}

// packageOID is the FortiManager package object id from the inventory
// snapshot, or 0 when the snapshot has no package list or no oid.
func (s *Service) packageOID(profile, adom, pkg string) int64 {
	if s == nil || s.store == nil || pkg == "" {
		return 0
	}
	for _, record := range s.store.Snapshot().ADOMs {
		if record.Profile != profile || record.ADOM.Name != adom || !record.PackagesKnown {
			continue
		}
		for _, item := range record.Packages {
			if item.Name == pkg {
				return item.OID
			}
		}
	}
	return 0
}

// cachedPolicyTables copies the cached tables into found and returns the
// tables that must be read.
func (s *Service) cachedPolicyTables(managerName, adom, pkg string, tables []string, snapshotAt time.Time, found map[string][]fortinet.FirewallPolicy) []string {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	var missing []string
	for _, table := range tables {
		entry, ok := s.policyCache[policyTableKey(managerName, adom, pkg, table)]
		if ok && policyEntryFresh(entry, s.packageOID(managerName, adom, pkg), snapshotAt) {
			found[table] = entry.policies
			continue
		}
		missing = append(missing, table)
	}
	return missing
}

// packagePolicies returns the requested policy tables of one package
// ("policy", "policy6", "security-policy", "proxy-policy") from the policy
// cache and reads the missing ones in one multiplexed request when the
// client supports it. Concurrent callers share one read. A missing optional
// table is returned and cached as empty; other failures are returned per
// table and never cached, so the next call retries them.
func (s *Service) packagePolicies(ctx context.Context, manager fortinet.Manager, adom, pkg string, tables []string, snapshotAt time.Time) (map[string][]fortinet.FirewallPolicy, map[string]error) {
	policies := make(map[string][]fortinet.FirewallPolicy, len(tables))
	errs := make(map[string]error)
	missing := s.cachedPolicyTables(manager.Name(), adom, pkg, tables, snapshotAt, policies)
	if len(missing) == 0 {
		return policies, errs
	}
	read := func() (any, error) {
		return s.readPolicyTables(ctx, manager, adom, pkg, missing, snapshotAt), ctx.Err()
	}
	value, _ := s.sharedRead(ctx, "policies\x00"+policyTableKey(manager.Name(), adom, pkg, strings.Join(missing, ",")), read)
	reads, _ := value.(map[string]fortinet.PolicyTableRead)
	for _, table := range missing {
		result, ok := reads[table]
		if !ok {
			result = fortinet.PolicyTableRead{Err: fmt.Errorf("policy table %s of package %q in ADOM %q was not read: %w", table, pkg, adom, context.Cause(ctx))}
		}
		if result.Err != nil {
			errs[table] = result.Err
			continue
		}
		policies[table] = result.Policies
	}
	return policies, errs
}

func (s *Service) readPolicyTables(ctx context.Context, manager fortinet.Manager, adom, pkg string, tables []string, snapshotAt time.Time) map[string]fortinet.PolicyTableRead {
	epoch := s.cacheEpoch.Load()
	var reads map[string]fortinet.PolicyTableRead
	if reader, ok := manager.(fortinet.PackagePolicyReader); ok {
		reads = reader.ListPackagePolicyTables(ctx, adom, pkg, tables)
	} else {
		reads = make(map[string]fortinet.PolicyTableRead, len(tables))
		tableReader, hasTableReader := manager.(fortinet.PolicyTableReader)
		for _, table := range tables {
			var read fortinet.PolicyTableRead
			switch table {
			case "policy":
				read.Policies, read.Err = manager.ListPolicies(ctx, adom, pkg)
			case "policy6":
				read.Policies, read.Err = manager.ListIPv6Policies(ctx, adom, pkg)
				// Legacy policy6 entries keep their IPv6 addresses in the IPv4
				// column names; normalizing is a no-op for clients that did.
				read.Policies = fortinet.NormalizeLegacyIPv6Policies(append([]fortinet.FirewallPolicy(nil), read.Policies...))
			default:
				if hasTableReader {
					read.Policies, read.Err = tableReader.ListPolicyTable(ctx, adom, pkg, table)
				}
			}
			reads[table] = read
		}
	}
	now := time.Now()
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if !s.cacheWriteAllowed(epoch) {
		return reads
	}
	evictOlderThan(s.policyCache, objectCacheTTL, func(entry policyCacheEntry) time.Time { return entry.created })
	for _, table := range tables {
		read, ok := reads[table]
		if !ok {
			continue
		}
		if read.Err != nil {
			if !optionalPolicyTable(table) || !absentTable(read.Err) {
				continue
			}
			read = fortinet.PolicyTableRead{}
			reads[table] = read
		}
		s.policyCache[policyTableKey(manager.Name(), adom, pkg, table)] = policyCacheEntry{created: now, inventoryAt: snapshotAt, packageOID: s.packageOID(manager.Name(), adom, pkg), policies: read.Policies}
	}
	return reads
}

// cachedPolicies reads one package's firewall/policy table (ipv6 false) or
// its legacy IPv6 table (ipv6 true) through the policy cache.
func (s *Service) cachedPolicies(ctx context.Context, manager fortinet.Manager, adom, packageName string, ipv6 bool, snapshotAt time.Time) ([]fortinet.FirewallPolicy, error) {
	table := "policy"
	if ipv6 {
		table = "policy6"
	}
	policies, errs := s.packagePolicies(ctx, manager, adom, packageName, []string{table}, snapshotAt)
	return policies[table], errs[table]
}

// familyPolicies returns the policies that can match a flow of one IP
// family: firewall/policy (IPv4 and, since FortiOS 6.4, IPv6) and for IPv6
// also the legacy policy6 table of older ADOMs. Both are read together.
func (s *Service) familyPolicies(ctx context.Context, manager fortinet.Manager, adom, packageName string, ipv6 bool, snapshotAt time.Time) ([]fortinet.FirewallPolicy, error) {
	if !ipv6 {
		return s.cachedPolicies(ctx, manager, adom, packageName, false, snapshotAt)
	}
	tables, errs := s.packagePolicies(ctx, manager, adom, packageName, []string{"policy", "policy6"}, snapshotAt)
	if err := errs["policy"]; err != nil {
		return nil, err
	}
	policies := append(append([]fortinet.FirewallPolicy(nil), tables["policy"]...), tables["policy6"]...)
	if err := errs["policy6"]; err != nil {
		return policies, fmt.Errorf("legacy IPv6 policy table (partial result): %w", err)
	}
	return policies, nil
}

// objectRead is an ADOM's address objects of one IP family and, when
// requested, its service objects, with the failures of this read.
type objectRead struct {
	addresses []fortinet.AddressObject
	services  []fortinet.ServiceObject
	warnings  []string
	errors    []inventory.RefreshError
}

func (s *Service) cachedObjects(key string, snapshotAt time.Time) (objectCacheEntry, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	entry, ok := s.objectCache[key]
	// Object tables have no single ADOM revision in the inventory snapshot.
	// The five-minute TTL is the bound, and refresh_inventory drops the map.
	// A new inventory timestamp alone must not force another object read.
	return entry, ok && time.Since(entry.created) < objectCacheTTL
}

// policyObjects returns the address objects of one IP family and, with
// withServices, the service objects of an ADOM. Addresses are cached per
// family and services per ADOM, because services do not depend on the
// family. Missing groups are read in one multiplexed request that
// concurrent callers share. Failed tables are reported and never cached;
// tables absent from the ADOM's schema count as empty.
func (s *Service) policyObjects(ctx context.Context, manager fortinet.Manager, adom string, ipv6, withServices bool, snapshotAt time.Time) objectRead {
	family := "ipv4"
	if ipv6 {
		family = "ipv6"
	}
	addressKey := "addresses\x00" + manager.Name() + "\x00" + adom + "\x00" + family
	serviceKey := "services\x00" + manager.Name() + "\x00" + adom
	var read objectRead
	addressEntry, haveAddresses := s.cachedObjects(addressKey, snapshotAt)
	read.addresses = addressEntry.addresses
	needServices := false
	if withServices {
		serviceEntry, haveServices := s.cachedObjects(serviceKey, snapshotAt)
		read.services = serviceEntry.services
		needServices = !haveServices
	}
	if haveAddresses && !needServices {
		return read
	}
	flightKey := "objects\x00" + addressKey + "\x00" + strconv.FormatBool(!haveAddresses) + strconv.FormatBool(needServices)
	value, _ := s.sharedRead(ctx, flightKey, func() (any, error) {
		return s.readPolicyObjects(ctx, manager, adom, ipv6, !haveAddresses, needServices, snapshotAt, addressKey, serviceKey), ctx.Err()
	})
	fresh, ok := value.(objectRead)
	if !ok {
		refreshError := serviceRefreshError(manager.Name(), adom, "", "", "list_objects", fmt.Errorf("object read did not complete: %w", context.Cause(ctx)))
		read.errors = append(read.errors, refreshError)
		read.warnings = append(read.warnings, fmt.Sprintf("%s/%s objects: %s", manager.Name(), adom, refreshError.Message))
		return read
	}
	if !haveAddresses {
		read.addresses = fresh.addresses
	}
	if needServices {
		read.services = fresh.services
	}
	read.warnings, read.errors = fresh.warnings, fresh.errors
	return read
}

func (s *Service) readPolicyObjects(ctx context.Context, manager fortinet.Manager, adom string, ipv6, wantAddresses, wantServices bool, snapshotAt time.Time, addressKey, serviceKey string) objectRead {
	epoch := s.cacheEpoch.Load()
	var read objectRead
	var addressErr, serviceErr error
	if reader, ok := manager.(fortinet.PolicyObjectReader); ok {
		var tables []string
		if wantAddresses {
			tables = append(tables, fortinet.AddressTables(ipv6)...)
		}
		if wantServices {
			tables = append(tables, fortinet.ServiceTables()...)
		}
		objects, err := reader.ListPolicyObjects(ctx, adom, tables)
		if err != nil {
			addressErr, serviceErr = err, err
		} else {
			read.addresses, read.services = objects.Addresses, objects.Services
			addressErrors := fortinet.PolicyObjects{Errors: make(map[string]error)}
			serviceErrors := fortinet.PolicyObjects{Errors: make(map[string]error)}
			for table, tableErr := range objects.Errors {
				if absentTable(tableErr) {
					continue
				}
				if strings.HasPrefix(table, "firewall/service/") {
					serviceErrors.Errors[table] = tableErr
				} else {
					addressErrors.Errors[table] = tableErr
				}
			}
			addressErr = addressErrors.TableError("address objects", adom)
			serviceErr = serviceErrors.TableError("service objects", adom)
		}
	} else {
		if wantAddresses {
			if familyReader, ok := manager.(fortinet.AddressFamilyReader); ok {
				read.addresses, addressErr = familyReader.ListAddressesForFamily(ctx, adom, ipv6)
			} else {
				read.addresses, addressErr = manager.ListAddresses(ctx, adom)
			}
		}
		if wantServices {
			read.services, serviceErr = manager.ListServices(ctx, adom)
		}
	}
	// The parsed fields carry what evaluation needs; the appliance records
	// would only keep large per-device mappings in memory.
	for index := range read.addresses {
		read.addresses[index].Raw = nil
	}
	for index := range read.services {
		read.services[index].Raw = nil
	}
	now := time.Now()
	store := func(key string, entry objectCacheEntry) {
		s.cacheMu.Lock()
		defer s.cacheMu.Unlock()
		if !s.cacheWriteAllowed(epoch) {
			return
		}
		evictOlderThan(s.objectCache, objectCacheTTL, func(entry objectCacheEntry) time.Time { return entry.created })
		s.objectCache[key] = entry
	}
	if wantAddresses {
		if addressErr != nil {
			read.warnings = append(read.warnings, fmt.Sprintf("%s/%s address objects: %v", manager.Name(), adom, addressErr))
			read.errors = append(read.errors, serviceRefreshError(manager.Name(), adom, "", "", "list_addresses", addressErr))
		} else {
			store(addressKey, objectCacheEntry{created: now, inventoryAt: snapshotAt, addresses: read.addresses})
		}
	}
	if wantServices {
		if serviceErr != nil {
			read.warnings = append(read.warnings, fmt.Sprintf("%s/%s service objects: %v", manager.Name(), adom, serviceErr))
			read.errors = append(read.errors, serviceRefreshError(manager.Name(), adom, "", "", "list_services", serviceErr))
		} else {
			store(serviceKey, objectCacheEntry{created: now, inventoryAt: snapshotAt, services: read.services})
		}
	}
	return read
}

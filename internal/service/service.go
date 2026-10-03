package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

type Service struct {
	cfg       config.Config
	store     *inventory.Store
	managers  map[string]fortinet.Manager
	analyzers map[string]fortinet.Analyzer
	timeout   time.Duration
	resolver  dnsResolver

	cacheMu     sync.Mutex
	objectCache map[string]objectCacheEntry
	policyCache map[string]policyCacheEntry
	// readCache holds FortiAnalyzer reads. An explicit FortiManager refresh
	// does not drop it: analyzer status and device lists are independent of
	// the FortiManager snapshot.
	readCache map[string]readCacheEntry
	// managerCache holds FortiManager /sys/status and the ADOM list.
	managerCache map[string]readCacheEntry
	// monitorCache holds short-lived FortiGate monitor GETs that stay
	// meaningful for the length of a ticket. The session table is not here.
	monitorCache map[string]readCacheEntry
	// liveLookupCache holds one live policy-lookup tuple for a few seconds.
	liveLookupCache map[string]liveLookupEntry
	// objectListCache holds stripped list_policy_objects pages.
	objectListCache map[string]readCacheEntry
	// dnsCache caches DNS lookups with TTL
	dnsCacheMu sync.RWMutex
	dnsCache   map[string]dnsCacheEntry
	// flights shares concurrent cold reads of the same policies or objects.
	flights flightGroup
	// refreshMu prevents concurrent refresh_inventory calls from spawning
	// duplicate background refreshes.
	refreshMu sync.Mutex
	// background tracks refresh_inventory and web filter loads that outlive
	// the caller, so shutdown can wait for them before closing clients.
	background sync.WaitGroup
	// cacheEpoch increments on clearCaches. A read that started earlier
	// must not write its result back into the new maps.
	cacheEpoch atomic.Uint64
	webFilter  *webFilterCaches
	// ratingClients holds dedicated FortiManager rating accounts per profile
	// name; profiles without one rate with their own account.
	ratingClients map[string]RatingProxy
}

type dnsCacheEntry struct {
	addresses     []net.IPAddr
	addressErr    string
	addressExpiry time.Time
	haveAddresses bool
	cname         string
	cnameErr      string
	cnameExpiry   time.Time
	haveCNAME     bool
}

// RatingProxy is the part of a FortiManager client the rating lookup uses.
type RatingProxy interface {
	LookupURLRating(ctx context.Context, adom, device, vdom, target string) (fortinet.URLRating, error)
	ListFortiGateCategories(ctx context.Context, adom, device, vdom string) (map[int]string, error)
}

// SetRatingClient registers the dedicated rating account for a FortiManager
// profile (rating.api_key or rating.username/password).
func (s *Service) SetRatingClient(profile string, client RatingProxy) {
	if s.ratingClients == nil {
		s.ratingClients = make(map[string]RatingProxy)
	}
	s.ratingClients[profile] = client
}

// ratingProxyFor returns the dedicated rating account of a profile, or the
// profile's own FortiManager client.
func (s *Service) ratingProxyFor(profile string) (RatingProxy, string, error) {
	if client, ok := s.ratingClients[profile]; ok {
		return client, "dedicated rating account", nil
	}
	manager, err := s.manager(profile)
	if err != nil {
		return nil, "", err
	}
	proxy, ok := manager.(RatingProxy)
	if !ok {
		return nil, "", fmt.Errorf("FortiManager profile %q cannot proxy rating lookups", profile)
	}
	return proxy, "profile account", nil
}

// RatingDevice returns the configured rating FortiGate (rating.device), or
// "" when ratings use the FortiGate named in each request.
func (s *Service) RatingDevice() string {
	return strings.TrimSpace(s.cfg.Rating.Device)
}

func (s *Service) ResolveIPOwnership(ctx context.Context, query inventory.OwnershipQuery) (inventory.OwnershipResult, error) {
	if err := ctx.Err(); err != nil {
		return inventory.OwnershipResult{}, err
	}
	return s.store.ResolveIPOwnership(query)
}

type objectCacheEntry struct {
	created     time.Time
	inventoryAt time.Time
	addresses   []fortinet.AddressObject
	services    []fortinet.ServiceObject
}

type policyCacheEntry struct {
	created     time.Time
	inventoryAt time.Time
	packageOID  int64
	policies    []fortinet.FirewallPolicy
}

type liveLookupEntry struct {
	created time.Time
	result  fortinet.ProxyResult
}

type dnsResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupCNAME(context.Context, string) (string, error)
}

func New(cfg config.Config, store *inventory.Store, managers map[string]fortinet.Manager, analyzers map[string]fortinet.Analyzer) *Service {
	service := &Service{
		cfg:             cfg,
		store:           store,
		managers:        managers,
		analyzers:       analyzers,
		timeout:         cfg.RequestTimeoutDuration(),
		resolver:        net.DefaultResolver,
		objectCache:     make(map[string]objectCacheEntry),
		policyCache:     make(map[string]policyCacheEntry),
		readCache:       make(map[string]readCacheEntry),
		managerCache:    make(map[string]readCacheEntry),
		monitorCache:    make(map[string]readCacheEntry),
		liveLookupCache: make(map[string]liveLookupEntry),
		objectListCache: make(map[string]readCacheEntry),
		dnsCache:        make(map[string]dnsCacheEntry),
		webFilter:       newWebFilterCaches(),
	}
	if store != nil {
		// Background refreshes re-read policy tables a tool already cached.
		// Explicit refresh_inventory clears those caches and does not use
		// this hook, so it does not warm what it just dropped.
		store.SetAfterRefresh(service.warmCachedPolicies)
	}
	return service
}

// DNS cache TTL for successful A/AAAA and CNAME lookups. Failures use a
// shorter TTL so a missing name is not queried on every call, and a name
// that appears later is not stuck for the full success interval.
const (
	dnsCacheTTL         = 5 * time.Minute
	dnsNegativeCacheTTL = 30 * time.Second
)

func (s *Service) lookupIPAddrWithCache(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("hostname is required")
	}
	if addresses, err, ok := s.cachedAddresses(host); ok {
		return addresses, err
	}
	shared, err := s.sharedRead(ctx, "dns-a\x00"+host, func() (any, error) {
		if addresses, cachedErr, ok := s.cachedAddresses(host); ok {
			return dnsAddrResult{addresses: addresses, err: cachedErr}, nil
		}
		addresses, lookupErr := s.resolver.LookupIPAddr(ctx, host)
		if isContextError(lookupErr) {
			return nil, lookupErr
		}
		s.storeAddresses(host, addresses, lookupErr)
		if lookupErr != nil {
			return dnsAddrResult{err: lookupErr}, nil
		}
		return dnsAddrResult{addresses: cloneIPAddrs(addresses)}, nil
	})
	if err != nil {
		return nil, err
	}
	result, _ := shared.(dnsAddrResult)
	if result.err != nil {
		return nil, result.err
	}
	return result.addresses, nil
}

type dnsAddrResult struct {
	addresses []net.IPAddr
	err       error
}

func (s *Service) lookupCNAMEWithCache(ctx context.Context, host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("hostname is required")
	}
	if cname, err, ok := s.cachedCNAME(host); ok {
		return cname, err
	}
	shared, err := s.sharedRead(ctx, "dns-c\x00"+host, func() (any, error) {
		if cname, cachedErr, ok := s.cachedCNAME(host); ok {
			return dnsNameResult{cname: cname, err: cachedErr}, nil
		}
		cname, lookupErr := s.resolver.LookupCNAME(ctx, host)
		if isContextError(lookupErr) {
			return nil, lookupErr
		}
		s.storeCNAME(host, cname, lookupErr)
		return dnsNameResult{cname: cname, err: lookupErr}, nil
	})
	if err != nil {
		return "", err
	}
	result, _ := shared.(dnsNameResult)
	if result.err != nil {
		return "", result.err
	}
	return result.cname, nil
}

type dnsNameResult struct {
	cname string
	err   error
}

func (s *Service) cachedAddresses(host string) ([]net.IPAddr, error, bool) {
	s.dnsCacheMu.RLock()
	entry, ok := s.dnsCache[host]
	s.dnsCacheMu.RUnlock()
	if !ok || !entry.haveAddresses || time.Now().After(entry.addressExpiry) {
		return nil, nil, false
	}
	if entry.addressErr != "" {
		return nil, fmt.Errorf("%s", entry.addressErr), true
	}
	return cloneIPAddrs(entry.addresses), nil, true
}

func (s *Service) cachedCNAME(host string) (string, error, bool) {
	s.dnsCacheMu.RLock()
	entry, ok := s.dnsCache[host]
	s.dnsCacheMu.RUnlock()
	if !ok || !entry.haveCNAME || time.Now().After(entry.cnameExpiry) {
		return "", nil, false
	}
	if entry.cnameErr != "" {
		return "", fmt.Errorf("%s", entry.cnameErr), true
	}
	return entry.cname, nil, true
}

func (s *Service) storeAddresses(host string, addresses []net.IPAddr, err error) {
	s.dnsCacheMu.Lock()
	defer s.dnsCacheMu.Unlock()
	s.evictDNSLocked()
	entry := s.dnsCache[host]
	entry.haveAddresses = true
	entry.addresses = cloneIPAddrs(addresses)
	entry.addressErr = ""
	ttl := dnsCacheTTL
	if err != nil {
		entry.addresses = nil
		entry.addressErr = err.Error()
		ttl = dnsNegativeCacheTTL
	}
	entry.addressExpiry = time.Now().Add(ttl)
	s.dnsCache[host] = entry
}

func (s *Service) storeCNAME(host, cname string, err error) {
	s.dnsCacheMu.Lock()
	defer s.dnsCacheMu.Unlock()
	s.evictDNSLocked()
	entry := s.dnsCache[host]
	entry.haveCNAME = true
	entry.cname = cname
	entry.cnameErr = ""
	ttl := dnsCacheTTL
	if err != nil {
		entry.cname = ""
		entry.cnameErr = err.Error()
		ttl = dnsNegativeCacheTTL
	}
	entry.cnameExpiry = time.Now().Add(ttl)
	s.dnsCache[host] = entry
}

func cloneIPAddrs(addresses []net.IPAddr) []net.IPAddr {
	if len(addresses) == 0 {
		return nil
	}
	cloned := make([]net.IPAddr, len(addresses))
	for i, address := range addresses {
		cloned[i] = address
		cloned[i].IP = append(net.IP(nil), address.IP...)
	}
	return cloned
}

func (s *Service) evictDNSLocked() {
	now := time.Now()
	for host, entry := range s.dnsCache {
		addressesDead := !entry.haveAddresses || now.After(entry.addressExpiry)
		cnameDead := !entry.haveCNAME || now.After(entry.cnameExpiry)
		if addressesDead && cnameDead {
			delete(s.dnsCache, host)
		}
	}
}

func (s *Service) InventoryStatus(ctx context.Context) (inventory.Snapshot, error) {
	return s.store.Snapshot(), nil
}

// RefreshInventory refreshes the inventory and drops cached FortiManager
// objects, policies, monitor reads, live lookups and web filter settings,
// so a caller who just changed configuration gets fresh answers on the next
// lookup. FortiAnalyzer reads keep their own TTL.
//
// The refresh runs detached from the caller: a client that stops waiting
// does not cancel it, which would publish a partial snapshot marked stale.
// The call returns the inventory summary (as inventory_status without
// interfaces, routes or raw records) when the refresh finished, or the
// current summary with refresh_in_progress when the caller's wait ended
// first.
func (s *Service) RefreshInventory(ctx context.Context) (inventory.Snapshot, error) {
	if s.store == nil {
		return inventory.Snapshot{}, fmt.Errorf("inventory store is not configured")
	}
	// Use a mutex to prevent concurrent refresh calls from spawning duplicate
	// background refreshes. Only one caller triggers the actual refresh.
	if !s.refreshMu.TryLock() {
		// Another refresh is already in progress; return the current state
		// and let the caller know a refresh is running
		return s.ListFortiGates(ctx, "", "", false, false, false)
	}
	defer s.refreshMu.Unlock()
	done := make(chan struct{})
	s.goBackground(func() {
		defer close(done)
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("inventory refresh panicked", "panic", fmt.Sprint(recovered))
			}
		}()
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.RefreshTimeoutDuration())
		defer cancel()
		s.store.Refresh(refreshCtx)
		s.clearCaches()
	})
	select {
	case <-done:
	case <-ctx.Done():
	}
	return s.ListFortiGates(ctx, "", "", false, false, false)
}

// WaitBackground blocks until refresh_inventory calls and web filter loads
// started with goBackground have finished.
func (s *Service) WaitBackground() {
	s.background.Wait()
}

func (s *Service) goBackground(fn func()) {
	s.background.Go(func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("background task panicked", "panic", fmt.Sprint(recovered))
			}
		}()
		fn()
	})
}

func (s *Service) clearCaches() {
	s.cacheEpoch.Add(1)
	s.cacheMu.Lock()
	s.objectCache = make(map[string]objectCacheEntry)
	s.policyCache = make(map[string]policyCacheEntry)
	s.managerCache = make(map[string]readCacheEntry)
	s.monitorCache = make(map[string]readCacheEntry)
	s.liveLookupCache = make(map[string]liveLookupEntry)
	s.objectListCache = make(map[string]readCacheEntry)
	s.cacheMu.Unlock()
	s.webFilter.clear()
}

// cacheWriteAllowed reports whether a read that observed epoch may store
// its result. The caller holds the mutex that clearCaches takes for that map.
func (s *Service) cacheWriteAllowed(epoch uint64) bool {
	return s.cacheEpoch.Load() == epoch
}

func (s *Service) ListFortiGates(ctx context.Context, profile, adom string, includeInterfaces, includeRoutes, includeRaw bool) (inventory.Snapshot, error) {
	if s.store == nil {
		return inventory.Snapshot{}, fmt.Errorf("inventory store is not configured")
	}
	snapshot := s.store.Snapshot()
	{
		filtered := snapshot
		matchingProfiles := make(map[string]struct{})
		filtered.ADOMs = make([]inventory.ADOMRecord, 0, len(snapshot.ADOMs))
		for _, record := range snapshot.ADOMs {
			if profile != "" && record.Profile != profile {
				continue
			}
			if adom != "" && record.ADOM.Name != adom {
				continue
			}
			if !s.profileAllowsADOM(record.Profile, record.ADOM.Name) {
				continue
			}
			filtered.ADOMs = append(filtered.ADOMs, record)
			matchingProfiles[record.Profile] = struct{}{}
		}
		for _, device := range snapshot.Devices {
			if (profile == "" || device.Profile == profile) && (adom == "" || device.ADOM == adom) && s.profileAllowsADOM(device.Profile, device.ADOM) {
				matchingProfiles[device.Profile] = struct{}{}
			}
		}
		filtered.Profiles = make([]inventory.ProfileState, 0, len(snapshot.Profiles))
		for _, state := range snapshot.Profiles {
			if profile != "" && state.Profile != profile {
				continue
			}
			if profile == "" && adom != "" {
				if _, ok := matchingProfiles[state.Profile]; !ok {
					continue
				}
			}
			filtered.Profiles = append(filtered.Profiles, state)
		}
		filtered.Errors = make([]inventory.RefreshError, 0, len(snapshot.Errors))
		for _, refreshError := range snapshot.Errors {
			if profile != "" && refreshError.Profile != "" && refreshError.Profile != profile {
				continue
			}
			if adom != "" && refreshError.ADOM != "" && refreshError.ADOM != adom {
				continue
			}
			if refreshError.ADOM != "" && !s.profileAllowsADOM(refreshError.Profile, refreshError.ADOM) {
				continue
			}
			if profile == "" && adom != "" && refreshError.ADOM == "" {
				if _, ok := matchingProfiles[refreshError.Profile]; !ok {
					continue
				}
			}
			filtered.Errors = append(filtered.Errors, refreshError)
		}
		filtered.UnavailableDevices = make([]inventory.DeviceNotice, 0, len(snapshot.UnavailableDevices))
		for _, notice := range snapshot.UnavailableDevices {
			if (profile == "" || notice.Profile == profile) && (adom == "" || notice.ADOM == adom) && s.profileAllowsADOM(notice.Profile, notice.ADOM) {
				filtered.UnavailableDevices = append(filtered.UnavailableDevices, notice)
			}
		}
		snapshot = filtered
	}
	filteredDevices := make([]fortinet.Device, 0, len(snapshot.Devices))
	for _, device := range snapshot.Devices {
		if profile != "" && device.Profile != profile {
			continue
		}
		if adom != "" && device.ADOM != adom {
			continue
		}
		if !s.profileAllowsADOM(device.Profile, device.ADOM) {
			continue
		}
		if !includeInterfaces {
			device.Interfaces = nil
		}
		if !includeRoutes {
			device.Routes = nil
			device.PolicyRoutes = nil
			device.SDWAN = nil
		}
		if !includeRaw {
			stripDeviceRaw(&device)
		}
		filteredDevices = append(filteredDevices, device)
	}
	snapshot.Devices = filteredDevices
	if !includeRaw {
		for index := range snapshot.ADOMs {
			snapshot.ADOMs[index].ADOM.Raw = nil
		}
	}
	return snapshot, nil
}

// stripDeviceRaw drops the appliance records that parsed fields already
// summarize. Raw payloads dominate token cost and rarely add evidence.
func stripDeviceRaw(device *fortinet.Device) {
	device.Raw = nil
	if device.Interfaces != nil {
		interfaces := make([]fortinet.Interface, len(device.Interfaces))
		copy(interfaces, device.Interfaces)
		for index := range interfaces {
			interfaces[index].Raw = nil
		}
		device.Interfaces = interfaces
	}
	if device.Routes != nil {
		routes := make([]fortinet.Route, len(device.Routes))
		copy(routes, device.Routes)
		for index := range routes {
			routes[index].Raw = nil
		}
		device.Routes = routes
	}
}

func stripInterfaceRaw(interfaces []fortinet.Interface) []fortinet.Interface {
	result := make([]fortinet.Interface, len(interfaces))
	copy(result, interfaces)
	for index := range result {
		result[index].Raw = nil
	}
	return result
}

func stripPolicyRaw(policies []fortinet.FirewallPolicy) []fortinet.FirewallPolicy {
	result := make([]fortinet.FirewallPolicy, len(policies))
	copy(result, policies)
	for index := range result {
		result[index].Raw = nil
	}
	return result
}

// interfaceSnapshotUsable reports whether the stored interface list itself
// was read. A zone or route failure sets DataError and must not force
// another interface read.
func interfaceSnapshotUsable(device fortinet.Device) bool {
	if len(device.Interfaces) == 0 {
		return false
	}
	for stage := range strings.SplitSeq(device.DataError, ",") {
		if strings.TrimSpace(stage) == "list_interfaces" {
			return false
		}
	}
	return true
}

// GetInterfaces returns a FortiGate's interfaces with zones. The inventory
// snapshot already holds them (refreshed on the inventory interval), so they
// are served from there without a request unless fresh is set, the device
// is not inventoried, or its last interface read failed.
func (s *Service) GetInterfaces(ctx context.Context, profile, adom, device string, vdom string, includeRaw, fresh bool) (any, error) {
	adom, err := s.scopeADOM(profile, adom, device)
	if err != nil {
		return nil, err
	}
	manager, err := s.managerForScope(profile, adom, device)
	if err != nil {
		return nil, err
	}
	if err := s.validateManagerADOM(manager, adom); err != nil {
		return nil, err
	}
	if !fresh && s.store != nil {
		matches := s.store.FindDevices(manager.Name(), adom, device)
		if len(matches) == 1 && interfaceSnapshotUsable(matches[0]) {
			inventoried := matches[0]
			interfaces := inventoried.Interfaces
			if !includeRaw {
				interfaces = stripInterfaceRaw(interfaces)
			}
			note := "Served from the inventory snapshot (FortiManager device database as of data_as_of); pass fresh=true to read FortiManager now."
			if inventoried.DataError != "" {
				note = "Interfaces are from the inventory snapshot (data_as_of). data_error names a zone or route read that failed on the last refresh; pass fresh=true to read FortiManager now."
			}
			result := map[string]any{
				"profile": manager.Name(), "adom": adom, "device": device, "source": "inventory_snapshot", "data_as_of": inventoried.DataAsOf,
				"note": note,
			}
			if inventoried.DataError != "" {
				result["data_error"] = inventoried.DataError
			}
			if vdom != "" {
				result["vdom"] = vdom
				interfaces = interfacesInVDOM(interfaces, vdom)
			}
			result["interfaces"] = interfaces
			return result, nil
		}
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	type interfaceRead struct {
		interfaces []fortinet.Interface
		err        error
	}
	shared, ferr := s.sharedRead(ctx, "ifaces\x00"+manager.Name()+"\x00"+adom+"\x00"+device, func() (any, error) {
		interfaces, readErr := manager.ListInterfaces(ctx, adom, device)
		return interfaceRead{interfaces: interfaces, err: readErr}, nil
	})
	if ferr != nil {
		return nil, ferr
	}
	read, _ := shared.(interfaceRead)
	interfaces, err := read.interfaces, read.err
	if err != nil && interfaces == nil {
		return nil, err
	}
	warnings := []inventory.RefreshError{}
	if err != nil {
		warnings = append(warnings, serviceRefreshError(manager.Name(), adom, device, "", "list_interface_zones", err))
	}
	if !includeRaw {
		interfaces = stripInterfaceRaw(interfaces)
	}
	if vdom == "" {
		return map[string]any{"profile": manager.Name(), "adom": adom, "device": device, "source": "fortimanager", "interfaces": interfaces, "errors": warnings}, nil
	}
	return map[string]any{"profile": manager.Name(), "adom": adom, "device": device, "vdom": vdom, "source": "fortimanager", "interfaces": interfacesInVDOM(interfaces, vdom), "errors": warnings}, nil
}

func interfacesInVDOM(interfaces []fortinet.Interface, vdom string) []fortinet.Interface {
	filtered := make([]fortinet.Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.VDOM == vdom {
			filtered = append(filtered, iface)
		}
	}
	return filtered
}

// scopeADOM returns adom, or the ADOM of device from inventory when adom is
// empty, so tools accept a FortiGate name alone.
func (s *Service) scopeADOM(profile, adom, device string) (string, error) {
	adom, device = strings.TrimSpace(adom), strings.TrimSpace(device)
	if adom != "" {
		return adom, nil
	}
	if device == "" || s.store == nil {
		return "", fmt.Errorf("adom is required (or pass device: its ADOM is taken from the inventory)")
	}
	var found []string
	for _, candidate := range s.store.FindDevices(profile, "", device) {
		found = append(found, candidate.ADOM)
	}
	found = uniqueStrings(found)
	switch {
	case len(found) == 1:
		return found[0], nil
	case len(found) > 1:
		return "", fmt.Errorf("device %q exists in several ADOMs (%s); pass adom", device, strings.Join(found, ", "))
	case !s.store.HasSnapshot():
		return "", fmt.Errorf("adom is required while the inventory loads: %s", inventory.NotReadyMessage(s.store.Snapshot()))
	default:
		return "", fmt.Errorf("device %q is not in the inventory; pass adom or check the name with inventory_status", device)
	}
}

// proxyTimeoutSeconds asks FortiManager to give up on a FortiGate 5 s before
// the caller's deadline, so a silent FortiGate yields a clear timeout and
// frees the request lane instead of holding it for FortiManager's 60 s.
func proxyTimeoutSeconds(ctx context.Context) int {
	seconds := 60
	if deadline, ok := ctx.Deadline(); ok {
		seconds = int(time.Until(deadline).Seconds()) - 5
	}
	return min(max(seconds, 5), 60)
}

func (s *Service) GetFortiManagerSettings(ctx context.Context, profile, adom, device, vdom, resource string) (fortinet.ProxyResult, error) {
	resource = canonicalFortiGateResource(resource)
	if err := validateFortiGateReadResource(resource); err != nil {
		return fortinet.ProxyResult{}, err
	}
	adom, err := s.scopeADOM(profile, adom, device)
	if err != nil {
		return fortinet.ProxyResult{}, err
	}
	manager, err := s.managerForScope(profile, adom, device)
	if err != nil {
		return fortinet.ProxyResult{}, err
	}
	if err := s.validateManagerADOM(manager, adom); err != nil {
		return fortinet.ProxyResult{}, err
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	ttl, cacheable := cacheableProxyResource(resource)
	key := strings.Join([]string{manager.Name(), adom, device, vdom, resource}, "\x00")
	epoch := s.cacheEpoch.Load()
	if cacheable {
		if value, ok := s.loadCached("monitor", key, ttl); ok {
			if result, ok := value.(fortinet.ProxyResult); ok {
				return result, nil
			}
		}
	}
	shared, err := s.sharedRead(ctx, "proxy\x00"+key, func() (any, error) {
		if cacheable {
			if value, ok := s.loadCached("monitor", key, ttl); ok {
				return value, nil
			}
		}
		var result fortinet.ProxyResult
		var readErr error
		if reader, ok := manager.(fortinet.ProxyTimeoutReader); ok {
			result, readErr = reader.ProxyGetTimeout(ctx, adom, device, vdom, resource, proxyTimeoutSeconds(ctx))
		} else {
			result, readErr = manager.ProxyGet(ctx, adom, device, vdom, resource)
		}
		if readErr != nil {
			return nil, readErr
		}
		if cacheable {
			s.storeCacheValue(&s.monitorCache, key, result, ttl, epoch)
		}
		return result, nil
	})
	if err != nil {
		return fortinet.ProxyResult{}, err
	}
	result, _ := shared.(fortinet.ProxyResult)
	return result, nil
}

func (s *Service) GetFortiManagerRead(ctx context.Context, profile, resource string, data map[string]any) (any, error) {
	resource, err := validateFortiManagerReadResource(resource)
	if err != nil {
		return nil, err
	}
	manager, err := s.manager(profile)
	if err != nil {
		return nil, err
	}
	if adom, ok := resourceADOM(resource); ok {
		if err := s.validateManagerADOM(manager, adom); err != nil {
			return nil, err
		}
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	encoded, _ := json.Marshal(data)
	key := manager.Name() + "\x00" + resource + "\x00" + string(encoded)
	cacheable := cacheableManagerRead(resource)
	epoch := s.cacheEpoch.Load()
	if cacheable {
		if value, ok := s.loadCached("manager", key, managerMetaCacheTTL); ok {
			return value, nil
		}
	}
	return s.sharedRead(ctx, "fmg\x00"+key, func() (any, error) {
		if cacheable {
			if value, ok := s.loadCached("manager", key, managerMetaCacheTTL); ok {
				return value, nil
			}
		}
		value, err := manager.Read(ctx, resource, data)
		if err != nil {
			return nil, err
		}
		if cacheable {
			s.storeCacheValue(&s.managerCache, key, value, managerMetaCacheTTL, epoch)
		}
		return value, nil
	})
}

// PolicyListInput selects firewall policies for list_firewall_policies.
type PolicyListInput struct {
	Profile    string
	ADOM       string
	Package    string
	Device     string
	IPVersion  string
	PolicyID   int
	Limit      int
	Offset     int
	IncludeRaw bool
}

const (
	defaultPolicyListLimit = 100
	maxPolicyListLimit     = 1000
	defaultObjectListLimit = 100
	maxObjectListLimit     = 1000
)

// ListPolicies lists firewall policies through the shared policy cache, so
// lookups and listings of the same package read it once. With device the
// packages come from the inventory's package targets; FortiManager is asked
// for the package list only when those are unknown or unverified.
func (s *Service) ListPolicies(ctx context.Context, input PolicyListInput) (any, error) {
	packageName, device := strings.TrimSpace(input.Package), strings.TrimSpace(input.Device)
	adom, err := s.scopeADOM(input.Profile, input.ADOM, device)
	if err != nil {
		return nil, err
	}
	manager, err := s.managerForScope(input.Profile, adom, device)
	if err != nil {
		return nil, err
	}
	if err := s.validateManagerADOM(manager, adom); err != nil {
		return nil, err
	}
	ipv6 := false
	selectedIPVersion := "ipv4"
	switch strings.ToLower(strings.TrimSpace(input.IPVersion)) {
	case "", "4", "ipv4":
	case "6", "ipv6":
		ipv6, selectedIPVersion = true, "ipv6"
	default:
		return nil, fmt.Errorf("ip_version must be ipv4 or ipv6")
	}
	limit := input.Limit
	if limit <= 0 {
		limit = defaultPolicyListLimit
	}
	limit = min(limit, maxPolicyListLimit)
	if input.Offset < 0 {
		return nil, fmt.Errorf("offset must not be negative")
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	var snapshot inventory.Snapshot
	if s.store != nil {
		snapshot = s.store.Snapshot()
	}
	packages := []string{packageName}
	targetDevice := fortinet.Device{Name: device}
	scopeWarnings := make([]string, 0)
	scopeErrors := make([]inventory.RefreshError, 0)
	packageMissing := false
	scopeUnavailable := packageScopeUnavailable(snapshot, manager.Name(), adom)
	scopeVerified := device == ""
	if device != "" && s.store != nil {
		if matches := s.store.FindDevices(manager.Name(), adom, device); len(matches) > 0 {
			targetDevice = matches[0]
		}
		scopeVerified = !scopeUnavailable && targetDevice.ADOM == adom && (len(targetDevice.VDOMs) > 0 || len(targetDevice.Packages) > 0)
	}
	listedPackages, havePackageList := s.snapshotPackages(manager.Name(), adom)
	switch {
	case packageName == "" && device != "" && scopeVerified && len(targetDevice.Packages) > 0:
		// The inventory already maps this device to its packages.
		packages = append([]string(nil), targetDevice.Packages...)
	case packageName == "":
		listed, listErr := s.policyPackageList(ctx, manager, adom, listedPackages, havePackageList)
		if listErr != nil {
			if device == "" || len(targetDevice.Packages) == 0 {
				return nil, listErr
			}
			scopeVerified = false
			scopeWarnings = append(scopeWarnings, fmt.Sprintf("Could not refresh policy packages for %s/%s: %v; using last-known-good package associations.", adom, device, listErr))
			scopeErrors = append(scopeErrors, serviceRefreshError(manager.Name(), adom, device, "", "list_policy_packages", listErr))
			packages = append([]string(nil), targetDevice.Packages...)
		} else {
			packages = make([]string, 0, len(listed))
			for _, pkg := range listed {
				if device == "" || scopeUnavailable || packageTargetsDevice(pkg, targetDevice) {
					packages = append(packages, pkg.Name)
				}
			}
		}
	case device != "" && scopeVerified && containsString(targetDevice.Packages, packageName):
		// The inventory confirms the package is assigned to the device.
	case device != "":
		listed, listErr := s.policyPackageList(ctx, manager, adom, listedPackages, havePackageList)
		if listErr != nil {
			scopeVerified = false
			scopeWarnings = append(scopeWarnings, fmt.Sprintf("Could not verify policy package %q scope for %s/%s: %v", packageName, adom, device, listErr))
			scopeErrors = append(scopeErrors, serviceRefreshError(manager.Name(), adom, device, packageName, "list_policy_packages", listErr))
		} else {
			found := false
			for _, pkg := range listed {
				if pkg.Name != packageName {
					continue
				}
				found = true
				if !packageTargetsDevice(pkg, targetDevice) {
					scopeVerified = false
					scopeWarnings = append(scopeWarnings, fmt.Sprintf("Policy package %q is not assigned to %s/%s; package scope is unverified.", packageName, adom, device))
				}
				break
			}
			if !found {
				packageMissing = true
				scopeVerified = false
				scopeWarnings = append(scopeWarnings, fmt.Sprintf("Policy package %q was not found in ADOM %q; package scope is unverified.", packageName, adom))
				scopeErrors = append(scopeErrors, serviceRefreshError(manager.Name(), adom, device, packageName, "list_policy_packages", fmt.Errorf("policy package %q was not found in ADOM %q", packageName, adom)))
			}
		}
	}
	packages = uniqueStrings(packages)
	result := map[string]any{"profile": manager.Name(), "adom": adom, "ip_version": selectedIPVersion, "packages": map[string]any{}}
	if device != "" {
		result["device"] = device
		result["package_scope_verified"] = scopeVerified
		if len(targetDevice.VDOMs) > 0 {
			result["vdoms"] = append([]string(nil), targetDevice.VDOMs...)
		}
		if len(targetDevice.PackageTargets) > 0 {
			result["package_targets"] = append([]fortinet.PackageTarget(nil), targetDevice.PackageTargets...)
		}
	}
	warnings := append([]string(nil), scopeWarnings...)
	if scopeUnavailable && device != "" {
		warnings = append(warnings, "FortiManager device-group scope could not be refreshed for this ADOM; all listed packages were included for the requested device.")
	}
	packageResults := result["packages"].(map[string]any)
	total, skipped, returned := 0, 0, 0
	for _, pkg := range packages {
		if pkg == "" {
			continue
		}
		if packageMissing && pkg == packageName {
			packageResults[pkg] = structuredServiceError(fmt.Errorf("policy package %q was not found in ADOM %q", pkg, adom))
			continue
		}
		policies, policyErr := s.familyPolicies(ctx, manager, adom, pkg, ipv6, snapshot.GeneratedAt)
		if policyErr != nil {
			scopeErrors = append(scopeErrors, serviceRefreshError(manager.Name(), adom, device, pkg, "list_policies", policyErr))
			if len(policies) == 0 {
				packageResults[pkg] = structuredServiceError(policyErr)
				continue
			}
		}
		selected := make([]fortinet.FirewallPolicy, 0, len(policies))
		for _, policy := range policies {
			if input.PolicyID > 0 && policy.PolicyID != input.PolicyID {
				continue
			}
			if !policyHasFamily(policy, ipv6) {
				continue
			}
			total++
			if skipped < input.Offset {
				skipped++
				continue
			}
			if returned >= limit {
				continue
			}
			returned++
			// Copy: the cached policies are shared with other calls.
			if device != "" && scopeVerified && policy.Device == "" {
				policy.Device = device
			}
			if !input.IncludeRaw {
				policy.Raw = nil
			}
			selected = append(selected, policy)
		}
		packageResults[pkg] = selected
	}
	result["total"], result["returned"], result["offset"], result["limit"] = total, returned, input.Offset, limit
	if input.Offset+returned < total {
		result["truncated"] = true
		warnings = append(warnings, fmt.Sprintf("%d of %d matching policies returned; continue with offset=%d, or narrow with package, device or policy_id.", returned, total, input.Offset+returned))
	}
	if len(warnings) > 0 {
		result["warnings"] = warnings
	}
	if len(scopeErrors) > 0 {
		result["errors"] = scopeErrors
	}
	return result, nil
}

// policyHasFamily reports whether a policy can match flows of one IP
// family: FortiOS 6.4+ keeps IPv4 and IPv6 addresses in separate columns,
// and a policy with addresses of one family only applies to that family.
func policyHasFamily(policy fortinet.FirewallPolicy, ipv6 bool) bool {
	v4 := len(policy.SourceAddresses) > 0 || len(policy.DestinationAddresses) > 0 || policy.SourceInternetService || policy.DestinationInternetService
	v6 := len(policy.SourceAddresses6) > 0 || len(policy.DestinationAddresses6) > 0 || policy.SourceInternetService6 || policy.DestinationInternetService6
	if !v4 && !v6 {
		// Neither column was read; keep the policy rather than hide it.
		return true
	}
	if ipv6 {
		return v6
	}
	return v4
}

// ObjectListInput selects firewall objects for list_policy_objects.
type ObjectListInput struct {
	Profile                string
	ADOM                   string
	Device                 string
	ObjectType             string
	Name                   string
	Limit                  int
	Offset                 int
	IncludeDynamicMappings bool
}

// ListObjects reads one ADOM object table (or one object by name). The page
// is cut by FortiManager (range), not after downloading the whole table,
// and per-device mappings are left out unless requested.
func (s *Service) ListObjects(ctx context.Context, input ObjectListInput) (any, error) {
	objectType := strings.TrimSpace(input.ObjectType)
	if err := validateObjectType(objectType); err != nil {
		return nil, err
	}
	adom, err := s.scopeADOM(input.Profile, input.ADOM, input.Device)
	if err != nil {
		return nil, err
	}
	manager, err := s.managerForScope(input.Profile, adom, "")
	if err != nil {
		return nil, err
	}
	if err := s.validateManagerADOM(manager, adom); err != nil {
		return nil, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = defaultObjectListLimit
	}
	limit = min(limit, maxObjectListLimit)
	if input.Offset < 0 {
		return nil, fmt.Errorf("offset must not be negative")
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	resource := "/pm/config/adom/" + escapeSegment(adom) + "/obj/" + objectType
	data := map[string]any{}
	if input.Name != "" {
		resource += "/" + escapeSegment(input.Name)
	} else {
		data["range"] = []int{input.Offset, limit}
	}
	// The stripped page is safe to reuse. Dynamic mappings are large and stay live.
	cacheList := !input.IncludeDynamicMappings
	listKey := strings.Join([]string{manager.Name(), adom, objectType, input.Name, strconv.Itoa(input.Offset), strconv.Itoa(limit)}, "\x00")
	var objects any
	if cacheList {
		if value, ok := s.loadCached("objects", listKey, objectCacheTTL); ok {
			objects = value
		}
	}
	if objects == nil {
		epoch := s.cacheEpoch.Load()
		shared, err := s.sharedRead(ctx, "objlist\x00"+listKey+"\x00"+strconv.FormatBool(input.IncludeDynamicMappings), func() (any, error) {
			if cacheList {
				if value, ok := s.loadCached("objects", listKey, objectCacheTTL); ok {
					return value, nil
				}
			}
			read, readErr := manager.Read(ctx, resource, data)
			if readErr != nil {
				return nil, readErr
			}
			if cacheList {
				read = withoutDynamicMappings(read)
				s.storeCacheValue(&s.objectListCache, listKey, read, objectCacheTTL, epoch)
			}
			return read, nil
		})
		if err != nil {
			return nil, err
		}
		objects = shared
	}
	if !input.IncludeDynamicMappings {
		objects = withoutDynamicMappings(objects)
	}
	result := map[string]any{"profile": manager.Name(), "adom": adom, "object_type": objectType, "objects": limitAny(objects, limit)}
	if input.Name == "" {
		result["offset"], result["limit"] = input.Offset, limit
		if records, ok := objects.([]any); ok && len(records) >= limit {
			result["truncated"] = true
			result["hint"] = fmt.Sprintf("The page is full; more objects may exist. Continue with offset=%d, or read one object by name.", input.Offset+limit)
		}
	}
	return result, nil
}

// withoutDynamicMappings drops the per-device mappings of object records,
// which can be many times larger than the object itself.
func withoutDynamicMappings(value any) any {
	strip := func(record map[string]any) map[string]any {
		if _, ok := record["dynamic_mapping"]; !ok {
			return record
		}
		copied := make(map[string]any, len(record))
		for key, field := range record {
			if key != "dynamic_mapping" {
				copied[key] = field
			}
		}
		copied["dynamic_mapping_omitted"] = true
		return copied
	}
	switch typed := value.(type) {
	case []any:
		records := make([]any, len(typed))
		for index, item := range typed {
			if record, ok := item.(map[string]any); ok {
				records[index] = strip(record)
			} else {
				records[index] = item
			}
		}
		return records
	case map[string]any:
		return strip(typed)
	}
	return value
}

func serviceRefreshError(profile, adom, device, packageName, stage string, err error) inventory.RefreshError {
	info := fortinet.DescribeError(err)
	message := "service request failed"
	if err != nil {
		message = err.Error()
	}
	return inventory.RefreshError{
		Profile:    profile,
		ADOM:       adom,
		Device:     device,
		Package:    packageName,
		Stage:      stage,
		Kind:       info.Kind,
		Code:       info.Code,
		HTTPStatus: info.HTTPStatus,
		Resource:   info.Resource,
		Retryable:  info.Retryable,
		Message:    message,
		Hint:       info.Hint,
	}
}

func structuredServiceError(err error) map[string]any {
	return map[string]any{
		"error":         err.Error(),
		"error_details": fortinet.DescribeError(err),
	}
}

func (s *Service) FortiAnalyzerStatus(ctx context.Context, profile string) (any, error) {
	analyzer, err := s.analyzer(profile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	status, err := s.cachedAnalyzerRead(ctx, analyzer.Name(), "/sys/status", nil, func() (any, error) { return analyzer.Status(ctx) })
	if err != nil {
		return nil, err
	}
	return map[string]any{"profile": analyzer.Name(), "status": status}, nil
}

func (s *Service) SearchLogs(ctx context.Context, profile string, request fortinet.LogSearchRequest) (fortinet.LogSearchResult, error) {
	analyzer, err := s.analyzer(profile)
	if err != nil {
		return fortinet.LogSearchResult{}, err
	}
	if request.ADOM == "" {
		if configured, configErr := s.cfg.Profile(analyzer.Name(), config.ProductFortiAnalyzer); configErr == nil && len(configured.ADOMs) == 1 {
			request.ADOM = configured.ADOMs[0]
		}
	}
	if request.ADOM != "" {
		if err := s.validateAnalyzerADOM(analyzer, request.ADOM); err != nil {
			return fortinet.LogSearchResult{}, err
		}
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	result, err := analyzer.SearchLogs(ctx, request)
	if err != nil {
		return result, err
	}
	if result.Complete && !result.TimedOut && result.Count == 0 && result.Offset == 0 && result.ADOM != "" {
		stats, statsErr := s.FortiAnalyzerRead(ctx, analyzer.Name(), "/logview/adom/"+url.PathEscape(result.ADOM)+"/logstats", nil)
		if statsErr != nil {
			result.Warnings = append(result.Warnings, "Log receipt could not be read: "+statsErr.Error())
		} else {
			result.LogReceipt = stats
		}
	}
	return result, nil
}

func (s *Service) FortiAnalyzerRead(ctx context.Context, profile, resource string, data map[string]any) (any, error) {
	resource, err := validateFortiAnalyzerReadResource(resource)
	if err != nil {
		return nil, err
	}
	analyzer, err := s.analyzer(profile)
	if err != nil {
		return nil, err
	}
	if adom, ok := resourceADOM(resource); ok {
		if err := s.validateAnalyzerADOM(analyzer, adom); err != nil {
			return nil, err
		}
	}
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	return s.cachedAnalyzerRead(ctx, analyzer.Name(), resource, data, func() (any, error) { return analyzer.Read(ctx, resource, data) })
}

const (
	// analyzerCacheTTL bounds how long FortiAnalyzer reads that change rarely
	// (system status, device lists, Log View field lists, log receipt) are reused.
	analyzerCacheTTL = 5 * time.Minute
	// managerMetaCacheTTL matches the analyzer status cache.
	managerMetaCacheTTL = 5 * time.Minute
	// monitorCacheTTL is long enough that one investigation does not proxy
	// the same routing table or HA peer twice, and short enough that a
	// failover is not hidden.
	monitorCacheTTL = 30 * time.Second
	// liveLookupTTL bounds reuse of one live policy-lookup tuple.
	liveLookupTTL        = 30 * time.Second
	maxLiveLookupEntries = 1024
)

type readCacheEntry struct {
	created time.Time
	value   any
}

// cacheableAnalyzerRead names FortiAnalyzer reads whose answers change
// rarely: system status, the device list, and Log View field lists.
// Other /dvmdb paths (groups, tasks, a single device record) stay live.
func cacheableAnalyzerRead(resource string) bool {
	lower := strings.ToLower(strings.TrimSpace(resource))
	pathPart, _, _ := strings.Cut(lower, "?")
	if pathPart == "/sys/status" || pathPart == "/dvmdb/device" || strings.HasSuffix(pathPart, "/logfields") || strings.HasSuffix(pathPart, "/logstats") {
		return true
	}
	parts := strings.Split(strings.Trim(pathPart, "/"), "/")
	return len(parts) == 4 && parts[0] == "dvmdb" && parts[1] == "adom" && parts[3] == "device"
}

func (s *Service) cachedAnalyzerRead(ctx context.Context, profile, resource string, data map[string]any, read func() (any, error)) (any, error) {
	if !cacheableAnalyzerRead(resource) {
		return read()
	}
	encoded, _ := json.Marshal(data)
	key := profile + "\x00" + resource + "\x00" + string(encoded)
	epoch := s.cacheEpoch.Load()
	if value, ok := s.loadCached("read", key, analyzerCacheTTL); ok {
		return value, nil
	}
	value, err := s.sharedRead(ctx, "faz\x00"+key, func() (any, error) {
		if cached, ok := s.loadCached("read", key, analyzerCacheTTL); ok {
			return cached, nil
		}
		return read()
	})
	if err != nil {
		return nil, err
	}
	s.storeCacheValue(&s.readCache, key, value, analyzerCacheTTL, epoch)
	return value, nil
}

func (s *Service) loadCached(which, key string, ttl time.Duration) (any, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	var cache map[string]readCacheEntry
	switch which {
	case "read":
		cache = s.readCache
	case "manager":
		cache = s.managerCache
	case "monitor":
		cache = s.monitorCache
	case "objects":
		cache = s.objectListCache
	default:
		return nil, false
	}
	entry, ok := cache[key]
	if !ok || time.Since(entry.created) >= ttl {
		return nil, false
	}
	return entry.value, true
}

func (s *Service) storeCacheValue(cache *map[string]readCacheEntry, key string, value any, ttl time.Duration, epoch uint64) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if !s.cacheWriteAllowed(epoch) || cache == nil {
		return
	}
	if *cache == nil {
		*cache = make(map[string]readCacheEntry)
	}
	evictOlderThan(*cache, ttl, func(entry readCacheEntry) time.Time { return entry.created })
	(*cache)[key] = readCacheEntry{created: time.Now(), value: value}
}

// snapshotPackages returns the package list inventory already read for this
// ADOM. A failed package stage keeps the previous list only when
// PackagesKnown is still set; otherwise the caller reads FortiManager.
func (s *Service) snapshotPackages(profile, adom string) ([]fortinet.PolicyPackage, bool) {
	if s.store == nil {
		return nil, false
	}
	snapshot := s.store.Snapshot()
	if packageScopeUnavailable(snapshot, profile, adom) {
		return nil, false
	}
	for _, record := range snapshot.ADOMs {
		if record.Profile == profile && record.ADOM.Name == adom && record.PackagesKnown {
			return record.Packages, true
		}
	}
	return nil, false
}

// policyPackageList prefers the snapshot and falls back to one FortiManager
// read, shared with any concurrent caller for the same ADOM.
func (s *Service) policyPackageList(ctx context.Context, manager fortinet.Manager, adom string, listed []fortinet.PolicyPackage, known bool) ([]fortinet.PolicyPackage, error) {
	if known {
		return listed, nil
	}
	value, err := s.sharedRead(ctx, "packages\x00"+manager.Name()+"\x00"+adom, func() (any, error) {
		return manager.ListPolicyPackages(ctx, adom)
	})
	if err != nil {
		return nil, err
	}
	packages, _ := value.([]fortinet.PolicyPackage)
	return packages, nil
}

func cacheableManagerRead(resource string) bool {
	pathPart, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(resource)), "?")
	return pathPart == "/sys/status" || pathPart == "/dvmdb/adom"
}

func cacheableProxyResource(resource string) (time.Duration, bool) {
	pathPart, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(resource)), "?")
	switch pathPart {
	case "/api/v2/monitor/router/ipv4",
		"/api/v2/monitor/router/ipv6",
		"/api/v2/monitor/system/interface",
		"/api/v2/monitor/system/ha-peer",
		"/api/v2/monitor/system/ha-checksums",
		"/api/v2/monitor/vpn/ipsec",
		"/api/v2/monitor/vpn/ssl",
		"/api/v2/monitor/license/status",
		"/api/v2/monitor/system/fortiguard/server-info",
		"/api/v2/monitor/virtual-wan/sla-log",
		"/api/v2/monitor/router/bgp/neighbors",
		"/api/v2/monitor/router/ospf/neighbors",
		"/api/v2/cmdb/system/ha":
		return monitorCacheTTL, true
	default:
		return 0, false
	}
}

func evictOlderThan[K comparable, V any](entries map[K]V, ttl time.Duration, created func(V) time.Time) {
	now := time.Now()
	for key, entry := range entries {
		if now.Sub(created(entry)) >= ttl {
			delete(entries, key)
		}
	}
}

func (s *Service) manager(profile string) (fortinet.Manager, error) {
	if profile != "" {
		manager, ok := s.managers[profile]
		if !ok {
			return nil, fmt.Errorf("FortiManager profile %q not found; configured FortiManager profiles: %s", profile, s.profileNames(config.ProductFortiManager))
		}
		return manager, nil
	}
	for _, configured := range s.cfg.Profiles {
		if configured.Product == config.ProductFortiManager && configured.Default {
			if manager, ok := s.managers[configured.Name]; ok {
				return manager, nil
			}
		}
	}
	for _, configured := range s.cfg.Profiles {
		if configured.Product == config.ProductFortiManager {
			if manager, ok := s.managers[configured.Name]; ok {
				return manager, nil
			}
		}
	}
	return nil, fmt.Errorf("no FortiManager profile configured")
}

func (s *Service) managerForScope(profile, adom, device string) (fortinet.Manager, error) {
	if strings.TrimSpace(profile) != "" || (strings.TrimSpace(adom) == "" && strings.TrimSpace(device) == "") {
		return s.manager(profile)
	}

	names := make(map[string]struct{})
	if s.store == nil {
		configured := make([]string, 0)
		for _, profileConfig := range s.cfg.Profiles {
			if profileConfig.Product == config.ProductFortiManager {
				configured = append(configured, profileConfig.Name)
			}
		}
		if len(configured) == 1 {
			return s.manager(configured[0])
		}
		return nil, fmt.Errorf("inventory store is not configured; specify profile explicitly")
	}
	if device != "" {
		for _, candidate := range s.store.FindDevices(profile, adom, device) {
			names[candidate.Profile] = struct{}{}
		}
	} else {
		for _, record := range s.store.Snapshot().ADOMs {
			if adom == "" || record.ADOM.Name == adom {
				names[record.Profile] = struct{}{}
			}
		}
	}
	if len(names) == 1 {
		for name := range names {
			return s.manager(name)
		}
	}
	if len(names) > 1 {
		return nil, fmt.Errorf("scope %s/%s belongs to multiple FortiManager profiles; specify profile explicitly", adom, device)
	}

	configured := make([]string, 0)
	for _, profileConfig := range s.cfg.Profiles {
		if profileConfig.Product == config.ProductFortiManager {
			configured = append(configured, profileConfig.Name)
		}
	}
	if len(configured) == 1 {
		return s.manager(configured[0])
	}
	if !s.store.HasSnapshot() {
		return nil, fmt.Errorf("could not resolve FortiManager profile for scope %s/%s: %s Alternatively specify profile explicitly (configured: %s)", adom, device, inventory.NotReadyMessage(s.store.Snapshot()), s.profileNames(config.ProductFortiManager))
	}
	return nil, fmt.Errorf("could not resolve FortiManager profile for scope %s/%s; no inventoried ADOM or device has that name. Specify profile explicitly (configured: %s) or check names with inventory_status", adom, device, s.profileNames(config.ProductFortiManager))
}

func (s *Service) analyzer(profile string) (fortinet.Analyzer, error) {
	if profile != "" {
		analyzer, ok := s.analyzers[profile]
		if !ok {
			return nil, fmt.Errorf("FortiAnalyzer profile %q not found; configured FortiAnalyzer profiles: %s", profile, s.profileNames(config.ProductFortiAnalyzer))
		}
		return analyzer, nil
	}
	for _, configured := range s.cfg.Profiles {
		if configured.Product == config.ProductFortiAnalyzer && configured.Default {
			if analyzer, ok := s.analyzers[configured.Name]; ok {
				return analyzer, nil
			}
		}
	}
	for _, configured := range s.cfg.Profiles {
		if configured.Product == config.ProductFortiAnalyzer {
			if analyzer, ok := s.analyzers[configured.Name]; ok {
				return analyzer, nil
			}
		}
	}
	return nil, fmt.Errorf("no FortiAnalyzer profile configured")
}

func (s *Service) profileNames(product string) string {
	names := make([]string, 0, len(s.cfg.Profiles))
	for _, configured := range s.cfg.Profiles {
		if configured.Product == product {
			names = append(names, configured.Name)
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func (s *Service) profileAllowsADOM(profile, adom string) bool {
	for _, configured := range s.cfg.Profiles {
		if configured.Name == profile && configured.Product == config.ProductFortiManager {
			return configured.AllowsADOM(adom)
		}
	}
	return true
}

func (s *Service) validateManagerADOM(manager fortinet.Manager, adom string) error {
	if !s.profileAllowsADOM(manager.Name(), adom) {
		return fmt.Errorf("ADOM %q is not configured for FortiManager profile %q", adom, manager.Name())
	}
	if allowlist, ok := manager.(fortinet.ADOMAllowlist); ok && !allowlist.AllowsADOM(adom) {
		return fmt.Errorf("ADOM %q is not configured for FortiManager profile %q", adom, manager.Name())
	}
	return nil
}

func (s *Service) validateAnalyzerADOM(analyzer fortinet.Analyzer, adom string) error {
	for _, configured := range s.cfg.Profiles {
		if configured.Name == analyzer.Name() && configured.Product == config.ProductFortiAnalyzer && !configured.AllowsADOM(adom) {
			return fmt.Errorf("ADOM %q is not configured for FortiAnalyzer profile %q; configured ADOMs: %s. FortiAnalyzer ADOM names differ from FortiManager ADOM names; omit adom to use the configured default", adom, analyzer.Name(), strings.Join(configured.ADOMs, ", "))
		}
	}
	if allowlist, ok := analyzer.(fortinet.ADOMAllowlist); ok && !allowlist.AllowsADOM(adom) {
		return fmt.Errorf("ADOM %q is not configured for FortiAnalyzer profile %q", adom, analyzer.Name())
	}
	return nil
}

func resourceADOM(resource string) (string, bool) {
	parsed, err := url.Parse(resource)
	if err != nil {
		return "", false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for index := 0; index+1 < len(parts); index++ {
		if !strings.EqualFold(parts[index], "adom") {
			continue
		}
		adom, err := url.PathUnescape(parts[index+1])
		if err != nil {
			adom = parts[index+1]
		}
		return adom, adom != ""
	}
	return "", false
}

func (s *Service) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= s.timeout {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.timeout)
}

func (s *Service) withRefreshTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := s.cfg.RefreshTimeoutDuration()
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= timeout {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func packageTargetsDevice(pkg fortinet.PolicyPackage, device fortinet.Device) bool {
	if len(pkg.Members) == 0 {
		return true
	}
	for _, member := range pkg.Members {
		if member.Device == device.Name || containsString(device.Groups, member.Device) {
			return true
		}
	}
	return false
}

func packageScopeUnavailable(snapshot inventory.Snapshot, profile, adom string) bool {
	for _, refreshError := range snapshot.Errors {
		if refreshError.Profile != profile {
			continue
		}
		if refreshError.ADOM != "" && refreshError.ADOM != adom {
			continue
		}
		if refreshError.Stage == "list_adoms" || refreshError.Stage == "refresh" || refreshError.Stage == "list_device_groups" || refreshError.Stage == "list_policy_packages" || refreshError.Stage == "list_devices" {
			return true
		}
	}
	for _, state := range snapshot.Profiles {
		if state.Profile == profile && state.Stale && state.Error != "" {
			return true
		}
	}
	return false
}

// canonicalFortiGateResource maps short aliases onto FortiOS monitor paths.
func canonicalFortiGateResource(resource string) string {
	switch strings.ToLower(strings.TrimSpace(resource)) {
	case "routing-table":
		return "/api/v2/monitor/router/ipv4"
	case "routing-table6":
		return "/api/v2/monitor/router/ipv6"
	case "sdwan-health":
		return "/api/v2/monitor/virtual-wan/health-check"
	case "sessions":
		return "/api/v2/monitor/firewall/session"
	case "interfaces":
		return "/api/v2/monitor/system/interface"
	case "ha-peer":
		return "/api/v2/monitor/system/ha-peer"
	case "ha-checksums", "ha-checksum":
		return "/api/v2/monitor/system/ha-checksums"
	case "ipsec":
		return "/api/v2/monitor/vpn/ipsec"
	case "ssl-vpn", "sslvpn":
		return "/api/v2/monitor/vpn/ssl"
	case "bgp-neighbors":
		return "/api/v2/monitor/router/bgp/neighbors"
	case "ospf-neighbors":
		return "/api/v2/monitor/router/ospf/neighbors"
	case "sdwan-sla":
		return "/api/v2/monitor/virtual-wan/sla-log"
	case "license":
		return "/api/v2/monitor/license/status"
	default:
		return strings.TrimSpace(resource)
	}
}

// warmCachedPolicies re-reads policy tables already present in the cache so
// they match the snapshot just published. Packages that no tool has read
// are left alone.
func (s *Service) warmCachedPolicies(ctx context.Context, snapshot inventory.Snapshot) {
	if !s.cfg.Server.PrefetchCachedPolicies || snapshot.GeneratedAt.IsZero() || ctx.Err() != nil {
		return
	}
	type packageKey struct{ manager, adom, pkg string }
	seen := make(map[packageKey]struct{})
	s.cacheMu.Lock()
	for key := range s.policyCache {
		parts := strings.Split(key, "\x00")
		if len(parts) != 4 {
			continue
		}
		seen[packageKey{parts[0], parts[1], parts[2]}] = struct{}{}
	}
	cachedOID := make(map[packageKey]int64, len(seen))
	for key := range seen {
		var oid int64
		for _, table := range policyTableNames {
			entry, ok := s.policyCache[policyTableKey(key.manager, key.adom, key.pkg, table)]
			if ok {
				oid = entry.packageOID
				break
			}
		}
		cachedOID[key] = oid
	}
	s.cacheMu.Unlock()
	for key := range seen {
		if ctx.Err() != nil {
			return
		}
		current := s.packageOID(key.manager, key.adom, key.pkg)
		// A known oid that did not change is still inside the five-minute
		// TTL. An unknown oid cannot be compared, so those packages are
		// warmed the way they were before revision tracking.
		if current != 0 && current == cachedOID[key] {
			continue
		}
		manager, err := s.manager(key.manager)
		if err != nil {
			continue
		}
		_, _ = s.packagePolicies(ctx, manager, key.adom, key.pkg, policyTableNames, snapshot.GeneratedAt)
	}
}

func validateFortiGateReadResource(resource string) error {
	resource = strings.TrimSpace(resource)
	parsed, err := url.Parse(resource)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Path == "" {
		return fmt.Errorf("invalid FortiGate resource")
	}
	if !strings.HasPrefix(parsed.Path, "/api/v2/monitor/") && !strings.HasPrefix(parsed.Path, "/api/v2/cmdb/") {
		return fmt.Errorf("FortiGate resource must use /api/v2/monitor/* or /api/v2/cmdb/*")
	}
	if strings.Contains(parsed.Path, "..") || strings.ContainsAny(resource, "\r\n") {
		return fmt.Errorf("invalid FortiGate resource")
	}
	return nil
}

var (
	fortiManagerReadPrefixes  = []string{"/sys/", "/dvmdb/", "/pm/", "/task/", "/securityconsole/"}
	fortiAnalyzerReadPrefixes = []string{"/sys/", "/dvmdb/", "/task/", "/logview/", "/fortiview/", "/report/", "/event/", "/eventmgmt/", "/incidents/"}
)

// normalizeReadResource accepts the forms agents actually send (with or
// without a leading slash, with surrounding spaces) and rejects traversal.
func normalizeReadResource(resource string) (string, error) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", fmt.Errorf("resource is required")
	}
	if strings.Contains(resource, "..") || strings.ContainsAny(resource, "\r\n") {
		return "", fmt.Errorf("invalid resource %q: traversal and control characters are not allowed", resource)
	}
	pathPart, query, hasQuery := strings.Cut(resource, "?")
	if !strings.HasPrefix(pathPart, "/") {
		pathPart = "/" + pathPart
	}
	pathPart = path.Clean(pathPart)
	if hasQuery {
		return pathPart + "?" + query, nil
	}
	return pathPart, nil
}

func validateReadResource(product, resource string, prefixes []string, example string) (string, error) {
	normalized, err := normalizeReadResource(resource)
	if err != nil {
		return "", fmt.Errorf("%s read: %w", product, err)
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(normalized+"/", prefix) {
			return normalized, nil
		}
	}
	return "", fmt.Errorf("%s read resource %q is not a permitted read-only path; use a path under %s (for example %s)", product, resource, strings.Join(prefixes, ", "), example)
}

func validateFortiManagerReadResource(resource string) (string, error) {
	return validateReadResource("FortiManager", resource, fortiManagerReadPrefixes, "/dvmdb/adom/<adom>/device or /task/task/<id>")
}

func validateFortiAnalyzerReadResource(resource string) (string, error) {
	return validateReadResource("FortiAnalyzer", resource, fortiAnalyzerReadPrefixes, "/dvmdb/adom/<adom>/device, /logview/adom/<adom>/logfields or /logview/adom/<adom>/logsearch/<task_id>")
}

func validateObjectType(objectType string) error {
	objectType = strings.TrimSpace(objectType)
	if objectType == "" {
		return fmt.Errorf("object_type is required")
	}
	if !strings.HasPrefix(objectType, "firewall/") || strings.Contains(objectType, "..") || strings.ContainsAny(objectType, "\r\n?#") {
		return fmt.Errorf("unsupported object_type %q; use a firewall/... read-only object path such as firewall/address, firewall/addrgrp, firewall/vip, firewall/service/custom, firewall/service/group, or firewall/ippool", objectType)
	}
	for segment := range strings.SplitSeq(objectType, "/") {
		if segment == "" {
			return fmt.Errorf("unsupported object_type %q; empty path segment", objectType)
		}
		for _, character := range segment {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '-' && character != '.' {
				return fmt.Errorf("unsupported object_type %q; invalid path character", objectType)
			}
		}
	}
	return nil
}

func escapeSegment(value string) string {
	return strings.ReplaceAll(url.PathEscape(strings.Trim(value, "/")), "%20", " ")
}

func limitAny(value any, limit int) any {
	if limit <= 0 {
		return value
	}
	if records, ok := value.([]any); ok && len(records) > limit {
		return records[:limit]
	}
	if records, ok := value.([]map[string]any); ok && len(records) > limit {
		return records[:limit]
	}
	return value
}

func parseIP(value string) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", value)
	}
	return ip, nil
}

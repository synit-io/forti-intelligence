package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

type PolicyLookupInput struct {
	Profile         string `json:"profile,omitempty" jsonschema:"FortiManager profile name; all inventoried FortiManager profiles are searched when omitted"`
	ADOM            string `json:"adom,omitempty" jsonschema:"Limit candidates to one ADOM"`
	Device          string `json:"device,omitempty" jsonschema:"Limit candidates to one managed FortiGate name"`
	VDOM            string `json:"vdom,omitempty" jsonschema:"Limit candidates to one VDOM; overlapping VDOMs remain separate when omitted"`
	SourceIP        string `json:"source_ip" jsonschema:"Source IPv4 or IPv6 address of the flow"`
	DestinationIP   string `json:"destination_ip" jsonschema:"Destination IP address or FQDN; FQDNs are resolved with the MCP host's DNS and every same-family address is evaluated"`
	SourcePort      int    `json:"source_port,omitempty" jsonschema:"Source port for configured service constraints and live lookup; constrained services remain tentative when omitted"`
	DestinationPort int    `json:"destination_port" jsonschema:"Destination port, 1-65535"`
	Protocol        string `json:"protocol,omitempty" jsonschema:"tcp, udp, sctp, icmp, any, or an IP protocol number 1-255. When omitted the live lookup runs for TCP and UDP"`
	SourceInterface string `json:"source_interface,omitempty" jsonschema:"Ingress interface or zone name when inventory cannot infer it, for example for routed sources"`
}

type PolicyLookupOutput struct {
	Query                 PolicyLookupInput        `json:"query"`
	DestinationResolution DestinationResolution    `json:"destination_resolution"`
	SnapshotAt            time.Time                `json:"inventory_snapshot_at"`
	InventoryErrors       []inventory.RefreshError `json:"inventory_errors,omitempty"`
	Errors                []inventory.RefreshError `json:"errors,omitempty"`
	CandidateDevices      []PolicyCandidate        `json:"candidate_devices,omitempty"`
	// Decisions states the configured verdict per device, package and
	// destination: the first matching policy or the implicit deny.
	Decisions   []PolicyDecision   `json:"decisions,omitempty"`
	LiveLookups []LivePolicyLookup `json:"live_lookups,omitempty"`
	// Matches lists every matching policy in FortiOS evaluation order per
	// device, package and destination; first_match marks the verdict.
	Matches   []PolicyMatch    `json:"matches,omitempty"`
	Evaluated PolicyEvaluation `json:"evaluated"`
	// Complete is false when a policy, package or object read failed or the
	// budget ended, so a missing match does not prove the implicit deny.
	Complete bool     `json:"complete"`
	Warnings []string `json:"warnings,omitempty"`
}

// PolicyDecision is the configured verdict of one package for one
// destination: the first matching policy in FortiOS evaluation order, or the
// implicit deny when no policy matches and every read succeeded.
type PolicyDecision struct {
	Profile       string `json:"profile"`
	ADOM          string `json:"adom"`
	Device        string `json:"device"`
	VDOM          string `json:"vdom,omitempty"`
	Package       string `json:"package"`
	DestinationIP string `json:"destination_ip"`
	PolicyID      int    `json:"policy_id"`
	Action        string `json:"action"`
	Confidence    string `json:"confidence"`
	Note          string `json:"note,omitempty"`
}

type DestinationResolution struct {
	Input              string   `json:"input"`
	CanonicalName      string   `json:"canonical_name,omitempty"`
	Resolver           string   `json:"resolver,omitempty"`
	Addresses          []string `json:"addresses"`
	EvaluatedAddresses []string `json:"evaluated_addresses,omitempty"`
	ExcludedAddresses  []string `json:"excluded_addresses,omitempty"`
}

type PolicyCandidate struct {
	Profile               string                   `json:"profile"`
	ADOM                  string                   `json:"adom"`
	Device                string                   `json:"device"`
	VDOMs                 []string                 `json:"vdoms,omitempty"`
	SourceInterfaces      []string                 `json:"source_interfaces,omitempty"`
	DestinationInterfaces []string                 `json:"destination_interfaces,omitempty"`
	SourceZones           []string                 `json:"source_zones,omitempty"`
	DestinationZones      []string                 `json:"destination_zones,omitempty"`
	Packages              []string                 `json:"packages,omitempty"`
	PackageTargets        []fortinet.PackageTarget `json:"package_targets,omitempty"`
	Resolution            string                   `json:"resolution"`
	Routing               []RouteDecision          `json:"routing,omitempty"`
	Warnings              []string                 `json:"warnings,omitempty"`
}

type LivePolicyLookup struct {
	Profile         string `json:"profile"`
	ADOM            string `json:"adom"`
	Device          string `json:"device"`
	VDOM            string `json:"vdom,omitempty"`
	SourceInterface string `json:"source_interface"`
	SourceZone      string `json:"source_zone,omitempty"`
	DestinationIP   string `json:"destination_ip"`
	Protocol        string `json:"protocol"`
	EvidenceType    string `json:"evidence_type"`
	// PolicyID is the policy the FortiGate selected; StaticFirstMatch and
	// Agreement compare it with the configured verdict.
	PolicyID         *int                `json:"policy_id,omitempty"`
	StaticFirstMatch *int                `json:"static_first_match,omitempty"`
	Agreement        string              `json:"agreement,omitempty"`
	Result           any                 `json:"result,omitempty"`
	Error            string              `json:"error,omitempty"`
	ErrorDetails     *fortinet.ErrorInfo `json:"error_details,omitempty"`
}

type PolicyMatch struct {
	Profile       string `json:"profile"`
	ADOM          string `json:"adom"`
	Device        string `json:"device"`
	VDOM          string `json:"vdom,omitempty"`
	Package       string `json:"package"`
	DestinationIP string `json:"destination_ip"`
	// Position is the policy's place in its package (evaluation order).
	Position              int                     `json:"position"`
	FirstMatch            bool                    `json:"first_match,omitempty"`
	Policy                fortinet.FirewallPolicy `json:"policy"`
	SourceInterfaces      []string                `json:"source_interfaces,omitempty"`
	DestinationInterfaces []string                `json:"destination_interfaces,omitempty"`
	SourceZones           []string                `json:"source_zones,omitempty"`
	DestinationZones      []string                `json:"destination_zones,omitempty"`
	AddressEvidence       []string                `json:"address_evidence,omitempty"`
	TranslationEvidence   []string                `json:"translation_evidence,omitempty"`
	ServiceEvidence       []string                `json:"service_evidence,omitempty"`
	Score                 int                     `json:"score"`
	Confidence            string                  `json:"confidence"`
	EvidenceType          string                  `json:"evidence_type"`
	Warnings              []string                `json:"warnings,omitempty"`
}

type PolicyEvaluation struct {
	Devices        int `json:"devices"`
	Packages       int `json:"packages"`
	Policies       int `json:"policies"`
	AddressObjects int `json:"address_objects"`
	ServiceObjects int `json:"service_objects"`
}

type addressResolver struct {
	objects  map[string]fortinet.AddressObject
	visiting map[string]bool
}

const (
	maxDestinationAddresses = 16
	// objectCacheTTL bounds how long address/service object tables are reused
	// between lookups. Object edits in FortiManager are rare within minutes,
	// and each miss costs up to six appliance reads per ADOM.
	objectCacheTTL = 5 * time.Minute
)

type serviceResolver struct {
	objects  map[string]fortinet.ServiceObject
	visiting map[string]bool
}

func (s *Service) LookupPolicies(ctx context.Context, input PolicyLookupInput) (PolicyLookupOutput, error) {
	input.Profile = strings.TrimSpace(input.Profile)
	input.ADOM = strings.TrimSpace(input.ADOM)
	input.Device = strings.TrimSpace(input.Device)
	input.VDOM = strings.TrimSpace(input.VDOM)
	input.SourceIP = strings.TrimSpace(input.SourceIP)
	input.DestinationIP = strings.TrimSpace(input.DestinationIP)
	sourceIP, err := parseIP(input.SourceIP)
	if err != nil {
		return PolicyLookupOutput{}, err
	}
	if input.DestinationPort < 1 || input.DestinationPort > 65535 {
		return PolicyLookupOutput{}, fmt.Errorf("destination_port must be between 1 and 65535")
	}
	if input.SourcePort < 0 || input.SourcePort > 65535 {
		return PolicyLookupOutput{}, fmt.Errorf("source_port must be between 0 and 65535")
	}
	rawProtocol := strings.TrimSpace(input.Protocol)
	if rawProtocol == "" {
		input.Protocol = "any"
	} else {
		input.Protocol = normalizeProtocol(rawProtocol)
		if input.Protocol == "" {
			return PolicyLookupOutput{}, fmt.Errorf("unsupported protocol %q; use tcp, udp, sctp, icmp, any, or a number from 1 to 255", rawProtocol)
		}
	}

	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	resolvedDestination, err := s.resolveDestination(ctx, input.DestinationIP)
	if err != nil {
		return PolicyLookupOutput{}, err
	}
	if s.store == nil {
		return PolicyLookupOutput{}, fmt.Errorf("inventory store is not configured")
	}
	snapshot := s.store.Snapshot()
	if snapshot.GeneratedAt.IsZero() {
		return PolicyLookupOutput{Query: input, DestinationResolution: resolvedDestination.info}, fmt.Errorf("%s", inventory.NotReadyMessage(snapshot))
	}
	output := PolicyLookupOutput{
		Query:                 input,
		DestinationResolution: resolvedDestination.info,
		SnapshotAt:            snapshot.GeneratedAt,
	}
	output.InventoryErrors = matchingInventoryErrors(snapshot, input)
	for _, state := range snapshot.Profiles {
		if !state.Stale || state.Error == "" {
			continue
		}
		if input.Profile != "" && state.Profile != input.Profile {
			continue
		}
		duplicate := false
		for _, refreshError := range output.InventoryErrors {
			if refreshError.Profile == state.Profile {
				duplicate = true
				break
			}
		}
		if !duplicate {
			refreshError := serviceRefreshError(state.Profile, "", "", "", "profile_refresh", fmt.Errorf("%s", state.Error))
			output.InventoryErrors = append(output.InventoryErrors, refreshError)
		}
	}
	for _, refreshError := range output.InventoryErrors {
		output.Warnings = append(output.Warnings, fmt.Sprintf("Inventory refresh %s/%s/%s failed: %s", refreshError.Profile, refreshError.ADOM, refreshError.Stage, refreshError.Message))
	}
	familyDestinationIPs := resolvedDestination.sameIPVersionAs(sourceIP)
	destinationIPs := familyDestinationIPs
	if len(destinationIPs) > maxDestinationAddresses {
		destinationIPs = append([]net.IP(nil), destinationIPs[:maxDestinationAddresses]...)
		output.Warnings = append(output.Warnings, fmt.Sprintf("Destination %q resolved to %d %s addresses; only the first %d were evaluated to bound lookup fan-out.", input.DestinationIP, len(familyDestinationIPs), ipVersion(sourceIP), maxDestinationAddresses))
	}
	output.DestinationResolution.EvaluatedAddresses = ipStrings(destinationIPs)
	output.DestinationResolution.ExcludedAddresses = differenceIPStrings(resolvedDestination.ips, destinationIPs)
	if len(destinationIPs) == 0 {
		return output, fmt.Errorf("destination %q resolved to no address matching source IP version", input.DestinationIP)
	}
	if len(destinationIPs) > 1 {
		output.Warnings = append(output.Warnings, fmt.Sprintf("Destination %q resolved to %d addresses; each address was evaluated independently.", input.DestinationIP, len(destinationIPs)))
	}
	if len(familyDestinationIPs) != len(resolvedDestination.ips) {
		output.Warnings = append(output.Warnings, fmt.Sprintf("Destination %q resolved to addresses in both IP families; only addresses matching source %s were evaluated.", input.DestinationIP, ipVersion(sourceIP)))
	}

	devices := make([]fortinet.Device, 0, len(snapshot.Devices))
	offlineDevices := make(map[string]bool)
	for _, device := range snapshot.Devices {
		if input.Profile != "" && device.Profile != input.Profile {
			continue
		}
		if input.ADOM != "" && device.ADOM != input.ADOM {
			continue
		}
		if !s.profileAllowsADOM(device.Profile, device.ADOM) {
			continue
		}
		if input.Device != "" && device.Name != input.Device {
			continue
		}
		// Offline FortiGates keep their FortiManager configuration, so static
		// evaluation still runs; only the live lookup through them is skipped.
		if unavailable, _ := fortinet.DeviceUnavailable(device); unavailable {
			offlineDevices[device.Profile+"\x00"+device.ADOM+"\x00"+device.Name] = true
			output.Errors = append(output.Errors, unavailableLookupError(device))
		}
		devices = append(devices, policyDeviceScopes(device, input.VDOM)...)
	}
	if len(devices) == 0 {
		return output, fmt.Errorf("inventory has no matching FortiGates for profile %q, ADOM %q, device %q; check the names with inventory_status (profiles: %s)", input.Profile, input.ADOM, input.Device, s.profileNames(config.ProductFortiManager))
	}

	candidates := make([]candidateState, 0, len(devices))
	for _, device := range devices {
		candidate, found := s.policyCandidate(ctx, device, sourceIP, destinationIPs, input, snapshot.GeneratedAt)
		if found {
			for _, warning := range candidate.candidate.Warnings {
				output.Warnings = append(output.Warnings, fmt.Sprintf("%s/%s/%s: %s", device.ADOM, device.Name, device.VDOMs[0], warning))
			}
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		if input.SourceInterface != "" {
			return output, fmt.Errorf("inventory could not identify a FortiGate/interface for source %s and destination %s", input.SourceIP, input.DestinationIP)
		}
		for _, device := range devices {
			candidates = append(candidates, candidateState{
				device: device,
				candidate: PolicyCandidate{
					Profile: device.Profile, ADOM: device.ADOM, Device: device.Name,
					VDOMs: append([]string(nil), device.VDOMs...), Packages: append([]string(nil), device.Packages...),
					PackageTargets: append([]fortinet.PackageTarget(nil), device.PackageTargets...),
					Resolution:     "fallback-all-inventory-devices",
					Warnings:       []string{"Neither source nor destination IP matched a known interface subnet; this candidate is a fallback across inventoried devices."},
				},
			})
		}
	}
	if len(candidates) == 0 {
		return output, fmt.Errorf("inventory could not identify a FortiGate/interface for source %s and destination %s", input.SourceIP, input.DestinationIP)
	}
	if allFallback(candidates) {
		output.Warnings = append(output.Warnings, "Neither IP matched a known interface subnet; policies were evaluated across all inventoried FortiGates.")
	}
	if len(candidates) > 1 {
		output.Warnings = append(output.Warnings, fmt.Sprintf("Multiple FortiGate/VDOM candidates (%d) matched the available inventory evidence; results are not uniquely scoped.", len(candidates)))
	}
	if input.Protocol == "any" {
		output.Warnings = append(output.Warnings, "Protocol was omitted. Static service matching accepts TCP/UDP-compatible services; live FortiOS policy lookup runs once for TCP and once for UDP.")
	}

	output.CandidateDevices = make([]PolicyCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		output.CandidateDevices = append(output.CandidateDevices, candidate.candidate)
	}
	output.Evaluated.Devices = len(candidates)

	// Stored configuration first: it answers without touching FortiGates and
	// is complete even when a FortiGate is slow. Live lookups follow within
	// the remaining budget.
	output.Complete = true
	ipv6 := sourceIP.To4() == nil
	objectReads := make(map[string]objectRead)      // one object read per ADOM and call
	packageLists := make(map[string]packageListing) // one package list per ADOM and call
	groupComplete := make(map[string]bool)
	var groupOrder []string
	var liveTargets []liveTarget
	for _, candidate := range candidates {
		manager, managerErr := s.manager(candidate.device.Profile)
		if managerErr != nil {
			output.Complete = false
			output.Warnings = append(output.Warnings, managerErr.Error())
			output.Errors = append(output.Errors, serviceRefreshError(candidate.device.Profile, candidate.device.ADOM, candidate.device.Name, "", "manager", managerErr))
			continue
		}
		if ctx.Err() != nil {
			output.Complete = false
			output.Warnings = append(output.Warnings, fmt.Sprintf("The request budget ended before %s/%s was evaluated; repeat the lookup, the reads made so far are cached.", candidate.device.ADOM, candidate.device.Name))
			continue
		}
		vdoms := candidate.device.VDOMs
		if len(vdoms) == 0 {
			vdoms = []string{"root"}
		}
		// FortiOS evaluates a live policy lookup against the ingress
		// interface; srcintf must name an interface, never a zone (FortiOS
		// answers HTTP 400 for a zone). Zones are used for static matching.
		liveInterfaces := candidate.candidate.SourceInterfaces
		if input.SourceInterface != "" {
			liveInterfaces = interfacesContaining(candidate.device.Interfaces, candidate.candidate.SourceInterfaces, sourceIP)
			for _, iface := range candidate.device.Interfaces {
				if iface.Name == input.SourceInterface {
					liveInterfaces = []string{iface.Name}
					break
				}
			}
			if !interfaceContainsName(candidate.device.Interfaces, input.SourceInterface) {
				output.Warnings = append(output.Warnings, fmt.Sprintf("Explicit source interface %q was not present in %s/%s inventory.", input.SourceInterface, candidate.device.ADOM, candidate.device.Name))
			} else if !interfaceContainsAddress(candidate.device.Interfaces, input.SourceInterface, sourceIP) {
				output.Warnings = append(output.Warnings, fmt.Sprintf("Explicit source interface %q was selected, but inventory could not prove that source IP %s belongs to its subnet on %s/%s.", input.SourceInterface, input.SourceIP, candidate.device.ADOM, candidate.device.Name))
			}
		}
		switch {
		case offlineDevices[candidate.device.Profile+"\x00"+candidate.device.ADOM+"\x00"+candidate.device.Name]:
			_, reason := fortinet.DeviceUnavailable(candidate.device)
			output.Warnings = append(output.Warnings, fmt.Sprintf("%s/%s is offline (%s): the live policy lookup was skipped and the FortiManager policy configuration was evaluated instead.", candidate.device.ADOM, candidate.device.Name, reason))
		case len(liveInterfaces) > 0:
			liveTargets = append(liveTargets, liveTarget{candidate: candidate, manager: manager, vdoms: vdoms, interfaces: liveInterfaces})
		default:
			output.Warnings = append(output.Warnings, fmt.Sprintf("No source interface was resolved for %s/%s; live policy lookup was skipped and package policies were used.", candidate.device.ADOM, candidate.device.Name))
		}

		selectedVDOM := selectedVDOMForCandidate(candidate, input.SourceInterface)
		packages := packageNamesForCandidate(candidate.device, selectedVDOM)
		scopeUnavailable := packageScopeUnavailable(snapshot, candidate.device.Profile, candidate.device.ADOM)
		if len(packages) == 0 || scopeUnavailable {
			listingKey := candidate.device.Profile + "\x00" + candidate.device.ADOM
			listing, listed := packageLists[listingKey]
			if !listed {
				if known, ok := s.snapshotPackages(candidate.device.Profile, candidate.device.ADOM); ok {
					listing.packages = known
				} else {
					listing.packages, listing.err = manager.ListPolicyPackages(ctx, candidate.device.ADOM)
				}
				packageLists[listingKey] = listing
			}
			if listing.err != nil {
				output.Warnings = append(output.Warnings, fmt.Sprintf("%s/%s packages: %v", candidate.device.ADOM, candidate.device.Name, listing.err))
				output.Errors = append(output.Errors, serviceRefreshError(candidate.device.Profile, candidate.device.ADOM, candidate.device.Name, "", "list_policy_packages", listing.err))
				if len(packages) == 0 {
					output.Complete = false
					continue
				}
				output.Warnings = append(output.Warnings, fmt.Sprintf("Using last-known-good package associations for %s/%s; package scope is tentative.", candidate.device.ADOM, candidate.device.Name))
			} else {
				if scopeUnavailable {
					output.Warnings = append(output.Warnings, fmt.Sprintf("%s/%s device-group scope was unavailable during inventory refresh; all ADOM packages were evaluated tentatively.", candidate.device.ADOM, candidate.device.Name))
				}
				for _, pkg := range listing.packages {
					if scopeUnavailable || (packageTargetsDevice(pkg, candidate.device) && packageTargetsVDOM(pkg, selectedVDOM)) {
						packages = append(packages, pkg.Name)
					}
				}
			}
		}
		packages = uniqueStrings(packages)
		objectKey := candidate.device.Profile + "\x00" + candidate.device.ADOM
		for _, packageName := range packages {
			output.Evaluated.Packages++
			policies, policyErr := s.familyPolicies(ctx, manager, candidate.device.ADOM, packageName, ipv6, output.SnapshotAt)
			if policyErr != nil {
				output.Complete = false
				output.Warnings = append(output.Warnings, fmt.Sprintf("%s/%s/%s policies: %v", candidate.device.Profile, candidate.device.ADOM, packageName, policyErr))
				output.Errors = append(output.Errors, serviceRefreshError(candidate.device.Profile, candidate.device.ADOM, candidate.device.Name, packageName, "list_policies", policyErr))
				if len(policies) == 0 {
					// Report the package as undecided rather than leaving it out,
					// so its absence is not read as "no policy matches".
					for _, destinationIP := range destinationIPs {
						key := decisionKey(manager.Name(), candidate.device.ADOM, candidate.device.Name, selectedVDOM, packageName, destinationIP.String())
						if _, seen := groupComplete[key]; !seen {
							groupOrder = append(groupOrder, key)
						}
						groupComplete[key] = false
					}
					continue
				}
			}
			output.Evaluated.Policies += len(policies)
			objects, read := objectReads[objectKey]
			if !read {
				objects = s.policyObjects(ctx, manager, candidate.device.ADOM, ipv6, true, output.SnapshotAt)
				objectReads[objectKey] = objects
				appendUniqueWarnings(&output, objects.warnings...)
				output.Errors = append(output.Errors, objects.errors...)
				output.Evaluated.AddressObjects += len(objects.addresses)
				output.Evaluated.ServiceObjects += len(objects.services)
			}
			complete := policyErr == nil && len(objects.errors) == 0
			if !complete {
				output.Complete = false
			}
			addressMatcher := newAddressResolver(objects.addresses)
			serviceMatcher := newServiceResolver(objects.services)
			for _, destinationIP := range destinationIPs {
				key := decisionKey(manager.Name(), candidate.device.ADOM, candidate.device.Name, selectedVDOM, packageName, destinationIP.String())
				if _, seen := groupComplete[key]; !seen {
					groupOrder = append(groupOrder, key)
				}
				groupComplete[key] = complete
				scoped := candidate
				if destination, ok := candidate.destinations[destinationIP.String()]; ok {
					scoped.candidate = destination
				}
				for position, policy := range policies {
					matched, match := matchPolicy(policy, scoped, packageName, input, sourceIP, destinationIP, addressMatcher, serviceMatcher)
					if matched {
						match.Profile = manager.Name()
						match.DestinationIP = destinationIP.String()
						match.Position = position + 1
						output.Matches = append(output.Matches, match)
					}
				}
			}
		}
	}

	// FortiOS applies the first matching policy of a package in sequence
	// order, so matches are listed in that order per device, package and
	// destination; the first one is the configured verdict.
	sort.SliceStable(output.Matches, func(i, j int) bool {
		left, right := output.Matches[i], output.Matches[j]
		leftKey := decisionKey(left.Profile, left.ADOM, left.Device, left.VDOM, left.Package, left.DestinationIP)
		rightKey := decisionKey(right.Profile, right.ADOM, right.Device, right.VDOM, right.Package, right.DestinationIP)
		if leftKey != rightKey {
			return leftKey < rightKey
		}
		return left.Position < right.Position
	})
	output.Decisions = policyDecisions(output.Matches, groupOrder, groupComplete)
	s.runLiveLookups(ctx, &output, liveTargets, input, sourceIP, destinationIPs)
	return output, nil
}

type packageListing struct {
	packages []fortinet.PolicyPackage
	err      error
}

type liveTarget struct {
	candidate  candidateState
	manager    fortinet.Manager
	vdoms      []string
	interfaces []string
}

const (
	// maxLiveLookups bounds the live FortiOS policy lookups of one call;
	// each can wait PolicyLookupTimeoutSeconds for a FortiGate.
	maxLiveLookups = 4
	// liveLookupReserve is the budget a live lookup needs: the FortiGate
	// wait plus the FortiManager round trip.
	liveLookupReserve = time.Duration(fortinet.PolicyLookupTimeoutSeconds)*time.Second + 2*time.Second
)

// cachedPolicyLookup reuses one live tuple for liveLookupTTL and joins a
// second caller that asks for it while the first proxy call is in flight.
// Failures are not cached. refresh_inventory drops the map.
func (s *Service) cachedPolicyLookup(ctx context.Context, key string, lookup func() (fortinet.ProxyResult, error)) (fortinet.ProxyResult, error) {
	s.cacheMu.Lock()
	if entry, ok := s.liveLookupCache[key]; ok && time.Since(entry.created) < liveLookupTTL {
		result := entry.result
		s.cacheMu.Unlock()
		return result, nil
	}
	s.cacheMu.Unlock()
	epoch := s.cacheEpoch.Load()
	shared, err := s.sharedRead(ctx, "live\x00"+key, func() (any, error) {
		s.cacheMu.Lock()
		if entry, ok := s.liveLookupCache[key]; ok && time.Since(entry.created) < liveLookupTTL {
			result := entry.result
			s.cacheMu.Unlock()
			return result, nil
		}
		s.cacheMu.Unlock()
		result, lookupErr := lookup()
		if lookupErr != nil {
			return nil, lookupErr
		}
		s.cacheMu.Lock()
		if s.cacheWriteAllowed(epoch) {
			if s.liveLookupCache == nil {
				s.liveLookupCache = make(map[string]liveLookupEntry)
			}
			evictOlderThan(s.liveLookupCache, liveLookupTTL, func(entry liveLookupEntry) time.Time { return entry.created })
			if len(s.liveLookupCache) >= maxLiveLookupEntries {
				var oldestKey string
				var oldest time.Time
				for cachedKey, entry := range s.liveLookupCache {
					if oldest.IsZero() || entry.created.Before(oldest) {
						oldestKey, oldest = cachedKey, entry.created
					}
				}
				delete(s.liveLookupCache, oldestKey)
			}
			s.liveLookupCache[key] = liveLookupEntry{created: time.Now(), result: result}
		}
		s.cacheMu.Unlock()
		return result, nil
	})
	if err != nil {
		return fortinet.ProxyResult{}, err
	}
	result, _ := shared.(fortinet.ProxyResult)
	return result, nil
}

// runLiveLookups asks the candidate FortiGates for their live policy
// decision, bounded in number and by the remaining budget, and compares
// each answer with the configured verdict.
func (s *Service) runLiveLookups(ctx context.Context, output *PolicyLookupOutput, targets []liveTarget, input PolicyLookupInput, sourceIP net.IP, destinationIPs []net.IP) {
	protocols := []string{input.Protocol}
	if input.Protocol == "any" {
		protocols = []string{"tcp", "udp"}
	}
	sent, capped, outOfBudget, afterTimeout := 0, 0, 0, 0
	timedOut := make(map[string]bool)
	for _, target := range targets {
		device := target.candidate.device
		deviceKey := device.Profile + "\x00" + device.ADOM + "\x00" + device.Name
		for _, protocol := range protocols {
			for _, sourceInterface := range target.interfaces {
				vdom := vdomForInterface(device.Interfaces, sourceInterface)
				if vdom == "" {
					vdom = target.vdoms[0]
				}
				for _, destinationIP := range destinationIPs {
					switch {
					case timedOut[deviceKey]:
						afterTimeout++
						continue
					case sent >= maxLiveLookups:
						capped++
						continue
					}
					if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < liveLookupReserve {
						outOfBudget++
						continue
					}
					sent++
					lookupKey := strings.Join([]string{device.Profile, device.ADOM, device.Name, vdom, input.SourceIP, destinationIP.String(), protocol, strconv.Itoa(input.SourcePort), strconv.Itoa(input.DestinationPort), sourceInterface}, "\x00")
					live, liveErr := s.cachedPolicyLookup(ctx, lookupKey, func() (fortinet.ProxyResult, error) {
						return target.manager.PolicyLookup(ctx, device.ADOM, device.Name, vdom, fortinet.PolicyLookupRequest{
							SourceIP: input.SourceIP, DestinationIP: destinationIP.String(), SourcePort: input.SourcePort,
							DestinationPort: input.DestinationPort, Protocol: protocol, SourceInterface: sourceInterface,
						})
					})
					entry := LivePolicyLookup{
						Profile: target.manager.Name(), ADOM: device.ADOM, Device: device.Name,
						VDOM: vdom, SourceInterface: sourceInterface, SourceZone: firstNonEmpty(interfaceZonesForNames(device.Interfaces, []string{sourceInterface})...),
						DestinationIP: destinationIP.String(), Protocol: protocol,
						EvidenceType: "live_policy_lookup",
					}
					if liveErr != nil {
						entry.Error = liveErr.Error()
						info := fortinet.DescribeError(liveErr)
						entry.ErrorDetails = &info
						output.Errors = append(output.Errors, serviceRefreshError(device.Profile, device.ADOM, device.Name, "", "policy_lookup", liveErr))
						if info.Kind == fortinet.ErrorKindTimeout {
							timedOut[deviceKey] = true
						}
					} else {
						entry.Result = live.Data
						entry.PolicyID = livePolicyID(live.Data)
						reconcileLive(&entry, output)
					}
					output.LiveLookups = append(output.LiveLookups, entry)
				}
			}
		}
	}
	if capped > 0 {
		output.Warnings = append(output.Warnings, fmt.Sprintf("%d further live policy lookups were skipped (at most %d per call); narrow the lookup with device, source_interface or protocol for live evidence on every path.", capped, maxLiveLookups))
	}
	if outOfBudget > 0 {
		output.Warnings = append(output.Warnings, fmt.Sprintf("%d live policy lookups were skipped because the remaining request budget could not wait for a FortiGate answer; the configured verdicts are complete.", outOfBudget))
	}
	if afterTimeout > 0 {
		output.Warnings = append(output.Warnings, fmt.Sprintf("%d live policy lookups were skipped on FortiGates that did not answer a previous lookup within %d s.", afterTimeout, fortinet.PolicyLookupTimeoutSeconds))
	}
}

func decisionKey(profile, adom, device, vdom, pkg, destination string) string {
	return strings.Join([]string{profile, adom, device, vdom, pkg, destination}, "\x00")
}

// policyDecisions marks the first match of every device, package and
// destination and states the configured verdict: that policy's action, or
// the implicit deny when no policy matched and every read succeeded.
func policyDecisions(matches []PolicyMatch, order []string, complete map[string]bool) []PolicyDecision {
	first := make(map[string]int)
	for index := range matches {
		key := decisionKey(matches[index].Profile, matches[index].ADOM, matches[index].Device, matches[index].VDOM, matches[index].Package, matches[index].DestinationIP)
		if _, seen := first[key]; !seen {
			first[key] = index
			matches[index].FirstMatch = true
		}
	}
	decisions := make([]PolicyDecision, 0, len(order))
	for _, key := range order {
		parts := strings.Split(key, "\x00")
		decision := PolicyDecision{Profile: parts[0], ADOM: parts[1], Device: parts[2], VDOM: parts[3], Package: parts[4], DestinationIP: parts[5]}
		if index, ok := first[key]; ok {
			match := matches[index]
			decision.VDOM, decision.PolicyID, decision.Action, decision.Confidence = match.VDOM, match.Policy.PolicyID, strings.ToLower(match.Policy.Action), match.Confidence
			if match.Confidence == "tentative" {
				decision.Note = "The first matching policy is tentative (see its warnings); if it does not apply, the next match in the list applies."
			}
		} else if complete[key] {
			decision.Action, decision.Confidence = "implicit_deny", "likely"
			decision.Note = "No configured policy of this package matches; FortiOS drops the traffic with the implicit deny (policy 0)."
		} else {
			decision.Action, decision.Confidence = "unknown", "inconclusive"
			decision.Note = "Policies or objects could not be read completely (see errors), so a missing match does not prove the implicit deny."
		}
		decisions = append(decisions, decision)
	}
	return decisions
}

// livePolicyID extracts the policy a FortiGate's policy-lookup selected. It
// returns nil when the answer names no policy.
func livePolicyID(data any) *int {
	var found *int
	var walk func(any)
	walk = func(value any) {
		if found != nil {
			return
		}
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if strings.EqualFold(key, "policy_id") || strings.EqualFold(key, "policyid") {
					if number, ok := child.(float64); ok {
						id := int(number)
						found = &id
						return
					}
				}
			}
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(data)
	return found
}

// reconcileLive compares a live policy-lookup answer with the configured
// verdict of the same device and destination.
func reconcileLive(entry *LivePolicyLookup, output *PolicyLookupOutput) {
	if entry.PolicyID == nil {
		return
	}
	var selected *PolicyDecision
	for i := range output.Decisions {
		decision := &output.Decisions[i]
		if decision.Profile != entry.Profile || decision.ADOM != entry.ADOM || decision.Device != entry.Device || decision.VDOM != entry.VDOM || decision.DestinationIP != entry.DestinationIP {
			continue
		}
		if selected != nil {
			entry.Agreement = "ambiguous_configured_verdict"
			output.Warnings = append(output.Warnings, fmt.Sprintf("Live lookup on %s/%s/%s/%s to %s has several configured package verdicts; check the installed package before comparing policy IDs.", entry.Profile, entry.ADOM, entry.Device, entry.VDOM, entry.DestinationIP))
			return
		}
		selected = decision
	}
	if selected == nil || selected.Action == "unknown" {
		entry.Agreement = "no_configured_verdict"
		return
	}
	static := selected.PolicyID
	entry.StaticFirstMatch = &static
	if static == *entry.PolicyID {
		entry.Agreement = "agrees"
		return
	}
	entry.Agreement = "differs"
	output.Warnings = append(output.Warnings, fmt.Sprintf("Live policy lookup on %s/%s/%s/%s (%s) selected policy %d, but the FortiManager configuration's first match in package %s is %d: check the installed package and unresolved match conditions.", entry.Profile, entry.ADOM, entry.Device, entry.VDOM, entry.Protocol, *entry.PolicyID, selected.Package, static))
}

type candidateState struct {
	device       fortinet.Device
	candidate    PolicyCandidate
	destinations map[string]PolicyCandidate
}

type resolvedDestination struct {
	info DestinationResolution
	ips  []net.IP
}

func (s *Service) resolveDestination(ctx context.Context, value string) (resolvedDestination, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return resolvedDestination{}, fmt.Errorf("destination_ip is required")
	}
	if ip := net.ParseIP(value); ip != nil {
		ip = append(net.IP(nil), ip...)
		return resolvedDestination{
			info: DestinationResolution{Input: value, Resolver: "literal", Addresses: []string{ip.String()}},
			ips:  []net.IP{ip},
		}, nil
	}
	host := strings.TrimSuffix(value, ".")
	if err := validateDestinationHostname(host); err != nil {
		return resolvedDestination{}, err
	}
	// Use cached DNS lookups to reduce external DNS calls
	addresses, err := s.lookupIPAddrWithCache(ctx, host)
	if err != nil {
		return resolvedDestination{}, fmt.Errorf("resolve destination hostname %q: %w", value, err)
	}
	ips := make([]net.IP, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if address.IP == nil {
			continue
		}
		ip := append(net.IP(nil), address.IP...)
		key := ip.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return resolvedDestination{}, fmt.Errorf("resolve destination hostname %q returned no IP addresses", value)
	}

	canonicalName := ""
	if canonical, cnameErr := s.lookupCNAMEWithCache(ctx, host); cnameErr == nil {
		canonical = strings.TrimSuffix(strings.TrimSpace(canonical), ".")
		if canonical != "" && !strings.EqualFold(canonical, host) {
			canonicalName = canonical
		}
	}
	resolved := resolvedDestination{info: DestinationResolution{Input: value, CanonicalName: canonicalName, Resolver: "system"}, ips: ips}
	resolved.info.Addresses = make([]string, 0, len(ips))
	for _, ip := range ips {
		resolved.info.Addresses = append(resolved.info.Addresses, ip.String())
	}
	return resolved, nil
}

func (d resolvedDestination) sameIPVersionAs(sourceIP net.IP) []net.IP {
	wantIPv6 := sourceIP.To4() == nil
	result := make([]net.IP, 0, len(d.ips))
	for _, ip := range d.ips {
		if (ip.To4() == nil) == wantIPv6 {
			result = append(result, ip)
		}
	}
	return result
}

func validateDestinationHostname(host string) error {
	if host == "" {
		return fmt.Errorf("destination_ip must be an IP address or hostname")
	}
	if len(host) > 253 || strings.ContainsAny(host, "/?#@:[] \t\r\n") {
		return fmt.Errorf("invalid destination hostname %q", host)
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid destination hostname %q", host)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' && character != '_' {
				return fmt.Errorf("invalid destination hostname %q", host)
			}
		}
	}
	return nil
}

func ipVersion(ip net.IP) string {
	if ip.To4() == nil {
		return "IPv6"
	}
	return "IPv4"
}

// policyDeviceScopes preserves overlapping VDOMs as separate candidates.
func policyDeviceScopes(device fortinet.Device, wanted string) []fortinet.Device {
	vdoms := make([]string, 0, len(device.VDOMs)+len(device.Interfaces))
	for _, vdom := range device.VDOMs {
		vdoms = append(vdoms, routeVDOM(vdom))
	}
	for _, iface := range device.Interfaces {
		vdoms = append(vdoms, routeVDOM(iface.VDOM))
	}
	if len(vdoms) == 0 {
		vdoms = []string{"root"}
	}
	var scopes []fortinet.Device
	for _, vdom := range uniqueStrings(vdoms) {
		if wanted != "" && vdom != wanted {
			continue
		}
		scoped := device
		scoped.VDOMs = []string{vdom}
		scoped.Packages = packageNamesForCandidate(device, vdom)
		scoped.PackageTargets = nil
		for _, target := range device.PackageTargets {
			if target.VDOM == "" || target.VDOM == vdom {
				scoped.PackageTargets = append(scoped.PackageTargets, target)
			}
		}
		scoped.Interfaces = nil
		for _, iface := range device.Interfaces {
			if routeVDOM(iface.VDOM) == vdom {
				scoped.Interfaces = append(scoped.Interfaces, iface)
			}
		}
		scopes = append(scopes, scoped)
	}
	return scopes
}

// policyCandidate keeps a summary for display and independent destination
// selectors for evaluation. One DNS address must not borrow another's egress.
func (s *Service) policyCandidate(ctx context.Context, device fortinet.Device, sourceIP net.IP, destinationIPs []net.IP, input PolicyLookupInput, snapshotAt time.Time) (candidateState, bool) {
	source, _ := matchingInterfaces(device.Interfaces, sourceIP, nil, input.SourceInterface)
	if input.SourceInterface != "" && len(source) == 0 {
		return candidateState{}, false
	}
	base := PolicyCandidate{
		Profile: device.Profile, ADOM: device.ADOM, Device: device.Name,
		VDOMs: append([]string(nil), device.VDOMs...), SourceInterfaces: source,
		SourceZones:    interfaceZonesForNames(device.Interfaces, source),
		Packages:       append([]string(nil), device.Packages...),
		PackageTargets: append([]fortinet.PackageTarget(nil), device.PackageTargets...),
		Resolution:     "inventory-interface-match",
	}
	if input.SourceInterface != "" {
		base.Resolution = "explicit-source-interface"
	} else if len(source) == 0 {
		base.Resolution = "destination-interface-only"
		base.Warnings = []string{"Source IP did not match an inventoried interface; this candidate was selected from destination interface evidence only."}
	}
	state := candidateState{device: device, candidate: base, destinations: make(map[string]PolicyCandidate)}
	for _, destination := range destinationIPs {
		scoped := base
		_, scoped.DestinationInterfaces = matchingInterfaces(device.Interfaces, sourceIP, []net.IP{destination}, input.SourceInterface)
		scoped.DestinationZones = interfaceZonesForNames(device.Interfaces, scoped.DestinationInterfaces)
		if len(source) > 0 && len(scoped.DestinationInterfaces) == 0 {
			var warnings []string
			scoped.Routing, scoped.DestinationInterfaces, scoped.DestinationZones, warnings = s.routedDestination(ctx, device, sourceIP, source, base.SourceZones, []net.IP{destination}, input, snapshotAt)
			scoped.Warnings = append(append([]string(nil), base.Warnings...), warnings...)
		}
		state.destinations[destination.String()] = scoped
		state.candidate.DestinationInterfaces = append(state.candidate.DestinationInterfaces, scoped.DestinationInterfaces...)
		state.candidate.DestinationZones = append(state.candidate.DestinationZones, scoped.DestinationZones...)
		state.candidate.Routing = append(state.candidate.Routing, scoped.Routing...)
		state.candidate.Warnings = append(state.candidate.Warnings, scoped.Warnings...)
	}
	state.candidate.DestinationInterfaces = uniqueStrings(state.candidate.DestinationInterfaces)
	state.candidate.DestinationZones = uniqueStrings(state.candidate.DestinationZones)
	state.candidate.Warnings = uniqueStrings(state.candidate.Warnings)
	return state, len(source) > 0 || len(state.candidate.DestinationInterfaces) > 0
}

func matchingInterfaces(interfaces []fortinet.Interface, sourceIP net.IP, destinationIPs []net.IP, explicit string) ([]string, []string) {
	var source, destination []string
	for _, iface := range interfaces {
		if explicit != "" && interfaceSelectorMatches(iface, explicit) || explicit == "" && fortinetInterfaceContains(iface, sourceIP) {
			source = append(source, iface.Name)
		}
		for _, destinationIP := range destinationIPs {
			if fortinetInterfaceContains(iface, destinationIP) {
				destination = append(destination, iface.Name)
				break
			}
		}
	}
	return uniqueStrings(source), uniqueStrings(destination)
}

// routedDestination derives egress interfaces and zones from the configured
// routing decision of the source interfaces' VDOM for every destination.
func (s *Service) routedDestination(ctx context.Context, device fortinet.Device, sourceIP net.IP, sourceInterfaces, sourceZones []string, destinationIPs []net.IP, input PolicyLookupInput, snapshotAt time.Time) ([]RouteDecision, []string, []string, []string) {
	vdom := ""
	for _, name := range sourceInterfaces {
		if vdom = vdomForInterface(device.Interfaces, name); vdom != "" {
			break
		}
	}
	vdom = routeVDOM(vdom)
	tuple := routeTuple{dstPort: input.DestinationPort, srcPort: input.SourcePort, ingress: uniqueStrings(append(append([]string(nil), sourceInterfaces...), sourceZones...))}
	if source, ok := netip.AddrFromSlice(sourceIP); ok {
		tuple.src = source.Unmap()
	}
	if input.Protocol != "any" {
		tuple.protocol, _ = protocolToNumber(input.Protocol)
	}
	var sink inventory.RouteResult
	resolver, resolverNotes := (*addressResolver)(nil), []string(nil)
	resolverLoaded := false
	var decisions []RouteDecision
	var interfaces, zones, warnings []string
	for _, destinationIP := range destinationIPs {
		addr, ok := netip.AddrFromSlice(destinationIP)
		if !ok {
			continue
		}
		tuple.dst = addr.Unmap()
		if !resolverLoaded {
			resolver, resolverNotes = s.routeResolver(ctx, device, vdom, tuple.dst.Is6(), snapshotAt, &sink)
			resolverLoaded = true
		}
		decision := evaluateRouting(device, vdom, tuple, resolver)
		decision.Notes = append(decision.Notes, resolverNotes...)
		decisions = append(decisions, decision)
		interfaces = append(interfaces, decision.EgressInterfaces...)
		zones = append(zones, decision.EgressZones...)
		switch decision.Stage {
		case "blackhole":
			warnings = append(warnings, fmt.Sprintf("Configured route for %s in VDOM %s is a blackhole; traffic is dropped before policy evaluation unless a dynamic route overrides it.", destinationIP, vdom))
		case "no_route":
			warnings = append(warnings, fmt.Sprintf("No configured route for %s in VDOM %s; the destination interface is unresolved.", destinationIP, vdom))
		default:
			label := decision.Stage
			if decision.PolicyRoute != nil {
				label = fmt.Sprintf("policy route %d", decision.PolicyRoute.SeqNum)
			} else if decision.SDWANRule != nil {
				label = fmt.Sprintf("SD-WAN rule %d %q", decision.SDWANRule.ID, decision.SDWANRule.Name)
			}
			warnings = append(warnings, fmt.Sprintf("Destination interface for %s derived from configured routing (%s, %s) in VDOM %s: %s; dynamic routes and live SD-WAN health are not evaluated.", destinationIP, label, decision.Confidence, vdom, strings.Join(decision.EgressInterfaces, ", ")))
		}
	}
	return decisions, uniqueStrings(interfaces), uniqueStrings(zones), warnings
}

func interfaceContainsName(interfaces []fortinet.Interface, name string) bool {
	for _, iface := range interfaces {
		if interfaceSelectorMatches(iface, name) {
			return true
		}
	}
	return false
}

func interfaceContainsAddress(interfaces []fortinet.Interface, name string, address net.IP) bool {
	for _, iface := range interfaces {
		if interfaceSelectorMatches(iface, name) {
			if fortinetInterfaceContains(iface, address) {
				return true
			}
		}
	}
	return false
}

func interfaceSelectorMatches(iface fortinet.Interface, selector string) bool {
	return iface.Name == selector || (iface.Zone != "" && iface.Zone == selector)
}

func interfaceZonesForNames(interfaces []fortinet.Interface, names []string) []string {
	zones := make([]string, 0, len(names))
	for _, name := range names {
		for _, iface := range interfaces {
			if iface.Name == name && iface.Zone != "" {
				zones = append(zones, iface.Zone)
				break
			}
		}
	}
	return uniqueStrings(zones)
}

// interfacesContaining returns the named interfaces whose networks contain
// address, or all of them when none does (for example a routed source
// behind an explicitly named zone).
func interfacesContaining(interfaces []fortinet.Interface, names []string, address net.IP) []string {
	var containing []string
	for _, name := range names {
		for _, iface := range interfaces {
			if iface.Name == name && fortinetInterfaceContains(iface, address) {
				containing = append(containing, name)
				break
			}
		}
	}
	if len(containing) == 0 {
		return uniqueStrings(names)
	}
	return uniqueStrings(containing)
}

// Keep the network calculation local to the service package so interfaceNetwork
// remains an implementation detail of the Fortinet parser.
func fortinetInterfaceContains(iface fortinet.Interface, address net.IP) bool {
	if iface.Network != "" {
		if network, ok := parseSubnet(iface.Network); ok && usableInterfaceNetwork(network) && network.Contains(address) {
			return true
		}
	}
	for _, networkValue := range iface.Networks {
		if network, ok := parseSubnet(networkValue); ok && usableInterfaceNetwork(network) && network.Contains(address) {
			return true
		}
	}
	if iface.IP != "" && iface.IP != "0.0.0.0" && iface.IP != "0.0.0.0/0" {
		if network, ok := parseSubnet(iface.IP); ok && usableInterfaceNetwork(network) && network.Contains(address) {
			return true
		}
		if iface.Netmask != "" {
			if network, ok := parseSubnet(iface.IP + " " + iface.Netmask); ok && usableInterfaceNetwork(network) && network.Contains(address) {
				return true
			}
		}
	}
	for _, secondary := range iface.Addresses {
		if network, ok := parseSubnet(secondary); ok && usableInterfaceNetwork(network) && network.Contains(address) {
			return true
		}
	}
	for _, ipv6 := range iface.IPv6 {
		if network, ok := parseSubnet(ipv6); ok && usableInterfaceNetwork(network) && network.Contains(address) {
			return true
		}
	}
	return false
}

func usableInterfaceNetwork(network *net.IPNet) bool {
	ones, bits := network.Mask.Size()
	return bits != 0 && ones != 0
}

func vdomForInterface(interfaces []fortinet.Interface, name string) string {
	for _, iface := range interfaces {
		if interfaceSelectorMatches(iface, name) {
			return iface.VDOM
		}
	}
	return ""
}

func allFallback(candidates []candidateState) bool {
	for _, candidate := range candidates {
		if candidate.candidate.Resolution != "fallback-all-inventory-devices" {
			return false
		}
	}
	return len(candidates) > 0
}

func matchingInventoryErrors(snapshot inventory.Snapshot, input PolicyLookupInput) []inventory.RefreshError {
	result := make([]inventory.RefreshError, 0)
	for _, refreshError := range snapshot.Errors {
		if input.Profile != "" && refreshError.Profile != "" && refreshError.Profile != input.Profile {
			continue
		}
		if input.ADOM != "" && refreshError.ADOM != "" && refreshError.ADOM != input.ADOM {
			continue
		}
		if input.Device != "" && refreshError.Device != "" && refreshError.Device != input.Device {
			continue
		}
		result = append(result, refreshError)
	}
	return result
}

func unavailableLookupError(device fortinet.Device) inventory.RefreshError {
	_, reason := fortinet.DeviceUnavailable(device)
	return inventory.RefreshError{
		Profile:   device.Profile,
		ADOM:      device.ADOM,
		Device:    device.Name,
		Stage:     "live_policy_lookup",
		Kind:      fortinet.ErrorKindDeviceUnavailable,
		Retryable: true,
		Message:   fmt.Sprintf("live policy lookup skipped, device is offline: %s", reason),
		Hint:      "Static evaluation used the FortiManager configuration. A live FortiOS lookup needs the FortiGate to reconnect to FortiManager; an inventory refresh does not change that.",
	}
}

func ipStrings(values []net.IP) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}

func differenceIPStrings(all, included []net.IP) []string {
	seen := make(map[string]struct{}, len(included))
	for _, value := range included {
		seen[value.String()] = struct{}{}
	}
	result := make([]string, 0)
	for _, value := range all {
		if _, exists := seen[value.String()]; !exists {
			result = append(result, value.String())
		}
	}
	return result
}

func selectedVDOMForCandidate(candidate candidateState, explicitInterface string) string {
	if explicitInterface != "" {
		if vdom := vdomForInterface(candidate.device.Interfaces, explicitInterface); vdom != "" {
			return vdom
		}
	}
	for _, interfaceName := range candidate.candidate.SourceInterfaces {
		if vdom := vdomForInterface(candidate.device.Interfaces, interfaceName); vdom != "" {
			return vdom
		}
	}
	if len(candidate.device.VDOMs) == 1 {
		return candidate.device.VDOMs[0]
	}
	return ""
}

func packageNamesForCandidate(device fortinet.Device, vdom string) []string {
	if len(device.PackageTargets) == 0 {
		return uniqueStrings(device.Packages)
	}
	packages := make([]string, 0, len(device.PackageTargets))
	for _, target := range device.PackageTargets {
		if target.VDOM == "" || vdom == "" || target.VDOM == vdom {
			packages = append(packages, target.Package)
		}
	}
	return uniqueStrings(packages)
}

func packageTargetsVDOM(pkg fortinet.PolicyPackage, vdom string) bool {
	if vdom == "" || len(pkg.Members) == 0 {
		return true
	}
	for _, member := range pkg.Members {
		if member.VDOM == "" || member.VDOM == vdom {
			return true
		}
	}
	return false
}

func appendUniqueWarnings(output *PolicyLookupOutput, warnings ...string) {
	for _, warning := range warnings {
		if warning == "" || containsString(output.Warnings, warning) {
			continue
		}
		output.Warnings = append(output.Warnings, warning)
	}
}

func matchPolicy(policy fortinet.FirewallPolicy, candidate candidateState, packageName string, input PolicyLookupInput, sourceIP, destinationIP net.IP, addresses *addressResolver, services *serviceResolver) (bool, PolicyMatch) {
	if strings.EqualFold(policy.Status, "disable") {
		return false, PolicyMatch{}
	}
	if policy.Device != "" && policy.Device != candidate.device.Name {
		return false, PolicyMatch{}
	}
	if policy.VDOM != "" && len(candidate.device.VDOMs) > 0 && !containsString(candidate.device.VDOMs, policy.VDOM) {
		return false, PolicyMatch{}
	}

	matchVDOM := policy.VDOM
	if matchVDOM == "" {
		for _, interfaceName := range append(append([]string{}, candidate.candidate.SourceInterfaces...), candidate.candidate.DestinationInterfaces...) {
			interfaceVDOM := vdomForInterface(candidate.device.Interfaces, interfaceName)
			if interfaceVDOM == "" {
				continue
			}
			if matchVDOM != "" && matchVDOM != interfaceVDOM {
				matchVDOM = ""
				break
			}
			matchVDOM = interfaceVDOM
		}
	}
	if matchVDOM == "" && len(candidate.device.VDOMs) == 1 {
		matchVDOM = candidate.device.VDOMs[0]
	}
	match := PolicyMatch{
		ADOM: candidate.device.ADOM, Device: candidate.device.Name, Package: packageName,
		VDOM: matchVDOM, Policy: policy,
		SourceInterfaces:      candidate.candidate.SourceInterfaces,
		DestinationInterfaces: candidate.candidate.DestinationInterfaces,
		SourceZones:           candidate.candidate.SourceZones,
		DestinationZones:      candidate.candidate.DestinationZones,
		EvidenceType:          "configured_policy",
	}
	// A policy installed only on selected devices (install-on) does not
	// exist on the others.
	if len(policy.Scope) > 0 && !policyScopeIncludes(policy.Scope, candidate.device, matchVDOM) {
		return false, PolicyMatch{}
	}
	match.Warnings = append(match.Warnings, candidate.candidate.Warnings...)
	if match.VDOM == "" {
		match.Warnings = append(match.Warnings, "VDOM could not be uniquely resolved from the policy and inventory.")
	}

	// FortiOS 6.4+ keeps IPv4 and IPv6 addresses (and internet services) of
	// one policy in separate columns; only the flow's family applies.
	ipv6 := sourceIP.To4() == nil
	sourceNames, destinationNames := policy.SourceAddresses, policy.DestinationAddresses
	otherSource, otherDestination := policy.SourceAddresses6, policy.DestinationAddresses6
	sourceISDB, destinationISDB := policy.SourceInternetService, policy.DestinationInternetService
	if ipv6 {
		sourceNames, destinationNames = policy.SourceAddresses6, policy.DestinationAddresses6
		otherSource, otherDestination = policy.SourceAddresses, policy.DestinationAddresses
		sourceISDB, destinationISDB = policy.SourceInternetService6, policy.DestinationInternetService6
	}
	if !sourceISDB && len(sourceNames) == 0 && len(otherSource) > 0 || !destinationISDB && len(destinationNames) == 0 && len(otherDestination) > 0 {
		// A policy with addresses of the other family only does not apply.
		return false, PolicyMatch{}
	}

	sourceSelectors := append(append([]string{}, candidate.candidate.SourceInterfaces...), candidate.candidate.SourceZones...)
	destinationSelectors := append(append([]string{}, candidate.candidate.DestinationInterfaces...), candidate.candidate.DestinationZones...)
	destinationResolved := len(candidate.candidate.DestinationInterfaces) > 0
	if mapped := addresses.mappedIPs(destinationNames, destinationIP); len(mapped) > 0 {
		// FortiOS matches a VIP policy's dstintf against the path to the
		// mapped (internal) address, not to the address the client used.
		interfaces, zones := mappedDestinationSelectors(candidate.device, mapped)
		destinationSelectors = append(interfaces, zones...)
		destinationResolved = len(interfaces) > 0
		if !destinationResolved {
			match.Warnings = append(match.Warnings, "The destination is a VIP whose mapped address is not on a connected interface in inventory, so the policy's destination interface was not used as a hard filter.")
		}
	}
	if !interfacePolicyMatch(policy.SourceInterfaces, sourceSelectors) || !interfacePolicyMatch(policy.DestinationInterfaces, destinationSelectors) {
		return false, PolicyMatch{}
	}
	if len(sourceSelectors) > 0 {
		match.Score += 3
	}
	if len(destinationSelectors) > 0 {
		match.Score += 3
	}
	if len(candidate.candidate.SourceInterfaces) == 0 && len(policy.SourceInterfaces) > 0 && !containsFold(policy.SourceInterfaces, "any") {
		match.Warnings = append(match.Warnings, "Source interface was not resolved from inventory; policy interface was not used as a hard filter.")
	}
	if !destinationResolved && len(policy.DestinationInterfaces) > 0 && !containsFold(policy.DestinationInterfaces, "any") {
		match.Warnings = append(match.Warnings, "Destination interface was not resolved from inventory; policy interface was not used as a hard filter.")
	}

	sourceMatched, sourceKnown, sourceEvidence := addresses.side(sourceNames, sourceISDB, sourceIP, policy.SourceNegate)
	destinationMatched, destinationKnown, destinationEvidence := addresses.side(destinationNames, destinationISDB, destinationIP, policy.DestinationNegate)
	if !sourceMatched && sourceKnown {
		return false, PolicyMatch{}
	}
	if !destinationMatched && destinationKnown {
		return false, PolicyMatch{}
	}
	match.AddressEvidence = append(match.AddressEvidence, sourceEvidence...)
	match.AddressEvidence = append(match.AddressEvidence, destinationEvidence...)
	match.TranslationEvidence = addresses.translations(destinationNames, destinationIP)
	if sourceISDB || destinationISDB {
		match.Warnings = append(match.Warnings, fmt.Sprintf("The policy matches an Internet Service (ISDB) entry (%s) instead of addresses; its address list is not in FortiManager, so the match is tentative.", strings.Join(policy.InternetServices, ", ")))
	}
	if len(policy.Users) > 0 || len(policy.Groups) > 0 {
		match.Warnings = append(match.Warnings, fmt.Sprintf("The policy also requires user identity (%s); the user of this flow is not evaluated.", strings.Join(append(append([]string(nil), policy.Users...), policy.Groups...), ", ")))
	}
	if sourceKnown {
		match.Score += 3
	} else {
		match.Warnings = append(match.Warnings, "Source address could not be proven from FortiManager objects; this is a tentative match.")
	}
	if destinationKnown {
		match.Score += 3
	} else {
		match.Warnings = append(match.Warnings, "Destination address could not be proven from FortiManager objects; this is a tentative match.")
	}

	serviceMatched, serviceKnown, serviceEvidence := services.matches(policy.Services, input.Protocol, input.DestinationPort, input.SourcePort, policy.ServiceNegate)
	if !serviceMatched && serviceKnown {
		return false, PolicyMatch{}
	}
	match.ServiceEvidence = serviceEvidence
	if serviceKnown {
		match.Score += 4
	} else {
		match.Warnings = append(match.Warnings, "Service conditions, including any source-port range, could not be proven; this is a tentative match. Provide source_port when the service restricts it.")
	}
	if len(policy.Schedule) > 0 && !containsFold(policy.Schedule, "always") {
		match.Warnings = append(match.Warnings, fmt.Sprintf("Policy schedule %s was not evaluated; the match only applies while that schedule is active.", strings.Join(policy.Schedule, ", ")))
	}
	// The parsed fields carry every attribute the match used; the appliance
	// record would only repeat them at several times the size.
	match.Policy.Raw = nil
	match.Confidence = "likely"
	if len(match.Warnings) > 0 {
		match.Confidence = "tentative"
	}
	return true, match
}

func interfacePolicyMatch(policyInterfaces, candidateInterfaces []string) bool {
	if len(policyInterfaces) == 0 || containsFold(policyInterfaces, "any") {
		return true
	}
	if len(candidateInterfaces) == 0 {
		// An absent candidate list means inventory could not infer that side of
		// the path. Keep the static result tentative instead of dropping a
		// policy whose destination is reached through routing/SD-WAN.
		return true
	}
	for _, policyInterface := range policyInterfaces {
		for _, candidateInterface := range candidateInterfaces {
			if strings.EqualFold(policyInterface, candidateInterface) {
				return true
			}
		}
	}
	return false
}

func newAddressResolver(objects []fortinet.AddressObject) *addressResolver {
	resolver := &addressResolver{objects: make(map[string]fortinet.AddressObject, len(objects)), visiting: make(map[string]bool)}
	for _, object := range objects {
		resolver.objects[object.Name] = object
	}
	return resolver
}

// side evaluates one side (source or destination) of a firewall policy for
// the flow's IP family. An internet service replaces the address list and
// cannot be evaluated from FortiManager; an empty list (fields missing from
// the read) is unknown rather than "all".
func (r *addressResolver) side(names []string, internetService bool, ip net.IP, negate bool) (matched, known bool, evidence []string) {
	if internetService {
		return true, false, []string{"internet-service"}
	}
	if len(names) == 0 {
		return true, false, nil
	}
	return r.matches(names, ip, negate)
}

func (r *addressResolver) matches(names []string, ip net.IP, negate bool) (matched, known bool, evidence []string) {
	if len(names) == 0 || containsFold(names, "all") || containsFold(names, "all_ipv4") && ip.To4() != nil || containsFold(names, "all_ipv6") && ip.To4() == nil {
		return !negate, true, []string{"all"}
	}
	unknown := false
	for _, name := range names {
		objectMatched, objectKnown := r.matchesOne(name, ip)
		if objectMatched {
			evidence = append(evidence, name)
			if negate {
				return false, objectKnown, evidence
			}
			return true, objectKnown, evidence
		}
		if !objectKnown {
			unknown = true
		}
	}
	if negate {
		return !unknown, !unknown, evidence
	}
	return false, !unknown, evidence
}

func (r *addressResolver) matchesOne(name string, ip net.IP) (bool, bool) {
	name = strings.TrimSpace(name)
	if strings.EqualFold(name, "all") {
		return true, true
	}
	if literal := net.ParseIP(name); literal != nil {
		return literal.Equal(ip), true
	}
	object, ok := r.objects[name]
	if !ok {
		return false, false
	}
	if r.visiting[name] {
		return false, false
	}
	r.visiting[name] = true
	defer delete(r.visiting, name)
	if object.DynamicMappings > 0 {
		// Per-device mappings give this object another value on some
		// FortiGates; which one applies is not evaluated.
		matched, _ := r.matchesObject(object, ip)
		return matched, false
	}
	return r.matchesObject(object, ip)
}

func (r *addressResolver) matchesObject(object fortinet.AddressObject, ip net.IP) (bool, bool) {
	if object.Subnet != "" {
		if network, ok := parseSubnet(object.Subnet); ok {
			return network.Contains(ip), true
		}
	}
	if object.StartIP != "" && object.EndIP != "" {
		start, startErr := parseIP(object.StartIP)
		end, endErr := parseIP(object.EndIP)
		if startErr == nil && endErr == nil {
			if (ip.To4() == nil) != (start.To4() == nil) || (ip.To4() == nil) != (end.To4() == nil) {
				return false, true
			}
			return bytesCompare(ip, start) >= 0 && bytesCompare(ip, end) <= 0, true
		}
	}
	if len(object.Members) > 0 {
		unknown := false
		for _, member := range object.Members {
			matched, known := r.matchesOne(member, ip)
			if matched {
				if len(object.ExcludeMembers) > 0 {
					// exclude enable: addresses of the excluded members do not
					// match the group.
					for _, excluded := range object.ExcludeMembers {
						excludedMatch, excludedKnown := r.matchesOne(excluded, ip)
						if excludedMatch {
							return false, excludedKnown && known
						}
						if !excludedKnown {
							known = false
						}
					}
				}
				return true, known
			}
			if !known {
				unknown = true
			}
		}
		return false, !unknown
	}
	// FQDN, dynamic, wildcard, geography, and interface-derived objects need
	// runtime FortiGate state and cannot be proven from the FMG object table.
	return false, false
}

// mappedIPs returns the mapped (internal) addresses of the VIPs among names
// that match ip.
func (r *addressResolver) mappedIPs(names []string, ip net.IP) []net.IP {
	var mapped []net.IP
	visiting := make(map[string]bool)
	var visit func(string)
	visit = func(name string) {
		object, ok := r.objects[strings.TrimSpace(name)]
		if !ok || visiting[object.Name] {
			return
		}
		visiting[object.Name] = true
		defer delete(visiting, object.Name)
		if object.MappedIP != "" {
			if matched, _ := r.matchesOne(object.Name, ip); matched {
				first := strings.FieldsFunc(object.MappedIP, func(r rune) bool { return r == '-' || r == ' ' || r == ',' || r == '/' })
				if len(first) > 0 {
					if address := net.ParseIP(strings.TrimSpace(first[0])); address != nil {
						mapped = append(mapped, address)
					}
				}
			}
		}
		for _, member := range object.Members {
			visit(member)
		}
	}
	for _, name := range names {
		visit(name)
	}
	return mapped
}

// mappedDestinationSelectors returns the interfaces (and their zones) of a
// device whose connected networks hold the mapped VIP addresses.
func mappedDestinationSelectors(device fortinet.Device, mapped []net.IP) ([]string, []string) {
	var interfaces []string
	for _, iface := range device.Interfaces {
		for _, address := range mapped {
			if fortinetInterfaceContains(iface, address) {
				interfaces = append(interfaces, iface.Name)
				break
			}
		}
	}
	interfaces = uniqueStrings(interfaces)
	return interfaces, interfaceZonesForNames(device.Interfaces, interfaces)
}

func (r *addressResolver) translations(names []string, ip net.IP) []string {
	seen := make(map[string]struct{})
	visiting := make(map[string]bool)
	var result []string
	var visit func(string)
	visit = func(name string) {
		name = strings.TrimSpace(name)
		object, ok := r.objects[name]
		if !ok || visiting[name] {
			return
		}
		visiting[name] = true
		defer delete(visiting, name)
		matched, _ := r.matchesOne(name, ip)
		if matched && object.MappedIP != "" {
			evidence := fmt.Sprintf("%s -> %s", object.Name, object.MappedIP)
			if object.MappedPort != "" {
				evidence += ":" + object.MappedPort
			}
			if _, exists := seen[evidence]; !exists {
				seen[evidence] = struct{}{}
				result = append(result, evidence)
			}
		}
		for _, member := range object.Members {
			visit(member)
		}
	}
	for _, name := range names {
		visit(name)
	}
	return result
}

func parseSubnet(value string) (*net.IPNet, bool) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		_, network, err := net.ParseCIDR(value)
		return network, err == nil
	}
	parts := strings.Fields(value)
	if len(parts) != 2 {
		return nil, false
	}
	ip := net.ParseIP(parts[0])
	maskIP := net.ParseIP(parts[1])
	if ip == nil || maskIP == nil || ip.To4() == nil || maskIP.To4() == nil {
		return nil, false
	}
	mask := net.IPMask(maskIP.To4())
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, true
}

func newServiceResolver(objects []fortinet.ServiceObject) *serviceResolver {
	resolver := &serviceResolver{objects: make(map[string]fortinet.ServiceObject, len(objects)), visiting: make(map[string]bool)}
	for _, object := range objects {
		resolver.objects[object.Name] = object
	}
	return resolver
}

func (r *serviceResolver) matches(names []string, protocol string, destinationPort, sourcePort int, negate bool) (matched, known bool, evidence []string) {
	if len(names) == 0 || containsFold(names, "all") {
		return !negate, true, []string{"ALL"}
	}
	unknown := false
	for _, name := range names {
		objectMatched, objectKnown := r.matchesOne(name, protocol, destinationPort, sourcePort)
		if objectMatched {
			evidence = append(evidence, name)
			if negate {
				return false, objectKnown, evidence
			}
			return true, objectKnown, evidence
		}
		if !objectKnown {
			unknown = true
		}
	}
	if negate {
		return !unknown, !unknown, evidence
	}
	return false, !unknown, evidence
}

func (r *serviceResolver) matchesOne(name, protocol string, port, sourcePort int) (bool, bool) {
	name = strings.TrimSpace(name)
	if strings.EqualFold(name, "all") || strings.EqualFold(name, "all_tcp") && (protocol == "tcp" || protocol == "any") || strings.EqualFold(name, "all_udp") && (protocol == "udp" || protocol == "any") {
		return true, true
	}
	object, ok := r.objects[name]
	if !ok {
		// The ADOM's own service objects win; the built-in definitions only
		// cover predefined services missing from the read.
		if builtin, found := builtinServices[strings.ToLower(name)]; found {
			return builtinProtocolPort(builtin, protocol, port), true
		}
		return false, false
	}
	if r.visiting[name] {
		return false, false
	}
	r.visiting[name] = true
	defer delete(r.visiting, name)
	if len(object.Members) > 0 {
		unknown := false
		for _, member := range object.Members {
			matched, known := r.matchesOne(member, protocol, port, sourcePort)
			if matched {
				return true, known
			}
			if !known {
				unknown = true
			}
		}
		return false, !unknown
	}
	selected := object.PortRange
	switch protocol {
	case "tcp":
		if object.TCPPortRange != "" {
			selected = object.TCPPortRange
		}
	case "udp":
		if object.UDPPortRange != "" {
			selected = object.UDPPortRange
		}
	case "sctp":
		if object.SCTPPortRange != "" {
			selected = object.SCTPPortRange
		}
	case "any":
		selected = strings.TrimSpace(object.TCPPortRange + " " + object.UDPPortRange + " " + object.PortRange)
	}
	if selected == "" {
		return false, false
	}
	if object.Protocol != "" && protocol != "any" && !serviceProtocolMatches(object.Protocol, protocol) {
		return false, true
	}
	return servicePortsMatch(selected, port, sourcePort)
}

type builtinService struct {
	protocol string
	ports    string
}

var builtinServices = map[string]builtinService{
	"http":   {protocol: "tcp", ports: "80"},
	"https":  {protocol: "tcp", ports: "443"},
	"ssh":    {protocol: "tcp", ports: "22"},
	"ftp":    {protocol: "tcp", ports: "21"},
	"telnet": {protocol: "tcp", ports: "23"},
	"smtp":   {protocol: "tcp", ports: "25"},
	"smtps":  {protocol: "tcp", ports: "465"},
	"dns":    {protocol: "tcp/udp", ports: "53"},
	"ntp":    {protocol: "tcp/udp", ports: "123"},
	"ldap":   {protocol: "tcp", ports: "389"},
	"ldaps":  {protocol: "tcp", ports: "636"},
	"rdp":    {protocol: "tcp", ports: "3389"},
}

func builtinProtocolPort(service builtinService, protocol string, port int) bool {
	if !serviceProtocolMatches(service.protocol, protocol) {
		return false
	}
	return portInRanges(service.ports, port)
}

func serviceProtocolMatches(value, wanted string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || wanted == "any" {
		return true
	}
	for _, token := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == ',' || r == ' ' || r == ';' }) {
		if normalizeProtocol(token) == wanted || token == wanted {
			return true
		}
	}
	return false
}

// servicePortsMatch evaluates paired destination:source ranges. An omitted
// source port leaves a matching restricted range unresolved.
func servicePortsMatch(value string, destinationPort, sourcePort int) (bool, bool) {
	tentative := false
	for _, token := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == ';' }) {
		destination, source, paired := strings.Cut(strings.Trim(token, "[]()\""), ":")
		if !portInRanges(destination, destinationPort) {
			continue
		}
		if !paired || source == "" || source == "0-65535" {
			return true, true
		}
		if sourcePort == 0 {
			tentative = true
			continue
		}
		if portInRanges(source, sourcePort) {
			return true, true
		}
	}
	return tentative, !tentative
}

func portInRanges(value string, port int) bool {
	for _, token := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == ';' }) {
		token = strings.Trim(token, "[]()\"")
		// FortiOS writes "dstlow-dsthigh:srclow-srchigh"; the destination
		// port range is the part before the colon.
		if colon := strings.Index(token, ":"); colon >= 0 {
			token = token[:colon]
		}
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			start, startErr := strconv.Atoi(parts[0])
			end, endErr := strconv.Atoi(parts[1])
			if startErr == nil && endErr == nil && port >= start && port <= end {
				return true
			}
			continue
		}
		if parsed, err := strconv.Atoi(token); err == nil && parsed == port {
			return true
		}
	}
	return false
}

func normalizeProtocol(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "any", "all":
		return "any"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "132":
		return "sctp"
	case "1":
		return "icmp"
	case "tcp", "udp", "sctp", "icmp":
		return value
	default:
		number, err := strconv.Atoi(value)
		if err == nil && number >= 1 && number <= 255 {
			return strconv.Itoa(number)
		}
		return ""
	}
}

func bytesCompare(left, right net.IP) int {
	left = left.To16()
	right = right.To16()
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return 0
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func containsString(values []string, wanted string) bool {
	return slices.Contains(values, wanted)
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

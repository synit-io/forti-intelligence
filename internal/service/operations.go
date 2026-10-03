package service

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/synit-io/forti-intelligence/internal/config"
	"github.com/synit-io/forti-intelligence/internal/fortinet"
)

// DeviceScope names one managed FortiGate. adom is taken from the inventory
// when it is omitted and device is known.
type DeviceScope struct {
	Profile string `json:"profile,omitempty" jsonschema:"FortiManager profile name. The default profile is used when omitted."`
	ADOM    string `json:"adom,omitempty" jsonschema:"ADOM that manages the FortiGate; taken from the inventory when omitted"`
	Device  string `json:"device" jsonschema:"Managed FortiGate name as shown in inventory_status"`
	VDOM    string `json:"vdom,omitempty" jsonschema:"VDOM; root when omitted"`
}

type SessionQuery struct {
	DeviceScope
	SourceIP        string `json:"source_ip,omitempty" jsonschema:"Keep sessions whose source address is this IP"`
	DestinationIP   string `json:"destination_ip,omitempty" jsonschema:"Keep sessions whose destination address is this IP"`
	SourcePort      int    `json:"source_port,omitempty" jsonschema:"Keep sessions whose source port is this value"`
	DestinationPort int    `json:"destination_port,omitempty" jsonschema:"Keep sessions whose destination port is this value"`
	Protocol        string `json:"protocol,omitempty" jsonschema:"tcp, udp, icmp, or an IP protocol number"`
	PolicyID        int    `json:"policy_id,omitempty" jsonschema:"Keep sessions matched by this firewall policy id"`
	Count           int    `json:"count,omitempty" jsonschema:"How many sessions to ask the FortiGate for before local filtering. Default 50, at most 200. The session table is not cached."`
}

type AddressIdentityQuery struct {
	DeviceScope
	IP string `json:"ip" jsonschema:"IPv4 or IPv6 address to look up in DHCP leases, ARP, FSSO and firewall user tables"`
}

type LogFocusQuery struct {
	Profile string `json:"profile,omitempty" jsonschema:"FortiAnalyzer profile. The default profile is used when omitted."`
	ADOM    string `json:"adom,omitempty" jsonschema:"FortiAnalyzer ADOM, not the FortiManager ADOM"`
	Device  string `json:"device,omitempty" jsonschema:"Logged device name (devname). Use map_analyzer_device to translate a FortiManager FortiGate name."`
	Filter  string `json:"filter,omitempty" jsonschema:"Extra Log View filter, ANDed with the focus filter"`
	Start   string `json:"start,omitempty" jsonschema:"Range start as RFC3339 with an explicit offset; one hour ago when omitted"`
	End     string `json:"end,omitempty" jsonschema:"Range end as RFC3339 with an explicit offset; now when omitted"`
	Focus   string `json:"focus,omitempty" jsonschema:"all (default), deny (traffic action deny), webfilter, or ips"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Match budget of the count search, default 500, at most 500. The rows are not returned."`
}

type AnalyzerDeviceQuery struct {
	Profile         string `json:"profile,omitempty" jsonschema:"FortiManager profile of the FortiGate"`
	ADOM            string `json:"adom,omitempty" jsonschema:"FortiManager ADOM; taken from the inventory when omitted"`
	Device          string `json:"device" jsonschema:"FortiManager FortiGate name"`
	AnalyzerProfile string `json:"analyzer_profile,omitempty" jsonschema:"FortiAnalyzer profile. The default profile is used when omitted."`
	AnalyzerADOM    string `json:"analyzer_adom,omitempty" jsonschema:"FortiAnalyzer ADOM. The configured ADOM is used when the profile allows exactly one."`
}

type NATQuery struct {
	DeviceScope
	SourceIP      string `json:"source_ip,omitempty" jsonschema:"Source address of the flow, matched against central SNAT and IP pools when those objects carry an address"`
	DestinationIP string `json:"destination_ip,omitempty" jsonschema:"Destination address, matched against VIP external addresses"`
	Port          int    `json:"port,omitempty" jsonschema:"Destination port, matched against VIP external ports when present"`
}

type PolicyUsageQuery struct {
	DeviceScope
	PolicyID   int    `json:"policy_id,omitempty" jsonschema:"Limit hit counts to this policy id"`
	ObjectType string `json:"object_type,omitempty" jsonschema:"firewall/address, firewall/service/custom, or another firewall object path. Used with name for where-used."`
	Name       string `json:"name,omitempty" jsonschema:"Object name to find in the ADOM policy tables"`
}

type SSLProfileQuery struct {
	Profile string `json:"profile,omitempty" jsonschema:"FortiManager profile. The default profile is used when omitted."`
	ADOM    string `json:"adom,omitempty" jsonschema:"ADOM that stores the profile; taken from the inventory when device is set"`
	Device  string `json:"device,omitempty" jsonschema:"FortiGate name, used only to find the ADOM when adom is omitted"`
	Name    string `json:"name" jsonschema:"ssl-ssh-profile name, as shown on the firewall policy"`
}

type LogReceiptQuery struct {
	Profile string `json:"profile,omitempty" jsonschema:"FortiAnalyzer profile. The default profile is used when omitted."`
	ADOM    string `json:"adom,omitempty" jsonschema:"FortiAnalyzer ADOM"`
	Device  string `json:"device,omitempty" jsonschema:"Keep the logstats row whose name, serial or devname matches. All rows when omitted."`
}

type PackageHistoryQuery struct {
	DeviceScope
	Package string `json:"package,omitempty" jsonschema:"Policy package name. The device's assigned packages are used when omitted."`
}

// GetFirewallSessions reads a short, filtered slice of the live session
// table. FortiOS often ignores a session filter and returns the first count
// rows, so the rows are filtered again locally. The result is not cached.
func (s *Service) GetFirewallSessions(ctx context.Context, input SessionQuery) (any, error) {
	count := input.Count
	if count <= 0 {
		count = 50
	}
	count = min(count, 200)
	query := url.Values{}
	query.Set("count", strconv.Itoa(count))
	resource := "/api/v2/monitor/firewall/session?" + query.Encode()
	proxy, err := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, resource)
	if err != nil {
		return nil, err
	}
	protocol := protocolFilter(input.Protocol)
	var sessions []map[string]any
	for _, record := range recordsOf(proxy.Data) {
		if input.SourceIP != "" && !fieldEquals(record, input.SourceIP, "src", "source", "srcip", "src_ip", "saddr") {
			continue
		}
		if input.DestinationIP != "" && !fieldEquals(record, input.DestinationIP, "dst", "destination", "dstip", "dst_ip", "daddr") {
			continue
		}
		if input.SourcePort > 0 && !fieldEquals(record, strconv.Itoa(input.SourcePort), "sport", "srcport", "src_port") {
			continue
		}
		if input.DestinationPort > 0 && !fieldEquals(record, strconv.Itoa(input.DestinationPort), "dport", "dstport", "dst_port") {
			continue
		}
		if input.PolicyID > 0 && !fieldEquals(record, strconv.Itoa(input.PolicyID), "policyid", "policy_id", "policy") {
			continue
		}
		if protocol != "" && !protocolMatches(record, protocol) {
			continue
		}
		sessions = append(sessions, shortSession(record))
	}
	profileName := input.Profile
	if manager, mgrErr := s.managerForScope(input.Profile, proxy.ADOM, input.Device); mgrErr == nil {
		profileName = manager.Name()
	}
	return map[string]any{
		"profile": profileName, "adom": proxy.ADOM, "device": proxy.Device, "vdom": input.VDOM,
		"source": "fortigate", "cached": false, "requested": count, "returned": len(sessions),
		"filtered_locally": true,
		"note":             "The session table is read live and is not cached. FortiOS may ignore a filter and return the first requested rows; those rows are filtered locally. A later matching session can be absent when the page is shorter than the table. Raise count (at most 200) or pass policy_id.",
		"sessions":         sessions,
	}, nil
}

// ResolveAddressIdentity reads DHCP, ARP, FSSO and firewall-user tables for
// one address. A failed source is reported and the others still run.
func (s *Service) ResolveAddressIdentity(ctx context.Context, input AddressIdentityQuery) (any, error) {
	ip := strings.TrimSpace(input.IP)
	if ip == "" {
		return nil, fmt.Errorf("ip is required")
	}
	sources := []struct{ name, resource string }{
		{"dhcp", "/api/v2/monitor/system/dhcp"},
		{"arp", "/api/v2/monitor/network/arp"},
		{"fsso", "/api/v2/monitor/user/fsso"},
		{"firewall_user", "/api/v2/monitor/user/firewall"},
	}
	found := map[string][]map[string]any{}
	var errors []any
	for _, source := range sources {
		proxy, err := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, source.resource)
		if err != nil {
			errors = append(errors, map[string]any{"source": source.name, "error": err.Error()})
			continue
		}
		var matches []map[string]any
		for _, record := range recordsOf(proxy.Data) {
			if recordMentions(record, ip) {
				matches = append(matches, record)
			}
		}
		found[source.name] = matches
	}
	return map[string]any{
		"device": input.Device, "vdom": input.VDOM, "ip": ip,
		"note":    "Connected-subnet ownership is resolve_ip_ownership. This read is who held the address in DHCP, ARP, FSSO or the firewall user table at the time of the call. An empty source is not proof the address was never used.",
		"matches": found, "errors": errors,
	}, nil
}

// GetVPNStatus reads IPsec tunnels and SSL-VPN sessions and returns a short
// row for each. Both monitor documents are reused for 30 seconds.
func (s *Service) GetVPNStatus(ctx context.Context, input DeviceScope) (any, error) {
	ipsec, ipsecErr := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, "ipsec")
	ssl, sslErr := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, "ssl-vpn")
	var errors []any
	if ipsecErr != nil {
		errors = append(errors, map[string]any{"source": "ipsec", "error": ipsecErr.Error()})
	}
	if sslErr != nil {
		errors = append(errors, map[string]any{"source": "ssl_vpn", "error": sslErr.Error()})
	}
	return map[string]any{
		"adom": ipsec.ADOM, "device": input.Device, "vdom": input.VDOM,
		"ipsec_tunnels": summarizeIPsec(ipsec.Data),
		"ssl_vpn":       summarizeSSLVPN(ssl.Data),
		"errors":        errors,
		"note":          "Status is the live FortiGate monitor, reused for 30 seconds. It is not the configured phase1 object.",
	}, nil
}

// GetHAStatus reads HA role, peers and checksums.
func (s *Service) GetHAStatus(ctx context.Context, input DeviceScope) (any, error) {
	peer, peerErr := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, "ha-peer")
	checksums, checksumErr := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, "ha-checksums")
	config, configErr := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, "/api/v2/cmdb/system/ha")
	var errors []any
	if peerErr != nil {
		errors = append(errors, map[string]any{"source": "ha_peer", "error": peerErr.Error()})
	}
	if checksumErr != nil {
		errors = append(errors, map[string]any{"source": "ha_checksums", "error": checksumErr.Error()})
	}
	if configErr != nil {
		errors = append(errors, map[string]any{"source": "ha_config", "error": configErr.Error()})
	}
	peers := summarizeHAPeers(peer.Data)
	sums := checksumValues(checksums.Data)
	inSync := len(sums) > 1
	for i := 1; inSync && i < len(sums); i++ {
		inSync = sums[i] == sums[0]
	}
	if len(sums) < 2 {
		inSync = false
	}
	return map[string]any{
		"adom": peer.ADOM, "device": input.Device, "vdom": input.VDOM,
		"ha":            firstRecord(config.Data),
		"peers":         peers,
		"checksums":     sums,
		"checksum_sync": inSync,
		"errors":        errors,
		"note":          "checksum_sync is true only when at least two checksums were read and they are equal. A peer read that failed leaves checksum_sync false.",
	}, nil
}

// GetPackageInstallStatus reads FortiManager's stored install state for one
// device. vdom empty reads every inventoried VDOM, capped at 48.
func (s *Service) GetPackageInstallStatus(ctx context.Context, input DeviceScope) (any, error) {
	adom, err := s.scopeADOM(input.Profile, input.ADOM, input.Device)
	if err != nil {
		return nil, err
	}
	manager, err := s.managerForScope(input.Profile, adom, input.Device)
	if err != nil {
		return nil, err
	}
	if err := s.validateManagerADOM(manager, adom); err != nil {
		return nil, err
	}
	reader, ok := manager.(fortinet.PackageStatusReader)
	if !ok {
		return nil, fmt.Errorf("FortiManager profile %q cannot read package install status", manager.Name())
	}
	vdoms := []string{input.VDOM}
	configStatus := ""
	if input.VDOM == "" {
		vdoms = []string{"root"}
		if s.store != nil {
			if matches := s.store.FindDevices(manager.Name(), adom, input.Device); len(matches) == 1 {
				if len(matches[0].VDOMs) > 0 {
					vdoms = append([]string(nil), matches[0].VDOMs...)
				}
				configStatus = matches[0].ConfigStatus
			}
		}
	}
	members := make([]fortinet.PackageMember, 0, len(vdoms))
	for _, vdom := range vdoms {
		if vdom == "" {
			vdom = "root"
		}
		members = append(members, fortinet.PackageMember{Device: input.Device, VDOM: vdom})
	}
	truncated := false
	if len(members) > maxPackageStatusReads {
		truncated = true
		members = members[:maxPackageStatusReads]
	}
	statuses, err := s.packageInstallStatuses(ctx, reader, manager.Name(), adom, members)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"profile": manager.Name(), "adom": adom, "device": input.Device,
		"config_status": configStatus, "truncated": truncated,
		"install_status": statuses,
		"note":           "status is FortiManager's stored package install state (installed, modified, unknown). It is not the FortiGate's running checksum.",
	}, nil
}

func (s *Service) packageInstallStatuses(ctx context.Context, reader fortinet.PackageStatusReader, profile, adom string, members []fortinet.PackageMember) (map[string]fortinet.PackageStatus, error) {
	if s.webFilter == nil {
		s.webFilter = newWebFilterCaches()
	}
	prefix := profile + "\x00" + adom + "\x00"
	epoch := s.cacheEpoch.Load()
	statuses := make(map[string]fortinet.PackageStatus, len(members))
	missing := make([]fortinet.PackageMember, 0, len(members))
	s.webFilter.mu.Lock()
	for _, member := range members {
		key := member.Device + "/" + member.VDOM
		if entry, cached := s.webFilter.status[prefix+key]; cached && time.Since(entry.created) < webFilterConfigTTL {
			if entry.found {
				statuses[key] = entry.status
			}
			continue
		}
		missing = append(missing, member)
	}
	s.webFilter.mu.Unlock()
	if len(missing) == 0 {
		return statuses, nil
	}
	memberKey := make([]string, len(missing))
	for i, member := range missing {
		memberKey[i] = member.Device + "/" + member.VDOM
	}
	shared, err := s.sharedRead(ctx, "pkgstatus\x00"+prefix+strings.Join(memberKey, ","), func() (any, error) {
		return reader.PackageStatusBatch(ctx, adom, missing)
	})
	if err != nil {
		return nil, err
	}
	read, _ := shared.(map[string]fortinet.PackageStatus)
	now := time.Now()
	s.webFilter.mu.Lock()
	if s.cacheWriteAllowed(epoch) {
		if s.webFilter.status == nil {
			s.webFilter.status = map[string]packageStatusEntry{}
		}
		evictOlderThan(s.webFilter.status, webFilterConfigTTL, func(entry packageStatusEntry) time.Time { return entry.created })
		for _, member := range missing {
			key := member.Device + "/" + member.VDOM
			status, found := read[key]
			if found {
				statuses[key] = status
			}
			s.webFilter.status[prefix+key] = packageStatusEntry{created: now, status: status, found: found}
		}
	} else {
		for _, member := range missing {
			key := member.Device + "/" + member.VDOM
			if status, found := read[key]; found {
				statuses[key] = status
			}
		}
	}
	s.webFilter.mu.Unlock()
	return statuses, nil
}

// CountFortiAnalyzerLogs submits a Log View search and then reads its count.
// Rows are not returned. focus selects a deny, web filter, or IPS search.
func (s *Service) CountFortiAnalyzerLogs(ctx context.Context, input LogFocusQuery) (any, error) {
	request := fortinet.LogSearchRequest{ADOM: input.ADOM, Filter: input.Filter, Device: input.Device, Limit: input.Limit}
	var err error
	request.StartTime, err = parseClock(input.Start)
	if err != nil {
		return nil, err
	}
	request.EndTime, err = parseClock(input.End)
	if err != nil {
		return nil, err
	}
	if err := applyLogFocus(&request, input.Focus); err != nil {
		return nil, err
	}
	if request.Limit <= 0 {
		request.Limit = fortinet.MaxLogSearchLimit()
	}
	search, err := s.SearchLogs(ctx, input.Profile, request)
	if err != nil && !logResultUsable(search) {
		return nil, err
	}
	taskID := strings.TrimSpace(fmt.Sprint(search.TaskID))
	if taskID == "" || taskID == "<nil>" {
		return map[string]any{"search": searchWithoutRows(search), "note": "FortiAnalyzer returned no task id, so the count URL was not read."}, nil
	}
	countResource := "/logview/adom/" + url.PathEscape(search.ADOM) + "/logsearch/count/" + url.PathEscape(taskID)
	count, countErr := s.FortiAnalyzerRead(ctx, input.Profile, countResource, nil)
	result := map[string]any{
		"profile": search.Profile, "adom": search.ADOM, "device": search.Device,
		"log_type": search.LogType, "filter": search.Filter, "task_id": search.TaskID,
		"complete": search.Complete, "timed_out": search.TimedOut, "progress": search.Progress,
		"match_budget": search.Limit, "page_count": search.Count, "total_count": search.TotalCount,
		"hint": search.Hint, "warnings": search.Warnings, "log_receipt": search.LogReceipt,
		"note": "match_budget is the limit sent on submit. FortiAnalyzer stops collecting once it has that many matches, so a count can be lower than the number of matching logs. total_count can count scanned lines. Rows are omitted; call search_fortianalyzer_logs with the same task_id only when the budget is larger than the page you want, otherwise submit a new search.",
	}
	if countErr != nil {
		result["count_error"] = countErr.Error()
	} else {
		result["count"] = count
	}
	if err != nil {
		result["search_error"] = err.Error()
	}
	return result, nil
}

// MapAnalyzerDevice matches an inventoried FortiGate to the FortiAnalyzer
// device name used in log filters.
func (s *Service) MapAnalyzerDevice(ctx context.Context, input AnalyzerDeviceQuery) (any, error) {
	adom, err := s.scopeADOM(input.Profile, input.ADOM, input.Device)
	if err != nil {
		return nil, err
	}
	manager, err := s.managerForScope(input.Profile, adom, input.Device)
	if err != nil {
		return nil, err
	}
	var device fortinet.Device
	if s.store != nil {
		matches := s.store.FindDevices(manager.Name(), adom, input.Device)
		if len(matches) == 1 {
			device = matches[0]
		}
	}
	fazADOM, adomSource, err := s.resolveAnalyzerADOM(input.AnalyzerProfile, input.AnalyzerADOM)
	if err != nil {
		return nil, err
	}
	resource := "/dvmdb/adom/" + url.PathEscape(fazADOM) + "/device"
	listed, err := s.FortiAnalyzerRead(ctx, input.AnalyzerProfile, resource, nil)
	if err != nil {
		return nil, err
	}
	want := []string{device.Serial, device.Hostname, device.Name, input.Device}
	var matches []map[string]any
	for _, record := range recordsOf(listed) {
		matchedOn := ""
		for _, candidate := range want {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				continue
			}
			if fieldEqualsFold(record, candidate, "sn", "serial", "hostname", "name", "devname", "ip") {
				matchedOn = candidate
				break
			}
		}
		if matchedOn != "" {
			row := map[string]any{"matched_on": matchedOn, "device": record}
			matches = append(matches, row)
		}
	}
	return map[string]any{
		"fortimanager_device": input.Device, "serial": device.Serial, "hostname": device.Hostname,
		"analyzer_adom": fazADOM, "analyzer_adom_source": adomSource, "matches": matches,
		"note": "Use the FortiAnalyzer name or serial as search_fortianalyzer_logs device. The FortiManager name often does not match devname.",
	}, nil
}

// GetNATMapping reads central SNAT, IP pools and VIPs from the ADOM and
// returns the rows that mention the flow. Matching is by address text in
// the object, not a FortiGate NAT trace.
func (s *Service) GetNATMapping(ctx context.Context, input NATQuery) (any, error) {
	adom, err := s.scopeADOM(input.Profile, input.ADOM, input.Device)
	if err != nil {
		return nil, err
	}
	manager, err := s.managerForScope(input.Profile, adom, input.Device)
	if err != nil {
		return nil, err
	}
	var errors []any
	load := func(objectType string) []map[string]any {
		value, readErr := s.ListObjects(ctx, ObjectListInput{
			Profile: manager.Name(), ADOM: adom, ObjectType: objectType, Limit: 200,
		})
		if readErr != nil {
			errors = append(errors, map[string]any{"object_type": objectType, "error": readErr.Error()})
			return nil
		}
		return recordsOf(value)
	}
	needles := []string{input.SourceIP, input.DestinationIP}
	if input.Port > 0 {
		needles = append(needles, strconv.Itoa(input.Port))
	}
	return map[string]any{
		"profile": manager.Name(), "adom": adom, "device": input.Device,
		"central_snat": filterRecords(load("firewall/central-snat-map"), needles),
		"ippool":       filterRecords(load("firewall/ippool"), needles),
		"vip":          filterRecords(load("firewall/vip"), needles),
		"errors":       errors,
		"note":         "Each table is the first 200 ADOM objects. A row is kept when it contains the source, destination or port text. This is not the address the FortiGate wrote on the wire; confirm with a session or a traffic log.",
	}, nil
}

// GetRoutingNeighbors reads BGP peers, OSPF neighbors and SD-WAN SLA history.
func (s *Service) GetRoutingNeighbors(ctx context.Context, input DeviceScope) (any, error) {
	bgp, bgpErr := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, "bgp-neighbors")
	ospf, ospfErr := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, "ospf-neighbors")
	sla, slaErr := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, "sdwan-sla")
	var errors []any
	if bgpErr != nil {
		errors = append(errors, map[string]any{"source": "bgp", "error": bgpErr.Error()})
	}
	if ospfErr != nil {
		errors = append(errors, map[string]any{"source": "ospf", "error": ospfErr.Error()})
	}
	if slaErr != nil {
		errors = append(errors, map[string]any{"source": "sdwan_sla", "error": slaErr.Error()})
	}
	return map[string]any{
		"adom": bgp.ADOM, "device": input.Device, "vdom": input.VDOM,
		"bgp_neighbors":  summarizeNeighbors(bgp.Data, "neighbor_ip", "router_id", "state", "admin_status"),
		"ospf_neighbors": summarizeNeighbors(ospf.Data, "router_id", "neighbor_ip", "state", "priority"),
		"sdwan_sla":      summarizeSLA(sla.Data),
		"errors":         errors,
		"note":           "BGP, OSPF and SLA samples are live FortiGate monitor reads, reused for 30 seconds. Configured routes stay on resolve_route.",
	}, nil
}

// GetPackageHistory returns the package oid from inventory, the install
// state, and the device config status. A revision list is included when
// FortiManager answers the device revision get.
func (s *Service) GetPackageHistory(ctx context.Context, input PackageHistoryQuery) (any, error) {
	adom, err := s.scopeADOM(input.Profile, input.ADOM, input.Device)
	if err != nil {
		return nil, err
	}
	manager, err := s.managerForScope(input.Profile, adom, input.Device)
	if err != nil {
		return nil, err
	}
	var packages []map[string]any
	if listed, ok := s.snapshotPackages(manager.Name(), adom); ok {
		for _, pkg := range listed {
			if input.Package != "" && pkg.Name != input.Package {
				continue
			}
			if input.Device != "" && !packageTargetsDevice(pkg, fortinet.Device{Name: input.Device}) && len(pkg.Members) > 0 {
				continue
			}
			packages = append(packages, map[string]any{"name": pkg.Name, "oid": pkg.OID, "type": pkg.Type})
		}
	}
	install, installErr := s.GetPackageInstallStatus(ctx, input.DeviceScope)
	deviceRecord, deviceErr := manager.Read(ctx, "/dvmdb/adom/"+escapeSegment(adom)+"/device/"+escapeSegment(input.Device), map[string]any{
		"fields": []string{"name", "sn", "conf_status", "db_status", "conn_status", "platform_str"},
	})
	revisions, revisionErr := manager.Read(ctx, "/dvmdb/adom/"+escapeSegment(adom)+"/device/"+escapeSegment(input.Device)+"/revision", nil)
	var errors []any
	if installErr != nil {
		errors = append(errors, map[string]any{"source": "install_status", "error": installErr.Error()})
	}
	if deviceErr != nil {
		errors = append(errors, map[string]any{"source": "device", "error": deviceErr.Error()})
	}
	if revisionErr != nil {
		errors = append(errors, map[string]any{"source": "revision", "error": revisionErr.Error()})
	}
	return map[string]any{
		"profile": manager.Name(), "adom": adom, "device": input.Device,
		"packages": packages, "install_status": install, "device_record": shortMap(deviceRecord),
		"revisions": revisions, "errors": errors,
		"note": "oid changes when FortiManager changes the package. revisions is present only when this FortiManager release answers the device revision get. Install history timestamps that require an exec call are not requested.",
	}, nil
}

// GetPolicyUsage returns live hit counts and the policy rows that reference
// an object name. where-used walks the ADOM policy tables this server has
// already learned how to read. It does not call FortiManager's where-used exec.
func (s *Service) GetPolicyUsage(ctx context.Context, input PolicyUsageQuery) (any, error) {
	var errors []any
	var hits []map[string]any
	proxy, err := s.GetFortiManagerSettings(ctx, input.Profile, input.ADOM, input.Device, input.VDOM, "/api/v2/monitor/firewall/policy")
	if err != nil {
		errors = append(errors, map[string]any{"source": "hit_count", "error": err.Error()})
	} else {
		for _, record := range recordsOf(proxy.Data) {
			if input.PolicyID > 0 && !fieldEquals(record, strconv.Itoa(input.PolicyID), "policyid", "policy_id") {
				continue
			}
			hits = append(hits, map[string]any{
				"policy_id": firstField(record, "policyid", "policy_id"),
				"name":      firstField(record, "name"),
				"hit_count": firstField(record, "hit_count", "hitcount", "packets"),
				"bytes":     firstField(record, "bytes"),
				"last_used": firstField(record, "last_used", "last_session"),
			})
		}
	}
	var used []map[string]any
	whereUsedComplete := false
	if input.Name != "" {
		var readErrors []any
		used, readErrors, err = s.whereUsed(ctx, input)
		errors = append(errors, readErrors...)
		whereUsedComplete = err == nil && len(readErrors) == 0
		if err != nil {
			errors = append(errors, map[string]any{"source": "where_used", "error": err.Error()})
		}
	}
	return map[string]any{
		"device": input.Device, "vdom": input.VDOM, "policy_id": input.PolicyID,
		"hit_counts": hits, "where_used": used, "where_used_complete": whereUsedComplete, "errors": errors,
		"note": "Hit counts are the live FortiGate monitor and are not cached. where_used lists firewall, IPv6, security and proxy policies in the ADOM packages that name the object. where_used_complete is false when no name was requested or a read failed; errors identify failed tables and successful references remain available. It is not FortiManager's cross-object where-used index.",
	}, nil
}

func (s *Service) whereUsed(ctx context.Context, input PolicyUsageQuery) ([]map[string]any, []any, error) {
	adom, err := s.scopeADOM(input.Profile, input.ADOM, input.Device)
	if err != nil {
		return nil, nil, err
	}
	manager, err := s.managerForScope(input.Profile, adom, input.Device)
	if err != nil {
		return nil, nil, err
	}
	listed, known := s.snapshotPackages(manager.Name(), adom)
	listed, err = s.policyPackageList(ctx, manager, adom, listed, known)
	if err != nil {
		return nil, nil, fmt.Errorf("list packages for %s/%s: %w", manager.Name(), adom, err)
	}
	var packages []string
	for _, pkg := range listed {
		packages = append(packages, pkg.Name)
	}
	packages = uniqueStrings(packages)
	snapshotAt := s.snapshotGeneratedAt()
	var used []map[string]any
	var readErrors []any
	for _, pkg := range packages {
		tables, errs := s.packagePolicies(ctx, manager, adom, pkg, policyTableNames, snapshotAt)
		for _, table := range policyTableNames {
			if readErr := errs[table]; readErr != nil {
				readErrors = append(readErrors, map[string]any{
					"source": "where_used", "profile": manager.Name(), "adom": adom,
					"package": pkg, "table": table, "error": readErr.Error(),
				})
			}
		}
		for table, policies := range tables {
			if errs[table] != nil {
				continue
			}
			for _, policy := range policies {
				fields := referencesObject(policy, input.Name)
				if len(fields) == 0 {
					continue
				}
				used = append(used, map[string]any{
					"package": pkg, "table": table, "policy_id": policy.PolicyID, "name": policy.Name, "fields": fields,
				})
			}
		}
	}
	return used, readErrors, nil
}

// GetSSLSSHProfile reads one ssl-ssh profile from the ADOM and returns the
// inspection mode and the protocol sections that decide certificate versus
// deep inspection.
func (s *Service) GetSSLSSHProfile(ctx context.Context, input SSLProfileQuery) (any, error) {
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	adom, err := s.scopeADOM(input.Profile, input.ADOM, input.Device)
	if err != nil {
		return nil, err
	}
	manager, err := s.managerForScope(input.Profile, adom, input.Device)
	if err != nil {
		return nil, err
	}
	value, err := s.ListObjects(ctx, ObjectListInput{
		Profile: manager.Name(), ADOM: adom, Device: input.Device, ObjectType: "firewall/ssl-ssh-profile", Name: name,
	})
	if err != nil {
		return nil, err
	}
	record := firstRecord(value)
	if record == nil {
		record = map[string]any{}
	}
	return map[string]any{
		"profile": manager.Name(), "adom": adom, "name": name,
		"inspection_mode": firstField(record, "inspection-mode", "inspection_mode", "ssl-inspection-mode"),
		"https":           firstField(record, "https", "https-status"),
		"ssh":             firstField(record, "ssh", "ssh-status"),
		"smtps":           firstField(record, "smtps"),
		"untrusted_cert":  firstField(record, "untrusted-cert", "untrusted_cert", "ssl-anomalies-log"),
		"profile_object":  record,
		"note":            "This is the ADOM ssl-ssh profile object. The policy field inspection-mode is the policy's own mode; the profile decides certificate inspection versus deep inspection for each protocol.",
	}, nil
}

// GetLogReceipt reads FortiAnalyzer logstats and optionally keeps one device.
func (s *Service) GetLogReceipt(ctx context.Context, input LogReceiptQuery) (any, error) {
	adom, _, err := s.resolveAnalyzerADOM(input.Profile, input.ADOM)
	if err != nil {
		return nil, err
	}
	stats, err := s.FortiAnalyzerRead(ctx, input.Profile, "/logview/adom/"+url.PathEscape(adom)+"/logstats", nil)
	if err != nil {
		return nil, err
	}
	rows := recordsOf(stats)
	if input.Device != "" {
		var kept []map[string]any
		for _, record := range rows {
			if fieldEqualsFold(record, input.Device, "devname", "name", "device", "sn", "serial", "devid") {
				kept = append(kept, record)
			}
		}
		rows = kept
	}
	return map[string]any{
		"adom": adom, "device": input.Device, "devices": rows,
		"note": "A device with no row, or an old last-received time, means a zero log search may be a logging gap. devname here is the FortiAnalyzer name.",
	}, nil
}

func (s *Service) snapshotGeneratedAt() time.Time {
	if s == nil || s.store == nil {
		return time.Time{}
	}
	return s.store.Snapshot().GeneratedAt
}

// resolveAnalyzerADOM uses the requested FortiAnalyzer ADOM, the single
// ADOM configured on the profile, or root when the profile allows every ADOM.
func (s *Service) resolveAnalyzerADOM(profile, requested string) (adom, source string, err error) {
	requested = strings.TrimSpace(requested)
	if requested != "" {
		return requested, "request", nil
	}
	analyzer, err := s.analyzer(profile)
	if err != nil {
		return "", "", err
	}
	configured, configErr := s.cfg.Profile(analyzer.Name(), config.ProductFortiAnalyzer)
	if configErr != nil || len(configured.ADOMs) == 0 {
		return "root", "default_root", nil
	}
	if len(configured.ADOMs) == 1 {
		return configured.ADOMs[0], "configured", nil
	}
	return "", "", fmt.Errorf("analyzer_adom is required; FortiAnalyzer profile %q has several ADOMs (%s)", analyzer.Name(), strings.Join(configured.ADOMs, ", "))
}

func parseClock(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time %s; use RFC3339 with an explicit timezone, for example 2026-09-22T14:05:00+02:00", value)
	}
	return parsed, nil
}

func applyLogFocus(request *fortinet.LogSearchRequest, focus string) error {
	switch strings.ToLower(strings.TrimSpace(focus)) {
	case "", "all":
		return nil
	case "deny":
		if request.LogType == "" {
			request.LogType = "traffic"
		}
		request.Filter = andFilter(request.Filter, `action="deny"`)
	case "webfilter", "web-filter", "web_filter":
		if request.LogType == "" {
			request.LogType = "webfilter"
		}
	case "ips", "attack":
		if request.LogType == "" {
			request.LogType = "attack"
		}
	default:
		return fmt.Errorf("focus %q is not supported; use all, deny, webfilter, or ips", focus)
	}
	return nil
}

func andFilter(existing, extra string) string {
	existing = strings.TrimSpace(existing)
	if existing == "" {
		return extra
	}
	return existing + " AND " + extra
}

func searchWithoutRows(result fortinet.LogSearchResult) fortinet.LogSearchResult {
	result.Records = nil
	return result
}

func recordsOf(value any) []map[string]any {
	switch typed := value.(type) {
	case nil:
		return nil
	case []map[string]any:
		return append([]map[string]any(nil), typed...)
	case []any:
		rows := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if row, ok := item.(map[string]any); ok {
				rows = append(rows, row)
			}
		}
		return rows
	case map[string]any:
		for _, key := range []string{"objects", "results", "records", "sessions", "data"} {
			nested, ok := typed[key]
			if !ok || nested == nil {
				continue
			}
			switch nested.(type) {
			case []any, []map[string]any:
				return recordsOf(nested)
			case map[string]any:
				if rows := recordsOf(nested); len(rows) > 0 {
					return rows
				}
			}
		}
		if len(typed) > 0 {
			rows := make([]map[string]any, 0, len(typed))
			allMaps := true
			for name, item := range typed {
				row, ok := item.(map[string]any)
				if !ok {
					allMaps = false
					break
				}
				if _, exists := row["name"]; !exists {
					copied := make(map[string]any, len(row)+1)
					maps.Copy(copied, row)
					copied["name"] = name
					row = copied
				}
				rows = append(rows, row)
			}
			if allMaps {
				sort.Slice(rows, func(i, j int) bool { return fmt.Sprint(rows[i]["name"]) < fmt.Sprint(rows[j]["name"]) })
				return rows
			}
		}
		return []map[string]any{typed}
	default:
		return nil
	}
}

func fieldValue(record map[string]any, keys ...string) (any, bool) {
	if record == nil {
		return nil, false
	}
	for _, key := range keys {
		if value, ok := record[key]; ok && value != nil {
			return value, true
		}
		for have, value := range record {
			if strings.EqualFold(have, key) && value != nil {
				return value, true
			}
		}
	}
	return nil, false
}

func firstField(record map[string]any, keys ...string) any {
	value, ok := fieldValue(record, keys...)
	if !ok {
		return nil
	}
	return value
}

func firstRecord(value any) map[string]any {
	rows := recordsOf(value)
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}

func fieldEquals(record map[string]any, want string, keys ...string) bool {
	want = strings.TrimSpace(want)
	value, ok := fieldValue(record, keys...)
	return ok && strings.TrimSpace(fmt.Sprint(value)) == want
}

func fieldEqualsFold(record map[string]any, want string, keys ...string) bool {
	want = strings.TrimSpace(want)
	value, ok := fieldValue(record, keys...)
	return ok && strings.EqualFold(strings.TrimSpace(fmt.Sprint(value)), want)
}

func protocolFilter(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "any":
		return ""
	case "tcp":
		return "6"
	case "udp":
		return "17"
	case "icmp":
		return "1"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

func protocolMatches(record map[string]any, protocol string) bool {
	want := protocolFilter(protocol)
	if want == "" {
		return true
	}
	got := strings.ToLower(strings.TrimSpace(fmt.Sprint(firstField(record, "proto", "protocol"))))
	if got == want {
		return true
	}
	switch want {
	case "6":
		return got == "tcp"
	case "17":
		return got == "udp"
	case "1":
		return got == "icmp"
	default:
		return false
	}
}

func shortSession(record map[string]any) map[string]any {
	return map[string]any{
		"src":       firstField(record, "src", "saddr", "srcip", "src_ip", "source"),
		"dst":       firstField(record, "dst", "daddr", "dstip", "dst_ip", "destination"),
		"sport":     firstField(record, "sport", "srcport", "src_port"),
		"dport":     firstField(record, "dport", "dstport", "dst_port"),
		"proto":     firstField(record, "proto", "protocol"),
		"policy_id": firstField(record, "policyid", "policy_id", "policy"),
		"snat":      firstField(record, "snat", "snat_ip", "snatip", "snaddr", "srcnat", "naddr"),
		"duration":  firstField(record, "duration", "expiry"),
		"bytes":     firstField(record, "bytes", "sentbyte", "rcvdbyte"),
	}
}

func summarizeIPsec(value any) []map[string]any {
	var rows []map[string]any
	for _, record := range recordsOf(value) {
		rows = append(rows, map[string]any{
			"name":           firstField(record, "name", "p1name", "parent"),
			"remote_gateway": firstField(record, "rgwy", "remote_gateway", "remote-gateway", "gateway"),
			"status":         firstField(record, "status", "state", "connection_status"),
			"incoming_bytes": firstField(record, "incoming_bytes", "in_bytes", "incoming"),
			"outgoing_bytes": firstField(record, "outgoing_bytes", "out_bytes", "outgoing"),
		})
	}
	return rows
}

func summarizeSSLVPN(value any) []map[string]any {
	var rows []map[string]any
	for _, record := range recordsOf(value) {
		rows = append(rows, map[string]any{
			"user":        firstField(record, "user", "user_name", "username"),
			"remote_host": firstField(record, "remote_host", "remote", "src"),
			"duration":    firstField(record, "duration", "last_login"),
		})
	}
	return rows
}

func summarizeHAPeers(value any) []map[string]any {
	var rows []map[string]any
	for _, record := range recordsOf(value) {
		rows = append(rows, map[string]any{
			"serial":   firstField(record, "serial_no", "serial", "sn"),
			"hostname": firstField(record, "hostname", "name"),
			"role":     firstField(record, "role", "mode", "priority"),
		})
	}
	return rows
}

func checksumValues(value any) []string {
	var sums []string
	add := func(item any) {
		text := strings.TrimSpace(fmt.Sprint(item))
		if text != "" && text != "<nil>" {
			sums = append(sums, text)
		}
	}
	for _, record := range recordsOf(value) {
		if got, ok := fieldValue(record, "checksum", "global_checksum", "all"); ok {
			add(got)
		}
	}
	if len(sums) == 0 {
		if row, ok := value.(map[string]any); ok {
			for _, item := range row {
				if text, ok := item.(string); ok {
					add(text)
				}
			}
		}
	}
	sort.Strings(sums)
	return sums
}

func summarizeNeighbors(value any, fields ...string) []map[string]any {
	var rows []map[string]any
	for _, record := range recordsOf(value) {
		row := map[string]any{}
		for _, field := range fields {
			if got, ok := fieldValue(record, field, strings.ReplaceAll(field, "_", "-")); ok {
				row[field] = got
			}
		}
		if _, ok := row["neighbor_ip"]; !ok {
			if got, ok := fieldValue(record, "neighbor_ip", "neighbor-ip", "ip", "remote_ip"); ok {
				row["neighbor_ip"] = got
			}
		}
		if _, ok := row["state"]; !ok {
			if got, ok := fieldValue(record, "state", "status"); ok {
				row["state"] = got
			}
		}
		if len(row) > 0 {
			rows = append(rows, row)
		}
	}
	return rows
}

func summarizeSLA(value any) []map[string]any {
	var rows []map[string]any
	for _, record := range recordsOf(value) {
		rows = append(rows, map[string]any{
			"interface":   firstField(record, "interface", "name", "link"),
			"latency":     firstField(record, "latency", "latency_avg"),
			"jitter":      firstField(record, "jitter", "jitter_avg"),
			"packet_loss": firstField(record, "packetloss", "packet_loss", "loss"),
			"state":       firstField(record, "state", "status", "sla_targets_met"),
		})
	}
	return rows
}

func filterRecords(rows []map[string]any, needles []string) []map[string]any {
	var wanted []string
	for _, needle := range needles {
		needle = strings.TrimSpace(needle)
		if needle != "" {
			wanted = append(wanted, needle)
		}
	}
	if len(wanted) == 0 {
		return rows
	}
	var kept []map[string]any
	for _, row := range rows {
		for _, needle := range wanted {
			if recordMentions(row, needle) {
				kept = append(kept, row)
				break
			}
		}
	}
	return kept
}

func recordMentions(record map[string]any, needle string) bool {
	return valueMentions(record, strings.TrimSpace(needle))
}

func valueMentions(value any, needle string) bool {
	if needle == "" {
		return false
	}
	switch typed := value.(type) {
	case string:
		return addressToken(typed, needle)
	case map[string]any:
		for _, item := range typed {
			if valueMentions(item, needle) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if valueMentions(item, needle) {
				return true
			}
		}
	case []string:
		for _, item := range typed {
			if addressToken(item, needle) {
				return true
			}
		}
	default:
		return fmt.Sprint(typed) == needle
	}
	return false
}

func addressToken(text, needle string) bool {
	if text == needle {
		return true
	}
	start := 0
	for {
		index := strings.Index(text[start:], needle)
		if index < 0 {
			return false
		}
		index += start
		end := index + len(needle)
		beforeOK := index == 0 || !isAddrChar(text[index-1])
		afterOK := end == len(text) || !isAddrChar(text[end])
		if beforeOK && afterOK {
			return true
		}
		start = index + 1
		if start >= len(text) {
			return false
		}
	}
}

func isAddrChar(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F') || value == '.' || value == ':'
}

func shortMap(value any) map[string]any {
	if row, ok := value.(map[string]any); ok {
		if _, wrapped := row["objects"]; !wrapped {
			if _, wrapped = row["results"]; !wrapped {
				return row
			}
		}
	}
	rows := recordsOf(value)
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}

func referencesObject(policy fortinet.FirewallPolicy, name string) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	var fields []string
	check := func(field string, values []string) {
		if slices.Contains(values, name) {
			fields = append(fields, field)
			return
		}
	}
	check("source_addresses", policy.SourceAddresses)
	check("destination_addresses", policy.DestinationAddresses)
	check("source_addresses6", policy.SourceAddresses6)
	check("destination_addresses6", policy.DestinationAddresses6)
	check("services", policy.Services)
	if policy.SSLSSHProfile == name {
		fields = append(fields, "ssl_ssh_profile")
	}
	return fields
}

package fortinet

import (
	"encoding/json"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
)

func dataFromResult(result any) any {
	switch typed := result.(type) {
	case map[string]any:
		if data := field(typed, "data", "payload", "records", "results", "items"); data != nil {
			return dataFromResult(data)
		}
		return typed
	case []any:
		if len(typed) == 1 {
			if item, ok := typed[0].(map[string]any); ok {
				if data := field(item, "data", "payload", "records", "results", "items"); data != nil {
					return dataFromResult(data)
				}
			}
		}
		var merged []any
		foundData := false
		for _, item := range typed {
			if itemMap, ok := item.(map[string]any); ok {
				if data := field(itemMap, "data", "payload"); data != nil {
					foundData = true
					if records, ok := dataFromResult(data).([]any); ok {
						merged = append(merged, records...)
					} else {
						merged = append(merged, dataFromResult(data))
					}
					continue
				}
			}
			merged = append(merged, item)
		}
		if foundData {
			return merged
		}
		return typed
	default:
		return result
	}
}

func recordMaps(result any) []map[string]any {
	result = dataFromResult(result)
	switch typed := result.(type) {
	case []any:
		records := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if record, ok := item.(map[string]any); ok {
				records = append(records, record)
			}
		}
		return records
	case map[string]any:
		if data := field(typed, "data", "payload", "records", "results", "items"); data != nil {
			return recordMaps(data)
		}
		// Some DVMDB endpoints return a map keyed by object name.
		if _, hasName := typed["name"]; !hasName {
			var records []map[string]any
			allMaps := len(typed) > 0
			for key, value := range typed {
				record, ok := value.(map[string]any)
				if !ok {
					allMaps = false
					break
				}
				if _, ok := record["name"]; !ok {
					record["name"] = key
				}
				records = append(records, record)
			}
			if allMaps {
				return records
			}
		}
		return []map[string]any{typed}
	default:
		return nil
	}
}

func parseADOMs(result any) []ADOM {
	records := recordMaps(result)
	adoms := make([]ADOM, 0, len(records))
	for _, record := range records {
		name := stringValueValue(field(record, "name", "adom", "adom_name", "adom-name"))
		if name == "" {
			continue
		}
		adoms = append(adoms, ADOM{
			Name:    name,
			Version: stringValueValue(field(record, "version", "os_ver", "os-version")),
			Raw:     record,
		})
	}
	return adoms
}

func parseDevices(result any, adom, profile string) []Device {
	records := recordMaps(result)
	devices := make([]Device, 0, len(records))
	for _, record := range records {
		name := stringValueValue(field(record, "name", "device", "hostname", "device_name", "device-name"))
		if name == "" {
			continue
		}
		devices = append(devices, Device{
			Profile:          profile,
			ADOM:             adom,
			Name:             name,
			Hostname:         stringValueValue(field(record, "hostname", "host-name")),
			Serial:           stringValueValue(field(record, "serial", "serial-number", "sn")),
			ManagementIP:     stringValueValue(field(record, "ip", "ipaddr", "ip-address", "management_ip")),
			Version:          stringValueValue(field(record, "version", "os_ver", "os-version", "firmware")),
			OSType:           stringValueValue(field(record, "ostype", "os_type", "os-type", "product", "product_type", "product-type", "type")),
			Platform:         stringValueValue(field(record, "platform_str", "platform", "platform-string")),
			Status:           stringValueValue(field(record, "status")),
			ConnectionStatus: stringValueValue(field(record, "conn_status", "conn-status", "connection_status")),
			ConfigStatus:     stringValueValue(field(record, "conf_status", "conf-status", "config_status")),
			VDOMs:            stringSlice(field(record, "vdom", "vdoms", "vdom-list")),
			Raw:              record,
		})
	}
	return devices
}

func parseDeviceGroups(result any) []DeviceGroup {
	records := recordMaps(result)
	groups := make([]DeviceGroup, 0, len(records))
	for _, record := range records {
		name := stringValueValue(field(record, "name", "group", "group_name", "group-name"))
		if name == "" {
			continue
		}
		groups = append(groups, DeviceGroup{
			Name:    name,
			Members: parsePackageMembersResult(field(record, "object member", "object-member", "members", "member")),
			Raw:     record,
		})
	}
	return groups
}

func parsePackages(result any) []PolicyPackage {
	records := recordMaps(result)
	packages := make([]PolicyPackage, 0, len(records))
	var walk func(map[string]any, string)
	walk = func(record map[string]any, parent string) {
		// FortiManager returns folder children in subobj without repeating the
		// parent path. Normalize a shallow copy so the existing package-name
		// parser can preserve paths such as TG/fw_tg_new.
		normalized := make(map[string]any, len(record)+1)
		maps.Copy(normalized, record)
		if parent != "" &&
			!strings.Contains(stringValueValue(field(normalized, "name", "package_name", "package-name")), "/") &&
			stringValueValue(field(normalized, "folder", "folder_path", "folder-path", "parent", "parent_path", "parent-path")) == "" &&
			stringValueValue(field(normalized, "pkg_path", "pkg-path", "package_path", "package-path", "path")) == "" {
			normalized["folder"] = parent
		}

		name := parsePackageName(normalized)
		packageType := strings.ToLower(strings.TrimSpace(stringValueValue(field(normalized, "type", "package_type", "package-type"))))
		if name != "" && packageType != "folder" {
			packages = append(packages, PolicyPackage{
				Name:    name,
				Type:    packageType,
				OID:     int64(intValue(field(normalized, "oid", "obj id", "obj-id"))),
				Members: parsePackageMembersResult(field(normalized, "scope member", "scope-member", "members", "member", "targets")),
				Raw:     normalized,
			})
		}

		for _, child := range recordMaps(field(record, "subobj", "sub-obj", "subobjects", "children")) {
			walk(child, name)
		}
	}
	for _, record := range records {
		walk(record, "")
	}
	return packages
}

func parsePackageName(record map[string]any) string {
	value := field(record, "pkg_path", "pkg-path", "package_path", "package-path", "pkg", "package", "name", "package_name", "package-name", "path")
	name := strings.Trim(stringValueValue(value), "/")
	if name == "" {
		return ""
	}
	if strings.Contains(name, "/") {
		return name
	}
	folder := strings.Trim(stringValueValue(field(record, "folder", "folder_path", "folder-path", "parent", "parent_path", "parent-path")), "/")
	if folder == "" || folder == "." {
		return name
	}
	return folder + "/" + name
}

func parsePackageMembersResult(result any) []PackageMember {
	records := recordMaps(result)
	if len(records) > 0 {
		values := make([]any, 0, len(records))
		for _, record := range records {
			values = append(values, record)
		}
		return parsePackageMembers(values)
	}
	return parsePackageMembers(dataFromResult(result))
}

func parsePackageMembers(value any) []PackageMember {
	var members []PackageMember
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case []string:
			for _, item := range typed {
				walk(item)
			}
		case string:
			if device := strings.TrimSpace(typed); device != "" {
				members = append(members, PackageMember{Device: device})
			}
		case map[string]any:
			device := stringValueValue(field(typed, "device", "device_name", "device-name", "name", "member"))
			vdom := stringValueValue(field(typed, "vdom", "vd", "vdom_name", "vdom-name"))
			if device != "" && (field(typed, "device", "device_name", "device-name", "name", "member") != nil) {
				members = append(members, PackageMember{Device: device, VDOM: vdom})
				return
			}
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return uniquePackageMembers(members)
}

func parseInterfaces(result any) []Interface {
	records := recordMaps(result)
	interfaces := make([]Interface, 0, len(records))
	for _, record := range records {
		name := stringValueValue(field(record, "name", "interface", "mkey"))
		if name == "" {
			continue
		}
		ipParts := make([]string, 0)
		for _, value := range interfaceAddressValues(field(record, "ip", "address")) {
			ipParts = append(ipParts, strings.Fields(value)...)
		}
		ip, netmask := "", ""
		if len(ipParts) > 0 {
			ip = ipParts[0]
		}
		if len(ipParts) > 1 {
			netmask = ipParts[1]
		}
		interfaces = append(interfaces, Interface{
			Name:      name,
			Alias:     stringValueValue(field(record, "alias", "description")),
			Type:      stringValueValue(field(record, "type")),
			IP:        ip,
			Netmask:   netmask,
			Network:   interfaceNetwork(ip, netmask),
			Networks:  interfaceNetworks(ip, netmask, interfaceAddressValues(field(record, "secondaryip", "secondary-ip", "addresses")), ipv6AddressStrings(field(record, "ipv6", "ip6", "ip6-address", "ipv6-address"))),
			IPv6:      ipv6AddressStrings(field(record, "ipv6", "ip6", "ip6-address", "ipv6-address")),
			VDOM:      firstStringValue(field(record, "vdom", "vdom_name", "vdom-name")),
			Status:    stringValueValue(field(record, "status", "link", "link-status")),
			Role:      stringValueValue(field(record, "role")),
			Parent:    firstStringValue(field(record, "interface", "parent")),
			Zone:      stringValueValue(field(record, "zone", "zone_name", "zone-name", "sdwan-zone", "sdwan_zone")),
			Addresses: interfaceAddressValues(field(record, "secondaryip", "secondary-ip", "addresses")),
			Raw:       record,
		})
	}
	return interfaces
}

// firstStringValue returns the first element of a FortiManager list field
// or the scalar itself. An empty list is an unset reference, not "[]".
func firstStringValue(value any) string {
	switch value.(type) {
	case []any, []string:
		if values := stringSlice(value); len(values) > 0 {
			return values[0]
		}
		return ""
	}
	return stringValueValue(value)
}

func interfaceAddressValues(value any) []string {
	var values []string
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case string:
			if value := strings.TrimSpace(typed); value != "" {
				values = append(values, value)
			}
		case []string:
			for _, item := range typed {
				walk(item)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			address := stringValueValue(field(typed, "ip", "address", "ip-address", "ip6-address", "prefix"))
			if address != "" {
				mask := stringValueValue(field(typed, "netmask", "net-mask", "mask", "subnet-mask"))
				if mask != "" && !strings.Contains(address, "/") {
					address += " " + mask
				}
				walk(address)
				return
			}
			for _, key := range []string{"secondaryip", "secondary-ip", "addresses", "ip6-extra-addr", "ip6_extra_addr"} {
				if nested := field(typed, key); nested != nil {
					walk(nested)
				}
			}
		default:
			if value := strings.TrimSpace(stringValueValue(typed)); value != "" {
				values = append(values, value)
			}
		}
	}
	walk(value)
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func interfaceNetwork(address, netmask string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	// FortiOS emits 0.0.0.0/0 and ::/0 for unconfigured interfaces. They are
	// defaults, not connected networks; retaining them would make every policy
	// lookup candidate match every address.
	if addressIP := net.ParseIP(strings.SplitN(address, "/", 2)[0]); addressIP != nil && addressIP.IsUnspecified() {
		return ""
	}
	if _, network, err := net.ParseCIDR(address); err == nil {
		return network.String()
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return ""
	}
	mask := parseInterfaceMask(netmask, ip)
	if mask == nil {
		return ""
	}
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}

func parseInterfaceMask(value string, ip net.IP) net.IPMask {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if prefix, err := strconv.Atoi(value); err == nil {
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		if prefix >= 0 && prefix <= bits {
			return net.CIDRMask(prefix, bits)
		}
	}
	maskIP := net.ParseIP(value)
	if maskIP == nil {
		return nil
	}
	if ip.To4() != nil {
		maskIP = maskIP.To4()
	}
	if maskIP == nil {
		return nil
	}
	return net.IPMask(maskIP)
}

func interfaceNetworks(ip, netmask string, secondary, ipv6 []string) []string {
	var networks []string
	appendNetwork := func(value string, mask string) {
		if network := interfaceNetwork(value, mask); network != "" && !containsInterfaceNetwork(networks, network) {
			networks = append(networks, network)
		}
	}
	appendNetwork(ip, netmask)
	for _, address := range secondary {
		parts := strings.Fields(address)
		if len(parts) > 1 {
			appendNetwork(parts[0], parts[1])
		} else {
			appendNetwork(address, "")
		}
	}
	for _, address := range ipv6 {
		appendNetwork(address, "")
	}
	return networks
}

type interfaceZoneMembership struct {
	Interface string
	Zone      string
}

func parseInterfaceZones(result any) []interfaceZoneMembership {
	var memberships []interfaceZoneMembership
	for _, record := range recordMaps(result) {
		zone := stringValueValue(field(record, "name", "zone", "zone_name", "zone-name"))
		if zone == "" {
			continue
		}
		members := interfaceMemberNames(field(record, "interface", "interfaces", "member", "members", "interface-name", "interface_name"))
		for _, member := range members {
			member = strings.TrimSpace(member)
			if member != "" {
				memberships = append(memberships, interfaceZoneMembership{Interface: member, Zone: zone})
			}
		}
	}
	return memberships
}

func interfaceMemberNames(value any) []string {
	var names []string
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case string:
			names = append(names, strings.Fields(typed)...)
		case []string:
			for _, item := range typed {
				walk(item)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			if named := field(typed, "name", "mkey", "member", "value"); named != nil {
				walk(stringValueValue(named))
				return
			}
			for name := range typed {
				if strings.TrimSpace(name) != "" {
					names = append(names, name)
				}
			}
		}
	}
	walk(value)
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}

func applyInterfaceZones(interfaces []Interface, memberships []interfaceZoneMembership) {
	for _, membership := range memberships {
		for index := range interfaces {
			if interfaces[index].Name == membership.Interface {
				interfaces[index].Zone = membership.Zone
			}
		}
	}
}

func containsInterfaceNetwork(values []string, want string) bool {
	return slices.Contains(values, want)
}

func ipv6AddressStrings(value any) []string {
	var result []string
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case string:
			value := strings.TrimSpace(typed)
			if strings.Contains(value, ":") {
				result = append(result, value)
			}
		case []string:
			for _, item := range typed {
				walk(item)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			for _, key := range []string{"ip6-address", "ip6_address", "address", "prefix", "ip6-extra-addr", "ip6_extra_addr"} {
				if nested := field(typed, key); nested != nil {
					walk(nested)
				}
			}
		}
	}
	walk(value)
	seen := make(map[string]struct{}, len(result))
	unique := make([]string, 0, len(result))
	for _, item := range result {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		unique = append(unique, item)
	}
	return unique
}

// parseRoutes reads FortiOS router/static or router/static6 records from the
// FortiManager device database. Default routes keep their /0 prefix.
func parseRoutes(result any, family, vdom string) []Route {
	records := recordMaps(result)
	routes := make([]Route, 0, len(records))
	for _, record := range records {
		route := Route{
			Family:         family,
			VDOM:           vdom,
			SeqNum:         intValue(field(record, "seq-num", "seq_num", "seqnum", "id")),
			Destination:    routeDestination(strings.Join(stringSlice(field(record, "dst")), " "), family),
			DstAddrObject:  firstStringValue(field(record, "dstaddr")),
			Gateway:        stringValueValue(field(record, "gateway")),
			Interface:      firstStringValue(field(record, "device", "interface")),
			SDWANZone:      firstStringValue(field(record, "sdwan-zone", "sdwan_zone")),
			Distance:       intValue(field(record, "distance")),
			Priority:       intValue(field(record, "priority")),
			Weight:         intValue(field(record, "weight")),
			Status:         strings.ToLower(strings.TrimSpace(stringValueValue(field(record, "status")))),
			Blackhole:      boolValue(field(record, "blackhole")),
			DynamicGateway: boolValue(field(record, "dynamic-gateway", "dynamic_gateway")),
			Comment:        stringValueValue(field(record, "comment", "comments")),
			Raw:            record,
		}
		if gateway := net.ParseIP(route.Gateway); gateway != nil && gateway.IsUnspecified() {
			route.Gateway = ""
		}
		if route.SDWANZone == "" && boolValue(field(record, "sdwan", "virtual-wan-link")) {
			// FortiOS 6.4 marks SD-WAN routes with "set sdwan enable".
			route.SDWANZone = "virtual-wan-link"
		}
		if route.Destination == "" && route.DstAddrObject == "" && route.SeqNum == 0 {
			continue
		}
		routes = append(routes, route)
	}
	return routes
}

func parsePolicyRoutes(result any, family, vdom string) []PolicyRoute {
	records := recordMaps(result)
	routes := make([]PolicyRoute, 0, len(records))
	for _, record := range records {
		route := PolicyRoute{
			Family:          family,
			VDOM:            vdom,
			SeqNum:          intValue(field(record, "seq-num", "seq_num", "seqnum", "id")),
			InputDevices:    stringSlice(field(record, "input-device", "input_device")),
			InputNegate:     boolValue(field(record, "input-device-negate", "input_device_negate")),
			SrcAddr:         stringSlice(field(record, "srcaddr", "srcaddr6")),
			SrcNegate:       boolValue(field(record, "src-negate", "src_negate")),
			DstAddr:         stringSlice(field(record, "dstaddr", "dstaddr6")),
			DstNegate:       boolValue(field(record, "dst-negate", "dst_negate")),
			Protocol:        intValue(field(record, "protocol")),
			StartPort:       intValue(field(record, "start-port", "start_port")),
			EndPort:         intValue(field(record, "end-port", "end_port")),
			StartSourcePort: intValue(field(record, "start-source-port", "start_source_port")),
			EndSourcePort:   intValue(field(record, "end-source-port", "end_source_port")),
			Action:          strings.ToLower(strings.TrimSpace(stringValueValue(field(record, "action")))),
			Gateway:         stringValueValue(field(record, "gateway")),
			OutputDevice:    firstStringValue(field(record, "output-device", "output_device")),
			Status:          strings.ToLower(strings.TrimSpace(stringValueValue(field(record, "status")))),
			Comment:         stringValueValue(field(record, "comments", "comment")),
		}
		route.Src = routeSubnets(field(record, "src"), family)
		route.Dst = routeSubnets(field(record, "dst"), family)
		for _, key := range []string{"internet-service-id", "internet-service-custom", "internet-service-name"} {
			route.InternetServices = append(route.InternetServices, stringSlice(field(record, key))...)
		}
		if tos := strings.TrimSpace(stringValueValue(field(record, "tos-mask"))); tos != "" && tos != "0x00" && tos != "0" {
			route.TOSMatch = true
		}
		if gateway := net.ParseIP(route.Gateway); gateway != nil && gateway.IsUnspecified() {
			route.Gateway = ""
		}
		if route.Action == "" {
			route.Action = "permit"
		}
		routes = append(routes, route)
	}
	return routes
}

// routeSubnets normalizes FortiOS subnet lists that arrive as ["ip mask"],
// ["ip", "mask"] pairs, or CIDR strings. Match-all entries are dropped.
func routeSubnets(value any, family string) []string {
	raw := stringSlice(value)
	var tokens []string
	for index := 0; index < len(raw); index++ {
		item := strings.TrimSpace(raw[index])
		if item == "" {
			continue
		}
		if !strings.Contains(item, "/") && !strings.Contains(item, " ") && index+1 < len(raw) && strings.Contains(raw[index+1], ".") && net.ParseIP(raw[index+1]) != nil && net.ParseIP(item) != nil && net.ParseIP(item).To4() != nil {
			item = item + " " + raw[index+1]
			index++
		}
		tokens = append(tokens, item)
	}
	result := make([]string, 0, len(tokens))
	for _, token := range tokens {
		network := routeDestination(token, family)
		if network == "" || strings.HasSuffix(network, "/0") {
			continue
		}
		result = append(result, network)
	}
	return result
}

func parseSDWAN(result any, vdom string) (SDWANConfig, bool) {
	records := recordMaps(result)
	if len(records) == 0 {
		return SDWANConfig{}, false
	}
	record := records[0]
	config := SDWANConfig{
		VDOM:   vdom,
		Status: strings.ToLower(strings.TrimSpace(stringValueValue(field(record, "status")))),
	}
	for _, zone := range recordMaps(field(record, "zone")) {
		if name := stringValueValue(field(zone, "name")); name != "" {
			config.Zones = append(config.Zones, name)
		}
	}
	for _, member := range recordMaps(field(record, "members")) {
		entry := SDWANMember{
			SeqNum:    intValue(field(member, "seq-num", "seq_num")),
			Interface: firstStringValue(field(member, "interface")),
			Zone:      firstStringValue(field(member, "zone")),
			Gateway:   stringValueValue(field(member, "gateway")),
			Status:    strings.ToLower(strings.TrimSpace(stringValueValue(field(member, "status")))),
			Priority:  intValue(field(member, "priority")),
			Cost:      intValue(field(member, "cost")),
		}
		if gateway := net.ParseIP(entry.Gateway); gateway != nil && gateway.IsUnspecified() {
			entry.Gateway = ""
		}
		if entry.Zone == "" {
			entry.Zone = "virtual-wan-link"
		}
		if entry.Interface != "" {
			config.Members = append(config.Members, entry)
		}
	}
	for _, rule := range recordMaps(field(record, "service")) {
		entry := SDWANRule{
			ID:              intValue(field(rule, "id")),
			Name:            stringValueValue(field(rule, "name")),
			Mode:            strings.ToLower(strings.TrimSpace(stringValueValue(field(rule, "mode")))),
			Status:          strings.ToLower(strings.TrimSpace(stringValueValue(field(rule, "status")))),
			Dst:             stringSlice(field(rule, "dst")),
			DstNegate:       boolValue(field(rule, "dst-negate", "dst_negate")),
			Src:             stringSlice(field(rule, "src")),
			SrcNegate:       boolValue(field(rule, "src-negate", "src_negate")),
			InputDevices:    stringSlice(field(rule, "input-device", "input_device")),
			Protocol:        intValue(field(rule, "protocol")),
			StartPort:       intValue(field(rule, "start-port", "start_port")),
			EndPort:         intValue(field(rule, "end-port", "end_port")),
			InternetService: boolValue(field(rule, "internet-service", "internet_service")),
			PriorityZones:   stringSlice(field(rule, "priority-zone", "priority_zone")),
		}
		if len(stringSlice(field(rule, "users"))) > 0 || len(stringSlice(field(rule, "groups"))) > 0 {
			entry.Identity = true
		}
		for _, member := range stringSlice(field(rule, "priority-members", "priority_members")) {
			if seq := intValue(member); seq > 0 {
				entry.PriorityMembers = append(entry.PriorityMembers, seq)
			}
		}
		config.Rules = append(config.Rules, entry)
	}
	if config.Status == "" && len(config.Members) > 0 {
		config.Status = "enable"
	}
	return config, config.Status == "enable" && len(config.Members) > 0
}

func parsePackageStatus(result any, device, vdom string) (PackageStatus, bool) {
	for _, record := range recordMaps(result) {
		status := strings.ToLower(strings.TrimSpace(stringValueValue(field(record, "status", "pkg_status", "package_status"))))
		if status == "" {
			continue
		}
		entry := PackageStatus{
			Device:  firstNonEmptyString(stringValueValue(field(record, "dev", "device", "name")), device),
			VDOM:    firstNonEmptyString(stringValueValue(field(record, "vdom")), vdom),
			Package: stringValueValue(field(record, "pkg", "package", "pkgname")),
			Status:  status,
		}
		return entry, true
	}
	return PackageStatus{}, false
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func routeDestination(value, family string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if _, network, err := net.ParseCIDR(value); err == nil {
		return network.String()
	}
	parts := strings.Fields(value)
	if len(parts) == 2 {
		ip := net.ParseIP(parts[0])
		mask := parseInterfaceMask(parts[1], ip)
		if ip != nil && mask != nil {
			return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
		}
	}
	if ip := net.ParseIP(value); ip != nil {
		bits := 32
		if ip.To4() == nil || family == "ipv6" {
			bits = 128
		}
		return (&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}).String()
	}
	return ""
}

func parsePolicies(result any) []FirewallPolicy {
	records := recordMaps(result)
	policies := make([]FirewallPolicy, 0, len(records))
	for _, record := range records {
		id := intValue(field(record, "policyid", "policy_id", "id"))
		sequence := intValue(field(record, "obj seq", "obj_seq", "sequence", "seq"))
		if id == 0 && sequence == 0 && stringValueValue(field(record, "name")) == "" {
			continue
		}
		policies = append(policies, FirewallPolicy{
			PolicyID:                    id,
			Sequence:                    sequence,
			Name:                        stringValueValue(field(record, "name")),
			Status:                      stringValueValue(field(record, "status")),
			Action:                      stringValueValue(field(record, "action")),
			SourceInterfaces:            stringSlice(field(record, "srcintf", "src_intf", "source-interface")),
			DestinationInterfaces:       stringSlice(field(record, "dstintf", "dst_intf", "destination-interface")),
			SourceAddresses:             stringSlice(field(record, "srcaddr", "src_addr", "source-address")),
			DestinationAddresses:        stringSlice(field(record, "dstaddr", "dst_addr", "destination-address")),
			SourceAddresses6:            stringSlice(field(record, "srcaddr6")),
			DestinationAddresses6:       stringSlice(field(record, "dstaddr6")),
			SourceInternetService:       boolValue(field(record, "internet-service-src")),
			DestinationInternetService:  boolValue(field(record, "internet-service")),
			SourceInternetService6:      boolValue(field(record, "internet-service6-src")),
			DestinationInternetService6: boolValue(field(record, "internet-service6")),
			InternetServices: uniqueNonEmptyStrings(append(append(append(
				stringSlice(field(record, "internet-service-name", "internet-service-id")),
				stringSlice(field(record, "internet-service-src-name", "internet-service-src-id"))...),
				stringSlice(field(record, "internet-service6-name"))...),
				stringSlice(field(record, "internet-service6-src-name"))...)),
			Users:             stringSlice(field(record, "users")),
			Groups:            stringSlice(field(record, "groups")),
			Services:          stringSlice(field(record, "service", "services")),
			Schedule:          stringSlice(field(record, "schedule")),
			SourceNegate:      boolValue(field(record, "srcaddr-negate", "srcaddr_negate", "source-negate")),
			DestinationNegate: boolValue(field(record, "dstaddr-negate", "dstaddr_negate", "destination-negate")),
			ServiceNegate:     boolValue(field(record, "service-negate", "service_negate")),
			Device:            stringValueValue(field(record, "device", "device_name")),
			VDOM:              stringValueValue(field(record, "vdom")),
			UTMStatus:         stringValueValue(field(record, "utm-status", "utm_status")),
			ProfileType:       stringValueValue(field(record, "profile-type", "profile_type")),
			ProfileGroup:      firstStringValue(field(record, "profile-group", "profile_group")),
			WebFilterProfile:  firstStringValue(field(record, "webfilter-profile", "webfilter_profile")),
			InspectionMode:    stringValueValue(field(record, "inspection-mode", "inspection_mode")),
			SSLSSHProfile:     firstStringValue(field(record, "ssl-ssh-profile", "ssl_ssh_profile")),
			Scope:             parsePackageMembersResult(field(record, "_scope", "scope")),
			Raw:               record,
		})
	}
	return policies
}

func parseAddresses(result any) []AddressObject {
	records := recordMaps(result)
	objects := make([]AddressObject, 0, len(records))
	for _, record := range records {
		name := stringValueValue(field(record, "name", "mkey"))
		if name == "" {
			continue
		}
		subnetValue := field(record, "subnet", "ip6")
		subnetParts := stringSlice(subnetValue)
		subnet := ""
		if len(subnetParts) >= 2 {
			subnet = subnetParts[0] + " " + subnetParts[1]
		} else if len(subnetParts) == 1 {
			subnet = subnetParts[0]
		} else if ipv6 := ipv6AddressStrings(subnetValue); len(ipv6) > 0 {
			subnet = ipv6[0]
		}
		startIP := stringValueValue(field(record, "start-ip", "start_ip"))
		endIP := stringValueValue(field(record, "end-ip", "end_ip"))
		externalIP := stringValueValue(field(record, "extip", "ext-ip", "external-ip", "external_ip"))
		if startIP == "" && endIP == "" {
			startIP, endIP = splitAddressRange(externalIP)
		}
		if startIP != "" && endIP == "" {
			endIP = startIP
		}
		object := AddressObject{
			Name:         name,
			Subnet:       subnet,
			StartIP:      startIP,
			EndIP:        endIP,
			ExternalIP:   externalIP,
			MappedIP:     stringValueValue(field(record, "mappedip", "mapped-ip", "mapped_ip", "mappedip6", "mapped-ip6", "mapped_ip6")),
			ExternalPort: stringValueValue(field(record, "extport", "ext-port", "ext_port", "external-port", "external_port")),
			MappedPort:   stringValueValue(field(record, "mappedport", "mapped-port", "mapped_port")),
			FQDN:         stringValueValue(field(record, "fqdn")),
			Wildcard:     stringValueValue(field(record, "wildcard")),
			Interface:    stringValueValue(field(record, "associated-interface", "associated_interface", "interface")),
			Members:      stringSlice(field(record, "member", "members")),
			Type:         stringValueValue(field(record, "type")),
			Raw:          record,
		}
		if boolValue(field(record, "exclude")) {
			object.ExcludeMembers = stringSlice(field(record, "exclude-member", "exclude_member"))
		}
		if mappings, ok := field(record, "dynamic_mapping", "dynamic-mapping").([]any); ok {
			object.DynamicMappings = len(mappings)
		}
		objects = append(objects, object)
	}
	return objects
}

func splitAddressRange(value string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(value), "-", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	if len(parts) == 1 {
		value := strings.TrimSpace(parts[0])
		return value, value
	}
	return "", ""
}

func parseServices(result any) []ServiceObject {
	records := recordMaps(result)
	objects := make([]ServiceObject, 0, len(records))
	for _, record := range records {
		name := stringValueValue(field(record, "name", "mkey"))
		if name == "" {
			continue
		}
		objects = append(objects, ServiceObject{
			Name:          name,
			Protocol:      stringValueValue(field(record, "protocol", "protocol-number")),
			TCPPortRange:  joinStrings(stringSlice(field(record, "tcp-portrange", "tcp_portrange", "tcp-port-range"))),
			UDPPortRange:  joinStrings(stringSlice(field(record, "udp-portrange", "udp_portrange", "udp-port-range"))),
			SCTPPortRange: joinStrings(stringSlice(field(record, "sctp-portrange", "sctp_portrange", "sctp-port-range"))),
			PortRange:     joinStrings(stringSlice(field(record, "portrange", "port-range", "port"))),
			Members:       stringSlice(field(record, "member", "members")),
			Type:          stringValueValue(field(record, "type")),
			Raw:           record,
		})
	}
	return objects
}

func joinStrings(values []string) string {
	return strings.Join(values, " ")
}

func stringSlice(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if nested, ok := item.([]any); ok {
				result = append(result, stringSlice(nested)...)
				continue
			}
			if itemMap, ok := item.(map[string]any); ok {
				if named := field(itemMap, "name", "mkey", "member", "value"); named != nil {
					if value := strings.TrimSpace(stringValueValue(named)); value != "" {
						result = append(result, value)
					}
					continue
				}
			}
			if value := strings.TrimSpace(stringValueValue(item)); value != "" {
				result = append(result, value)
			}
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	case map[string]any:
		if named := field(typed, "name", "mkey", "member", "value"); named != nil {
			if value := strings.TrimSpace(stringValueValue(named)); value != "" {
				return []string{value}
			}
		}
		return nil
	case string:
		value := strings.TrimSpace(typed)
		if value == "" {
			return nil
		}
		// Fortinet returns some CLI lists as space-separated strings. Preserve
		// ranges such as 1024-65535 as one element.
		return strings.Fields(value)
	default:
		if marshaled, err := json.Marshal(typed); err == nil {
			var values []any
			if json.Unmarshal(marshaled, &values) == nil {
				return stringSlice(values)
			}
		}
		return []string{stringValueValue(typed)}
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		value, _ := typed.Int64()
		return int(value)
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return 0
		}
		negative := strings.HasPrefix(text, "-")
		text = strings.TrimPrefix(text, "-")
		parsed, _ := strconv.Atoi(text)
		if negative {
			return -parsed
		}
		return parsed
	default:
		return 0
	}
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case float64:
		return typed != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "yes", "enable", "enabled", "on":
			return true
		}
	}
	return false
}

func uniquePackageMembers(members []PackageMember) []PackageMember {
	seen := make(map[string]struct{}, len(members))
	result := make([]PackageMember, 0, len(members))
	for _, member := range members {
		key := member.Device + "\x00" + member.VDOM
		if member.Device == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, member)
	}
	return result
}

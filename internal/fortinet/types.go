package fortinet

import (
	"context"
	"time"
)

type ADOM struct {
	Name    string         `json:"name"`
	Version string         `json:"version,omitempty"`
	Raw     map[string]any `json:"raw,omitempty"`
}

type Device struct {
	Profile          string `json:"profile"`
	ADOM             string `json:"adom"`
	Name             string `json:"name"`
	Hostname         string `json:"hostname,omitempty"`
	Serial           string `json:"serial,omitempty"`
	ManagementIP     string `json:"management_ip,omitempty"`
	Version          string `json:"version,omitempty"`
	OSType           string `json:"os_type,omitempty"`
	Platform         string `json:"platform,omitempty"`
	Status           string `json:"status,omitempty"`
	ConnectionStatus string `json:"connection_status,omitempty"`
	ConfigStatus     string `json:"config_status,omitempty"`
	// DataAsOf is when interfaces and routing were last read from the
	// FortiManager device database; older values mean retained data.
	DataAsOf time.Time `json:"data_as_of"`
	// DataError names the device reads that failed in the latest refresh;
	// the affected data is retained from DataAsOf.
	DataError      string          `json:"data_error,omitempty"`
	VDOMs          []string        `json:"vdoms,omitempty"`
	Groups         []string        `json:"groups,omitempty"`
	Interfaces     []Interface     `json:"interfaces,omitempty"`
	Routes         []Route         `json:"routes,omitempty"`
	PolicyRoutes   []PolicyRoute   `json:"policy_routes,omitempty"`
	SDWAN          []SDWANConfig   `json:"sdwan,omitempty"`
	Packages       []string        `json:"packages,omitempty"`
	PackageTargets []PackageTarget `json:"package_targets,omitempty"`
	Raw            map[string]any  `json:"raw,omitempty"`
}

type DeviceGroup struct {
	Name    string          `json:"name"`
	Members []PackageMember `json:"members,omitempty"`
	Raw     map[string]any  `json:"raw,omitempty"`
}

type PolicyPackage struct {
	Name    string          `json:"name"`
	Type    string          `json:"type,omitempty"`
	// OID is FortiManager's package object id. It changes when the package
	// changes, so caches can keep a policy table until this value changes.
	OID     int64           `json:"oid,omitempty"`
	Members []PackageMember `json:"members,omitempty"`
	Raw     map[string]any  `json:"raw,omitempty"`
}

type PackageMember struct {
	Device string `json:"device"`
	VDOM   string `json:"vdom,omitempty"`
}

type PackageTarget struct {
	Package string `json:"package"`
	VDOM    string `json:"vdom,omitempty"`
}

type Interface struct {
	Name      string         `json:"name"`
	Alias     string         `json:"alias,omitempty"`
	Type      string         `json:"type,omitempty"`
	IP        string         `json:"ip,omitempty"`
	Netmask   string         `json:"netmask,omitempty"`
	Network   string         `json:"network,omitempty"`
	Networks  []string       `json:"networks,omitempty"`
	IPv6      []string       `json:"ipv6,omitempty"`
	VDOM      string         `json:"vdom,omitempty"`
	Status    string         `json:"status,omitempty"`
	Role      string         `json:"role,omitempty"`
	Parent    string         `json:"interface,omitempty"`
	Zone      string         `json:"zone,omitempty"`
	Addresses []string       `json:"addresses,omitempty"`
	Raw       map[string]any `json:"raw,omitempty"`
}

// Route is one configured static route from the FortiManager device
// database. It is configuration evidence: dynamic routes, policy routes and
// SD-WAN rule selection only exist on the live FortiGate.
type Route struct {
	Family         string         `json:"family"`
	VDOM           string         `json:"vdom"`
	SeqNum         int            `json:"seq_num,omitempty"`
	Destination    string         `json:"destination,omitempty"`
	DstAddrObject  string         `json:"dstaddr_object,omitempty"`
	Gateway        string         `json:"gateway,omitempty"`
	Interface      string         `json:"interface,omitempty"`
	SDWANZone      string         `json:"sdwan_zone,omitempty"`
	Distance       int            `json:"distance,omitempty"`
	Priority       int            `json:"priority,omitempty"`
	Weight         int            `json:"weight,omitempty"`
	Status         string         `json:"status,omitempty"`
	Blackhole      bool           `json:"blackhole,omitempty"`
	DynamicGateway bool           `json:"dynamic_gateway,omitempty"`
	Comment        string         `json:"comment,omitempty"`
	Raw            map[string]any `json:"raw,omitempty"`
}

// PolicyRoute is one FortiOS policy route (router/policy) from the
// FortiManager device database. Policy routes are evaluated before the
// routing table in sequence order.
type PolicyRoute struct {
	Family           string   `json:"family"`
	VDOM             string   `json:"vdom"`
	SeqNum           int      `json:"seq_num"`
	InputDevices     []string `json:"input_devices,omitempty"`
	InputNegate      bool     `json:"input_negate,omitempty"`
	Src              []string `json:"src,omitempty"`
	SrcAddr          []string `json:"srcaddr,omitempty"`
	SrcNegate        bool     `json:"src_negate,omitempty"`
	Dst              []string `json:"dst,omitempty"`
	DstAddr          []string `json:"dstaddr,omitempty"`
	DstNegate        bool     `json:"dst_negate,omitempty"`
	Protocol         int      `json:"protocol,omitempty"`
	StartPort        int      `json:"start_port,omitempty"`
	EndPort          int      `json:"end_port,omitempty"`
	StartSourcePort  int      `json:"start_source_port,omitempty"`
	EndSourcePort    int      `json:"end_source_port,omitempty"`
	Action           string   `json:"action,omitempty"`
	Gateway          string   `json:"gateway,omitempty"`
	OutputDevice     string   `json:"output_device,omitempty"`
	InternetServices []string `json:"internet_services,omitempty"`
	TOSMatch         bool     `json:"tos_match,omitempty"`
	Status           string   `json:"status,omitempty"`
	Comment          string   `json:"comment,omitempty"`
}

// SDWANConfig is the SD-WAN section of one device VDOM.
type SDWANConfig struct {
	VDOM    string        `json:"vdom"`
	Status  string        `json:"status,omitempty"`
	Zones   []string      `json:"zones,omitempty"`
	Members []SDWANMember `json:"members,omitempty"`
	Rules   []SDWANRule   `json:"rules,omitempty"`
}

type SDWANMember struct {
	SeqNum    int    `json:"seq_num"`
	Interface string `json:"interface"`
	Zone      string `json:"zone,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	Status    string `json:"status,omitempty"`
	Priority  int    `json:"priority,omitempty"`
	Cost      int    `json:"cost,omitempty"`
}

// SDWANRule is one SD-WAN service rule. Address fields hold object names.
type SDWANRule struct {
	ID              int      `json:"id"`
	Name            string   `json:"name,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	Status          string   `json:"status,omitempty"`
	Dst             []string `json:"dst,omitempty"`
	DstNegate       bool     `json:"dst_negate,omitempty"`
	Src             []string `json:"src,omitempty"`
	SrcNegate       bool     `json:"src_negate,omitempty"`
	InputDevices    []string `json:"input_devices,omitempty"`
	Protocol        int      `json:"protocol,omitempty"`
	StartPort       int      `json:"start_port,omitempty"`
	EndPort         int      `json:"end_port,omitempty"`
	InternetService bool     `json:"internet_service,omitempty"`
	Identity        bool     `json:"identity,omitempty"`
	PriorityMembers []int    `json:"priority_members,omitempty"`
	PriorityZones   []string `json:"priority_zones,omitempty"`
}

// PackageStatus is FortiManager's stored installation state of a policy
// package on one device VDOM.
type PackageStatus struct {
	Device  string `json:"device"`
	VDOM    string `json:"vdom"`
	Package string `json:"package,omitempty"`
	Status  string `json:"status"`
}

// PackageStatusReader is an optional Manager capability.
type PackageStatusReader interface {
	PackageStatusBatch(context.Context, string, []PackageMember) (map[string]PackageStatus, error)
}

// RouteTarget names one device VDOM whose static routes should be read.
// IPv6 requests the static6 table as well.
type RouteTarget struct {
	Device string
	VDOM   string
	IPv6   bool
}

// RouteBatchResult carries the routing tables of one device. Each *OK flag
// says whether that table was read in this refresh, so callers can keep
// last-known-good data for the tables that failed.
type RouteBatchResult struct {
	Routes       []Route
	PolicyRoutes []PolicyRoute
	SDWAN        []SDWANConfig
	StaticOK     bool
	PolicyOK     bool
	SDWANOK      bool
	Err          error
}

// RouteBatchReader is an optional Manager capability: read the configured
// static routes of several device VDOMs from the FortiManager database in
// bounded batches, without touching the live FortiGate.
type RouteBatchReader interface {
	ListRoutesBatch(context.Context, string, []RouteTarget) (map[string]RouteBatchResult, error)
}

// InterfaceBatchResult keeps the interface table result separate from the
// optional zone-table result. FortiManager can return usable interfaces even
// when the zone endpoint is unsupported or denied for a device.
type InterfaceBatchResult struct {
	Interfaces     []Interface
	InterfaceError error
	ZoneError      error
}

// InterfaceBatchReader is an optional capability implemented by the native
// FortiManager client. Inventory supplies several device names per bounded
// read cycle; the client uses one JSON-RPC batch when supported and verifies
// appliance-rejected multi-param batches with individual reads, while keeping
// Manager source-compatible with test doubles.
type InterfaceBatchReader interface {
	ListInterfacesBatch(context.Context, string, []string) (map[string]InterfaceBatchResult, error)
}

type FirewallPolicy struct {
	PolicyID              int      `json:"policy_id"`
	Sequence              int      `json:"sequence,omitempty"`
	Name                  string   `json:"name,omitempty"`
	Status                string   `json:"status,omitempty"`
	Action                string   `json:"action,omitempty"`
	SourceInterfaces      []string `json:"source_interfaces,omitempty"`
	DestinationInterfaces []string `json:"destination_interfaces,omitempty"`
	SourceAddresses       []string `json:"source_addresses,omitempty"`
	DestinationAddresses  []string `json:"destination_addresses,omitempty"`
	// SourceAddresses6 and DestinationAddresses6 are the IPv6 addresses of a
	// consolidated FortiOS 6.4+ policy, or of a legacy policy6 entry.
	SourceAddresses6      []string `json:"source_addresses6,omitempty"`
	DestinationAddresses6 []string `json:"destination_addresses6,omitempty"`
	// Internet service (ISDB) matching replaces the address list on that
	// side, per IP family.
	SourceInternetService       bool     `json:"source_internet_service,omitempty"`
	DestinationInternetService  bool     `json:"destination_internet_service,omitempty"`
	SourceInternetService6      bool     `json:"source_internet_service6,omitempty"`
	DestinationInternetService6 bool     `json:"destination_internet_service6,omitempty"`
	InternetServices            []string `json:"internet_services,omitempty"`
	Users                       []string `json:"users,omitempty"`
	Groups                      []string `json:"groups,omitempty"`
	Services                    []string `json:"services,omitempty"`
	Schedule                    []string `json:"schedule,omitempty"`
	SourceNegate                bool     `json:"source_negate,omitempty"`
	DestinationNegate           bool     `json:"destination_negate,omitempty"`
	ServiceNegate               bool     `json:"service_negate,omitempty"`
	Device                      string   `json:"device,omitempty"`
	VDOM                        string   `json:"vdom,omitempty"`
	UTMStatus                   string   `json:"utm_status,omitempty"`
	ProfileType                 string   `json:"profile_type,omitempty"`
	ProfileGroup                string   `json:"profile_group,omitempty"`
	WebFilterProfile            string   `json:"webfilter_profile,omitempty"`
	InspectionMode              string   `json:"inspection_mode,omitempty"`
	SSLSSHProfile               string   `json:"ssl_ssh_profile,omitempty"`
	// Scope lists per-policy installation targets when FortiManager restricts
	// the policy to selected devices; empty means the package scope applies.
	Scope []PackageMember `json:"scope,omitempty"`
	Raw   map[string]any  `json:"raw,omitempty"`
}

type AddressObject struct {
	Name         string   `json:"name"`
	Subnet       string   `json:"subnet,omitempty"`
	StartIP      string   `json:"start_ip,omitempty"`
	EndIP        string   `json:"end_ip,omitempty"`
	ExternalIP   string   `json:"external_ip,omitempty"`
	MappedIP     string   `json:"mapped_ip,omitempty"`
	ExternalPort string   `json:"external_port,omitempty"`
	MappedPort   string   `json:"mapped_port,omitempty"`
	FQDN         string   `json:"fqdn,omitempty"`
	Wildcard     string   `json:"wildcard,omitempty"`
	Interface    string   `json:"interface,omitempty"`
	Members      []string `json:"members,omitempty"`
	// ExcludeMembers lists the members an address group excludes (exclude
	// enable): an address that matches them does not match the group.
	ExcludeMembers []string `json:"exclude_members,omitempty"`
	// DynamicMappings counts per-device mappings, which give the object a
	// different value on the FortiGates they name.
	DynamicMappings int            `json:"dynamic_mappings,omitempty"`
	Type            string         `json:"type,omitempty"`
	Raw             map[string]any `json:"raw,omitempty"`
}

type ServiceObject struct {
	Name          string         `json:"name"`
	Protocol      string         `json:"protocol,omitempty"`
	TCPPortRange  string         `json:"tcp_port_range,omitempty"`
	UDPPortRange  string         `json:"udp_port_range,omitempty"`
	SCTPPortRange string         `json:"sctp_port_range,omitempty"`
	PortRange     string         `json:"port_range,omitempty"`
	Members       []string       `json:"members,omitempty"`
	Type          string         `json:"type,omitempty"`
	Raw           map[string]any `json:"raw,omitempty"`
}

type ProxyResult struct {
	ADOM     string `json:"adom"`
	Device   string `json:"device"`
	VDOM     string `json:"vdom,omitempty"`
	Resource string `json:"resource"`
	Data     any    `json:"data,omitempty"`
	// Raw is the full JSON-RPC envelope. Data already carries the proxied
	// FortiOS payload, so Raw is kept for callers but never serialized.
	Raw any `json:"-"`
}

type PolicyLookupRequest struct {
	SourceIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	Protocol        string
	SourceInterface string
}

type LogSearchRequest struct {
	ADOM      string
	LogType   string
	Filter    string
	StartTime time.Time
	EndTime   time.Time
	Device    string
	Limit     int
	Offset    int
	// TaskID resumes an existing Log View search instead of submitting a new
	// one. Use it after a timed-out search or to page through results.
	TaskID string
}

type LogSearchResult struct {
	Profile    string    `json:"profile"`
	ADOM       string    `json:"adom"`
	Device     string    `json:"device,omitempty"`
	LogType    string    `json:"log_type"`
	Filter     string    `json:"filter,omitempty"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Timezone   string    `json:"timezone,omitempty"`
	TaskID     any       `json:"task_id,omitempty"`
	Count      int       `json:"count,omitempty"`
	TotalCount int       `json:"total_count,omitempty"`
	Offset     int       `json:"offset,omitempty"`
	Limit      int       `json:"limit,omitempty"`
	Progress   int       `json:"progress,omitempty"`
	Complete   bool      `json:"complete"`
	TimedOut   bool      `json:"timed_out,omitempty"`
	Resumed    bool      `json:"resumed,omitempty"`
	// ApplianceTimezone is the configured zone used to express time_range_sent;
	// empty means the caller's zone was sent unchanged.
	ApplianceTimezone string            `json:"appliance_timezone,omitempty"`
	TimeRangeSent     map[string]string `json:"time_range_sent,omitempty"`
	Warnings          []string          `json:"warnings,omitempty"`
	Hint              string            `json:"hint,omitempty"`
	// LogReceipt is the FortiAnalyzer logstats read attached to a finished
	// search that returned no rows, so a zero count can be compared with
	// when the device last sent logs.
	LogReceipt any `json:"log_receipt,omitempty"`
	Records    any `json:"records,omitempty"`
}

type Manager interface {
	Name() string
	ListADOMs(context.Context) ([]ADOM, error)
	ListDevices(context.Context, string) ([]Device, error)
	ListDeviceGroups(context.Context, string) ([]DeviceGroup, error)
	ListPolicyPackages(context.Context, string) ([]PolicyPackage, error)
	ListPolicies(context.Context, string, string) ([]FirewallPolicy, error)
	ListIPv6Policies(context.Context, string, string) ([]FirewallPolicy, error)
	ListAddresses(context.Context, string) ([]AddressObject, error)
	ListServices(context.Context, string) ([]ServiceObject, error)
	ListInterfaces(context.Context, string, string) ([]Interface, error)
	ProxyGet(context.Context, string, string, string, string) (ProxyResult, error)
	PolicyLookup(context.Context, string, string, string, PolicyLookupRequest) (ProxyResult, error)
	Read(context.Context, string, map[string]any) (any, error)
	Close() error
}

// ADOMAllowlist is implemented by clients with profile-level ADOM scope.
// Kept separate from Manager so test doubles and external managers remain
// source-compatible while inventory can still enforce configured scope.
type ADOMAllowlist interface {
	AllowsADOM(string) bool
}

type Analyzer interface {
	Name() string
	Status(context.Context) (any, error)
	SearchLogs(context.Context, LogSearchRequest) (LogSearchResult, error)
	Read(context.Context, string, map[string]any) (any, error)
	Close() error
}

// WebFilterProfile is the FortiManager web filter profile subset needed to
// explain a URL decision. Raw keeps the appliance record for auditing.
type WebFilterProfile struct {
	Name               string           `json:"name"`
	Comment            string           `json:"comment,omitempty"`
	InspectionMode     string           `json:"inspection_mode,omitempty"`
	FeatureSet         string           `json:"feature_set,omitempty"`
	FortiGuardDisabled bool             `json:"fortiguard_disabled"`
	FortiGuardOptions  []string         `json:"fortiguard_options,omitempty"`
	Filters            []CategoryFilter `json:"filters,omitempty"`
	URLFilterTable     string           `json:"urlfilter_table,omitempty"`
	Raw                map[string]any   `json:"raw,omitempty"`
}

// CategoryFilter is one ftgd-wf filter entry. Category keeps the appliance
// representation (numeric id, name, or group token such as g01).
type CategoryFilter struct {
	ID            int      `json:"id"`
	Category      string   `json:"category"`
	Action        string   `json:"action"`
	Log           bool     `json:"log,omitempty"`
	WarningPrompt string   `json:"warning_prompt,omitempty"`
	AuthGroups    []string `json:"auth_groups,omitempty"`
}

type URLFilterTable struct {
	ID      int              `json:"id,omitempty"`
	Name    string           `json:"name"`
	Comment string           `json:"comment,omitempty"`
	Entries []URLFilterEntry `json:"entries,omitempty"`
}

type URLFilterEntry struct {
	ID           int      `json:"id"`
	URL          string   `json:"url"`
	Type         string   `json:"type"`
	Action       string   `json:"action"`
	Status       string   `json:"status,omitempty"`
	ReferrerHost string   `json:"referrer_host,omitempty"`
	Exempt       []string `json:"exempt,omitempty"`
}

// LocalRating is a FortiGuard local rating override stored in FortiManager.
type LocalRating struct {
	URL     string   `json:"url"`
	Rating  []string `json:"rating"`
	Status  string   `json:"status,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

type LocalCategory struct {
	ID          int    `json:"id"`
	Description string `json:"description"`
	Status      string `json:"status,omitempty"`
}

type ProfileGroup struct {
	Name             string `json:"name"`
	WebFilterProfile string `json:"webfilter_profile,omitempty"`
}

// URLRating is a live FortiGuard rating obtained through a managed FortiGate.
type URLRating struct {
	URL           string   `json:"url"`
	CategoryIDs   []int    `json:"category_ids"`
	CategoryNames []string `json:"category_names,omitempty"`
	Resource      string   `json:"resource,omitempty"`
	Raw           any      `json:"raw,omitempty"`
}

// WebFilterReader is an optional Manager capability used by the web filter
// lookup. Kept separate from Manager so existing test doubles still compile.
// An empty ADOM argument to the List methods reads the global ADOM.
type WebFilterReader interface {
	ListWebFilterProfiles(context.Context, string) ([]WebFilterProfile, error)
	ListURLFilterTables(context.Context, string) ([]URLFilterTable, error)
	ListLocalRatings(context.Context, string) ([]LocalRating, error)
	ListLocalCategories(context.Context, string) ([]LocalCategory, error)
	ListProfileGroups(context.Context, string) ([]ProfileGroup, error)
	ListFortiGuardCategories(context.Context, string) (map[int]string, error)
	ListFortiGateCategories(context.Context, string, string, string) (map[int]string, error)
	LookupURLRating(context.Context, string, string, string, string) (URLRating, error)
}

// PolicyTableReader reads additional policy tables of a package that can
// carry security profiles: "security-policy" (NGFW policy-based mode) and
// "proxy-policy" (explicit web proxy).
type PolicyTableReader interface {
	ListPolicyTable(context.Context, string, string, string) ([]FirewallPolicy, error)
}

// PolicyObjectReader reads several ADOM firewall object tables in one
// multiplexed request (see FortiManager.ListPolicyObjects).
type PolicyObjectReader interface {
	ListPolicyObjects(context.Context, string, []string) (PolicyObjects, error)
}

// PackagePolicyReader reads several policy tables of one package in one
// multiplexed request (see FortiManager.ListPackagePolicyTables).
type PackagePolicyReader interface {
	ListPackagePolicyTables(context.Context, string, string, []string) map[string]PolicyTableRead
}

// WebFilterObjectReader reads an ADOM's (or the global ADOM's) web filter
// objects in one multiplexed request.
type WebFilterObjectReader interface {
	ReadWebFilterObjects(context.Context, string) WebFilterObjects
}

// ProxyTimeoutReader sends a live FortiGate read with a bound on how long
// FortiManager waits for the FortiGate.
type ProxyTimeoutReader interface {
	ProxyGetTimeout(context.Context, string, string, string, string, int) (ProxyResult, error)
}

// AddressFamilyReader lets callers skip the IPv6 (or IPv4) object tables when
// a lookup only needs one family.
type AddressFamilyReader interface {
	ListAddressesForFamily(context.Context, string, bool) ([]AddressObject, error)
}

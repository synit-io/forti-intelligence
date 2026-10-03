package fortinet

import (
	"sort"
	"strconv"
	"strings"
)

// CategoryInfo describes one FortiGuard web filter category.
type CategoryInfo struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group,omitempty"`
}

// fortiGuardCategoryTable is a static reference of FortiGuard category ids.
// Ids have been stable since FortiOS 5.0; names follow the current FortiGuard
// catalogue. Live FortiGate or FortiManager category lists override it.
var fortiGuardCategoryTable = []CategoryInfo{
	{1, "Drug Abuse", "Potentially Liable"},
	{3, "Hacking", "Potentially Liable"},
	{4, "Illegal or Unethical", "Potentially Liable"},
	{5, "Discrimination", "Potentially Liable"},
	{6, "Explicit Violence", "Potentially Liable"},
	{12, "Extremist Groups", "Potentially Liable"},
	{59, "Proxy Avoidance", "Potentially Liable"},
	{62, "Plagiarism", "Potentially Liable"},
	{83, "Child Sexual Abuse", "Potentially Liable"},
	{96, "Terrorism", "Potentially Liable"},
	{2, "Alternative Beliefs", "Adult/Mature Content"},
	{7, "Abortion", "Adult/Mature Content"},
	{8, "Other Adult Materials", "Adult/Mature Content"},
	{9, "Advocacy Organizations", "Adult/Mature Content"},
	{11, "Gambling", "Adult/Mature Content"},
	{13, "Nudity and Risque", "Adult/Mature Content"},
	{14, "Pornography", "Adult/Mature Content"},
	{15, "Dating", "Adult/Mature Content"},
	{16, "Weapons (Sales)", "Adult/Mature Content"},
	{57, "Marijuana", "Adult/Mature Content"},
	{63, "Sex Education", "Adult/Mature Content"},
	{64, "Alcohol", "Adult/Mature Content"},
	{65, "Tobacco", "Adult/Mature Content"},
	{66, "Lingerie and Swimsuit", "Adult/Mature Content"},
	{67, "Sports Hunting and War Games", "Adult/Mature Content"},
	{19, "Freeware and Software Downloads", "Bandwidth Consuming"},
	{24, "File Sharing and Storage", "Bandwidth Consuming"},
	{25, "Streaming Media and Download", "Bandwidth Consuming"},
	{72, "Peer-to-peer File Sharing", "Bandwidth Consuming"},
	{75, "Internet Radio and TV", "Bandwidth Consuming"},
	{76, "Internet Telephony", "Bandwidth Consuming"},
	{26, "Malicious Websites", "Security Risk"},
	{61, "Phishing", "Security Risk"},
	{86, "Spam URLs", "Security Risk"},
	{88, "Dynamic DNS", "Security Risk"},
	{90, "Newly Observed Domain", "Security Risk"},
	{91, "Newly Registered Domain", "Security Risk"},
	{31, "Finance and Banking", "General Interest - Business"},
	{41, "Search Engines and Portals", "General Interest - Business"},
	{43, "General Organizations", "General Interest - Business"},
	{49, "Business", "General Interest - Business"},
	{50, "Information and Computer Security", "General Interest - Business"},
	{51, "Government and Legal Organizations", "General Interest - Business"},
	{52, "Information Technology", "General Interest - Business"},
	{53, "Armed Forces", "General Interest - Business"},
	{56, "Secure Websites", "General Interest - Business"},
	{81, "Web Hosting", "General Interest - Business"},
	{84, "Web-based Applications", "General Interest - Business"},
	{17, "Advertising", "General Interest - Personal"},
	{18, "Brokerage and Trading", "General Interest - Personal"},
	{20, "Games", "General Interest - Personal"},
	{23, "Web-based Email", "General Interest - Personal"},
	{28, "Entertainment", "General Interest - Personal"},
	{29, "Arts and Culture", "General Interest - Personal"},
	{30, "Education", "General Interest - Personal"},
	{33, "Health and Wellness", "General Interest - Personal"},
	{34, "Job Search", "General Interest - Personal"},
	{35, "Medicine", "General Interest - Personal"},
	{36, "News and Media", "General Interest - Personal"},
	{37, "Social Networking", "General Interest - Personal"},
	{38, "Political Organizations", "General Interest - Personal"},
	{39, "Reference", "General Interest - Personal"},
	{40, "Global Religion", "General Interest - Personal"},
	{42, "Shopping", "General Interest - Personal"},
	{44, "Society and Lifestyles", "General Interest - Personal"},
	{46, "Sports", "General Interest - Personal"},
	{47, "Travel", "General Interest - Personal"},
	{48, "Personal Vehicles", "General Interest - Personal"},
	{54, "Dynamic Content", "General Interest - Personal"},
	{55, "Meaningless Content", "General Interest - Personal"},
	{58, "Folklore", "General Interest - Personal"},
	{68, "Web Chat", "General Interest - Personal"},
	{69, "Instant Messaging", "General Interest - Personal"},
	{70, "Newsgroups and Message Boards", "General Interest - Personal"},
	{71, "Digital Postcards", "General Interest - Personal"},
	{77, "Child Education", "General Interest - Personal"},
	{78, "Real Estate", "General Interest - Personal"},
	{79, "Restaurant and Dining", "General Interest - Personal"},
	{80, "Personal Websites and Blogs", "General Interest - Personal"},
	{82, "Content Servers", "General Interest - Personal"},
	{85, "Domain Parking", "General Interest - Personal"},
	{87, "Personal Privacy", "General Interest - Personal"},
	{0, "Not Rated", "Unrated"},
}

// categoryGroups maps FortiOS category-group tokens to their member ids
// (FortiOS 7.4.5 "get webfilter categories"). Firmware upgrades can add ids.
var categoryGroups = map[string][]int{
	"g01": {1, 3, 4, 5, 6, 12, 59, 62, 83, 96, 98, 99},
	"g02": {2, 7, 8, 9, 11, 13, 14, 15, 16, 57, 63, 64, 65, 66, 67},
	"g04": {19, 24, 25, 72, 75, 76},
	"g05": {26, 61, 86, 88, 90, 91},
	"g06": {17, 18, 20, 23, 28, 29, 30, 33, 34, 35, 36, 37, 38, 39, 40, 42, 44, 46, 47, 48, 54, 55, 58, 68, 69, 70, 71, 77, 78, 79, 80, 82, 85, 87, 89},
	"g07": {31, 41, 43, 49, 50, 51, 52, 53, 56, 81, 84, 92, 93, 94, 95, 97, 100, 101},
	"g21": {0, 255},
	"g22": {140, 141},
}

// CategoryGroupMembers returns the ids of a category-group token such as
// "g01". Unknown tokens return ok=false.
func CategoryGroupMembers(token string) ([]int, bool) {
	members, ok := categoryGroups[strings.ToLower(strings.TrimSpace(token))]
	return members, ok
}

// StaticCategories returns a copy of the built-in category reference keyed
// by id. Callers merge live appliance data on top of it.
func StaticCategories() map[int]CategoryInfo {
	result := make(map[int]CategoryInfo, len(fortiGuardCategoryTable))
	for _, category := range fortiGuardCategoryTable {
		result[category.ID] = category
	}
	return result
}

// StaticCategoryByName resolves a FortiGuard category name to its id using
// the static reference. The comparison ignores case and surrounding spaces.
func StaticCategoryByName(name string) (CategoryInfo, bool) {
	wanted := strings.ToLower(strings.TrimSpace(name))
	if wanted == "" {
		return CategoryInfo{}, false
	}
	if wanted == "unrated" {
		// FortiOS shows category 0 as "Unrated"; the table names it after
		// FortiGuard ("Not Rated") and keeps "Unrated" as its group.
		wanted = "not rated"
	}
	for _, category := range fortiGuardCategoryTable {
		if strings.ToLower(category.Name) == wanted {
			return category, true
		}
	}
	return CategoryInfo{}, false
}

// ParseCategoryReference turns an appliance category value (number, numeric
// string, or category name) into an id. Group tokens such as g01 and unknown
// names return ok=false so callers can keep them as unresolved evidence.
func ParseCategoryReference(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case string:
		text := strings.TrimSpace(typed)
		if number, err := strconv.Atoi(text); err == nil {
			return number, true
		}
		if category, ok := StaticCategoryByName(text); ok {
			return category.ID, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// SortedCategoryIDs returns ids in ascending order for deterministic output.
func SortedCategoryIDs(values map[int]struct{}) []int {
	result := make([]int, 0, len(values))
	for id := range values {
		result = append(result, id)
	}
	sort.Ints(result)
	return result
}

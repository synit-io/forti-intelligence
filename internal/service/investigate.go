package service

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/synit-io/forti-intelligence/internal/fortinet"
	"github.com/synit-io/forti-intelligence/internal/inventory"
)

// InvestigateInput is one traffic question. Steps that do not apply are
// skipped; a failed step is recorded and the remaining steps still run.
type InvestigateInput struct {
	SourceIP        string
	DestinationIP   string
	DestinationPort int
	Protocol        string
	SourcePort      int
	SourceInterface string
	Profile         string
	ADOM            string
	Device          string
	VDOM            string
	URL             string
	IncludeLogs     bool
	LogProfile      string
	LogADOM         string
	LogStart        time.Time
	LogEnd          time.Time
}

// InvestigateOutput collects the evidence from each step of the investigation.
type InvestigateOutput struct {
	Ownership inventory.OwnershipResult `json:"ownership"`
	Route     RouteLookupOutput         `json:"route"`
	Policy    *PolicyLookupOutput       `json:"policy,omitempty"`
	Rating    *RateURLOutput            `json:"rating,omitempty"`
	WebFilter *WebFilterCheckOutput     `json:"web_filter,omitempty"`
	Hops      []InvestigateHop          `json:"hops,omitempty"`
	Logs      *fortinet.LogSearchResult `json:"logs,omitempty"`
	Errors    []string                  `json:"errors,omitempty"`
	Warnings  []string                  `json:"warnings,omitempty"`
}

// InvestigateHop ties policy and web-filter evidence to one configured hop
// and one destination address. The top-level policy and web_filter fields
// retain the first hop's result for existing clients.
type InvestigateHop struct {
	DestinationIP string                `json:"destination_ip"`
	Route         RouteHop              `json:"route"`
	Policy        *PolicyLookupOutput   `json:"policy,omitempty"`
	WebFilter     *WebFilterCheckOutput `json:"web_filter,omitempty"`
	Errors        []string              `json:"errors,omitempty"`
	Warnings      []string              `json:"warnings,omitempty"`
}

// Investigate runs ownership, configured routing, policy lookup, and the
// optional URL and log steps under the caller's deadline.
func (s *Service) Investigate(ctx context.Context, input InvestigateInput) (InvestigateOutput, error) {
	input.SourceIP = strings.TrimSpace(input.SourceIP)
	input.DestinationIP = strings.TrimSpace(input.DestinationIP)
	input.URL = strings.TrimSpace(input.URL)
	if net.ParseIP(input.SourceIP) == nil {
		return InvestigateOutput{}, fmt.Errorf("source_ip must be an IPv4 or IPv6 address")
	}
	if input.DestinationIP == "" {
		return InvestigateOutput{}, fmt.Errorf("destination_ip is required")
	}
	if input.DestinationPort < 0 || input.DestinationPort > 65535 {
		return InvestigateOutput{}, fmt.Errorf("destination_port must be between 0 and 65535")
	}
	if input.SourcePort < 0 || input.SourcePort > 65535 {
		return InvestigateOutput{}, fmt.Errorf("source_port must be between 0 and 65535")
	}

	var output InvestigateOutput
	ownership, err := s.ResolveIPOwnership(ctx, inventory.OwnershipQuery{
		IP: input.SourceIP, Profile: input.Profile, ADOM: input.ADOM, Device: input.Device, VDOM: input.VDOM,
	})
	if err != nil {
		output.Errors = append(output.Errors, "ownership: "+err.Error())
	} else {
		output.Ownership = ownership
	}

	route, err := s.ResolveRoute(ctx, RouteLookupInput{
		IP: input.DestinationIP, SourceIP: input.SourceIP, SourceInterface: input.SourceInterface,
		Protocol: input.Protocol, DestinationPort: input.DestinationPort,
		SourcePort: input.SourcePort,
		Profile:    input.Profile, ADOM: input.ADOM, Device: input.Device, VDOM: input.VDOM, Follow: true,
	})
	if err != nil {
		output.Errors = append(output.Errors, "route: "+err.Error())
	} else {
		output.Route = route
		routes := append([]RouteLookupOutput{route}, route.OtherAddresses...)
		for _, destination := range routes {
			if destination.Path == nil {
				continue
			}
			for _, hop := range destination.Path.Hops {
				evidence := InvestigateHop{DestinationIP: destination.IP, Route: hop}
				if hop.Hop > 1 {
					evidence.Warnings = append(evidence.Warnings, "This hop is evaluated with the original flow tuple. Upstream NAT and the return path are not resolved; verify translated addresses and ports before treating this as the effective downstream policy.")
				}
				output.Hops = append(output.Hops, evidence)
			}
			if destination.Path.End != "destination_connected" && destination.Path.End != "leaves_managed_network" {
				output.Warnings = append(output.Warnings, fmt.Sprintf("Configured path to %s stopped with %s: %s", destination.IP, destination.Path.End, destination.Path.Note))
			}
		}
	}

	if input.DestinationPort == 0 {
		output.Warnings = append(output.Warnings, "destination_port was omitted, so the firewall policy lookup was skipped")
	} else if ctx.Err() == nil {
		policyInput := PolicyLookupInput{
			Profile: input.Profile, ADOM: input.ADOM, Device: input.Device, VDOM: input.VDOM,
			SourceIP: input.SourceIP, DestinationIP: input.DestinationIP,
			SourcePort: input.SourcePort, DestinationPort: input.DestinationPort,
			Protocol: input.Protocol, SourceInterface: input.SourceInterface,
		}
		if len(output.Hops) == 0 {
			policy, policyErr := s.LookupPolicies(ctx, policyInput)
			if policy.Query.SourceIP != "" {
				output.Policy = &policy
			}
			if policyErr != nil {
				output.Errors = append(output.Errors, "policy: "+policyErr.Error())
			}
		} else {
			for i := range output.Hops {
				hop := &output.Hops[i]
				if ctx.Err() != nil {
					hop.Errors = append(hop.Errors, "policy: request deadline ended before this hop was evaluated")
					continue
				}
				scoped := policyInput
				scoped.Profile, scoped.ADOM, scoped.Device, scoped.VDOM = hop.Route.Profile, hop.Route.ADOM, hop.Route.Device, hop.Route.VDOM
				scoped.DestinationIP = hop.DestinationIP
				if len(hop.Route.Ingress) > 0 {
					scoped.SourceInterface = hop.Route.Ingress[0]
				}
				policy, policyErr := s.LookupPolicies(ctx, scoped)
				if policy.Query.SourceIP != "" {
					hop.Policy = &policy
					if i == 0 {
						output.Policy = &policy
					}
				}
				if policyErr != nil {
					hop.Errors = append(hop.Errors, "policy: "+policyErr.Error())
					output.Errors = append(output.Errors, investigateHopLabel(*hop)+": policy: "+policyErr.Error())
				}
			}
		}
	}

	if input.URL != "" && ctx.Err() == nil {
		ratingInput := RateURLInput{
			URL: input.URL, Profile: input.Profile, ADOM: input.ADOM, Device: input.Device, VDOM: input.VDOM,
		}
		if len(output.Hops) > 0 {
			hop := output.Hops[0].Route
			ratingInput.Profile, ratingInput.ADOM, ratingInput.Device, ratingInput.VDOM = hop.Profile, hop.ADOM, hop.Device, hop.VDOM
		}
		rating, ratingErr := s.RateURL(ctx, ratingInput)
		if ratingErr != nil && rating.Host == "" {
			output.Errors = append(output.Errors, "rating: "+ratingErr.Error())
		} else {
			output.Rating = &rating
			if ratingErr != nil {
				output.Errors = append(output.Errors, "rating: "+ratingErr.Error())
			}
		}
		category := ""
		if output.Rating != nil {
			ids := make([]string, 0, len(output.Rating.Rating.Categories))
			for _, item := range output.Rating.Rating.Categories {
				if item.ID != 0 || item.Name != "" {
					ids = append(ids, strconv.Itoa(item.ID))
				}
			}
			category = strings.Join(ids, ",")
		}
		if len(output.Hops) == 0 {
			output.Warnings = append(output.Warnings, "Web filtering was not checked because the configured path has no uniquely scoped hop. Resolve profile, ADOM, device and VDOM first.")
		}
		for i := range output.Hops {
			hop := &output.Hops[i]
			if ctx.Err() != nil {
				hop.Errors = append(hop.Errors, "web_filter: request deadline ended before this hop was evaluated")
				continue
			}
			if hop.Policy != nil && len(hop.Policy.Decisions) == 1 {
				action := hop.Policy.Decisions[0].Action
				if action == "deny" || action == "implicit_deny" {
					hop.Warnings = append(hop.Warnings, "Web filtering is skipped for this configured denial. Read the verdict's confidence and unresolved conditions before treating it as an effective block.")
					continue
				}
			}
			id := singlePolicyID(hop.Policy, hop.Route.Device)
			if id == 0 {
				hop.Warnings = append(hop.Warnings, "No unique carrying policy is proven; web-filter results list candidate profiles on this scoped hop.")
			} else if hop.Policy.Decisions[0].Confidence == "tentative" {
				hop.Warnings = append(hop.Warnings, "The carrying policy is tentative; its web-filter decision is conditional on that policy applying.")
			}
			check, checkErr := s.CheckWebFilter(ctx, CheckWebFilterInput{
				Category: category, URL: input.URL, Profile: hop.Route.Profile, ADOM: hop.Route.ADOM,
				Device: hop.Route.Device, VDOM: hop.Route.VDOM, PolicyID: id,
			})
			if checkErr == nil || len(check.Profiles) > 0 || len(check.Errors) > 0 {
				hop.WebFilter = &check
				if i == 0 {
					output.WebFilter = &check
				}
			}
			if checkErr != nil {
				hop.Errors = append(hop.Errors, "web_filter: "+checkErr.Error())
				output.Errors = append(output.Errors, investigateHopLabel(*hop)+": web_filter: "+checkErr.Error())
			}
		}
	}

	if input.IncludeLogs && ctx.Err() == nil {
		logs, logErr := s.SearchLogs(ctx, input.LogProfile, fortinet.LogSearchRequest{
			ADOM: input.LogADOM, LogType: "traffic", Filter: logFilter(input),
			StartTime: input.LogStart, EndTime: input.LogEnd, Limit: 25,
		})
		if logErr != nil && !logResultUsable(logs) {
			output.Errors = append(output.Errors, "logs: "+logErr.Error())
		} else {
			output.Logs = &logs
			if logErr != nil {
				output.Errors = append(output.Errors, "logs: "+logErr.Error())
			}
		}
	}
	if ctx.Err() != nil {
		output.Errors = append(output.Errors, "deadline: "+ctx.Err().Error())
	}
	return output, nil
}

func singlePolicyID(policy *PolicyLookupOutput, device string) int {
	if policy == nil || !policy.Complete {
		return 0
	}
	id, count := 0, 0
	for _, decision := range policy.Decisions {
		if device != "" && decision.Device != device {
			continue
		}
		count++
		id = decision.PolicyID
	}
	if count != 1 {
		return 0
	}
	return id
}

func investigateHopLabel(hop InvestigateHop) string {
	return fmt.Sprintf("hop %d %s/%s/%s/%s to %s", hop.Route.Hop, hop.Route.Profile, hop.Route.ADOM, hop.Route.Device, hop.Route.VDOM, hop.DestinationIP)
}

// logResultUsable reports whether a log search returned something worth
// attaching. TaskID and Records are untyped appliance values.
func logResultUsable(result fortinet.LogSearchResult) bool {
	if result.Complete || result.TimedOut || result.Resumed || result.Count > 0 || result.TotalCount > 0 || result.Progress > 0 {
		return true
	}
	return !emptyAny(result.TaskID) || !emptyAny(result.Records)
}

func emptyAny(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return typed == ""
	case []any:
		return len(typed) == 0
	case []map[string]any:
		return len(typed) == 0
	case map[string]any:
		return len(typed) == 0
	default:
		return false
	}
}

func logFilter(input InvestigateInput) string {
	filter := "srcip=" + input.SourceIP
	if net.ParseIP(input.DestinationIP) != nil {
		filter += " and dstip=" + input.DestinationIP
	}
	if input.DestinationPort > 0 {
		filter += " and dstport=" + strconv.Itoa(input.DestinationPort)
	}
	return filter
}

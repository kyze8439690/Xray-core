package conf

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"google.golang.org/protobuf/proto"
)

type RouterRulesConfig struct {
	RuleList       []json.RawMessage `json:"rules"`
	DomainStrategy string            `json:"domainStrategy"`
}

// StrategyConfig represents a strategy config
type StrategyConfig struct {
	Type     string           `json:"type"`
	Settings *json.RawMessage `json:"settings"`
}

type BalancingRule struct {
	Tag       string         `json:"tag"`
	Selectors StringList     `json:"selector"`
	Strategy  StrategyConfig `json:"strategy"`
}

func (r *BalancingRule) Build() (*router.BalancingRule, error) {
	if r.Tag == "" {
		return nil, newError("empty balancer tag")
	}
	if len(r.Selectors) == 0 {
		return nil, newError("empty selector list")
	}

	var strategy string
	switch strings.ToLower(r.Strategy.Type) {
	case strategyRandom, "":
		strategy = strategyRandom
	case strategyLeastPing:
		strategy = "leastPing"
	default:
		return nil, newError("unknown balancing strategy: " + r.Strategy.Type)
	}

	return &router.BalancingRule{
		Tag:              r.Tag,
		OutboundSelector: []string(r.Selectors),
		Strategy:         strategy,
	}, nil
}

type RouterConfig struct {
	Settings       *RouterRulesConfig `json:"settings"` // Deprecated
	RuleList       []json.RawMessage  `json:"rules"`
	DomainStrategy *string            `json:"domainStrategy"`
	Balancers      []*BalancingRule   `json:"balancers"`

	DomainMatcher string `json:"domainMatcher"`
}

func (c *RouterConfig) getDomainStrategy() router.Config_DomainStrategy {
	ds := ""
	if c.DomainStrategy != nil {
		ds = *c.DomainStrategy
	} else if c.Settings != nil {
		ds = c.Settings.DomainStrategy
	}

	switch strings.ToLower(ds) {
	case "alwaysip":
		return router.Config_UseIp
	case "ipifnonmatch":
		return router.Config_IpIfNonMatch
	case "ipondemand":
		return router.Config_IpOnDemand
	default:
		return router.Config_AsIs
	}
}

func (c *RouterConfig) Build() (*router.Config, error) {
	config := new(router.Config)
	config.DomainStrategy = c.getDomainStrategy()

	var rawRuleList []json.RawMessage
	if c != nil {
		rawRuleList = c.RuleList
		if c.Settings != nil {
			c.RuleList = append(c.RuleList, c.Settings.RuleList...)
			rawRuleList = c.RuleList
		}
	}

	for _, rawRule := range rawRuleList {
		rule, err := ParseRule(rawRule)
		if err != nil {
			return nil, err
		}

		if rule.DomainMatcher == "" {
			rule.DomainMatcher = c.DomainMatcher
		}

		config.Rule = append(config.Rule, rule)
	}
	for _, rawBalancer := range c.Balancers {
		balancer, err := rawBalancer.Build()
		if err != nil {
			return nil, err
		}
		config.BalancingRule = append(config.BalancingRule, balancer)
	}
	return config, nil
}

type RouterRule struct {
	Type        string `json:"type"`
	OutboundTag string `json:"outboundTag"`
	BalancerTag string `json:"balancerTag"`

	DomainMatcher string `json:"domainMatcher"`
}

func ParseIP(s string) (*router.CIDR, error) {
	var addr, mask string
	i := strings.Index(s, "/")
	if i < 0 {
		addr = s
	} else {
		addr = s[:i]
		mask = s[i+1:]
	}
	ip := net.ParseAddress(addr)
	switch ip.Family() {
	case net.AddressFamilyIPv4:
		bits := uint32(32)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, newError("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 32 {
			return nil, newError("invalid network mask for router: ", bits)
		}
		return &router.CIDR{
			Ip:     []byte(ip.IP()),
			Prefix: bits,
		}, nil
	case net.AddressFamilyIPv6:
		bits := uint32(128)
		if len(mask) > 0 {
			bits64, err := strconv.ParseUint(mask, 10, 32)
			if err != nil {
				return nil, newError("invalid network mask for router: ", mask).Base(err)
			}
			bits = uint32(bits64)
		}
		if bits > 128 {
			return nil, newError("invalid network mask for router: ", bits)
		}
		return &router.CIDR{
			Ip:     []byte(ip.IP()),
			Prefix: bits,
		}, nil
	default:
		return nil, newError("unsupported address for router: ", s)
	}
}

var (
	FileCache = make(map[string][]byte)
)

func loadFile(file string) ([]byte, error) {
	if FileCache[file] == nil {
		bs, err := filesystem.ReadAsset(file)
		if err != nil {
			return nil, newError("failed to open file: ", file).Base(err)
		}
		if len(bs) == 0 {
			return nil, newError("empty file: ", file)
		}
		// Do not cache file, may save RAM when there
		// are many files, but consume CPU each time.
		return bs, nil
		FileCache[file] = bs
	}
	return FileCache[file], nil
}

func find(data, code []byte) []byte {
	codeL := len(code)
	if codeL == 0 {
		return nil
	}
	for {
		dataL := len(data)
		if dataL < 2 {
			return nil
		}
		x, y := DecodeVarint(data[1:])
		if x == 0 && y == 0 {
			return nil
		}
		headL, bodyL := 1+y, int(x)
		dataL -= headL
		if dataL < bodyL {
			return nil
		}
		data = data[headL:]
		if int(data[1]) == codeL {
			for i := 0; i < codeL && data[2+i] == code[i]; i++ {
				if i+1 == codeL {
					return data[:bodyL]
				}
			}
		}
		if dataL == bodyL {
			return nil
		}
		data = data[bodyL:]
	}
}

type AttributeMatcher interface {
	Match(*router.Domain) bool
}

type BooleanMatcher string

func (m BooleanMatcher) Match(domain *router.Domain) bool {
	for _, attr := range domain.Attribute {
		if attr.Key == string(m) {
			return true
		}
	}
	return false
}

type AttributeList struct {
	matcher []AttributeMatcher
}

func (al *AttributeList) Match(domain *router.Domain) bool {
	for _, matcher := range al.matcher {
		if !matcher.Match(domain) {
			return false
		}
	}
	return true
}

func (al *AttributeList) IsEmpty() bool {
	return len(al.matcher) == 0
}

func parseAttrs(attrs []string) *AttributeList {
	al := new(AttributeList)
	for _, attr := range attrs {
		lc := strings.ToLower(attr)
		al.matcher = append(al.matcher, BooleanMatcher(lc))
	}
	return al
}

func parseDomainRule(domain string) ([]*router.Domain, error) {
	domainRule := new(router.Domain)
	switch {
	case strings.HasPrefix(domain, "regexp:"):
		domainRule.Type = router.Domain_Regex
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "domain:"):
		domainRule.Type = router.Domain_Domain
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "full:"):
		domainRule.Type = router.Domain_Full
		domainRule.Value = domain[5:]

	case strings.HasPrefix(domain, "keyword:"):
		domainRule.Type = router.Domain_Plain
		domainRule.Value = domain[8:]

	case strings.HasPrefix(domain, "dotless:"):
		domainRule.Type = router.Domain_Regex
		switch substr := domain[8:]; {
		case substr == "":
			domainRule.Value = "^[^.]*$"
		case !strings.Contains(substr, "."):
			domainRule.Value = "^[^.]*" + substr + "[^.]*$"
		default:
			return nil, newError("substr in dotless rule should not contain a dot: ", substr)
		}

	default:
		domainRule.Type = router.Domain_Plain
		domainRule.Value = domain
	}
	return []*router.Domain{domainRule}, nil
}

func parseFieldRule(msg json.RawMessage) (*router.RoutingRule, error) {
	type RawFieldRule struct {
		RouterRule
		Domain     *StringList       `json:"domain"`
		Domains    *StringList       `json:"domains"`
		IP         *StringList       `json:"ip"`
		Port       *PortList         `json:"port"`
		Network    *NetworkList      `json:"network"`
		SourceIP   *StringList       `json:"source"`
		SourcePort *PortList         `json:"sourcePort"`
		User       *StringList       `json:"user"`
		InboundTag *StringList       `json:"inboundTag"`
		Protocols  *StringList       `json:"protocol"`
		Attributes map[string]string `json:"attrs"`
	}
	rawFieldRule := new(RawFieldRule)
	err := json.Unmarshal(msg, rawFieldRule)
	if err != nil {
		return nil, err
	}

	rule := new(router.RoutingRule)
	switch {
	case len(rawFieldRule.OutboundTag) > 0:
		rule.TargetTag = &router.RoutingRule_Tag{
			Tag: rawFieldRule.OutboundTag,
		}
	case len(rawFieldRule.BalancerTag) > 0:
		rule.TargetTag = &router.RoutingRule_BalancingTag{
			BalancingTag: rawFieldRule.BalancerTag,
		}
	default:
		return nil, newError("neither outboundTag nor balancerTag is specified in routing rule")
	}

	if rawFieldRule.DomainMatcher != "" {
		rule.DomainMatcher = rawFieldRule.DomainMatcher
	}

	if rawFieldRule.Domain != nil {
		for _, domain := range *rawFieldRule.Domain {
			rules, err := parseDomainRule(domain)
			if err != nil {
				return nil, newError("failed to parse domain rule: ", domain).Base(err)
			}
			rule.Domain = append(rule.Domain, rules...)
		}
	}

	if rawFieldRule.Domains != nil {
		for _, domain := range *rawFieldRule.Domains {
			rules, err := parseDomainRule(domain)
			if err != nil {
				return nil, newError("failed to parse domain rule: ", domain).Base(err)
			}
			rule.Domain = append(rule.Domain, rules...)
		}
	}

	if rawFieldRule.Port != nil {
		rule.PortList = rawFieldRule.Port.Build()
	}

	if rawFieldRule.Network != nil {
		rule.Networks = rawFieldRule.Network.Build()
	}

	if rawFieldRule.SourcePort != nil {
		rule.SourcePortList = rawFieldRule.SourcePort.Build()
	}

	if rawFieldRule.User != nil {
		for _, s := range *rawFieldRule.User {
			rule.UserEmail = append(rule.UserEmail, s)
		}
	}

	if rawFieldRule.InboundTag != nil {
		for _, s := range *rawFieldRule.InboundTag {
			rule.InboundTag = append(rule.InboundTag, s)
		}
	}

	if rawFieldRule.Protocols != nil {
		for _, s := range *rawFieldRule.Protocols {
			rule.Protocol = append(rule.Protocol, s)
		}
	}

	if len(rawFieldRule.Attributes) > 0 {
		rule.Attributes = rawFieldRule.Attributes
	}

	return rule, nil
}

func ParseRule(msg json.RawMessage) (*router.RoutingRule, error) {
	rawRule := new(RouterRule)
	err := json.Unmarshal(msg, rawRule)
	if err != nil {
		return nil, newError("invalid router rule").Base(err)
	}
	if strings.EqualFold(rawRule.Type, "field") {
		fieldrule, err := parseFieldRule(msg)
		if err != nil {
			return nil, newError("invalid field rule").Base(err)
		}
		return fieldrule, nil
	}
	return nil, newError("unknown router rule type: ", rawRule.Type)
}


package conf

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/app/router"
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

type RouterConfig struct {
	Settings       *RouterRulesConfig `json:"settings"` // Deprecated
	RuleList       []json.RawMessage  `json:"rules"`
}

func (c *RouterConfig) Build() (*router.Config, error) {
	config := new(router.Config)

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

		config.Rule = append(config.Rule, rule)
	}
	return config, nil
}

type RouterRule struct {
	Type        string `json:"type"`
	OutboundTag string `json:"outboundTag"`
}

var (
	FileCache = make(map[string][]byte)
)

func parseFieldRule(msg json.RawMessage) (*router.RoutingRule, error) {
	type RawFieldRule struct {
		RouterRule
		IP         *StringList       `json:"ip"`
		SourceIP   *StringList       `json:"source"`
		InboundTag *StringList       `json:"inboundTag"`
		Protocols  *StringList       `json:"protocol"`
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
	default:
		return nil, newError("neither outboundTag nor balancerTag is specified in routing rule")
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

	return rule, nil
}

func ParseRule(msg json.RawMessage) (*router.RoutingRule, error) {
	rawRule := new(RouterRule)
	err := json.Unmarshal(msg, rawRule)
	if err != nil {
		return nil, newError("invalid router rule").Base(err)
	}
	if rawRule.Type == "" || strings.EqualFold(rawRule.Type, "field") {
		fieldrule, err := parseFieldRule(msg)
		if err != nil {
			return nil, newError("invalid field rule").Base(err)
		}
		return fieldrule, nil
	}
	return nil, newError("unknown router rule type: ", rawRule.Type)
}


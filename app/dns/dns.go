// Package dns is an implementation of core.DNS feature.
package dns

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
)

// DNS is a DNS rely server.
type DNS struct {
	sync.Mutex
	tag                    string
	disableCache           bool
	disableFallback        bool
	disableFallbackIfMatch bool
	ipOption               *dns.IPOption
	clients                []*Client
	ctx                    context.Context
}

// New creates a new DNS server with given configuration.
func New(ctx context.Context, config *Config) (*DNS, error) {
	var tag string
	if len(config.Tag) > 0 {
		tag = config.Tag
	} else {
		tag = generateRandomTag()
	}

	var clientIP net.IP
	switch len(config.ClientIp) {
	case 0, net.IPv4len, net.IPv6len:
		clientIP = net.IP(config.ClientIp)
	default:
		return nil, newError("unexpected client IP length ", len(config.ClientIp))
	}

	var ipOption *dns.IPOption
	switch config.QueryStrategy {
	case QueryStrategy_USE_IP:
		ipOption = &dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
		}
	case QueryStrategy_USE_IP4:
		ipOption = &dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
		}
	case QueryStrategy_USE_IP6:
		ipOption = &dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
		}
	}

	clients := []*Client{}

	for _, endpoint := range config.NameServers {
		features.PrintDeprecatedFeatureWarning("simple DNS server")
		client, err := NewSimpleClient(ctx, endpoint, clientIP)
		if err != nil {
			return nil, newError("failed to create client").Base(err)
		}
		clients = append(clients, client)
	}

	for _, ns := range config.NameServer {

		myClientIP := clientIP
		switch len(ns.ClientIp) {
		case net.IPv4len, net.IPv6len:
			myClientIP = net.IP(ns.ClientIp)
		}
		client, err := NewClient(ctx, ns, myClientIP)
		if err != nil {
			return nil, newError("failed to create client").Base(err)
		}
		clients = append(clients, client)
	}

	// If there is no DNS client in config, add a `localhost` DNS client
	if len(clients) == 0 {
		clients = append(clients, NewLocalDNSClient())
	}

	return &DNS{
		tag:                    tag,
		ipOption:               ipOption,
		clients:                clients,
		ctx:                    ctx,
		disableCache:           config.DisableCache,
		disableFallback:        config.DisableFallback,
		disableFallbackIfMatch: config.DisableFallbackIfMatch,
	}, nil
}

// Type implements common.HasType.
func (*DNS) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (s *DNS) Start() error {
	return nil
}

// Close implements common.Closable.
func (s *DNS) Close() error {
	return nil
}

// IsOwnLink implements proxy.dns.ownLinkVerifier
func (s *DNS) IsOwnLink(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	return inbound != nil && inbound.Tag == s.tag
}

// LookupIP implements dns.Client.
func (s *DNS) LookupIP(domain string, option dns.IPOption) ([]net.IP, error) {
	if domain == "" {
		return nil, newError("empty domain name")
	}

	option.IPv4Enable = option.IPv4Enable && s.ipOption.IPv4Enable
	option.IPv6Enable = option.IPv6Enable && s.ipOption.IPv6Enable

	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, dns.ErrEmptyResponse
	}

	// Normalize the FQDN form query
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}

	// Name servers lookup
	errs := []error{}
	ctx := session.ContextWithInbound(s.ctx, &session.Inbound{Tag: s.tag})
	for _, client := range s.sortClients(domain) {
		ips, err := client.QueryIP(ctx, domain, option, s.disableCache)
		if len(ips) > 0 {
			return ips, nil
		}
		if err != nil {
			newError("failed to lookup ip for domain ", domain, " at server ", client.Name()).Base(err).WriteToLog()
			errs = append(errs, err)
		}
		if err != context.Canceled && err != context.DeadlineExceeded && err != errExpectedIPNonMatch && err != dns.ErrEmptyResponse {
			return nil, err
		}
	}

	return nil, newError("returning nil for domain ", domain).Base(errors.Combine(errs...))
}

// GetIPOption implements ClientWithIPOption.
func (s *DNS) GetIPOption() *dns.IPOption {
	return s.ipOption
}

// SetQueryOption implements ClientWithIPOption.
func (s *DNS) SetQueryOption(isIPv4Enable, isIPv6Enable bool) {
	s.ipOption.IPv4Enable = isIPv4Enable
	s.ipOption.IPv6Enable = isIPv6Enable
}

func (s *DNS) sortClients(domain string) []*Client {
	clients := make([]*Client, 0, len(s.clients))
	clientUsed := make([]bool, len(s.clients))
	clientNames := make([]string, 0, len(s.clients))
	domainRules := []string{}

	if !(s.disableFallback) {
		// Default round-robin query
		for idx, client := range s.clients {
			if clientUsed[idx] || client.skipFallback {
				continue
			}
			clientUsed[idx] = true
			clients = append(clients, client)
			clientNames = append(clientNames, client.Name())
		}
	}

	if len(domainRules) > 0 {
		newError("domain ", domain, " matches following rules: ", domainRules).AtDebug().WriteToLog()
	}
	if len(clientNames) > 0 {
		newError("domain ", domain, " will use DNS in order: ", clientNames).AtDebug().WriteToLog()
	}

	if len(clients) == 0 {
		clients = append(clients, s.clients[0])
		clientNames = append(clientNames, s.clients[0].Name())
		newError("domain ", domain, " will use the first DNS: ", clientNames).AtDebug().WriteToLog()
	}

	return clients
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

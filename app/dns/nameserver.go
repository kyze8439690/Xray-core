package dns

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
)

// Server is the interface for Name Server.
type Server interface {
	// Name of the Client.
	Name() string
	// QueryIP sends IP queries to its configured server.
	QueryIP(ctx context.Context, domain string, clientIP net.IP, option dns.IPOption, disableCache bool) ([]net.IP, error)
}

// Client is the interface for DNS client.
type Client struct {
	server       Server
	clientIP     net.IP
	skipFallback bool
	domains      []string
}

var errExpectedIPNonMatch = errors.New("expectIPs not match")

// NewServer creates a name server object according to the network destination url.
func NewServer(dest net.Destination, dispatcher routing.Dispatcher, queryStrategy QueryStrategy) (Server, error) {
	if address := dest.Address; address.Family().IsDomain() {
		u, err := url.Parse(address.Domain())
		if err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(u.String(), "localhost"):
			return NewLocalNameServer(), nil
		}
	}
	if dest.Network == net.Network_Unknown {
		dest.Network = net.Network_UDP
	}
	if dest.Network == net.Network_UDP { // UDP classic DNS mode
		return NewClassicNameServer(dest, dispatcher), nil
	}
	return nil, newError("No available name server could be created from ", dest).AtWarning()
}

// NewClient creates a DNS client managing a name server with client IP, domain rules and expected IPs.
func NewClient(
	ctx context.Context,
	ns *NameServer,
	clientIP net.IP,
) (*Client, error) {
	client := &Client{}

	err := core.RequireFeatures(ctx, func(dispatcher routing.Dispatcher) error {
		// Create a new server for each client for now
		server, err := NewServer(ns.Address.AsDestination(), dispatcher, ns.GetQueryStrategy())
		if err != nil {
			return newError("failed to create nameserver").Base(err).AtWarning()
		}

		// Establish domain rules
		var rules []string

		if len(clientIP) > 0 {
			switch ns.Address.Address.GetAddress().(type) {
			case *net.IPOrDomain_Domain:
				newError("DNS: client ", ns.Address.Address.GetDomain(), " uses clientIP ", clientIP.String()).AtInfo().WriteToLog()
			case *net.IPOrDomain_Ip:
				newError("DNS: client ", ns.Address.Address.GetIp(), " uses clientIP ", clientIP.String()).AtInfo().WriteToLog()
			}
		}

		client.server = server
		client.clientIP = clientIP
		client.skipFallback = ns.SkipFallback
		client.domains = rules
		return nil
	})
	return client, err
}

// NewSimpleClient creates a DNS client with a simple destination.
func NewSimpleClient(ctx context.Context, endpoint *net.Endpoint, clientIP net.IP) (*Client, error) {
	client := &Client{}
	err := core.RequireFeatures(ctx, func(dispatcher routing.Dispatcher) error {
		server, err := NewServer(endpoint.AsDestination(), dispatcher, QueryStrategy_USE_IP)
		if err != nil {
			return newError("failed to create nameserver").Base(err).AtWarning()
		}
		client.server = server
		client.clientIP = clientIP
		return nil
	})

	if len(clientIP) > 0 {
		switch endpoint.Address.GetAddress().(type) {
		case *net.IPOrDomain_Domain:
			newError("DNS: client ", endpoint.Address.GetDomain(), " uses clientIP ", clientIP.String()).AtInfo().WriteToLog()
		case *net.IPOrDomain_Ip:
			newError("DNS: client ", endpoint.Address.GetIp(), " uses clientIP ", clientIP.String()).AtInfo().WriteToLog()
		}
	}

	return client, err
}

// Name returns the server name the client manages.
func (c *Client) Name() string {
	return c.server.Name()
}

// QueryIP sends DNS query to the name server with the client's IP.
func (c *Client) QueryIP(ctx context.Context, domain string, option dns.IPOption, disableCache bool) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	ips, err := c.server.QueryIP(ctx, domain, c.clientIP, option, disableCache)
	cancel()

	if err != nil {
		return ips, err
	}
	return ips, nil
}

func ResolveIpOptionOverride(queryStrategy QueryStrategy, ipOption dns.IPOption) dns.IPOption {
	switch queryStrategy {
	case QueryStrategy_USE_IP:
		return ipOption
	case QueryStrategy_USE_IP4:
		return dns.IPOption{
			IPv4Enable: ipOption.IPv4Enable,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP6:
		return dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: ipOption.IPv6Enable,
			FakeEnable: false,
		}
	default:
		return ipOption
	}
}

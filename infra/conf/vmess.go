package conf

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vmess"
	"github.com/xtls/xray-core/proxy/vmess/outbound"
	"google.golang.org/protobuf/proto"
)

type VMessAccount struct {
	ID          string `json:"id"`
	AlterIds    uint16 `json:"alterId"`
	Security    string `json:"security"`
	Experiments string `json:"experiments"`
}

// Build implements Buildable
func (a *VMessAccount) Build() *vmess.Account {
	var st protocol.SecurityType
	switch strings.ToLower(a.Security) {
	case "aes-128-gcm":
		st = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		st = protocol.SecurityType_CHACHA20_POLY1305
	case "auto":
		st = protocol.SecurityType_AUTO
	case "none":
		st = protocol.SecurityType_NONE
	case "zero":
		st = protocol.SecurityType_ZERO
	default:
		st = protocol.SecurityType_AUTO
	}
	return &vmess.Account{
		Id:      a.ID,
		AlterId: uint32(a.AlterIds),
		SecuritySettings: &protocol.SecurityConfig{
			Type: st,
		},
		TestsEnabled: a.Experiments,
	}
}

type VMessDetourConfig struct {
	ToTag string `json:"to"`
}

type FeaturesConfig struct {
	Detour *VMessDetourConfig `json:"detour"`
}

type VMessDefaultConfig struct {
	AlterIDs uint16 `json:"alterId"`
	Level    byte   `json:"level"`
}

type VMessOutboundTarget struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VMessOutboundConfig struct {
	Receivers []*VMessOutboundTarget `json:"vnext"`
}

// Build implements Buildable
func (c *VMessOutboundConfig) Build() (proto.Message, error) {
	config := new(outbound.Config)

	if len(c.Receivers) == 0 {
		return nil, newError("0 VMess receiver configured")
	}
	serverSpecs := make([]*protocol.ServerEndpoint, len(c.Receivers))
	for idx, rec := range c.Receivers {
		if len(rec.Users) == 0 {
			return nil, newError("0 user configured for VMess outbound")
		}
		if rec.Address == nil {
			return nil, newError("address is not set in VMess outbound config")
		}
		spec := &protocol.ServerEndpoint{
			Address: rec.Address.Build(),
			Port:    uint32(rec.Port),
		}
		for _, rawUser := range rec.Users {
			user := new(protocol.User)
			if err := json.Unmarshal(rawUser, user); err != nil {
				return nil, newError("invalid VMess user").Base(err)
			}
			account := new(VMessAccount)
			if err := json.Unmarshal(rawUser, account); err != nil {
				return nil, newError("invalid VMess user").Base(err)
			}

			u, err := uuid.ParseString(account.ID)
			if err != nil {
				return nil, err
			}
			account.ID = u.String()

			user.Account = serial.ToTypedMessage(account.Build())
			spec.User = append(spec.User, user)
		}
		serverSpecs[idx] = spec
	}
	config.Receiver = serverSpecs
	return config, nil
}

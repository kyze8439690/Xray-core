package policy

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/policy"
)

// Instance is an instance of Policy manager.
type Instance struct {
	levels map[uint32]*Policy
}

// New creates new Policy manager instance.
func New(config *Config) (*Instance, error) {
	m := &Instance{
		levels: make(map[uint32]*Policy),
	}
	if len(config.Level) > 0 {
		for lv, p := range config.Level {
			pp := defaultPolicy()
			pp.overrideWith(p)
			m.levels[lv] = pp
		}
	}

	return m, nil
}

// Type implements common.HasType.
func (*Instance) Type() interface{} {
	return policy.ManagerType()
}

// ForLevel implements policy.Manager.
func (m *Instance) ForLevel(level uint32) policy.Session {
	if p, ok := m.levels[level]; ok {
		return p.ToCorePolicy()
	}
	return policy.SessionDefault()
}

// Start implements common.Runnable.Start().
func (m *Instance) Start() error {
	return nil
}

// Close implements common.Closable.Close().
func (m *Instance) Close() error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(config.(*Config))
	}))
}

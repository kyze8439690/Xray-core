package all

import (
	"github.com/xtls/xray-core/main/commands/base"
)

// go:generate go run github.com/xtls/xray-core/common/errors/errorgen

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		// cmdConvert,
		cmdUUID,
		cmdX25519,
		cmdWG,
	)
}

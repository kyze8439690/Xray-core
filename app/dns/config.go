package dns

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
)

func toNetIP(addrs []net.Address) ([]net.IP, error) {
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Family().IsIP() {
			ips = append(ips, addr.IP())
		} else {
			return nil, newError("Failed to convert address", addr, "to Net IP.").AtWarning()
		}
	}
	return ips, nil
}

func generateRandomTag() string {
	id := uuid.New()
	return "xray.system." + id.String()
}

package scan

import (
	"net"
	"net/netip"
	"sync"
)

var (
	v6Once sync.Once
	v6OK   bool
)

// HasGlobalIPv6 reports whether this machine holds a globally routable IPv6
// address, i.e. whether scanning IPv6 candidates could possibly succeed. On a
// v4-only host every IPv6 dial fails instantly with "network unreachable", which
// would burn the whole candidate budget on guaranteed misses and report zero
// results — so callers use this to drop the v6 half of an "auto" scan instead.
//
// Interfaces are inspected rather than a probe connection being opened: a
// UDP-connect test would need real traffic to distinguish a working stack from a
// tunnel that black-holes, and the result is cached for the process lifetime
// anyway. Link-local (fe80::/10), unique-local (fc00::/7) and loopback addresses
// don't count — they can't reach a CDN edge.
func HasGlobalIPv6() bool {
	v6Once.Do(func() { v6OK = detectGlobalIPv6() })
	return v6OK
}

func detectGlobalIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is4() {
				continue
			}
			if addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLinkLocalUnicast() {
				return true
			}
		}
	}
	return false
}

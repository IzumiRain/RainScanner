// Package iprange expands IPv4 CIDR blocks into host addresses with optional
// sampling so enormous CDN allocations can be probed without enumerating every
// address. IPv6 is intentionally unsupported and silently dropped.
package iprange

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
)

// Strategy controls how a CIDR is expanded.
type Strategy struct {
	// SamplePer24 limits how many hosts are emitted from each /24 worth of
	// space. 0 means "emit every host" (full enumeration).
	SamplePer24 int
	// MaxHostsPerCIDR caps total hosts emitted from a single CIDR. 0 = no cap.
	MaxHostsPerCIDR int
	// MaxTotal caps the total number of hosts emitted across ALL CIDRs by
	// randomly sampling the pool (reservoir sampling). 0 = no cap (full pool).
	// This is the "scan N random IPs out of millions" control: memory stays
	// bounded at MaxTotal regardless of pool size, which keeps huge providers
	// (e.g. Cloudflare's ~1.5M IPs) light on low-end machines.
	MaxTotal int
}

// Expand turns a list of CIDR strings into deduplicated IPv4 host addresses.
// Non-IPv4 entries are skipped. A deterministic stride is used for the per-/24
// sampling so those runs are reproducible. When MaxTotal>0 a random reservoir
// sample of the whole pool is taken instead (intentionally non-deterministic).
func Expand(cidrs []string, s Strategy) ([]netip.Addr, error) {
	// In random-sample mode memory is bounded to MaxTotal via reservoir
	// sampling, and the global dedup map is skipped (CDN CIDRs are disjoint, so
	// the only possible dups are operator-supplied overlaps — negligible). In
	// full mode we dedup exactly as before.
	var (
		seen map[netip.Addr]struct{}
		out  []netip.Addr
		n    int // unique candidates considered so far (reservoir counter)
	)
	if s.MaxTotal <= 0 {
		seen = make(map[netip.Addr]struct{})
	}

	emit := func(a netip.Addr) {
		if seen != nil {
			if _, dup := seen[a]; dup {
				return
			}
			seen[a] = struct{}{}
		}
		if s.MaxTotal <= 0 {
			out = append(out, a)
			return
		}
		// Reservoir sampling: keep the first MaxTotal, then each later item has
		// a MaxTotal/n chance of replacing a random slot.
		n++
		if len(out) < s.MaxTotal {
			out = append(out, a)
			return
		}
		if j := rand.IntN(n); j < s.MaxTotal {
			out[j] = a
		}
	}

	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			// Allow bare IPs as /32.
			if a, aerr := netip.ParseAddr(c); aerr == nil && a.Is4() {
				emit(a)
				continue
			}
			return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		if !p.Addr().Is4() {
			continue // IPv4-only
		}
		expandPrefix(p.Masked(), s, emit)
	}
	return out, nil
}

func expandPrefix(p netip.Prefix, s Strategy, emit func(netip.Addr)) {
	bits := p.Bits()
	hostBits := 32 - bits
	total := uint64(1) << uint(hostBits)

	// Determine stride for sampling.
	stride := uint64(1)
	if s.SamplePer24 > 0 && hostBits > 8 {
		// number of /24s in this prefix
		num24 := uint64(1) << uint(hostBits-8)
		want := num24 * uint64(s.SamplePer24)
		if want < total && want > 0 {
			stride = total / want
			if stride == 0 {
				stride = 1
			}
		}
	}

	emitted := 0
	start := ipToU32(p.Addr().As4())

	for i := uint64(0); i < total; i += stride {
		if s.MaxHostsPerCIDR > 0 && emitted >= s.MaxHostsPerCIDR {
			break
		}
		emit(u32ToIP(start + uint32(i)))
		emitted++
	}
}

func ipToU32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32ToIP(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// FilterV4 keeps only IPv4 CIDR/IP strings from a mixed list.
func FilterV4(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			if p.Addr().Is4() {
				out = append(out, e)
			}
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil && a.Is4() {
			out = append(out, e)
		}
	}
	return out
}

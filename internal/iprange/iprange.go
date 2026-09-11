// Package iprange expands IPv4 and IPv6 CIDR blocks into host addresses with
// optional sampling, so enormous CDN allocations can be probed without
// enumerating every address.
//
// The two families are expanded very differently, because their host spaces are
// nothing alike:
//
//   - An IPv4 prefix is walked with a deterministic stride. A /24-sampled run is
//     therefore reproducible, and a whole /12 can still be enumerated exactly.
//   - An IPv6 prefix cannot be walked at all: a single /64 holds 1.8e19 hosts, so
//     "every Nth address" would never leave the bottom of the block and a stride
//     large enough to cover it would need 128-bit arithmetic to no benefit.
//     Instead a bounded number of addresses is drawn uniformly at random from the
//     prefix — which is how CDN IPv6 anycast space is probed in practice, since
//     the whole announced block answers rather than a handful of hosts in it.
package iprange

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sort"
	"strings"
)

// DefaultV6HostsPerCIDR is how many addresses are drawn from one IPv6 prefix
// when the caller doesn't say. IPv6 has no meaningful "enumerate it all" mode,
// so this default always applies; it is deliberately modest because a provider
// like Cloudflare publishes several v6 prefixes and each one is effectively
// infinite.
const DefaultV6HostsPerCIDR = 256

// Family selects which address families are expanded and scanned.
type Family uint8

const (
	// FamilyAuto is the zero value: expand whatever it is given. Callers that
	// dial the results (pipeline.Run) resolve it to Both or V4 depending on
	// whether the machine actually has IPv6 connectivity.
	FamilyAuto Family = iota
	FamilyV4          // IPv4 only
	FamilyV6          // IPv6 only
	FamilyBoth        // both families, regardless of local connectivity
)

// ParseFamily reads the user-facing spelling of a family selector ("4", "ipv6",
// "both", ...). Anything unrecognised — including "" and "auto" — is FamilyAuto.
func ParseFamily(s string) Family {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "4", "v4", "ip4", "ipv4":
		return FamilyV4
	case "6", "v6", "ip6", "ipv6":
		return FamilyV6
	case "both", "dual", "dualstack", "dual-stack", "all", "46":
		return FamilyBoth
	default:
		return FamilyAuto
	}
}

func (f Family) String() string {
	switch f {
	case FamilyV4:
		return "ipv4"
	case FamilyV6:
		return "ipv6"
	case FamilyBoth:
		return "dual-stack"
	default:
		return "auto"
	}
}

// Allows reports whether addr belongs to a family this selector accepts.
func (f Family) Allows(addr netip.Addr) bool {
	switch f {
	case FamilyV4:
		return addr.Is4() || addr.Is4In6()
	case FamilyV6:
		return addr.Is6() && !addr.Is4In6()
	default:
		return true
	}
}

// Strategy controls how a CIDR is expanded.
type Strategy struct {
	// SamplePer24 limits how many hosts are emitted from each /24 worth of
	// space. 0 means "emit every host" (full enumeration). IPv4 only — there is
	// no useful IPv6 analogue, since a v6 prefix holds more /24-equivalents than
	// the entire IPv4 internet.
	SamplePer24 int
	// MaxHostsPerCIDR caps total hosts emitted from a single CIDR. 0 = no cap
	// for IPv4; for IPv6 see MaxHostsPerV6CIDR (there is no uncapped v6 mode).
	MaxHostsPerCIDR int
	// MaxTotal caps the total number of hosts emitted across ALL CIDRs by
	// randomly sampling the pool (reservoir sampling). 0 = no cap (full pool).
	// This is the "scan N random IPs out of millions" control: memory stays
	// bounded at MaxTotal regardless of pool size, which keeps huge providers
	// (e.g. Cloudflare's ~1.5M IPs) light on low-end machines.
	MaxTotal int
	// Family restricts which address families are expanded. The zero value
	// (FamilyAuto) expands everything it is given.
	Family Family
	// MaxHostsPerV6CIDR caps how many addresses are drawn from ONE IPv6 prefix.
	// Unlike MaxHostsPerCIDR, 0 does not mean "unlimited" — it falls back to
	// DefaultV6HostsPerCIDR, because an IPv6 prefix cannot be enumerated.
	MaxHostsPerV6CIDR int
}

// Expand turns a list of CIDR strings into deduplicated host addresses of the
// selected families. Entries of an excluded family are skipped silently; an
// entry that is not a valid CIDR or IP at all is an error. A deterministic
// stride is used for IPv4 per-/24 sampling so those runs are reproducible; IPv6
// prefixes and MaxTotal sampling are intentionally non-deterministic.
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
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			// Allow a bare IP as a single-host prefix.
			a, aerr := netip.ParseAddr(strings.TrimSpace(c))
			if aerr != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
			}
			if s.Family.Allows(a) {
				emit(a.Unmap())
			}
			continue
		}
		p = p.Masked()
		if !s.Family.Allows(p.Addr()) {
			continue
		}
		if p.Addr().Is4() {
			expandPrefix4(p, s, emit)
		} else {
			expandPrefix6(p, s, emit)
		}
	}
	return out, nil
}

func expandPrefix4(p netip.Prefix, s Strategy, emit func(netip.Addr)) {
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

// expandPrefix6 draws host addresses from an IPv6 prefix. Prefixes small enough
// to fit inside the budget are enumerated exactly (so a /126 of four addresses
// behaves like its IPv4 counterpart); everything larger is sampled uniformly at
// random, because striding a /64 would only ever probe the first few addresses
// of a block whose whole span answers.
func expandPrefix6(p netip.Prefix, s Strategy, emit func(netip.Addr)) {
	hostBits := 128 - p.Bits()
	limit := s.MaxHostsPerV6CIDR
	if limit <= 0 {
		limit = DefaultV6HostsPerCIDR
	}
	if s.MaxHostsPerCIDR > 0 && s.MaxHostsPerCIDR < limit {
		limit = s.MaxHostsPerCIDR
	}

	base := p.Addr().As16()
	hi := binary.BigEndian.Uint64(base[:8])
	lo := binary.BigEndian.Uint64(base[8:])

	// Small enough to enumerate exactly? (hostBits < 63 keeps 1<<hostBits from
	// overflowing; anything at or above that is astronomically over the limit.)
	if hostBits < 63 {
		if total := uint64(1) << uint(hostBits); total <= uint64(limit) {
			for i := range total {
				emit(addr16(hi, lo+i))
			}
			return
		}
	}

	// Bounded uniform sample. Dedup within the prefix so a collision shrinks the
	// number of draws rather than the number of distinct hosts returned; the
	// retry budget stops a pathological small prefix from spinning.
	drawn := make(map[netip.Addr]struct{}, limit)
	for tries := 0; len(drawn) < limit && tries < limit*4; tries++ {
		a := randomIn6(hi, lo, hostBits)
		if _, dup := drawn[a]; dup {
			continue
		}
		drawn[a] = struct{}{}
		emit(a)
	}
}

// randomIn6 returns a uniformly random address inside the prefix whose masked
// base is (hi, lo) and which has hostBits free low bits. The host bits are
// already zero in the base, so the random bits are simply OR-ed in.
func randomIn6(hi, lo uint64, hostBits int) netip.Addr {
	lowBits := min(hostBits, 64)
	highBits := hostBits - lowBits
	return addr16(hi|(rand.Uint64()&maskBits(highBits)), lo|(rand.Uint64()&maskBits(lowBits)))
}

// maskBits returns a mask of the low n bits (n is clamped to 0..64).
func maskBits(n int) uint64 {
	switch {
	case n <= 0:
		return 0
	case n >= 64:
		return ^uint64(0)
	default:
		return (uint64(1) << uint(n)) - 1
	}
}

func addr16(hi, lo uint64) netip.Addr {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], hi)
	binary.BigEndian.PutUint64(b[8:], lo)
	return netip.AddrFrom16(b)
}

func ipToU32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32ToIP(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Filter keeps the entries that parse as a CIDR or bare IP of an accepted
// family, returned unchanged and in their original order. Garbage is dropped.
func Filter(entries []string, fam Family) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if a, ok := entryAddr(e); ok && fam.Allows(a) {
			out = append(out, e)
		}
	}
	return out
}

// Sort orders CIDR entries in place: IPv4 first, then IPv6, lexicographically
// within each family. Grouping by family keeps the two blocks readable wherever
// range lists are shown or committed; keeping the within-family order
// lexicographic means adding IPv6 support appends to the existing on-disk range
// files rather than reshuffling every IPv4 line in them.
func Sort(entries []string) {
	sort.Slice(entries, func(i, j int) bool {
		i6, j6 := strings.Contains(entries[i], ":"), strings.Contains(entries[j], ":")
		if i6 != j6 {
			return j6 // IPv4 sorts before IPv6
		}
		return entries[i] < entries[j]
	})
}

// Split counts how many entries are IPv4 and how many are IPv6. Used for the
// "N ranges (x IPv4 / y IPv6)" reporting in the CLI and GUI.
func Split(entries []string) (v4, v6 int) {
	for _, e := range entries {
		a, ok := entryAddr(e)
		if !ok {
			continue
		}
		if a.Is4() || a.Is4In6() {
			v4++
		} else {
			v6++
		}
	}
	return v4, v6
}

// entryAddr returns the address a CIDR or bare-IP entry starts at.
func entryAddr(e string) (netip.Addr, bool) {
	e = strings.TrimSpace(e)
	if p, err := netip.ParsePrefix(e); err == nil {
		return p.Addr(), true
	}
	if a, err := netip.ParseAddr(e); err == nil {
		return a, true
	}
	return netip.Addr{}, false
}

package iprange

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestIPv4SamplingExact(t *testing.T) {
	for _, tc := range []struct {
		cidr              string
		sample, cap, want int
	}{
		{"192.0.2.0/24", 1, 0, 1},
		{"192.0.2.0/23", 3, 0, 6},
		{"192.0.2.0/23", 3, 4, 4},
		{"192.0.2.0/25", 3, 0, 2},
		{"192.0.2.0/32", 1, 0, 1},
		{"192.0.2.0/24", 300, 0, 256},
		{"192.0.2.0/30", 0, 0, 4},
	} {
		t.Run(tc.cidr+"/sample="+strconv.Itoa(tc.sample), func(t *testing.T) {
			s := Strategy{SamplePer24: tc.sample, MaxHostsPerCIDR: tc.cap}
			got, err := Expand([]string{tc.cidr}, s)
			if err != nil || len(got) != tc.want {
				t.Fatalf("got %d hosts, %v; want %d", len(got), err, tc.want)
			}
			prefix := netip.MustParsePrefix(tc.cidr)
			seen := make(map[netip.Addr]bool)
			for _, a := range got {
				if !prefix.Contains(a) || seen[a] {
					t.Fatalf("invalid or duplicate address %v in %v", a, got)
				}
				seen[a] = true
			}
			if tc.cidr == "192.0.2.0/23" && tc.cap == 0 {
				counts := map[byte]int{}
				for _, a := range got {
					counts[a.As4()[2]]++
				}
				if counts[2] != 3 || counts[3] != 3 {
					t.Fatalf("not exactly three hosts per /24: %v", got)
				}
			}
			again, err := Expand([]string{tc.cidr}, s)
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				if got[i] != again[i] {
					t.Fatal("IPv4 sampling must be deterministic")
				}
			}
		})
	}
}

func TestExpandBoundedHugePool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := ExpandContext(ctx, []string{"0.0.0.0/0"}, Strategy{MaxTotal: 1})
	if err != nil || len(got) != 1 || !got[0].Is4() {
		t.Fatalf("bounded /0: got %v, err %v", got, err)
	}
}

func TestExpandCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExpandContext(ctx, []string{"0.0.0.0/0"}, Strategy{MaxTotal: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled expansion: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	// Cancel after parsing and some generation, without depending on scheduling.
	counted := &cancelAfterChecks{Context: ctx, cancel: cancel}
	_, err := ExpandContext(counted, []string{"0.0.0.0/0"}, Strategy{MaxTotal: 1 << 30})
	if !errors.Is(err, context.Canceled) || counted.checks != 100 {
		t.Fatalf("in-progress cancellation: checks=%d err=%v", counted.checks, err)
	}
}

type cancelAfterChecks struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelAfterChecks) Err() error {
	c.checks++
	if c.checks == 100 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestExpandFamilyCapsAndOverlaps(t *testing.T) {
	for _, family := range []Family{FamilyV4, FamilyV6, FamilyBoth} {
		got, err := Expand([]string{"192.0.2.0/24", "2001:db8::/64"}, Strategy{
			Family: family, MaxHostsPerCIDR: 3, MaxHostsPerV6CIDR: 2, MaxTotal: 4,
		})
		if err != nil || len(got) == 0 || len(got) > 4 {
			t.Fatalf("family %v: %v, %v", family, got, err)
		}
		v4, v6 := 0, 0
		for _, a := range got {
			if !family.Allows(a) {
				t.Fatalf("excluded address %v for %v", a, family)
			}
			if a.Is4() {
				v4++
			} else {
				v6++
			}
		}
		if v4 > 3 || v6 > 2 {
			t.Fatalf("per-prefix caps exceeded: v4=%d v6=%d", v4, v6)
		}
	}
	got, err := Expand([]string{"192.0.2.0/30", "192.0.2.1", "192.0.2.0/30"}, Strategy{})
	if err != nil || len(got) != 4 {
		t.Fatalf("overlaps not deduplicated: %v, %v", got, err)
	}
	got, err = Expand([]string{"2001:db8::/126"}, Strategy{})
	if err != nil || len(got) != 4 {
		t.Fatalf("small IPv6 block: %v, %v", got, err)
	}
	if _, err := Expand([]string{"not-a-cidr"}, Strategy{}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
}

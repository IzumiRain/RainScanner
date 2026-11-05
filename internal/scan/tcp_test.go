package scan

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestRunFindsReachableIPv4AndIPv6(t *testing.T) {
	for _, tc := range []struct{ network, host string }{{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}} {
		t.Run(tc.network, func(t *testing.T) {
			ln, err := net.Listen(tc.network, net.JoinHostPort(tc.host, "0"))
			if err != nil && tc.network == "tcp6" {
				t.Skipf("IPv6 loopback unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			addr := netip.MustParseAddr(tc.host)
			var got []Result
			var progress int
			for r := range Run(ctx, []netip.Addr{addr}, Options{Port: ln.Addr().(*net.TCPAddr).Port, Concurrency: 1}, func(done int) { progress = done }) {
				got = append(got, r)
			}
			if len(got) != 1 || got[0].Addr != addr || progress != 1 {
				t.Fatalf("results=%v progress=%d", got, progress)
			}
		})
	}
}

func TestRunCancellationClosesResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := Run(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Options{Port: 1, Concurrency: 1}, nil)
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("canceled dial produced reachable result")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled sweep did not close")
	}
}

func TestRunConcurrentProgressCountsEveryHost(t *testing.T) {
	hosts := make([]netip.Addr, 32)
	for i := range hosts {
		hosts[i] = netip.MustParseAddr("127.0.0.1")
	}
	var mu sync.Mutex
	seen := make(map[int]bool)
	for range Run(context.Background(), hosts, Options{Port: 1, Concurrency: 8, Timeout: 100 * time.Millisecond}, func(done int) { mu.Lock(); seen[done] = true; mu.Unlock() }) {
	}
	if len(seen) != len(hosts) || !seen[len(hosts)] {
		t.Fatalf("progress counts=%v", seen)
	}
}

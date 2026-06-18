// Package scan implements Stage 1: a high-concurrency TCP connect sweep used to
// cheaply discard dead IPs before the expensive Xray latency stage.
package scan

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Options configures the TCP connect scan.
type Options struct {
	Port        int           // target port (typically 443)
	Concurrency int           // max simultaneous dials
	Timeout     time.Duration // per-connection timeout
}

// Result reports one reachable host and how long the connect took.
type Result struct {
	Addr    netip.Addr
	Latency time.Duration
}

// Run sweeps hosts and streams reachable ones to the returned channel. The
// channel is closed when scanning completes or ctx is cancelled. Progress (count
// of hosts processed) is reported via the optional onProgress callback.
func Run(ctx context.Context, hosts []netip.Addr, opt Options, onProgress func(done int)) <-chan Result {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 512
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 3 * time.Second
	}
	out := make(chan Result, 256)

	go func() {
		defer close(out)
		sem := make(chan struct{}, opt.Concurrency)
		var wg sync.WaitGroup
		var mu sync.Mutex
		done := 0

		for _, h := range hosts {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(addr netip.Addr) {
				defer wg.Done()
				defer func() { <-sem }()

				lat, ok := dial(ctx, addr, opt.Port, opt.Timeout)
				if ok {
					select {
					case out <- Result{Addr: addr, Latency: lat}:
					case <-ctx.Done():
					}
				}
				if onProgress != nil {
					mu.Lock()
					done++
					d := done
					mu.Unlock()
					onProgress(d)
				}
			}(h)
		}
		wg.Wait()
	}()

	return out
}

func dial(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (time.Duration, bool) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := net.Dialer{}
	start := time.Now()
	conn, err := d.DialContext(dctx, "tcp4", net.JoinHostPort(addr.String(), itoa(port)))
	if err != nil {
		return 0, false
	}
	lat := time.Since(start)
	_ = conn.Close()
	return lat, true
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [6]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

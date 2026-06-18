// Package xray implements Stage 2: it generates Xray configs, runs xray-core as
// a subprocess, and measures REAL proxied latency by sending HTTP requests
// through the local proxy. Only IPs that complete real traffic within the
// latency budget are accepted. Candidates are tested in batches: one xray
// process serves many candidates at once (the v2rayN approach), so process
// spawn cost is amortised across the batch.
package xray

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"sort"
	"sync"
	"time"

	"cdnscan/internal/link"
)

// ProberOptions configures Stage 2 behaviour and the accuracy controls used to
// drive the false-positive / false-negative rate toward near-zero.
type ProberOptions struct {
	XrayPath     string        // path to xray-core binary
	Outbound     *link.Outbound
	ProbeURL     string        // real request target, e.g. https://www.gstatic.com/generate_204
	Probes       int           // measured probes per candidate (after warmup)
	Confirm      int           // required successes out of Probes to accept
	MaxLatency   time.Duration // median latency budget
	ProbeTimeout time.Duration // per-request timeout
	Startup      time.Duration // max wait for xray inbound to come up
	// BatchConcurrency caps simultaneous probes within ONE batch process. A full
	// 50-wide burst of TLS handshakes through a single xray causes contention
	// timeouts (false negatives) and a CPU spike (lag); a modest cap fixes both.
	BatchConcurrency int
}

// TestResult captures the outcome of probing one candidate IP.
type TestResult struct {
	Addr      netip.Addr
	OK        bool
	Median    time.Duration
	Successes int
	Total     int
	Err       string
}

// BatchItem is one candidate to probe in a batch.
type BatchItem struct {
	Addr netip.Addr
	Port int
}

// Prober runs Stage 2. It is safe for concurrent use: each TestBatch call runs
// its own xray process serving its own set of inbound ports.
type Prober struct {
	opt ProberOptions
}

// NewProber validates options and returns a ready prober.
func NewProber(opt ProberOptions) (*Prober, error) {
	if opt.XrayPath == "" {
		return nil, fmt.Errorf("xray path required")
	}
	if opt.Outbound == nil {
		return nil, fmt.Errorf("outbound template required")
	}
	if opt.Probes <= 0 {
		opt.Probes = 5
	}
	if opt.Confirm <= 0 {
		opt.Confirm = (opt.Probes / 2) + 1
	}
	if opt.Confirm > opt.Probes {
		opt.Confirm = opt.Probes
	}
	if opt.ProbeURL == "" {
		opt.ProbeURL = "https://www.gstatic.com/generate_204"
	}
	if opt.MaxLatency <= 0 {
		opt.MaxLatency = time.Second
	}
	if opt.ProbeTimeout <= 0 {
		// A probe slower than the latency budget is already a reject, so there
		// is no point waiting much longer than that. Derive a tight default
		// from MaxLatency (2x, floored at 1.5s) instead of a flat 5s: this
		// slashes the time wasted on TCP-open-but-dead IPs (which otherwise
		// burn the full timeout on every failed probe) without rejecting any
		// IP that would actually pass the median-latency check.
		opt.ProbeTimeout = max(2*opt.MaxLatency, 1500*time.Millisecond)
	}
	if opt.Startup <= 0 {
		opt.Startup = 5 * time.Second
	}
	if opt.BatchConcurrency <= 0 {
		opt.BatchConcurrency = 10
	}
	return &Prober{opt: opt}, nil
}

// TestBatch probes a set of candidates through a SINGLE xray process: it builds
// one config wiring each candidate to its own local inbound port, starts xray
// once, then probes every port concurrently. Results are returned index-aligned
// to items. This amortises the (expensive) process spawn across the whole batch.
func (p *Prober) TestBatch(ctx context.Context, items []BatchItem) []TestResult {
	res := make([]TestResult, len(items))
	for i, it := range items {
		res[i] = TestResult{Addr: it.Addr, Total: p.opt.Probes}
	}
	if len(items) == 0 {
		return res
	}

	setErr := func(msg string) []TestResult {
		for i := range res {
			res[i].Err = msg
		}
		return res
	}

	ports, err := freePorts(len(items))
	if err != nil {
		return setErr("alloc ports: " + err.Error())
	}
	targets := make([]BatchTarget, len(items))
	for i, it := range items {
		targets[i] = BatchTarget{IP: it.Addr.String(), Port: it.Port, InboundPort: ports[i]}
	}
	cfg, err := GenerateBatchConfig(p.opt.Outbound, targets)
	if err != nil {
		return setErr("gen config: " + err.Error())
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, p.opt.XrayPath, "run", "-c", "stdin:")
	cmd.Stdin = bytes.NewReader(cfg)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = childSysProcAttr() // below-normal priority + no window (Windows)
	if err := cmd.Start(); err != nil {
		return setErr("start xray: " + err.Error())
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	// Wait for the inbounds to come up. They bind in order at startup, so once
	// the LAST port is listening the whole batch is ready; then a short grace.
	if !waitPort(runCtx, ports[len(ports)-1], p.opt.Startup) {
		return setErr("xray inbounds did not start")
	}
	select {
	case <-time.After(200 * time.Millisecond):
	case <-runCtx.Done():
	}

	// Probe candidates concurrently, but cap simultaneous probes: a 50-wide burst
	// of TLS handshakes through one process causes contention timeouts (rejecting
	// good IPs) and a CPU spike. Limiting to BatchConcurrency fixes both.
	sem := make(chan struct{}, p.opt.BatchConcurrency)
	var wg sync.WaitGroup
	for i := range items {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			res[i] = p.probeEndpoint(runCtx, ctx, ports[i], items[i].Addr)
		}(i)
	}
	wg.Wait()
	return res
}

// probeEndpoint runs the warmup + fail-fast K-of-N latency measurement for one
// candidate against an already-running inbound on the given local port. runCtx
// bounds the xray process lifetime; parentCtx signals overall cancellation.
func (p *Prober) probeEndpoint(runCtx, parentCtx context.Context, inboundPort int, addr netip.Addr) TestResult {
	res := TestResult{Addr: addr, Total: p.opt.Probes}
	client := p.proxyClient(inboundPort)

	// Warmup request (establishes the proxied tunnel); result discarded so the
	// connection-setup cost does not skew the measured median. Capped to a short
	// timeout so a dead backend doesn't waste the full probe budget here.
	warmTO := p.opt.ProbeTimeout
	if warmTO > 2*time.Second {
		warmTO = 2 * time.Second
	}
	_, _ = p.probeOnce(runCtx, client, warmTO)

	// Fail-fast K-of-N: stop as soon as the outcome is decided.
	//   - accept path: break once we have Confirm successes
	//   - reject path: break once failures make Confirm unreachable
	// Both cut wasted time on slow/dead IPs without weakening the accept rule
	// (median latency is still checked below).
	maxFails := p.opt.Probes - p.opt.Confirm
	var lats []time.Duration
	fails, attempts := 0, 0
	for i := 0; i < p.opt.Probes; i++ {
		select {
		case <-parentCtx.Done():
			res.Err = "cancelled"
			res.Total = attempts
			return res
		default:
		}
		attempts++
		if d, ok := p.probeOnce(runCtx, client, p.opt.ProbeTimeout); ok {
			lats = append(lats, d)
			if len(lats) >= p.opt.Confirm {
				break
			}
		} else {
			fails++
			if fails > maxFails {
				break
			}
		}
	}

	res.Total = attempts
	res.Successes = len(lats)
	if len(lats) > 0 {
		res.Median = median(lats)
	}
	res.OK = res.Successes >= p.opt.Confirm && res.Median > 0 && res.Median <= p.opt.MaxLatency
	return res
}

func (p *Prober) proxyClient(inboundPort int) *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", itoa(inboundPort))}
	tr := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DisableKeepAlives:   false,
		MaxIdleConns:        2,
		TLSHandshakeTimeout: p.opt.ProbeTimeout,
	}
	return &http.Client{Transport: tr, Timeout: p.opt.ProbeTimeout}
}

func (p *Prober) probeOnce(ctx context.Context, client *http.Client, timeout time.Duration) (time.Duration, bool) {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, p.opt.ProbeURL, nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, false
	}
	return time.Since(start), true
}

// freePorts reserves n distinct free loopback ports. It opens all n listeners,
// simultaneously (so the ports are guaranteed distinct), records them, then
// closes them right before xray binds. The brief close->bind window can race in
// theory; a lost port just means that candidate's probes fail and it's dropped.
func freePorts(n int) ([]int, error) {
	listeners := make([]net.Listener, 0, n)
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, x := range listeners {
				_ = x.Close()
			}
			return nil, err
		}
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	return ports, nil
}

func waitPort(ctx context.Context, port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func median(ds []time.Duration) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	n := len(s)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

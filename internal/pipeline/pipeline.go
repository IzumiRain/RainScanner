// Package pipeline wires the stages together: fetch ranges -> expand -> TCP
// pre-filter -> Xray real-latency confirmation -> ranked output, per CDN.
package pipeline

import (
	"context"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"

	"cdnscan/internal/iprange"
	"cdnscan/internal/output"
	"cdnscan/internal/providers"
	"cdnscan/internal/scan"
	"cdnscan/internal/xray"
)

// Concurrency tiers. Stage 2 now tests candidates in BATCHES: one xray process
// serves BatchSize candidates at once (v2rayN approach), so XrayConcurrency is
// the number of concurrent xray PROCESSES, not per-candidate workers. Total
// probes in flight ≈ XrayConcurrency * BatchSize. Few processes keep spawn churn
// (the real lag source) low while each batch still fans out widely.
const (
	LiteXrayConcurrency = 1 // one xray process at a time
	LiteTCPConcurrency  = 100
	LiteBatchSize       = 25
	DefaultBatchSize    = 50 // candidates per xray process
)

// DefaultXrayConcurrency = max concurrent xray processes (batches). Kept small:
// process spawn/teardown is what froze the desktop, and each process already
// probes BatchSize candidates in parallel, so a handful of processes is plenty.
func DefaultXrayConcurrency() int {
	return min(max(runtime.NumCPU()/6, 1), 3) // 12 CPUs -> 2 processes
}

// DefaultTCPConcurrency keeps stage-1 in-flight dials moderate (64..128).
// Stage 1 is kernel/firewall-bound — every connect attempt traverses the Windows
// Filtering Platform + Defender — so flooding it lags the whole system in a way
// process priority can't fix. Lower in-flight = smoother desktop.
func DefaultTCPConcurrency() int {
	return min(max(runtime.NumCPU()*8, 64), 128)
}

// Config holds everything a run needs.
type Config struct {
	CDNs            []string
	Custom          *CustomTarget // when set, scan these CIDRs instead of CDNs
	Ports           []int         // ports to TCP-scan; empty falls back to TCP.Port
	IPsDir          string
	ResultsDir      string
	ForceRefresh    bool
	PreferBackup    bool // try backup source before official API
	NoBackup        bool // use official CDN API only; skip backup mirror
	Sample          iprange.Strategy
	TCP             scan.Options
	Prober          *xray.Prober
	XrayConcurrency int // max concurrent xray processes (batches)
	BatchSize       int // candidates tested per xray process (0 = default)
	CandidatePort   int
	HTTPClient      *http.Client
	Log             func(format string, args ...any)
	Progress        func(p Progress)
}

// CustomTarget is a user-supplied named set of CIDR ranges, used instead of a
// registered CDN provider.
type CustomTarget struct {
	Name  string
	CIDRs []string
}

// Progress reports how far the current stage has advanced.
type Progress struct {
	CDN   string `json:"cdn"`
	Stage string `json:"stage"` // "tcp" | "xray"
	Done  int    `json:"done"`
	Total int    `json:"total"`
}

// Endpoint is one reachable IP:port found by the TCP pre-filter.
type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Summary reports per-CDN outcome.
type Summary struct {
	CDN       string         `json:"cdn"`
	Ranges    int            `json:"ranges"`
	Hosts     int            `json:"hosts"`
	TCPOpen   int            `json:"tcp_open"`
	Confirmed int            `json:"confirmed"`
	OutPath   string         `json:"out_path"`
	Endpoints []Endpoint     `json:"endpoints"` // TCP-reachable IP:port survivors
	Entries   []output.Entry `json:"entries"`   // Xray-confirmed clean IPs
}

// Run executes the full pipeline for each selected CDN.
func Run(ctx context.Context, cfg Config) ([]Summary, error) {
	if cfg.Log == nil {
		cfg.Log = func(string, ...any) {}
	}
	if cfg.XrayConcurrency <= 0 {
		cfg.XrayConcurrency = DefaultXrayConcurrency()
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.CandidatePort <= 0 {
		cfg.CandidatePort = cfg.TCP.Port
	}

	if cfg.Custom != nil {
		s, err := runOne(ctx, cfg, cfg.Custom.Name, cfg.Custom.CIDRs)
		if err != nil {
			cfg.Log("[%s] error: %v", cfg.Custom.Name, err)
			return nil, nil
		}
		return []Summary{s}, nil
	}

	var summaries []Summary
	for _, cdn := range cfg.CDNs {
		s, err := runOne(ctx, cfg, cdn, nil)
		if err != nil {
			cfg.Log("[%s] error: %v", cdn, err)
			continue
		}
		summaries = append(summaries, s)
	}
	return summaries, nil
}

// ports returns the configured scan ports, falling back to the single TCP.Port.
func (cfg Config) ports() []int {
	if len(cfg.Ports) > 0 {
		return cfg.Ports
	}
	return []int{cfg.TCP.Port}
}

// runOne scans a single target. When cidrs is nil the ranges are fetched from
// the registered provider named by `name`; otherwise the given CIDRs are used
// directly (custom-range mode).
func runOne(ctx context.Context, cfg Config, name string, cidrs []string) (Summary, error) {
	s := Summary{CDN: name}

	if cidrs == nil {
		rf, err := providers.LoadOrRefresh(ctx, cfg.HTTPClient, name, cfg.IPsDir, cfg.ForceRefresh,
			providers.FetchOptions{PreferBackup: cfg.PreferBackup, NoBackup: cfg.NoBackup})
		if err != nil {
			return s, err
		}
		cidrs = rf.CIDRs
		s.Ranges = len(cidrs)
		if rf.Source != "" {
			cfg.Log("[%s] %d CIDR ranges (source: %s)", name, len(cidrs), rf.Source)
		} else {
			cfg.Log("[%s] %d CIDR ranges", name, len(cidrs))
		}
	} else {
		cidrs = iprange.FilterV4(cidrs)
		s.Ranges = len(cidrs)
		cfg.Log("[%s] %d CIDR ranges", name, len(cidrs))
	}

	hosts, err := iprange.Expand(cidrs, cfg.Sample)
	if err != nil {
		return s, err
	}
	s.Hosts = len(hosts)
	cfg.Log("[%s] expanded to %d candidate IPs", name, len(hosts))

	// Stage 1: TCP pre-filter across all configured ports.
	survivors := stage1(ctx, cfg, name, hosts)
	s.TCPOpen = len(survivors)
	s.Endpoints = survivors
	cfg.Log("[%s] stage1: %d reachable endpoint(s) on ports %v", name, len(survivors), cfg.ports())

	// Stage 2: Xray real-latency confirmation.
	entries := stage2(ctx, cfg, name, survivors)
	s.Confirmed = len(entries)
	cfg.Log("[%s] stage2: %d confirmed clean IPs", name, len(entries))

	path, err := output.Write(cfg.ResultsDir, name, entries)
	if err != nil {
		return s, err
	}
	s.OutPath = path
	s.Entries = entries
	return s, nil
}

func stage1(ctx context.Context, cfg Config, cdn string, hosts []netip.Addr) []Endpoint {
	ports := cfg.ports()
	total := len(hosts) * len(ports)
	step := total / 100
	if step < 1 {
		step = 1
	}
	var (
		survivors []Endpoint
		base      int // hosts already processed in completed port passes
	)
	for _, port := range ports {
		opt := cfg.TCP
		opt.Port = port
		offset := base
		resCh := scan.Run(ctx, hosts, opt, func(done int) {
			d := offset + done
			if cfg.Progress != nil && (d == total || d%step == 0) {
				cfg.Progress(Progress{CDN: cdn, Stage: "tcp", Done: d, Total: total})
			}
		})
		for r := range resCh {
			survivors = append(survivors, Endpoint{IP: r.Addr.String(), Port: port})
		}
		base += len(hosts)
	}
	return survivors
}

// stage2 confirms survivors via real proxied latency. Candidates are grouped
// into batches of cfg.BatchSize; each batch is tested by a single xray process,
// and up to cfg.XrayConcurrency batches run concurrently. This amortises the
// expensive per-process spawn — the dominant Stage-2 cost — across the batch.
func stage2(ctx context.Context, cfg Config, cdn string, survivors []Endpoint) []output.Entry {
	if cfg.Prober == nil || len(survivors) == 0 {
		return nil
	}
	total := len(survivors)
	step := total / 100
	if step < 1 {
		step = 1
	}

	batches := chunkEndpoints(survivors, cfg.BatchSize)
	sem := make(chan struct{}, cfg.XrayConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var entries []output.Entry
	var done int64

	for _, batch := range batches {
		select {
		case <-ctx.Done():
			wg.Wait()
			return entries
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(batch []Endpoint) {
			defer wg.Done()
			defer func() { <-sem }()

			items := make([]xray.BatchItem, 0, len(batch))
			idx := make([]Endpoint, 0, len(batch)) // index-aligned to items
			for _, ep := range batch {
				addr, err := netip.ParseAddr(ep.IP)
				if err != nil {
					nd := atomic.AddInt64(&done, 1)
					reportXrayProgress(cfg, cdn, int(nd), total, step)
					continue
				}
				items = append(items, xray.BatchItem{Addr: addr, Port: ep.Port})
				idx = append(idx, ep)
			}

			results := cfg.Prober.TestBatch(ctx, items)
			for i, tr := range results {
				ep := idx[i]
				if tr.OK {
					mu.Lock()
					entries = append(entries, output.Entry{
						IP:        ep.IP,
						Port:      ep.Port,
						MedianMS:  tr.Median.Milliseconds(),
						Successes: tr.Successes,
						Total:     tr.Total,
					})
					mu.Unlock()
					cfg.Log("[%s]  + %s:%d  median=%dms (%d/%d)", cdn, ep.IP, ep.Port, tr.Median.Milliseconds(), tr.Successes, tr.Total)
				}
				nd := atomic.AddInt64(&done, 1)
				reportXrayProgress(cfg, cdn, int(nd), total, step)
			}
		}(batch)
	}
	wg.Wait()
	return entries
}

func reportXrayProgress(cfg Config, cdn string, done, total, step int) {
	if cfg.Progress != nil && (done == total || done%step == 0) {
		cfg.Progress(Progress{CDN: cdn, Stage: "xray", Done: done, Total: total})
	}
}

// chunkEndpoints splits eps into slices of at most size.
func chunkEndpoints(eps []Endpoint, size int) [][]Endpoint {
	if size <= 0 {
		size = DefaultBatchSize
	}
	var out [][]Endpoint
	for i := 0; i < len(eps); i += size {
		end := min(i+size, len(eps))
		out = append(out, eps[i:end])
	}
	return out
}

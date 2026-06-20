// Package app is RainScanner's UI-agnostic core service. The web GUI, the CLI,
// and (later) the native app all drive scans and manage targets through Service,
// so behavior lives in exactly one place. Service owns the target registry, the
// scan engine wiring, and result reads, all behind the storage.Store port.
package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"cdnscan/internal/iprange"
	"cdnscan/internal/link"
	"cdnscan/internal/output"
	"cdnscan/internal/pipeline"
	"cdnscan/internal/providers"
	"cdnscan/internal/scan"
	"cdnscan/internal/storage"
	"cdnscan/internal/targets"
	"cdnscan/internal/xray"
)

// Service is the core facade.
type Service struct {
	reg        *targets.Registry
	store      storage.Store
	ipsDir     string
	resultsDir string
}

// New opens the registry over the store and returns a ready Service. ipsDir and
// resultsDir are retained for the scan engine's range cache + result writes.
// New also loads and installs the CDN manifest so built-in names are available.
func New(store storage.Store, ipsDir, resultsDir string) (*Service, error) {
	// Load the CDN manifest (best-effort; uses local cache on network failure).
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	manifest, err := providers.LoadManifest(ctx, &http.Client{Timeout: 8 * time.Second}, ipsDir)
	if err != nil {
		log.Printf("warning: could not load CDN manifest (%v); defaults unavailable until network restored", err)
		manifest = &providers.ManifestIndex{}
	}
	providers.SetManifest(manifest)

	reg, err := targets.Open(store)
	if err != nil {
		return nil, err
	}
	return &Service{reg: reg, store: store, ipsDir: ipsDir, resultsDir: resultsDir}, nil
}

// Targets returns all stored targets (built-ins first, then customs).
func (s *Service) Targets() []targets.Record { return s.reg.List() }

// Ranges returns the named target record and whether it exists.
func (s *Service) Ranges(name string) (targets.Record, bool) { return s.reg.Get(name) }

// Upsert creates or updates a target (built-in range edit or a custom).
func (s *Service) Upsert(rec targets.Record) (targets.Record, error) { return s.reg.Upsert(rec) }

// Delete removes a custom target (built-ins are non-deletable: removed=false).
func (s *Service) Delete(name string) (bool, error) { return s.reg.Delete(name) }

// Reload re-fetches a single target's ranges from its feed and persists them.
func (s *Service) Reload(ctx context.Context, name string, opts providers.FetchOptions) (targets.Record, error) {
	return s.reg.Reload(ctx, &http.Client{Timeout: 30 * time.Second}, name, opts)
}

// ReloadResult is one target's outcome in ReloadAll.
type ReloadResult struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

// ReloadAll re-fetches every target that has an API URL. Always returns a
// per-target summary; one dead feed doesn't fail the rest.
func (s *Service) ReloadAll(ctx context.Context, opts providers.FetchOptions) []ReloadResult {
	client := &http.Client{Timeout: 30 * time.Second}
	var out []ReloadResult
	for _, rec := range s.reg.List() {
		if rec.APIURL == "" {
			continue
		}
		res := ReloadResult{Name: rec.Name}
		if rr, err := s.reg.Reload(ctx, client, rec.Name, opts); err != nil {
			res.Error = err.Error()
		} else {
			res.Count = len(rr.CIDRs)
		}
		out = append(out, res)
	}
	return out
}

// Results returns the saved results for a target.
func (s *Service) Results(name string) (*output.ResultFile, error) { return s.store.Results(name) }

// CustomRange is an ad-hoc named CIDR set scanned directly (not stored).
type CustomRange struct {
	Name  string
	CIDRs []string
}

// ScanRequest is the transport-neutral description of a scan. Front-ends
// translate their own input (HTTP JSON, CLI flags) into this.
type ScanRequest struct {
	CDN             string
	Custom          *CustomRange
	Ports           []int
	Port            int
	Link            string
	XrayPath        string
	TCPConcurrency  int
	TCPTimeoutMS    int
	XrayConcurrency int
	BatchSize       int
	Probes          int
	Confirm         int
	MaxLatencyMS    int
	ProbeTimeoutMS  int
	ProbeURL        string
	SamplePer24     int
	MaxHostsPerCIDR int
	MaxTotal        int
	Lite            bool
	Refresh         bool
	PreferBackup    bool
	NoBackup        bool
}

// ScanHooks carry live log/progress callbacks (nil-safe).
type ScanHooks struct {
	Log      func(string, ...any)
	Progress func(pipeline.Progress)
}

// Scan builds the pipeline config from req and runs it. Target resolution: an
// explicit Custom wins; otherwise the named CDN is resolved from the registry so
// GUI edits to its ranges take effect (unless Refresh forces a re-fetch).
func (s *Service) Scan(ctx context.Context, req ScanRequest, hooks ScanHooks) ([]pipeline.Summary, error) {
	cfg, err := s.buildConfig(req)
	if err != nil {
		return nil, err
	}
	cfg.Log = hooks.Log
	cfg.Progress = hooks.Progress
	return pipeline.Run(ctx, cfg)
}

func (s *Service) buildConfig(req ScanRequest) (pipeline.Config, error) {
	port := orInt(req.Port, 443)

	var prober *xray.Prober
	if req.Link != "" {
		ob, err := link.Parse(req.Link)
		if err != nil {
			return pipeline.Config{}, fmt.Errorf("parse link: %w", err)
		}
		bin, err := xray.Resolve(req.XrayPath)
		if err != nil {
			return pipeline.Config{}, err
		}
		prober, err = xray.NewProber(xray.ProberOptions{
			XrayPath:     bin,
			Outbound:     ob,
			ProbeURL:     req.ProbeURL,
			Probes:       orInt(req.Probes, 5),
			Confirm:      orInt(req.Confirm, 3),
			MaxLatency:   time.Duration(orInt(req.MaxLatencyMS, 800)) * time.Millisecond,
			ProbeTimeout: time.Duration(req.ProbeTimeoutMS) * time.Millisecond,
		})
		if err != nil {
			return pipeline.Config{}, err
		}
	}

	ports := req.Ports
	if len(ports) == 0 {
		ports = []int{port}
	}

	tcpConc := orInt(req.TCPConcurrency, pipeline.DefaultTCPConcurrency())
	xrayConc := req.XrayConcurrency
	batchSize := req.BatchSize
	if req.Lite {
		tcpConc = pipeline.LiteTCPConcurrency
		xrayConc = pipeline.LiteXrayConcurrency
		batchSize = pipeline.LiteBatchSize
	}

	cfg := pipeline.Config{
		Ports:        ports,
		IPsDir:       s.ipsDir,
		ResultsDir:   s.resultsDir,
		ForceRefresh: req.Refresh,
		PreferBackup: req.PreferBackup,
		NoBackup:     req.NoBackup,
		Sample: iprange.Strategy{
			SamplePer24:     req.SamplePer24,
			MaxHostsPerCIDR: req.MaxHostsPerCIDR,
			MaxTotal:        req.MaxTotal,
		},
		TCP:             scan.Options{Port: port, Concurrency: tcpConc, Timeout: time.Duration(orInt(req.TCPTimeoutMS, 3000)) * time.Millisecond},
		Prober:          prober,
		XrayConcurrency: xrayConc,
		BatchSize:       batchSize,
		CandidatePort:   port,
		HTTPClient:      &http.Client{Timeout: 20 * time.Second},
	}

	switch {
	case req.Custom != nil:
		cfg.Custom = &pipeline.CustomTarget{Name: req.Custom.Name, CIDRs: req.Custom.CIDRs}
	default:
		if rec, ok := s.reg.Get(req.CDN); ok && len(rec.CIDRs) > 0 && !req.Refresh {
			cfg.Custom = &pipeline.CustomTarget{Name: rec.Name, CIDRs: rec.CIDRs}
		} else {
			cfg.CDNs = []string{req.CDN}
		}
	}
	return cfg, nil
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

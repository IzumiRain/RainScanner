// Package web serves a self-contained browser GUI for cdnscan: an embedded
// single-page app plus a JSON/SSE API that streams live scan progress.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"cdnscan/internal/iprange"
	"cdnscan/internal/link"
	"cdnscan/internal/output"
	"cdnscan/internal/pipeline"
	"cdnscan/internal/scan"
	"cdnscan/internal/targets"
	"cdnscan/internal/xray"
)

//go:embed static/*
var assets embed.FS

// Server hosts the GUI and scan API.
type Server struct {
	ipsDir     string
	resultsDir string
	store      *targets.Store

	mu     sync.Mutex
	jobs   map[string]*job
	nextID int

	// scanning guards against concurrent scans: only one runs at a time, so a
	// user can't stack three CPU-pegging scans by hammering Start.
	scanning atomic.Bool

	// cancel stops the scan currently in progress; nil when idle. Guarded by mu.
	cancel context.CancelFunc
}

// NewServer builds a GUI server writing caches/results under the given dirs. The
// persistent target store is opened (and seeded on first run) under ipsDir.
func NewServer(ipsDir, resultsDir string) *Server {
	store, err := targets.Open(ipsDir)
	if err != nil {
		// A broken store shouldn't take down the GUI; fall back to an empty one
		// so built-in scanning via the registry still works.
		log.Printf("targets store: %v (continuing with empty store)", err)
		store, _ = targets.Open(os.TempDir())
	}
	return &Server{ipsDir: ipsDir, resultsDir: resultsDir, store: store, jobs: map[string]*job{}}
}

// Listen binds addr and serves (blocking). It is shorthand for Bind+Serve.
func (s *Server) Listen(addr string) error {
	ln, err := s.Bind(addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Bind reserves the listen address. A failure here (e.g. address in use) lets
// the caller detect that another instance already owns the port and act on it
// instead of starting a duplicate server.
func (s *Server) Bind(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// Serve runs the HTTP server on an already-bound listener (blocking).
func (s *Server) Serve(ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	if staticFS, err := fs.Sub(assets, "static"); err == nil {
		mux.Handle("/static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))
	}
	mux.HandleFunc("/api/cdns", s.handleCDNs)
	mux.HandleFunc("/api/ranges", s.handleRanges)
	mux.HandleFunc("/api/targets", s.handleTargets)
	mux.HandleFunc("/api/targets/reload", s.handleTargetReload)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/stop", s.handleStop)
	mux.HandleFunc("/api/stream", s.handleStream)
	mux.HandleFunc("/api/xray/version", s.handleXrayVersion)
	mux.HandleFunc("/api/xray/update", s.handleXrayUpdate)
	return http.Serve(ln, mux)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := assets.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// handleCDNs returns just the target names, kept for backward compatibility.
// The GUI now uses /api/targets for the full editable records.
func (s *Server) handleCDNs(w http.ResponseWriter, r *http.Request) {
	recs := s.store.List()
	names := make([]string, 0, len(recs))
	for _, t := range recs {
		names = append(names, t.Name)
	}
	writeJSON(w, names)
}

// handleRanges returns the stored CIDR ranges for a target so the GUI can preview
// the "Selected Ranges" panel before a scan.
func (s *Server) handleRanges(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("cdn")
	if name == "" {
		http.Error(w, "missing cdn", http.StatusBadRequest)
		return
	}
	rec, ok := s.store.Get(name)
	if !ok {
		http.Error(w, "unknown target", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"name": rec.Name, "count": len(rec.CIDRs), "cidrs": rec.CIDRs})
}

// handleTargets is the CRUD endpoint for the persistent target store:
//
//	GET    -> list all targets ({name,cidrs,api_url,builtin})
//	POST   -> create/update one target (body: a single record)
//	DELETE -> remove a target by ?name=
func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.store.List())

	case http.MethodPost:
		var rec targets.Record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		saved, err := s.store.Upsert(rec)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, saved)

	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		removed, err := s.store.Delete(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]bool{"removed": removed})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTargetReload re-fetches a target's ranges from its API URL and persists
// them, returning the refreshed record. Body: {"name":"..."}.
func (s *Server) handleTargetReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	client := &http.Client{Timeout: 30 * time.Second}
	rec, err := s.store.Reload(r.Context(), client, req.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, rec)
}

type customReq struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

type scanReq struct {
	CDN             string     `json:"cdn"`
	Custom          *customReq `json:"custom"`
	Ports           []int      `json:"ports"`
	Link            string     `json:"link"`
	XrayPath        string     `json:"xray_path"`
	Port            int        `json:"port"`
	TCPConcurrency  int        `json:"tcp_concurrency"`
	XrayConcurrency int        `json:"xray_concurrency"` // max concurrent xray processes
	BatchSize       int        `json:"batch_size"`       // candidates per xray process (0 = default)
	Probes          int        `json:"probes"`
	Confirm         int        `json:"confirm"`
	MaxLatencyMS    int        `json:"max_latency_ms"`
	ProbeTimeoutMS  int        `json:"probe_timeout_ms"` // 0 = auto (derive from max latency)
	ProbeURL        string     `json:"probe_url"`
	SamplePer24     int        `json:"sample_per_24"`
	MaxHostsPerCIDR int        `json:"max_hosts_per_cidr"`
	MaxTotal        int        `json:"max_total"` // random-sample cap across the whole pool (0 = all)
	Lite            bool       `json:"lite"`      // low-power mode: hard-cap concurrency
	Refresh         bool       `json:"refresh"`
}

// scanResult is the consolidated payload sent in the SSE "result" event for the
// single-target GUI scan.
type scanResult struct {
	CDN          string         `json:"cdn"`
	Ranges       int            `json:"ranges"`
	Hosts        int            `json:"hosts"`
	TCPOpen      int            `json:"tcp_open"`
	Confirmed    int            `json:"confirmed"`
	TCPIPs       []string       `json:"tcp_ips"`       // unique TCP-reachable IPs (copy-only-IPs)
	Endpoints    []pipeline.Endpoint `json:"endpoints"` // IP:port detail
	ConfirmedIPs []string       `json:"confirmed_ips"` // Xray-confirmed IPs
	Entries      []output.Entry `json:"entries"`       // confirmed w/ latency
	Configs      []string       `json:"configs"`       // links with clean IP substituted
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req scanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Custom == nil && req.CDN == "" {
		http.Error(w, "select a CDN or add a custom range", http.StatusBadRequest)
		return
	}
	if req.Custom != nil && len(req.Custom.CIDRs) == 0 {
		http.Error(w, "custom range has no CIDRs", http.StatusBadRequest)
		return
	}

	cfg, err := s.buildConfig(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// One scan at a time. Reject (not queue) so the UI can tell the user plainly.
	if !s.scanning.CompareAndSwap(false, true) {
		http.Error(w, "a scan is already running — wait for it to finish or stop it first", http.StatusConflict)
		return
	}

	j := s.newJob()
	cfg.Log = func(format string, a ...any) { j.push(event{Type: "log", Line: fmt.Sprintf(format, a...)}) }
	cfg.Progress = func(p pipeline.Progress) { j.push(event{Type: "progress", Data: p}) }

	go func() {
		defer s.scanning.Store(false)
		ctx, cancel := context.WithCancel(context.Background())
		s.mu.Lock()
		s.cancel = cancel
		s.mu.Unlock()
		defer func() {
			cancel()
			s.mu.Lock()
			s.cancel = nil
			s.mu.Unlock()
		}()
		j.push(event{Type: "log", Line: "scan started"})
		summaries, err := pipeline.Run(ctx, cfg)
		if err != nil {
			j.push(event{Type: "error", Line: err.Error()})
		}
		j.push(event{Type: "result", Data: buildResult(summaries, req.Link)})
		j.finish()
	}()

	writeJSON(w, map[string]string{"id": j.id})
}

// handleStop cancels the scan currently in progress. The running goroutine owns
// the scan context; cancelling it unwinds stage1/stage2 and kills any live xray
// child processes (they are started with exec.CommandContext on this context).
// A no-op when nothing is running.
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	writeJSON(w, map[string]bool{"stopping": true})
}

// resolveXrayPath picks the xray binary to inspect/update: an explicit path wins,
// then PATH/local discovery; if nothing is found yet it falls back to a default
// local name so a first-time install lands next to the scanner.
func resolveXrayPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p, err := xray.FindBinary(""); err == nil {
		return p
	}
	if runtime.GOOS == "windows" {
		return "xray.exe"
	}
	return "xray"
}

// handleXrayVersion reports the installed xray-core version vs the latest release.
// Optional ?path= overrides which binary is inspected.
func (s *Server) handleXrayVersion(w http.ResponseWriter, r *http.Request) {
	bin := resolveXrayPath(r.URL.Query().Get("path"))
	client := &http.Client{Timeout: 20 * time.Second}
	info, err := xray.CheckUpdate(r.Context(), client, bin)
	if err != nil {
		// Still surface what we know (e.g. installed version) alongside the error.
		writeJSON(w, map[string]any{
			"current":          info.Current,
			"latest":           info.Latest,
			"asset":            info.Asset,
			"update_available": info.UpdateAvailable,
			"supported":        info.Supported,
			"error":            err.Error(),
		})
		return
	}
	writeJSON(w, info)
}

// handleXrayUpdate downloads and installs the latest xray-core (binary + geo data).
// It refuses while a scan is running so it can't replace a binary mid-use.
func (s *Server) handleXrayUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if s.scanning.Load() {
		http.Error(w, "a scan is running; stop it before updating xray", http.StatusConflict)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	bin := resolveXrayPath(req.Path)
	client := &http.Client{Timeout: 5 * time.Minute}
	version, err := xray.Update(r.Context(), client, bin, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "version": version})
}

// buildResult flattens the single-target summary into the GUI payload, deriving
// the TCP-reachable IP list and, when a link was provided, the per-IP configs
// with the clean candidate substituted in.
func buildResult(summaries []pipeline.Summary, rawLink string) scanResult {
	var res scanResult
	if len(summaries) == 0 {
		return res
	}
	s := summaries[0]
	res = scanResult{
		CDN: s.CDN, Ranges: s.Ranges, Hosts: s.Hosts,
		TCPOpen: s.TCPOpen, Confirmed: s.Confirmed,
		Endpoints: s.Endpoints, Entries: s.Entries,
	}

	seen := map[string]bool{}
	for _, ep := range s.Endpoints {
		if !seen[ep.IP] {
			seen[ep.IP] = true
			res.TCPIPs = append(res.TCPIPs, ep.IP)
		}
	}
	for _, e := range s.Entries {
		res.ConfirmedIPs = append(res.ConfirmedIPs, e.IP)
		if rawLink != "" {
			if cfg, err := link.Substitute(rawLink, e.IP, e.Port); err == nil {
				res.Configs = append(res.Configs, cfg)
			}
		}
	}
	return res
}

func (s *Server) buildConfig(req scanReq) (pipeline.Config, error) {
	port := orInt(req.Port, 443)

	var prober *xray.Prober
	if req.Link != "" {
		ob, err := link.Parse(req.Link)
		if err != nil {
			return pipeline.Config{}, fmt.Errorf("parse link: %w", err)
		}
		bin, err := xray.FindBinary(req.XrayPath)
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
			ProbeTimeout: time.Duration(req.ProbeTimeoutMS) * time.Millisecond, // 0 => auto-derive in NewProber
		})
		if err != nil {
			return pipeline.Config{}, err
		}
	}

	ports := req.Ports
	if len(ports) == 0 {
		ports = []int{port}
	}

	// Concurrency: Lite mode hard-caps everything for weak machines; otherwise
	// blank/0 means "auto" (see pipeline defaults). XrayConcurrency is concurrent
	// xray processes; BatchSize is candidates per process.
	tcpConc := orInt(req.TCPConcurrency, pipeline.DefaultTCPConcurrency())
	xrayConc := req.XrayConcurrency // 0 => pipeline auto
	batchSize := req.BatchSize      // 0 => pipeline default
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
		Sample: iprange.Strategy{
			SamplePer24:     req.SamplePer24,
			MaxHostsPerCIDR: req.MaxHostsPerCIDR,
			MaxTotal:        req.MaxTotal,
		},
		TCP:             scan.Options{Port: port, Concurrency: tcpConc, Timeout: 3 * time.Second},
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
		// Resolve the named target from the persistent store so GUI edits to a
		// built-in CDN's ranges take effect. If the stored record has ranges (or
		// the user forced a refresh-free run), scan those directly; otherwise fall
		// back to the compiled provider registry so a never-populated built-in
		// still fetches its feed on first scan.
		if rec, ok := s.store.Get(req.CDN); ok && len(rec.CIDRs) > 0 && !req.Refresh {
			cfg.Custom = &pipeline.CustomTarget{Name: rec.Name, CIDRs: rec.CIDRs}
		} else {
			cfg.CDNs = []string{req.CDN}
		}
	}
	return cfg, nil
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	j := s.jobs[id]
	s.mu.Unlock()
	if j == nil {
		http.Error(w, "unknown job", http.StatusNotFound)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	idx := 0
	for {
		evs, done := j.after(idx)
		for _, e := range evs {
			b, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", b)
			idx++
		}
		flusher.Flush()
		if done {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-j.wait():
		}
	}
}

// ---- job management ----

type event struct {
	Type string `json:"type"` // log | result | error | done
	Line string `json:"line,omitempty"`
	Data any    `json:"data,omitempty"`
}

type job struct {
	id     string
	mu     sync.Mutex
	events []event
	done   bool
	ch     chan struct{} // replaced on each push to broadcast
}

func (s *Server) newJob() *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	j := &job{id: strconv.Itoa(s.nextID), ch: make(chan struct{})}
	s.jobs[j.id] = j
	return j
}

func (j *job) push(e event) {
	j.mu.Lock()
	j.events = append(j.events, e)
	close(j.ch)
	j.ch = make(chan struct{})
	j.mu.Unlock()
}

func (j *job) finish() {
	j.mu.Lock()
	j.events = append(j.events, event{Type: "done"})
	j.done = true
	close(j.ch)
	j.ch = make(chan struct{})
	j.mu.Unlock()
}

// after returns events at/after idx and whether the job has finished.
func (j *job) after(idx int) ([]event, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []event
	if idx < len(j.events) {
		out = append(out, j.events[idx:]...)
	}
	return out, j.done && idx+len(out) >= len(j.events)
}

func (j *job) wait() <-chan struct{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.ch
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

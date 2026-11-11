package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"cdnscan/internal/iprange"
	"cdnscan/internal/link"
	"cdnscan/internal/output"
	"cdnscan/internal/pipeline"
	"cdnscan/internal/scan"
	"cdnscan/internal/xray"
)

// Opt in with RAINSCANNER_TEST_XRAY pointing to a real xray-core executable.
// All candidate addresses, upstream traffic, and credentials are local fixtures.
func TestRealXrayLocalPipeline(t *testing.T) {
	xrayPath := os.Getenv("RAINSCANNER_TEST_XRAY")
	if xrayPath == "" {
		t.Skip("set RAINSCANNER_TEST_XRAY to a real xray-core executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var slow atomic.Bool
	var targetHits atomic.Int64
	slowHit := make(chan struct{}, 1)
	releaseSlow := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		if slow.Load() {
			select {
			case slowHit <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
				return
			case <-releaseSlow:
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(func() {
		close(releaseSlow)
		target.CloseClientConnections()
		target.Close()
	})

	backendAddr := startRealXrayBackend(t, ctx, xrayPath)
	upstream, err := url.Parse("http://" + backendAddr)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	reverse := httputil.NewSingleHostReverseProxy(upstream)
	reverse.Transport = transport
	var accepted, rejected atomic.Int64
	gateListener := realXrayListen(t, "127.0.0.2:0")
	port := gateListener.Addr().(*net.TCPAddr).Port
	gate := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "origin.example" {
			rejected.Add(1)
			http.Error(w, "wrong virtual Host", http.StatusMisdirectedRequest)
			return
		}
		accepted.Add(1)
		reverse.ServeHTTP(w, r)
	})}
	gateDone := make(chan struct{})
	go func() {
		defer close(gateDone)
		_ = gate.Serve(gateListener)
	}()
	t.Cleanup(func() {
		_ = gate.Close()
		<-gateDone
	})

	// Stage 1 must keep this endpoint; only real tunneled traffic can reject it.
	bad := realXrayListen(t, net.JoinHostPort("127.0.0.3", strconv.Itoa(port)))
	badDone := make(chan struct{})
	go func() {
		defer close(badDone)
		for {
			conn, err := bad.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = bad.Close()
		<-badDone
	})

	const fixtureUUID = "11111111-1111-1111-1111-111111111111"
	original := fmt.Sprintf("vless://%s@origin.example:%d?type=ws&security=none&path=%%2Ffixture", fixtureUUID, port)
	prober := realXrayProber(t, xrayPath, original, target.URL)
	items := []xray.BatchItem{
		{Addr: netip.MustParseAddr("127.0.0.2"), Port: port},
		{Addr: netip.MustParseAddr("127.0.0.3"), Port: port},
	}
	results := prober.TestBatch(ctx, items)
	realXrayCandidateResults(t, results, items)
	realXrayConfirmed(t, results[0])
	if results[1].OK || results[1].Successes != 0 {
		t.Fatalf("TCP-only endpoint was confirmed: %+v", results[1])
	}

	cfg := pipeline.Config{
		Custom:          &pipeline.CustomTarget{Name: "real-ws", CIDRs: []string{"127.0.0.2/32", "127.0.0.3/32"}},
		Ports:           []int{port},
		ResultsDir:      t.TempDir(),
		Sample:          iprange.Strategy{Family: iprange.FamilyV4},
		TCP:             scan.Options{Port: port, Concurrency: 2, Timeout: 500 * time.Millisecond},
		Prober:          prober,
		XrayConcurrency: 1,
		BatchSize:       2,
	}
	summaries, err := pipeline.Run(ctx, cfg)
	if err != nil {
		t.Fatalf("real scanner pipeline: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("got %d summaries, want 1", len(summaries))
	}
	summary := summaries[0]
	if summary.TCPOpen != 2 || summary.Confirmed != 1 || len(summary.Entries) != 1 {
		t.Fatalf("want two TCP endpoints and only one confirmed endpoint: %+v", summary)
	}
	entry := summary.Entries[0]
	if entry.IP != items[0].Addr.String() || entry.Port != port || entry.Successes < 2 {
		t.Fatalf("wrong confirmed endpoint: %+v", entry)
	}
	if summary.OutPath != output.Path(cfg.ResultsDir, cfg.Custom.Name) {
		t.Fatalf("unexpected output path: %q", summary.OutPath)
	}
	before, err := os.ReadFile(summary.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved output.ResultFile
	if err := json.Unmarshal(before, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Count != 1 || len(saved.Results) != 1 || saved.Results[0] != entry {
		t.Fatalf("persisted output does not match real confirmation: %+v", saved)
	}

	// A fresh parser/prober must be able to use the exported link, not just the
	// original template whose implicit Host still came from origin.example.
	exported, err := link.Substitute(original, entry.IP, entry.Port)
	if err != nil {
		t.Fatal(err)
	}
	for _, replay := range []struct{ name, raw string }{
		{"exported", exported},
		{"explicit-host control", original + "&host=origin.example"},
	} {
		p := realXrayProber(t, xrayPath, replay.raw, target.URL)
		got := p.TestBatch(ctx, items[:1])
		realXrayCandidateResults(t, got, items[:1])
		if !got[0].OK {
			t.Fatalf("%s link failed through real virtual-host gate: %+v (rejected Hosts=%d)", replay.name, got[0], rejected.Load())
		}
		realXrayConfirmed(t, got[0])
	}
	if accepted.Load() == 0 || targetHits.Load() == 0 || rejected.Load() != 0 {
		t.Fatalf("virtual-host routing: accepted=%d rejected=%d target hits=%d", accepted.Load(), rejected.Load(), targetHits.Load())
	}

	// Cancel only after the request traverses Xray and reaches the slow target.
	// The seed is the actual successful pipeline output, not a synthetic file.
	slow.Store(true)
	scanCtx, stop := context.WithCancel(ctx)
	defer stop()
	runDone := make(chan struct{})
	var runErr error
	go func() {
		defer close(runDone)
		_, runErr = pipeline.Run(scanCtx, cfg)
	}()
	t.Cleanup(func() {
		stop()
		<-runDone
	})
	select {
	case <-slowHit:
		stop()
	case <-runDone:
		t.Fatalf("scan returned before reaching slow tunneled target: %v", runErr)
	case <-ctx.Done():
		t.Fatalf("waiting for slow tunneled target: %v", ctx.Err())
	}
	select {
	case <-runDone:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("canceled pipeline returned %v, want context.Canceled", runErr)
		}
	case <-ctx.Done():
		t.Fatalf("canceled pipeline did not return within test budget: %v", ctx.Err())
	}
	after, err := os.ReadFile(summary.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("canceled real scan replaced confirmed output:\nbefore: %s\nafter: %s", before, after)
	}
}

func realXrayProber(t *testing.T, path, raw, target string) *xray.Prober {
	t.Helper()
	outbound, err := link.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := xray.NewProber(xray.ProberOptions{
		XrayPath: path, Outbound: outbound, ProbeURL: target,
		Probes: 3, Confirm: 2, MaxLatency: time.Second,
		ProbeTimeout: 500 * time.Millisecond, Startup: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func realXrayCandidateResults(t *testing.T, results []xray.TestResult, items []xray.BatchItem) {
	t.Helper()
	if len(results) != len(items) {
		t.Fatalf("got %d batch results, want %d", len(results), len(items))
	}
	for i, result := range results {
		if xray.IsInfrastructureError(result.Err) {
			t.Fatalf("real Xray infrastructure failure for %v: %s", items[i], result.Err)
		}
		if result.Err != "" || result.Addr != items[i].Addr {
			t.Fatalf("unexpected batch result for %v: %+v", items[i], result)
		}
	}
}

func realXrayConfirmed(t *testing.T, result xray.TestResult) {
	t.Helper()
	if !result.OK || result.Successes < 2 || result.Total < 2 || result.Total > 3 || result.Median <= 0 || result.Median > time.Second {
		t.Fatalf("want real K-of-N confirmation within latency budget: %+v", result)
	}
}

func realXrayListen(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("listen on local fixture %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func startRealXrayBackend(t *testing.T, ctx context.Context, path string) string {
	t.Helper()
	reservation := realXrayListen(t, "127.0.0.1:0")
	addr := reservation.Addr().String()
	port := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "error"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": port, "protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": "11111111-1111-1111-1111-111111111111"}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network": "ws", "security": "none",
				"wsSettings": map[string]any{"path": "/fixture"},
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{
				// Recent Xray versions deny loopback unless explicitly allowed.
				"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}},
			},
		}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	processCtx, stop := context.WithCancel(ctx)
	cmd := exec.CommandContext(processCtx, path, "run", "-c", configPath)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		stop()
		t.Fatalf("start real Xray backend: %v", err)
	}
	exited := make(chan struct{})
	var exitErr error
	go func() {
		exitErr = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		stop()
		<-exited
		if t.Failed() {
			t.Logf("real Xray backend: %v\n%s", exitErr, logs.String())
		}
	})
	startupCtx, startupCancel := context.WithTimeout(ctx, 3*time.Second)
	defer startupCancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(startupCtx, "tcp4", addr)
		if err == nil {
			_ = conn.Close()
			return addr
		}
		select {
		case <-exited:
			t.Fatalf("real Xray backend exited during startup: %v\n%s", exitErr, logs.String())
		case <-startupCtx.Done():
			t.Fatalf("real Xray backend did not listen: %v", startupCtx.Err())
		case <-ticker.C:
		}
	}
}

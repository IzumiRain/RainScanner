package pipeline

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cdnscan/internal/iprange"
	"cdnscan/internal/link"
	"cdnscan/internal/output"
	"cdnscan/internal/providers"
	"cdnscan/internal/scan"
	"cdnscan/internal/xray"
)

func localConfig(t *testing.T) Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return Config{
		Custom:     &CustomTarget{Name: "demo", CIDRs: []string{"127.0.0.1/32"}},
		ResultsDir: t.TempDir(), IPsDir: t.TempDir(),
		Sample: iprange.Strategy{Family: iprange.FamilyV4},
		TCP:    scan.Options{Port: ln.Addr().(*net.TCPAddr).Port, Concurrency: 1, Timeout: 50 * time.Millisecond},
	}
}

func seededResults(t *testing.T, cfg Config) (string, []byte) {
	t.Helper()
	path, err := output.Write(cfg.ResultsDir, "demo", []output.Entry{{IP: "192.0.2.1", Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, before
}

func assertPreserved(t *testing.T, path string, before []byte) {
	t.Helper()
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("previous confirmed results changed: %s", after)
	}
}

func TestCanceledRunPreservesResults(t *testing.T) {
	for _, when := range []string{"before", "after-tcp", "before-write"} {
		t.Run(when, func(t *testing.T) {
			cfg := localConfig(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch when {
			case "before":
				cancel()
			case "after-tcp":
				cfg.Progress = func(p Progress) {
					if p.Stage == "tcp" {
						cancel()
					}
				}
			case "before-write":
				// No IPv4 survivors, so Stage 2 completes without starting Xray.
				cfg.Sample.Family = iprange.FamilyV6
				cfg.Prober = &xray.Prober{}
				cfg.Log = func(format string, _ ...any) {
					if strings.Contains(format, "stage2:") {
						cancel()
					}
				}
			}
			path, before := seededResults(t, cfg)
			sums, err := Run(ctx, cfg)
			if !errors.Is(err, context.Canceled) || len(sums) != 1 || sums[0].CDN != "demo" {
				t.Fatalf("got summaries=%+v, err=%v", sums, err)
			}
			assertPreserved(t, path, before)
		})
	}
}

func TestTCPOnlyReturnsEndpointsWithoutWriting(t *testing.T) {
	cfg := localConfig(t)
	path, before := seededResults(t, cfg)
	sums, err := Run(context.Background(), cfg)
	if err != nil || len(sums) != 1 || len(sums[0].Endpoints) != 1 {
		t.Fatalf("TCP results=%+v, err=%v", sums, err)
	}
	s := sums[0]
	if s.Endpoints[0] != (Endpoint{IP: "127.0.0.1", Port: cfg.TCP.Port}) || s.OutPath != "" || s.Confirmed != 0 {
		t.Fatalf("unexpected TCP-only summary: %+v", s)
	}
	assertPreserved(t, path, before)
	cfg.ResultsDir = filepath.Join(t.TempDir(), "must-not-be-created")
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.ResultsDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("TCP-only run created results directory: %v", err)
	}
}

func TestStage2InfrastructureErrorsPreserveResults(t *testing.T) {
	for _, network := range []string{"unsupported", "tcp"} {
		t.Run(network, func(t *testing.T) {
			cfg := localConfig(t)
			var err error
			cfg.Prober, err = xray.NewProber(xray.ProberOptions{
				XrayPath: filepath.Join(t.TempDir(), "missing-xray"), Startup: 20 * time.Millisecond,
				Outbound: &link.Outbound{Protocol: "vless", Address: "example.invalid", ID: "00000000-0000-0000-0000-000000000000", Network: network},
			})
			if err != nil {
				t.Fatal(err)
			}
			path, before := seededResults(t, cfg)
			sums, err := Run(context.Background(), cfg)
			if err == nil || len(sums) != 1 || sums[0].TCPOpen != 1 || sums[0].OutPath != "" {
				t.Fatalf("infrastructure error swallowed: sums=%+v err=%v", sums, err)
			}
			want := "start xray"
			if network == "unsupported" {
				want = "gen config"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("want %q in %v", want, err)
			}
			assertPreserved(t, path, before)
		})
	}
}

func TestRunJoinsErrorsAndKeepsSummaries(t *testing.T) {
	cfg := localConfig(t)
	cfg.Custom = nil
	cfg.CDNs = []string{"missing-first", "cached", "missing-last"}
	if err := providers.Save(cfg.IPsDir, &providers.RangeFile{CDN: "cached", Count: 1, CIDRs: []string{"127.0.0.1/32"}}); err != nil {
		t.Fatal(err)
	}
	sums, err := Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "missing-first") || !strings.Contains(err.Error(), "missing-last") {
		t.Fatalf("missing joined errors: %v", err)
	}
	if len(sums) != 3 || sums[1].CDN != "cached" || sums[1].TCPOpen != 1 {
		t.Fatalf("partial summaries lost: %+v", sums)
	}
}

func TestOutputWriteErrorIsReturned(t *testing.T) {
	cfg := localConfig(t)
	cfg.Sample.Family = iprange.FamilyV6
	cfg.Prober = &xray.Prober{}
	blocker := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.ResultsDir = blocker
	sums, err := Run(context.Background(), cfg)
	if err == nil || len(sums) != 1 || sums[0].OutPath != "" {
		t.Fatalf("write failure swallowed: sums=%+v err=%v", sums, err)
	}
}

func TestStage2CandidateRejectionIsNotInfrastructureFailure(t *testing.T) {
	ep := Endpoint{IP: "192.0.2.1", Port: 443}
	for _, result := range []xray.TestResult{{OK: false}, {OK: true}} {
		if err := stage2ResultError(ep, result); err != nil {
			t.Fatalf("normal candidate outcome became a run error: %v", err)
		}
	}
}

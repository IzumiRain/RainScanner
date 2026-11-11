package xray

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"cdnscan/internal/link"
)

// The subprocess is this test binary, never an external Xray or remote endpoint.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "run" && os.Getenv("RAINSCANNER_TEST_XRAY") != "" {
		os.Exit(fakeXray(os.Getenv("RAINSCANNER_TEST_XRAY")))
	}
	os.Exit(m.Run())
}

func fakeXray(mode string) int {
	if mode == "exit" {
		return 23
	}
	var cfg struct {
		Inbounds []struct {
			Port     int
			Settings struct{ Accounts []struct{ User, Pass string } }
		}
	}
	if json.NewDecoder(os.Stdin).Decode(&cfg) != nil {
		return 24
	}
	for _, inbound := range cfg.Inbounds {
		if len(inbound.Settings.Accounts) != 1 {
			return 25
		}
		account := inbound.Settings.Accounts[0]
		if len(account.User) != 32 || len(account.Pass) != 32 {
			return 26
		}
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(account.User+":"+account.Pass))
		if mode == "wrong-listener" {
			expected = "Basic " + base64.StdEncoding.EncodeToString([]byte("another-batch:unrelated-password"))
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", inbound.Port))
		if err != nil {
			return 27
		}
		go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mode != "open-listener" && r.Header.Get("Proxy-Authorization") != expected {
				w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			if mode == "exit-during-probe" {
				// Make listener loss observable before Wait can publish exit. This
				// also avoids depending on race-runtime shutdown scheduling.
				_ = ln.Close()
				os.Exit(28)
			}
			if mode == "lost-inbound" {
				_ = ln.Close()
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			if mode == "candidate-failure" {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
	}
	select {}
}

func testProber(t *testing.T, mode string) *Prober {
	t.Helper()
	t.Setenv("RAINSCANNER_TEST_XRAY", mode)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewProber(ProberOptions{
		XrayPath: exe, Outbound: &link.Outbound{Protocol: "vless", ID: "uuid", Network: "tcp"},
		ProbeURL: "http://probe.invalid/", Probes: 2, Confirm: 2, MaxLatency: time.Second,
		ProbeTimeout: time.Second, Startup: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBatchProcessExitIsPromptInfrastructureError(t *testing.T) {
	for _, mode := range []string{"exit", "exit-during-probe"} {
		t.Run(mode, func(t *testing.T) {
			p := testProber(t, mode)
			start := time.Now()
			res := p.TestBatch(context.Background(), []BatchItem{{Addr: netip.MustParseAddr("192.0.2.1"), Port: 443}})
			if time.Since(start) >= 3*time.Second {
				t.Fatal("process exit waited for startup timeout")
			}
			if len(res) != 1 || res[0].OK || !IsInfrastructureError(res[0].Err) {
				t.Fatalf("process failure not classified: %+v", res)
			}
		})
	}
}

func TestBatchRejectsWrongListener(t *testing.T) {
	for _, mode := range []string{"open-listener", "wrong-listener"} {
		for _, scheme := range []string{"http", "https"} {
			t.Run(mode+"/"+scheme, func(t *testing.T) {
				p := testProber(t, mode)
				p.opt.ProbeURL = scheme + "://probe.invalid/"
				res := p.TestBatch(context.Background(), []BatchItem{{Addr: netip.MustParseAddr("192.0.2.1"), Port: 443}})
				if res[0].OK || !IsInfrastructureError(res[0].Err) || !strings.Contains(res[0].Err, "authentication") {
					t.Fatalf("wrong listener was accepted or not classified: %+v", res)
				}
			})
		}
	}
}

func TestBatchLostInboundIsInfrastructureBeforeProcessExit(t *testing.T) {
	p := testProber(t, "lost-inbound")
	res := p.TestBatch(context.Background(), []BatchItem{{Addr: netip.MustParseAddr("192.0.2.1"), Port: 443}})
	if res[0].OK || !IsInfrastructureError(res[0].Err) || !strings.Contains(res[0].Err, "inbound authentication check") {
		t.Fatalf("listener loss while child remains alive was classified as candidate failure: %+v", res)
	}
}

func TestBatchConcurrentAuthenticatedCandidates(t *testing.T) {
	p := testProber(t, "success")
	const batches = 8
	var wg sync.WaitGroup
	results := make([][]TestResult, batches)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = p.TestBatch(context.Background(), []BatchItem{{Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), Port: 443}})
		}(i)
	}
	wg.Wait()
	for i, res := range results {
		if len(res) != 1 || !res[0].OK || res[0].Err != "" || res[0].Addr.As4()[3] != byte(i+1) {
			t.Fatalf("batch %d: %+v", i, res)
		}
	}
}

func TestBatchCandidateFailureIsNotInfrastructure(t *testing.T) {
	p := testProber(t, "candidate-failure")
	res := p.TestBatch(context.Background(), []BatchItem{{Addr: netip.MustParseAddr("192.0.2.1"), Port: 443}})
	if res[0].OK || res[0].Err != "" {
		t.Fatalf("ordinary rejection reported infrastructure error: %+v", res)
	}
}

func TestBatchMissingExecutableAndInvalidConfig(t *testing.T) {
	p := testProber(t, "success")
	for _, invalidConfig := range []bool{false, true} {
		copy := *p
		if invalidConfig {
			outbound := *p.opt.Outbound
			outbound.Network = "unsupported"
			copy.opt.Outbound = &outbound
		} else {
			copy.opt.XrayPath = t.TempDir() + "/nonexistent-xray"
		}
		res := copy.TestBatch(context.Background(), []BatchItem{{Addr: netip.MustParseAddr("192.0.2.1"), Port: 443}})
		if res[0].OK || !IsInfrastructureError(res[0].Err) {
			t.Fatalf("local failure not classified: %+v", res)
		}
	}
}

func TestBatchCancellation(t *testing.T) {
	p := testProber(t, "success")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := p.TestBatch(ctx, []BatchItem{{Addr: netip.MustParseAddr("192.0.2.1"), Port: 443}})
	if res[0].OK || res[0].Err != "cancelled" {
		t.Fatalf("cancellation not preserved: %+v", res)
	}
	if got := p.TestBatch(context.Background(), nil); len(got) != 0 {
		t.Fatalf("empty batch returned %+v", got)
	}
}

func TestPortLeasesAreDistinctUntilRelease(t *testing.T) {
	first, releaseFirst, err := leasePorts(16)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFirst()
	second, releaseSecond, err := leasePorts(16)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSecond()
	seen := make(map[int]bool)
	for _, port := range append(first, second...) {
		if seen[port] {
			t.Fatalf("duplicate port lease %d", port)
		}
		seen[port] = true
	}
}

func TestProbeEndpointClosesIdleConnections(t *testing.T) {
	closed := make(chan struct{}, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()
	p := testProber(t, "success")
	port := server.Listener.Addr().(*net.TCPAddr).Port
	res := p.probeEndpoint(context.Background(), context.Background(), port, netip.MustParseAddr("192.0.2.1"), "user", "password")
	if !res.OK {
		t.Fatalf("local proxy failed: %+v", res)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("candidate left an idle proxy connection open")
	}
}

func TestNewProberRejectsInvalidProbeURL(t *testing.T) {
	for _, raw := range []string{"relative", "ftp://example.test/", "http://"} {
		if _, err := NewProber(ProberOptions{XrayPath: "unused", Outbound: &link.Outbound{}, ProbeURL: raw}); err == nil {
			t.Errorf("invalid probe URL %q accepted", raw)
		}
	}
}

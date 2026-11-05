package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cdnscan/internal/output"
	"cdnscan/internal/pipeline"
)

func TestMain(m *testing.M) {
	if os.Getenv("RAINSCANNER_CLI_TEST_HELPER") == "1" {
		// Manifest refresh must use the seeded local cache, never the network.
		http.DefaultTransport = offlineTransport{}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type offlineTransport struct{}

func (offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in CLI regression helper")
}

func TestTCPOnlyCLIPrintsEndpointsAndPreservesResults(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	root := t.TempDir()
	ips, results := filepath.Join(root, "ips"), filepath.Join(root, "results")
	if err := os.MkdirAll(ips, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"index.json": `{"version":1,"cdns":[{"name":"demo","api":"","parser":"manual"}]}`,
		"demo.json":  `{"cdn":"demo","count":1,"cidrs":["127.0.0.1/32"]}`,
	} {
		if err := os.WriteFile(filepath.Join(ips, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path, err := output.Write(results, "demo", []output.Entry{{IP: "192.0.2.1", Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-cdn", "demo", "-ips-dir", ips, "-results-dir", results, "-port", port, "-family", "ipv4")
	cmd.Env = append(os.Environ(), "RAINSCANNER_CLI_TEST_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "127.0.0.1:"+port) || !strings.Contains(string(out), "tcp_open=1") {
		t.Fatalf("CLI omitted reachable endpoint: %s", out)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("CLI replaced confirmed results: %s", after)
	}
}

func TestTCPOnlySummaryPrintsReachableEndpoints(t *testing.T) {
	var out bytes.Buffer
	printSummaries(&out, []pipeline.Summary{{
		CDN: "demo", TCPOpen: 2,
		Endpoints: []pipeline.Endpoint{{IP: "127.0.0.1", Port: 443}, {IP: "2001:db8::1", Port: 8443}},
	}}, true)
	for _, want := range []string{"tcp_open=2", "127.0.0.1:443\n", "[2001:db8::1]:8443\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, &out)
		}
	}
}

func TestConfirmedSummaryDoesNotPrintUnconfirmedEndpoints(t *testing.T) {
	var out bytes.Buffer
	printSummaries(&out, []pipeline.Summary{{CDN: "demo", Endpoints: []pipeline.Endpoint{{IP: "192.0.2.1", Port: 443}}}}, false)
	if strings.Contains(out.String(), "192.0.2.1") {
		t.Fatalf("unconfirmed endpoint presented as result: %s", &out)
	}
}

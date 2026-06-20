// cdnscan: a unified, multi-CDN IPv4 scanner that confirms clean edge IPs by
// measuring real Xray-proxied latency, not plain ICMP/TCP reachability.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"cdnscan/internal/app"
	"cdnscan/internal/pipeline"
	"cdnscan/internal/providers"
	"cdnscan/internal/storage"
	"cdnscan/internal/web"
)

// version is the released product version, surfaced via the -version flag and
// the GUI launch banner. Bump it on each tagged release.
const version = "1.1.1"

func main() {
	var (
		cdnList     = flag.String("cdn", "", "comma-separated CDNs to scan, or 'all' (see -list)")
		linkStr     = flag.String("link", "", "vless:// or vmess:// share link (omit for TCP-only mode)")
		xrayPath    = flag.String("xray", "", "path to xray-core binary (default: search PATH)")
		port        = flag.Int("port", 443, "target TCP port")
		portsStr    = flag.String("ports", "", "comma-separated ports to scan (overrides -port; e.g. 443,80,8080)")
		tcpConc     = flag.Int("tcp-concurrency", 0, "stage1 max concurrent TCP dials (0 = auto: scaled to CPU)")
		tcpTimeout  = flag.Duration("tcp-timeout", 3*time.Second, "stage1 per-connection timeout")
		xrayConc    = flag.Int("xray-concurrency", 0, "stage2 max concurrent xray processes (0 = auto)")
		batchSize   = flag.Int("batch-size", 0, "stage2 candidates tested per xray process (0 = auto: 50)")
		lite        = flag.Bool("lite", false, "low-power mode: hard-cap concurrency for weak machines")
		maxTotal    = flag.Int("max-total", 0, "randomly sample at most N IPs across the whole pool (0 = all)")
		probes      = flag.Int("probes", 5, "stage2 measured probes per IP")
		confirm     = flag.Int("confirm", 3, "stage2 required successes to accept an IP")
		maxLatency  = flag.Duration("max-latency", 800*time.Millisecond, "stage2 max median latency")
		probeURL    = flag.String("probe-url", "https://www.gstatic.com/generate_204", "stage2 real request target")
		probeTO     = flag.Duration("probe-timeout", 0, "stage2 per-request timeout (0 = auto: 2x max-latency, min 1.5s)")
		samplePer24 = flag.Int("sample-per-24", 0, "sample N hosts per /24 (0 = full enumeration)")
		maxPerCIDR  = flag.Int("max-hosts-per-cidr", 0, "cap hosts emitted per CIDR (0 = unlimited)")
		refresh     = flag.Bool("refresh", false, "force re-fetch of provider ranges")
		ipsDir      = flag.String("ips-dir", "ips", "directory for cached per-CDN ranges")
		resultsDir  = flag.String("results-dir", "results", "directory for confirmed results")
		listCDN     = flag.Bool("list", false, "list supported CDNs and exit")
		showVersion = flag.Bool("version", false, "print version and exit")
		serve       = flag.Bool("serve", false, "launch the web GUI instead of a CLI scan")
		addr        = flag.String("addr", "127.0.0.1:8787", "web GUI listen address (with -serve)")
	)
	flag.Parse()

	// -version: print and exit before doing anything else.
	if *showVersion {
		fmt.Printf("RainScanner (cdnscan) v%s\n", version)
		return
	}

	// Double-click launch: no flags and no args means a user ran the .exe from
	// Explorer, so default to the GUI instead of erroring out with "no CDN".
	if flag.NFlag() == 0 && flag.NArg() == 0 {
		*serve = true
	}

	if *serve {
		// Stay responsive while scanning: drop to below-normal priority and
		// leave 2 logical CPUs for the desktop so the UI never starves.
		lowerProcessPriority()
		if n := runtime.NumCPU() - 2; n >= 2 {
			runtime.GOMAXPROCS(n)
		}
		url := guiURL(*addr)
		store := storage.NewFileStore(*ipsDir, *resultsDir)
		svc, serr := app.New(store, *ipsDir, *resultsDir)
		if serr != nil {
			log.Fatalf("init service: %v", serr)
		}
		srv := web.NewServer(svc)
		ln, err := srv.Bind(*addr)
		if err != nil {
			// Port already held — almost certainly another RainScanner instance.
			// Don't start a second heavy server; just surface the running one.
			log.Printf("RainScanner already running at %s — opening it (%v)", url, err)
			openBrowser(url)
			return
		}
		// Colourise the launch banner shown when the .exe is double-clicked.
		// enableConsoleColors flips Windows CMD into ANSI mode (no-op elsewhere);
		// the red/green/blue helpers degrade to plain text if that fails.
		enableConsoleColors()
		fmt.Printf("\n  %s\n  %s %s\n  %s\n\n",
			white("RainScanner is running."),
			green("Opening your browser at"), blue(url),
			green("Keep this window open while scanning — close it to stop RainScanner."))
		go func() {
			time.Sleep(400 * time.Millisecond) // let the listener come up first
			openBrowser(url)
		}()
		log.Fatal(srv.Serve(ln))
	}

	if *listCDN {
		fmt.Println("Supported CDNs:")
		for _, n := range providers.Names() {
			fmt.Println("  -", n)
		}
		return
	}

	if *cdnList == "" {
		log.Fatal("no CDN selected; use -cdn <name[,name...]> or -cdn all (see -list)")
	}
	cdns := selectCDNs(*cdnList)
	if len(cdns) == 0 {
		log.Fatal("no valid CDN names matched")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ports := parsePorts(*portsStr, *port)

	// Concurrency: Lite hard-caps everything; otherwise 0 = auto (pipeline picks).
	tcpConcN, xrayConcN, batchN := *tcpConc, *xrayConc, *batchSize
	if tcpConcN <= 0 {
		tcpConcN = pipeline.DefaultTCPConcurrency()
	}
	if *lite {
		tcpConcN = pipeline.LiteTCPConcurrency
		xrayConcN = pipeline.LiteXrayConcurrency // overrides; 0 below would also auto
		batchN = pipeline.LiteBatchSize
		lowerProcessPriority() // keep the box usable during a CLI scan
	}

	store := storage.NewFileStore(*ipsDir, *resultsDir)
	svc, err := app.New(store, *ipsDir, *resultsDir)
	if err != nil {
		log.Fatalf("init service: %v", err)
	}

	if *linkStr == "" {
		log.Print("no -link provided: running TCP-only (stage1) mode, no latency confirmation")
	}

	sb := newStatusBar()
	hooks := app.ScanHooks{Log: sb.logf, Progress: sb.progress}

	var summaries []pipeline.Summary
	for _, cdn := range cdns {
		sums, err := svc.Scan(ctx, app.ScanRequest{
			CDN:             cdn,
			Ports:           ports,
			Port:            *port,
			Link:            *linkStr,
			XrayPath:        *xrayPath,
			TCPConcurrency:  tcpConcN,
			TCPTimeoutMS:    int(tcpTimeout.Milliseconds()),
			XrayConcurrency: xrayConcN,
			BatchSize:       batchN,
			Probes:          *probes,
			Confirm:         *confirm,
			MaxLatencyMS:    int(maxLatency.Milliseconds()),
			ProbeTimeoutMS:  int(probeTO.Milliseconds()),
			ProbeURL:        *probeURL,
			SamplePer24:     *samplePer24,
			MaxHostsPerCIDR: *maxPerCIDR,
			MaxTotal:        *maxTotal,
			Lite:            *lite,
			Refresh:         *refresh,
		}, hooks)
		if err != nil {
			sb.finish()
			log.Fatalf("[%s] %v", cdn, err)
		}
		summaries = append(summaries, sums...)
	}
	sb.finish()

	fmt.Printf("\nTotal time: %.1fs\n", sb.elapsed().Seconds())
	fmt.Println("=== Summary ===")
	for _, s := range summaries {
		fmt.Printf("%-12s ranges=%d hosts=%d tcp_open=%d confirmed=%d -> %s\n",
			s.CDN, s.Ranges, s.Hosts, s.TCPOpen, s.Confirmed, s.OutPath)
	}
}

// statusBar renders an in-place progress bar with elapsed/ETA on stderr while
// still letting log lines scroll above it.
type statusBar struct {
	mu         sync.Mutex
	start      time.Time
	stageKey   string
	stageStart time.Time
	lastLine   string
}

func newStatusBar() *statusBar { return &statusBar{start: time.Now()} }

func (b *statusBar) elapsed() time.Duration { return time.Since(b.start) }

func (b *statusBar) logf(format string, a ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clear()
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	fmt.Fprint(os.Stderr, b.lastLine)
}

func (b *statusBar) progress(p pipeline.Progress) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := p.CDN + "/" + p.Stage
	if key != b.stageKey {
		b.stageKey = key
		b.stageStart = time.Now()
	}
	pct := 0
	if p.Total > 0 {
		pct = p.Done * 100 / p.Total
	}
	var eta float64
	if se := time.Since(b.stageStart).Seconds(); p.Done > 0 {
		eta = se / float64(p.Done) * float64(p.Total-p.Done)
	}
	stage := map[string]string{"tcp": "TCP  ", "xray": "Xray "}[p.Stage]
	b.lastLine = fmt.Sprintf("\r[%s %s] %s %3d%% %d/%d  elapsed %5.1fs  eta %5.1fs ",
		p.CDN, stage, renderBar(pct, 24), pct, p.Done, p.Total, b.elapsed().Seconds(), eta)
	fmt.Fprint(os.Stderr, b.lastLine)
}

func (b *statusBar) finish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clear()
	b.lastLine = ""
}

func (b *statusBar) clear() {
	if b.lastLine != "" {
		fmt.Fprint(os.Stderr, "\r"+strings.Repeat(" ", len(b.lastLine))+"\r")
	}
}

func renderBar(pct, width int) string {
	if pct > 100 {
		pct = 100
	} else if pct < 0 {
		pct = 0
	}
	filled := pct * width / 100
	bar := strings.Repeat("=", filled)
	if filled < width {
		bar += ">" + strings.Repeat(" ", width-filled-1)
	}
	return "[" + bar + "]"
}

// parsePorts turns a comma-separated port list into ints, falling back to the
// single -port value when the list is empty or yields nothing valid.
func parsePorts(arg string, fallback int) []int {
	var out []int
	for _, p := range strings.Split(arg, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			log.Printf("warning: invalid port %q (skipped)", p)
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return []int{fallback}
	}
	return out
}

// guiURL turns a listen address into a browser-openable URL, mapping wildcard
// binds (":8787", "0.0.0.0:8787") to a loopback host the browser can reach.
func guiURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// openBrowser launches the OS default browser at url. Best-effort: any failure
// is logged, not fatal (the user can always open the URL manually).
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("could not open browser automatically: %v (open %s yourself)", err, url)
	}
}

func selectCDNs(arg string) []string {
	if strings.EqualFold(arg, "all") {
		return providers.Names()
	}
	var out []string
	for _, p := range strings.Split(arg, ",") {
		name := strings.ToLower(strings.TrimSpace(p))
		if name == "" {
			continue
		}
		if _, ok := providers.Get(name); !ok {
			log.Printf("warning: unknown CDN %q (skipped)", name)
			continue
		}
		out = append(out, name)
	}
	return out
}

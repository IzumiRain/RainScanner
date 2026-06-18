// Package providers knows how to fetch published IPv4 ranges for each supported
// CDN and cache them as structured per-CDN files under the ips/ directory.
package providers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"cdnscan/internal/iprange"
)

// Provider describes one CDN and how to obtain its published IPv4 CIDR list.
// Every supported CDN is registered as one Provider in the package registry
// (see init). The two pieces that vary per CDN are the feed URL and the parser
// that turns that feed's particular format (plain text, JSON, ...) into a flat
// list of CIDR strings; everything else (caching, filtering, sorting) is shared.
type Provider struct {
	Name string
	// APIURL is the canonical published feed for this CDN. It is surfaced in the
	// GUI so the user can see exactly where the ranges come from and override it
	// if a CDN moves its endpoint. It is also reused by the fetcher below so the
	// URL shown in the UI and the URL actually downloaded can never drift apart.
	APIURL string
	// Fetch downloads APIURL (or whatever source this provider uses) and returns
	// the raw list of CIDR strings it found. Validation/normalisation to IPv4 is
	// done by the caller (Refresh), so a fetcher only has to extract strings.
	Fetch func(ctx context.Context, c *http.Client) ([]string, error)
}

// RangeFile is the on-disk structure written to ips/<cdn>.json.
type RangeFile struct {
	CDN       string   `json:"cdn"`
	FetchedAt string   `json:"fetched_at"`
	Count     int      `json:"count"`
	CIDRs     []string `json:"cidrs"`
}

// Canonical published feeds per CDN. These constants are referenced from two
// places — the Provider registration below and the format-specific fetchers —
// so that the API URL the GUI displays is byte-for-byte the URL that is actually
// downloaded. Defining them once removes any chance of the two drifting apart.
const (
	urlCloudflare = "https://www.cloudflare.com/ips-v4"
	urlFastly     = "https://api.fastly.com/public-ip-list"
	urlCloudFront = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	urlArvan      = "https://www.arvancloud.ir/en/ips.txt"
)

// registry holds every known Provider keyed by its lowercase name. It is
// populated once at startup by init() and only ever read afterwards, so no
// locking is needed.
var registry = map[string]Provider{}

func register(p Provider) { registry[p.Name] = p }

// init registers the shipped, built-in CDNs. These four are the defaults that
// exist out of the box; any extra ranges a user adds in the GUI are stored
// separately as "custom" targets (see the targets package) rather than here.
func init() {
	// Cloudflare publishes a plain-text list of one CIDR per line.
	register(Provider{Name: "cloudflare", APIURL: urlCloudflare, Fetch: fetchCloudflare})
	// Fastly publishes a JSON document with an "addresses" array.
	register(Provider{Name: "fastly", APIURL: urlFastly, Fetch: fetchFastly})
	// CloudFront ranges are buried inside AWS's combined ip-ranges.json and must
	// be filtered to the CLOUDFRONT service.
	register(Provider{Name: "cloudfront", APIURL: urlCloudFront, Fetch: fetchCloudFront})
	// ArvanCloud publishes a plain-text list; we extract CIDRs generically.
	register(Provider{Name: "arvan", APIURL: urlArvan, Fetch: fetchArvan})
}

// Names returns the sorted list of supported CDN names.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Get returns a provider by name.
func Get(name string) (Provider, bool) {
	p, ok := registry[strings.ToLower(name)]
	return p, ok
}

// APIURL returns the canonical feed URL for a registered provider, or "" if the
// name is unknown or the provider has no official feed.
func APIURL(name string) string {
	if p, ok := Get(name); ok {
		return p.APIURL
	}
	return ""
}

// cidrRe matches an IPv4 CIDR or a bare IPv4 address anywhere in a blob of text.
// Used by the generic scraper so a user-supplied feed URL of any shape (plain
// text list, JSON, HTML) can still yield ranges without a format-specific parser.
var cidrRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b`)

// ScrapeCIDRs fetches url and extracts every valid IPv4 CIDR / bare IP it can
// find, regardless of response format. Bare IPs are normalised to /32. Results
// are de-duplicated and sorted. This backs the GUI "reload range IPs" button for
// arbitrary (non-built-in) feed URLs.
func ScrapeCIDRs(ctx context.Context, c *http.Client, url string) ([]string, error) {
	b, err := httpGet(ctx, c, url)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []string
	for _, m := range cidrRe.FindAllString(string(b), -1) {
		cidr := m
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		norm := p.Masked().String()
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 ranges found at %s", url)
	}
	sort.Strings(out)
	return out, nil
}

// Refresh fetches a provider's ranges and writes ips/<cdn>.json.
func Refresh(ctx context.Context, c *http.Client, name, ipsDir string) (*RangeFile, error) {
	p, ok := Get(name)
	if !ok {
		return nil, fmt.Errorf("unknown CDN %q (supported: %s)", name, strings.Join(Names(), ", "))
	}
	cidrs, err := p.Fetch(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("%s: fetch: %w", name, err)
	}
	cidrs = iprange.FilterV4(cidrs)
	sort.Strings(cidrs)
	rf := &RangeFile{
		CDN:       name,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Count:     len(cidrs),
		CIDRs:     cidrs,
	}
	if err := Save(ipsDir, rf); err != nil {
		return nil, err
	}
	return rf, nil
}

// Load reads a cached ips/<cdn>.json.
func Load(ipsDir, name string) (*RangeFile, error) {
	path := filepath.Join(ipsDir, name+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf RangeFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("%s: parse cache: %w", path, err)
	}
	return &rf, nil
}

// Save writes ips/<cdn>.json (pretty-printed, deterministic).
func Save(ipsDir string, rf *RangeFile) error {
	if err := os.MkdirAll(ipsDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rf, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(ipsDir, rf.CDN+".json")
	return os.WriteFile(path, b, 0o644)
}

// LoadOrRefresh returns cached ranges if present, otherwise fetches them.
func LoadOrRefresh(ctx context.Context, c *http.Client, name, ipsDir string, forceRefresh bool) (*RangeFile, error) {
	if !forceRefresh {
		if rf, err := Load(ipsDir, name); err == nil && rf.Count > 0 {
			return rf, nil
		}
	}
	return Refresh(ctx, c, name, ipsDir)
}

func httpGet(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cdnscan/1.0")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func fetchCloudflare(ctx context.Context, c *http.Client) ([]string, error) {
	b, err := httpGet(ctx, c, urlCloudflare)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func fetchFastly(ctx context.Context, c *http.Client) ([]string, error) {
	b, err := httpGet(ctx, c, urlFastly)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return doc.Addresses, nil
}

func fetchCloudFront(ctx context.Context, c *http.Client) ([]string, error) {
	b, err := httpGet(ctx, c, urlCloudFront)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range doc.Prefixes {
		if p.Service == "CLOUDFRONT" {
			out = append(out, p.IPPrefix)
		}
	}
	return out, nil
}

// fetchArvan downloads ArvanCloud's published IP list. The feed is a simple
// plain-text document (one CIDR per line), but rather than assume an exact
// layout we hand it to the generic ScrapeCIDRs extractor, which pulls every
// valid IPv4 CIDR out of the response regardless of surrounding formatting.
// That keeps this fetcher robust if Arvan ever wraps the list in extra text.
func fetchArvan(ctx context.Context, c *http.Client) ([]string, error) {
	return ScrapeCIDRs(ctx, c, urlArvan)
}

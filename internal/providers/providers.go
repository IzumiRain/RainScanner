// Package providers resolves CDN IP ranges from a data-driven manifest.
// Built-in CDNs are defined in inside-api/index.json (committed to the repo and
// mirrored via jsDelivr / GitHub raw). A manifest is loaded at startup via
// LoadManifest and installed with SetManifest; Names/GetEntry/Entries read it.
// FetchRanges is the single entry point for fetching a CDN's ranges; it
// encapsulates source ordering (official → backup) and parser dispatch.
package providers

import (
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
	"sync"
	"time"

	"cdnscan/internal/iprange"
)

// ── Manifest types ───────────────────────────────────────────────────────────

// ManifestEntry describes one CDN in the manifest.
type ManifestEntry struct {
	Name   string `json:"name"`
	APIURL string `json:"api"`
	// APIURLv6 is an optional second feed carrying the CDN's IPv6 prefixes.
	// Some providers publish both families in one document (Fastly, Gcore, AWS);
	// others split them across two URLs (Cloudflare's ips-v4 / ips-v6). When set,
	// both feeds are fetched and merged. Absent = the single feed has everything.
	APIURLv6 string `json:"api_v6,omitempty"`
	Parser   string `json:"parser"` // "scrape" | "aws-cloudfront" | "manual"
}

// ManifestIndex is the root of inside-api/index.json.
type ManifestIndex struct {
	Version int             `json:"version"`
	CDNs    []ManifestEntry `json:"cdns"`
}

// FetchOptions controls which sources FetchRanges tries and in what order.
// Zero value = normal order: official first, backup allowed.
type FetchOptions struct {
	PreferBackup bool // try backup (GitHub raw→jsDelivr) before official API
	NoBackup     bool // skip backup entirely; official only (overrides PreferBackup)
}

// ── RangeFile ────────────────────────────────────────────────────────────────

// RangeFile is the on-disk structure written to ips/<cdn>.json.
// Source records which data source provided these ranges (for logging).
type RangeFile struct {
	CDN       string   `json:"cdn"`
	FetchedAt string   `json:"fetched_at"`
	Count     int      `json:"count"`
	CIDRs     []string `json:"cidrs"`
	Source    string   `json:"source,omitempty"` // "official"|"jsdelivr"|"github-raw"|"manual"|""
}

// ── Package-level manifest state ─────────────────────────────────────────────

var (
	manifestMu sync.RWMutex
	active     *ManifestIndex
)

// SetManifest installs the active manifest. Called once at startup (main.go).
// Pass nil to clear (useful in tests).
func SetManifest(m *ManifestIndex) {
	manifestMu.Lock()
	active = m
	manifestMu.Unlock()
}

// ManifestInstalled reports whether a manifest has been set via SetManifest.
// app.New uses this to skip network loading in test environments that
// pre-seed the manifest directly.
func ManifestInstalled() bool {
	manifestMu.RLock()
	defer manifestMu.RUnlock()
	return active != nil
}

func getManifest() *ManifestIndex {
	manifestMu.RLock()
	defer manifestMu.RUnlock()
	return active
}

// Names returns the sorted list of CDN names from the active manifest.
func Names() []string {
	m := getManifest()
	if m == nil {
		return nil
	}
	out := make([]string, len(m.CDNs))
	for i, e := range m.CDNs {
		out[i] = e.Name
	}
	sort.Strings(out)
	return out
}

// Entries returns all manifest entries.
func Entries() []ManifestEntry {
	m := getManifest()
	if m == nil {
		return nil
	}
	out := make([]ManifestEntry, len(m.CDNs))
	copy(out, m.CDNs)
	return out
}

// GetEntry returns the manifest entry for name (case-insensitive).
func GetEntry(name string) (ManifestEntry, bool) {
	m := getManifest()
	if m == nil {
		return ManifestEntry{}, false
	}
	name = strings.ToLower(name)
	for _, e := range m.CDNs {
		if strings.ToLower(e.Name) == name {
			return e, true
		}
	}
	return ManifestEntry{}, false
}

// APIURL returns the canonical feed URL for a CDN, or "" if unknown.
func APIURL(name string) string {
	e, ok := GetEntry(name)
	if !ok {
		return ""
	}
	return e.APIURL
}

// ── Manifest loading ──────────────────────────────────────────────────────────

// inside-api/ lives on main; GitHub raw resolves main instantly on every push.
// jsDelivr is kept as a fallback for networks where raw.githubusercontent.com is
// blocked (jsDelivr caches main with a short TTL).
const (
	jsdelivrBase = "https://cdn.jsdelivr.net/gh/IzumiRain/RainScanner@main/inside-api/"
	githubBase   = "https://raw.githubusercontent.com/IzumiRain/RainScanner/main/inside-api/"
)

// LoadManifest fetches the manifest from the GitHub mirror, then the local
// cache. On a successful remote fetch the local cache (ipsDir/index.json) is
// refreshed. Returns an empty non-nil index if all sources fail but no error so
// callers can start with zero CDNs rather than crashing.
//
// Source order is GitHub raw → jsDelivr. raw is always current on the main
// branch; jsDelivr is a fallback for networks where raw is blocked.
func LoadManifest(ctx context.Context, c *http.Client, ipsDir string) (*ManifestIndex, error) {
	urls := []string{githubBase + "index.json", jsdelivrBase + "index.json"}
	for _, url := range urls {
		if m, err := fetchManifestFrom(ctx, c, url); err == nil {
			_ = saveLocalManifest(ipsDir, m) // best-effort cache refresh
			return m, nil
		}
	}
	// Fall back to local cache.
	return loadLocalManifest(ipsDir)
}

func fetchManifestFrom(ctx context.Context, c *http.Client, url string) (*ManifestIndex, error) {
	b, err := httpGet(ctx, c, url)
	if err != nil {
		return nil, err
	}
	var m ManifestIndex
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest from %s: %w", url, err)
	}
	return &m, nil
}

func saveLocalManifest(ipsDir string, m *ManifestIndex) error {
	if err := os.MkdirAll(ipsDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(ipsDir, "index.json"), b, 0o644)
}

func loadLocalManifest(ipsDir string) (*ManifestIndex, error) {
	b, err := os.ReadFile(filepath.Join(ipsDir, "index.json"))
	if err != nil {
		return &ManifestIndex{}, fmt.Errorf("manifest unavailable (no network and no local cache): %w", err)
	}
	var m ManifestIndex
	if err := json.Unmarshal(b, &m); err != nil {
		return &ManifestIndex{}, fmt.Errorf("parse local manifest: %w", err)
	}
	return &m, nil
}

// ── FetchRanges ───────────────────────────────────────────────────────────────

// FetchRanges resolves CIDRs for entry by trying sources in order per opts.
// source ∈ {"official","jsdelivr","github-raw","manual"}.
// Returns an error only when ALL attempted sources fail.
func FetchRanges(ctx context.Context, c *http.Client, entry ManifestEntry, opts FetchOptions) ([]string, string, error) {
	official := func() ([]string, string, error) {
		cidrs, err := runParser(ctx, c, entry)
		return cidrs, "official", err
	}
	backup := func() ([]string, string, error) {
		return fetchBackupFile(ctx, c, entry.Name)
	}

	// manual parser: never call official; backup-only.
	if entry.Parser == "manual" {
		if opts.NoBackup {
			return nil, "", fmt.Errorf("%s: parser=manual but backup disabled", entry.Name)
		}
		return backup()
	}

	var lastErr error
	if opts.PreferBackup && !opts.NoBackup {
		if cidrs, src, err := backup(); err == nil {
			return cidrs, src, nil
		} else {
			lastErr = err
		}
		if cidrs, src, err := official(); err == nil {
			return cidrs, src, nil
		} else {
			lastErr = err
		}
	} else {
		if cidrs, src, err := official(); err == nil {
			return cidrs, src, nil
		} else {
			lastErr = err
		}
		if !opts.NoBackup {
			if cidrs, src, err := backup(); err == nil {
				return cidrs, src, nil
			} else {
				lastErr = err
			}
		}
	}
	return nil, "", fmt.Errorf("%s: all sources failed: %w", entry.Name, lastErr)
}

// fetchBackupFile fetches inside-api/<name>.json from the GitHub mirror. Order
// is GitHub raw → jsDelivr: raw serves main instantly; jsDelivr is a fallback for raw-blocked
// networks. It prefers the structured RangeFile JSON but tolerates a hand-edited
// file with a JSON typo by regex-scraping the CIDRs out of it (a single bad
// comma should not nuke the whole CDN).
func fetchBackupFile(ctx context.Context, c *http.Client, name string) ([]string, string, error) {
	type candidate struct {
		url    string
		source string
	}
	cands := []candidate{
		{githubBase + name + ".json", "github-raw"},
		{jsdelivrBase + name + ".json", "jsdelivr"},
	}
	for _, cand := range cands {
		b, err := httpGet(ctx, c, cand.url)
		if err != nil {
			continue
		}
		var rf RangeFile
		if json.Unmarshal(b, &rf) == nil && len(rf.CIDRs) > 0 {
			return rf.CIDRs, cand.source, nil
		}
		if scraped := scrapeCIDRBytes(b); len(scraped) > 0 {
			return scraped, cand.source, nil
		}
	}
	return nil, "", fmt.Errorf("backup unavailable for %s", name)
}

// ── Parser strategies ─────────────────────────────────────────────────────────

// runParser dispatches the entry's Parser field to the right strategy.
// Unknown parsers log a warning and return an error (they do NOT fall through
// to backup — that is FetchRanges's job — so the caller can decide).
func runParser(ctx context.Context, c *http.Client, entry ManifestEntry) ([]string, error) {
	switch entry.Parser {
	case "scrape":
		return scrapeBothFamilies(ctx, c, entry)
	case "aws-cloudfront":
		return fetchAWSCloudFront(ctx, c, entry.APIURL)
	case "manual":
		// manual entries are intercepted before runParser in FetchRanges.
		return nil, fmt.Errorf("%s: parser=manual has no official fetch", entry.Name)
	default:
		return nil, fmt.Errorf("%s: unknown parser %q", entry.Name, entry.Parser)
	}
}

// scrapeBothFamilies scrapes the entry's primary feed plus, when the manifest
// names one, its separate IPv6 feed, and merges the two lists. A provider that
// splits the families across two URLs (Cloudflare) therefore yields a dual-stack
// range set, while one that publishes both in a single document (Fastly, Gcore)
// needs no extra URL — the scraper already picks up both.
//
// The two feeds fail independently: whichever one answers is used. Only when
// both fail is an error returned, so a provider that temporarily 500s its v6
// endpoint still refreshes its v4 ranges instead of losing the whole target.
func scrapeBothFamilies(ctx context.Context, c *http.Client, entry ManifestEntry) ([]string, error) {
	primary, err := ScrapeCIDRs(ctx, c, entry.APIURL)
	if entry.APIURLv6 == "" {
		return primary, err
	}
	v6, v6err := ScrapeCIDRs(ctx, c, entry.APIURLv6)
	switch {
	case err != nil && v6err != nil:
		return nil, err
	case err != nil:
		return v6, nil
	case v6err != nil:
		return primary, nil
	}
	return normalizeCIDRs(append(primary, v6...)), nil
}

// ── Shared fetch / cache helpers ──────────────────────────────────────────────

// cidrRe matches an IPv4 CIDR or bare IPv4 address anywhere in text.
var cidrRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b`)

// cidr6Re matches an IPv6 CIDR or bare IPv6 address anywhere in text. It is
// deliberately loose — any run of hex groups joined by at least two colons, with
// an optional prefix length — because the shapes that appear in provider feeds
// vary ("2606:4700::/32", "2a04:4e42::/32", full 8-group addresses) and every
// match is validated by netip afterwards. Over-matching therefore costs nothing,
// while a stricter pattern would risk truncating a real prefix mid-address.
// Colon-separated noise (timestamps, MAC addresses) survives the regex but fails
// netip parsing and is dropped in normalizeCIDRs.
var cidr6Re = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?:/\d{1,3})?`)

// ScrapeCIDRs fetches url and extracts every valid IPv4 / IPv6 CIDR or bare IP.
// Bare IPs are normalised to /32 (v4) or /128 (v6). Results are de-duplicated
// and sorted, IPv4 first.
func ScrapeCIDRs(ctx context.Context, c *http.Client, url string) ([]string, error) {
	b, err := httpGet(ctx, c, url)
	if err != nil {
		return nil, err
	}
	out := scrapeCIDRBytes(b)
	if len(out) == 0 {
		return nil, fmt.Errorf("no IP ranges found at %s", url)
	}
	return out, nil
}

// FetchCIDRs retrieves a CIDR list from url, accepting (in priority order):
//  1. a RangeFile JSON object — {"cidrs":["1.2.3.0/24", ...]} (the same shape
//     RainScanner writes, so a custom CDN can host its list exactly like
//     inside-api/<cdn>.json);
//  2. a bare JSON array of strings — ["1.2.3.0/24", ...];
//  3. any other text blob — regex-scraped for CIDRs (plain-text feeds).
//
// This is what the GUI "reload" uses for a custom target or a built-in whose
// API URL the user overrode, so pointing a CDN at a GitHub-hosted JSON file
// works without the user having to match a specific text layout. Both address
// families are accepted; results are de-duplicated and sorted, IPv4 first.
func FetchCIDRs(ctx context.Context, c *http.Client, url string) ([]string, error) {
	b, err := httpGet(ctx, c, url)
	if err != nil {
		return nil, err
	}
	// 1. RangeFile JSON ({"cidrs":[...]}). Any JSON object unmarshals here, so
	//    we only accept it when it actually carried a non-empty cidrs array.
	var rf RangeFile
	if json.Unmarshal(b, &rf) == nil && len(rf.CIDRs) > 0 {
		if out := normalizeCIDRs(rf.CIDRs); len(out) > 0 {
			return out, nil
		}
	}
	// 2. Bare JSON array of CIDR strings.
	var arr []string
	if json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
		if out := normalizeCIDRs(arr); len(out) > 0 {
			return out, nil
		}
	}
	// 3. Regex scrape (plain-text or anything else).
	out := scrapeCIDRBytes(b)
	if len(out) == 0 {
		return nil, fmt.Errorf("no IP ranges found at %s", url)
	}
	return out, nil
}

// scrapeCIDRBytes regex-extracts every valid IPv4 / IPv6 CIDR or bare IP from b.
// Bare IPs are normalised to /32 or /128; results are de-duplicated and sorted.
func scrapeCIDRBytes(b []byte) []string {
	s := string(b)
	matches := cidrRe.FindAllString(s, -1)
	matches = append(matches, cidr6Re.FindAllString(s, -1)...)
	return normalizeCIDRs(matches)
}

// normalizeCIDRs validates, masks, de-duplicates, and sorts a list of CIDR /
// bare-IP strings of either family. Bare IPs become /32 (v4) or /128 (v6).
// Addresses that could never host a CDN edge — the unspecified address,
// loopback, link-local and multicast — are dropped, which is also what filters
// out the colon-separated noise the loose IPv6 regex picks up.
func normalizeCIDRs(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range in {
		cidr := strings.TrimSpace(m)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		a := p.Addr()
		if a.IsUnspecified() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() {
			continue
		}
		norm := p.Masked().String()
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	sortCIDRs(out)
	return out
}

// sortCIDRs orders entries IPv4 first, then IPv6, lexicographically within each
// family — see iprange.Sort.
func sortCIDRs(entries []string) { iprange.Sort(entries) }

func fetchAWSCloudFront(ctx context.Context, c *http.Client, url string) ([]string, error) {
	b, err := httpGet(ctx, c, url)
	if err != nil {
		return nil, err
	}
	// AWS publishes the two families as separate arrays with differently-named
	// fields in the same document, so both are read and merged.
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
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
	for _, p := range doc.IPv6Prefixes {
		if p.Service == "CLOUDFRONT" {
			out = append(out, p.IPv6Prefix)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CLOUDFRONT prefixes found in AWS ip-ranges.json")
	}
	return out, nil
}

// Refresh fetches a CDN's ranges and writes ips/<cdn>.json.
func Refresh(ctx context.Context, c *http.Client, name, ipsDir string, opts FetchOptions) (*RangeFile, error) {
	entry, ok := GetEntry(name)
	if !ok {
		return nil, fmt.Errorf("unknown CDN %q (not in active manifest)", name)
	}
	cidrs, source, err := FetchRanges(ctx, c, entry, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	cidrs = iprange.Filter(cidrs, iprange.FamilyAuto)
	sortCIDRs(cidrs)
	rf := &RangeFile{
		CDN:       name,
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Count:     len(cidrs),
		CIDRs:     cidrs,
		Source:    source,
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
	return os.WriteFile(filepath.Join(ipsDir, rf.CDN+".json"), b, 0o644)
}

// LoadOrRefresh returns cached ranges if present and not stale, otherwise refreshes.
func LoadOrRefresh(ctx context.Context, c *http.Client, name, ipsDir string, force bool, opts FetchOptions) (*RangeFile, error) {
	if !force {
		if rf, err := Load(ipsDir, name); err == nil && rf.Count > 0 {
			return rf, nil
		}
	}
	return Refresh(ctx, c, name, ipsDir, opts)
}

func httpGet(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cdnscan/2.0")
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

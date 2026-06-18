// Package targets is the in-memory + on-disk store of "scan targets" — the
// sources of candidate clean IPs. There are two kinds of target:
//
//   - Built-in CDNs (cloudflare, cloudfront, fastly, arvan): these are compiled
//     into the binary via the providers registry. Their fetched CIDR ranges are
//     cached on disk as one file per CDN, ips/<name>.json, in the providers
//     RangeFile format.
//   - Custom targets: arbitrary named CIDR sets the user adds in the GUI. All of
//     these live together in a single file, ips/custom.json, so the user's
//     personal additions are cleanly separated from the shipped defaults (and
//     are easy to exclude from version control).
//
// The Store presents both kinds through one uniform API (List/Get/Upsert/
// Delete/Reload) so the web layer doesn't have to care where a target is stored.
package targets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cdnscan/internal/iprange"
	"cdnscan/internal/providers"
)

// Record is one stored target as seen by callers and the GUI. It is the same
// shape regardless of whether the target is a built-in CDN or a user custom.
type Record struct {
	Name    string   `json:"name"`
	CIDRs   []string `json:"cidrs"`
	APIURL  string   `json:"api_url,omitempty"`
	Builtin bool     `json:"builtin"` // true => one of the compiled-in default CDNs
}

// customFile is the on-disk shape of ips/custom.json. It holds ONLY user-added
// custom targets; built-in CDN ranges are stored separately as ips/<name>.json.
type customFile struct {
	UpdatedAt string   `json:"updated_at"`
	Targets   []Record `json:"targets"`
}

// Store is a concurrency-safe collection of targets backed by the ips/ directory.
// The in-memory recs slice is the source of truth during a run; mutations are
// flushed to disk immediately (custom targets to custom.json, built-in range
// edits to that CDN's own cache file).
type Store struct {
	ipsDir     string
	customPath string

	mu   sync.Mutex
	recs []Record
}

// Open loads the store from the ips/ directory. Built-in CDNs are taken from the
// compiled provider registry, with their CIDRs filled in from any cached
// ips/<name>.json present (so the store is immediately usable offline). User
// customs are then loaded from ips/custom.json if it exists. The returned store
// is ready for concurrent use.
func Open(ipsDir string) (*Store, error) {
	s := &Store{ipsDir: ipsDir, customPath: filepath.Join(ipsDir, "custom.json")}

	// Seed the built-in CDNs from the registry, pulling any cached ranges.
	for _, name := range providers.Names() {
		rec := Record{Name: name, Builtin: true, APIURL: providers.APIURL(name)}
		if rf, err := providers.Load(ipsDir, name); err == nil {
			rec.CIDRs = rf.CIDRs
		}
		s.recs = append(s.recs, rec)
	}

	// Load user customs, if the file exists. A missing file is normal on first
	// run and is not an error; a malformed file is reported so the user knows
	// their customs failed to load rather than silently vanishing.
	b, err := os.ReadFile(s.customPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return s, nil
	}
	var f customFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: parse: %w", s.customPath, err)
	}
	for _, r := range f.Targets {
		r.Builtin = false // anything in custom.json is, by definition, a custom
		s.recs = append(s.recs, r)
	}
	return s, nil
}

// List returns a copy of all stored targets, built-ins first then customs, each
// group sorted by name. A copy is returned so callers can't mutate the store's
// internal slice without going through Upsert/Delete.
func (s *Store) List() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.recs))
	copy(out, s.recs)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin // built-ins first
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Get returns the named target (case-insensitive) and whether it exists.
func (s *Store) Get(name string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.indexOf(name); i >= 0 {
		return s.recs[i], true
	}
	return Record{}, false
}

// Upsert creates or replaces a target by name and persists it. CIDRs are
// filtered to valid IPv4 entries first. The Builtin flag is decided by the
// store, not the caller: a name that matches a compiled-in CDN is always treated
// as that built-in (so editing cloudflare's ranges in the GUI updates the
// built-in's cache file), and any other name is a custom. The persisted record
// is returned.
func (s *Store) Upsert(rec Record) (Record, error) {
	rec.Name = strings.TrimSpace(rec.Name)
	if rec.Name == "" {
		return Record{}, fmt.Errorf("target name is required")
	}
	rec.CIDRs = iprange.FilterV4(rec.CIDRs)

	s.mu.Lock()
	defer s.mu.Unlock()

	_, isBuiltin := providers.Get(rec.Name)
	rec.Builtin = isBuiltin

	if i := s.indexOf(rec.Name); i >= 0 {
		// Preserve the canonical name's existing casing/flag for built-ins.
		rec.Builtin = s.recs[i].Builtin || isBuiltin
		s.recs[i] = rec
	} else {
		s.recs = append(s.recs, rec)
	}

	if err := s.persistLocked(rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Delete removes a CUSTOM target by name and rewrites custom.json. Built-in CDNs
// are part of the shipped defaults and are not removable; attempting to delete
// one is a no-op that returns removed=false (with no error) so the GUI can treat
// it gracefully. Returns whether a record was actually removed.
func (s *Store) Delete(name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.indexOf(name)
	if i < 0 {
		return false, nil
	}
	if s.recs[i].Builtin {
		return false, nil // defaults are not deletable
	}
	s.recs = append(s.recs[:i], s.recs[i+1:]...)
	if err := s.saveCustomsLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// Reload re-fetches a target's CIDRs from its upstream feed and persists them.
// An unmodified built-in feed uses that provider's precise, format-aware parser;
// everything else (a custom target, or a built-in whose API URL the user has
// overridden) falls back to the generic IPv4-CIDR scraper. The refreshed record
// is returned.
func (s *Store) Reload(ctx context.Context, c *http.Client, name string) (Record, error) {
	rec, ok := s.Get(name)
	if !ok {
		return Record{}, fmt.Errorf("unknown target %q", name)
	}

	var cidrs []string
	var err error
	if p, isBuiltin := providers.Get(name); isBuiltin && rec.APIURL == p.APIURL && p.APIURL != "" {
		// Unmodified built-in feed: use its precise parser.
		cidrs, err = p.Fetch(ctx, c)
		if err == nil {
			cidrs = iprange.FilterV4(cidrs)
		}
	} else {
		if strings.TrimSpace(rec.APIURL) == "" {
			return Record{}, fmt.Errorf("%s has no API URL to reload from", name)
		}
		cidrs, err = providers.ScrapeCIDRs(ctx, c, rec.APIURL)
	}
	if err != nil {
		return Record{}, err
	}
	sort.Strings(cidrs)
	rec.CIDRs = cidrs
	return s.Upsert(rec)
}

// indexOf returns the position of name (case-insensitive) or -1. Caller holds mu.
func (s *Store) indexOf(name string) int {
	name = strings.TrimSpace(name)
	for i := range s.recs {
		if strings.EqualFold(s.recs[i].Name, name) {
			return i
		}
	}
	return -1
}

// persistLocked writes a single record to the right place: a built-in CDN's
// ranges go to its own cache file ips/<name>.json (providers RangeFile format),
// while a custom target triggers a rewrite of the consolidated custom.json.
// Caller holds mu.
func (s *Store) persistLocked(rec Record) error {
	if rec.Builtin {
		rf := &providers.RangeFile{
			CDN:       rec.Name,
			FetchedAt: time.Now().UTC().Format(time.RFC3339),
			Count:     len(rec.CIDRs),
			CIDRs:     rec.CIDRs,
		}
		return providers.Save(s.ipsDir, rf)
	}
	return s.saveCustomsLocked()
}

// saveCustomsLocked rewrites ips/custom.json from the current custom records.
// Built-ins are skipped entirely — they never appear in custom.json. Caller
// holds mu.
func (s *Store) saveCustomsLocked() error {
	if err := os.MkdirAll(s.ipsDir, 0o755); err != nil {
		return err
	}
	var customs []Record
	for _, r := range s.recs {
		if !r.Builtin {
			customs = append(customs, r)
		}
	}
	f := customFile{UpdatedAt: time.Now().UTC().Format(time.RFC3339), Targets: customs}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.customPath, b, 0o644)
}

// Package targets is the in-memory store of "scan targets" — the
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
// The Registry presents both kinds through one uniform API (List/Get/Upsert/
// Delete/Reload) so the web layer doesn't have to care where a target is stored.
package targets

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cdnscan/internal/iprange"
	"cdnscan/internal/providers"
	"cdnscan/internal/storage"
)

// Record is one stored target as seen by callers and the GUI. It is the same
// shape regardless of whether the target is a built-in CDN or a user custom.
type Record struct {
	Name    string   `json:"name"`
	CIDRs   []string `json:"cidrs"`
	APIURL  string   `json:"api_url,omitempty"`
	Builtin bool     `json:"builtin"` // true => one of the compiled-in default CDNs
}

// Registry is a concurrency-safe in-memory collection of targets. It is the
// source of truth during a run; mutations are flushed through the storage.Store
// (built-in range edits to ips/<name>.json, custom edits to ips/custom.json).
type Registry struct {
	store        storage.Store
	builtinNames map[string]bool // names seeded from the active manifest
	hidden       map[string]bool // built-in names the user deleted locally

	mu   sync.Mutex
	recs []Record
}

// Open builds a Registry: built-in CDNs seeded from the active manifest (with
// cached ranges from the store), minus any the user has deleted, then user
// customs loaded from the store.
func Open(store storage.Store) (*Registry, error) {
	r := &Registry{store: store, builtinNames: map[string]bool{}, hidden: map[string]bool{}}

	hidden, err := store.LoadHidden()
	if err != nil {
		return nil, err
	}
	for _, name := range hidden {
		r.hidden[strings.ToLower(name)] = true
	}

	for _, entry := range providers.Entries() {
		lower := strings.ToLower(entry.Name)
		r.builtinNames[lower] = true
		if r.hidden[lower] {
			continue // user deleted this default; don't re-seed it
		}
		rec := Record{Name: entry.Name, Builtin: true, APIURL: entry.APIURL}
		if rf, err := store.Ranges(entry.Name); err == nil {
			rec.CIDRs = rf.CIDRs
		}
		r.recs = append(r.recs, rec)
	}

	customs, err := store.LoadCustoms()
	if err != nil {
		return nil, err
	}
	for _, c := range customs {
		r.recs = append(r.recs, Record{Name: c.Name, CIDRs: c.CIDRs, APIURL: c.APIURL, Builtin: false})
	}
	return r, nil
}

// List returns a copy of all stored targets, built-ins first then customs, each
// group sorted by name. A copy is returned so callers can't mutate the store's
// internal slice without going through Upsert/Delete.
func (r *Registry) List() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, len(r.recs))
	copy(out, r.recs)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin // built-ins first
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Get returns the named target (case-insensitive) and whether it exists.
func (r *Registry) Get(name string) (Record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i := r.indexOf(name); i >= 0 {
		return r.recs[i], true
	}
	return Record{}, false
}

// Upsert creates or replaces a target by name and persists it. CIDRs are
// filtered to valid IPv4 entries first. The Builtin flag is decided by the
// registry, not the caller: a name that matches a compiled-in CDN is always
// treated as that built-in (so editing cloudflare's ranges in the GUI updates
// the built-in's cache file), and any other name is a custom. The persisted
// record is returned.
func (r *Registry) Upsert(rec Record) (Record, error) {
	rec.Name = strings.TrimSpace(rec.Name)
	if rec.Name == "" {
		return Record{}, fmt.Errorf("target name is required")
	}
	rec.CIDRs = iprange.FilterV4(rec.CIDRs)

	r.mu.Lock()
	defer r.mu.Unlock()

	lower := strings.ToLower(rec.Name)
	isBuiltin := r.builtinNames[lower]
	rec.Builtin = isBuiltin

	// Re-adding a previously-deleted built-in un-hides it so it sticks across
	// restarts (otherwise Open would skip it again).
	if isBuiltin && r.hidden[lower] {
		delete(r.hidden, lower)
		if err := r.saveHiddenLocked(); err != nil {
			return Record{}, err
		}
	}

	if i := r.indexOf(rec.Name); i >= 0 {
		// Preserve the canonical name's existing casing/flag for built-ins.
		rec.Builtin = r.recs[i].Builtin || isBuiltin
		// Preserve the existing APIURL if the caller didn't supply one.
		if rec.APIURL == "" {
			rec.APIURL = r.recs[i].APIURL
		}
		r.recs[i] = rec
	} else {
		r.recs = append(r.recs, rec)
	}

	if err := r.persistLocked(rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Delete removes a target by name. A custom target is dropped from custom.json.
// A built-in CDN is "hidden": removed from the live list and recorded in the
// persisted hidden set so it does not reappear when the manifest is re-seeded on
// the next start. (Re-adding it by name via Upsert un-hides it.) Returns whether
// a record was actually removed.
func (r *Registry) Delete(name string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.indexOf(name)
	if i < 0 {
		return false, nil
	}
	wasBuiltin := r.recs[i].Builtin
	r.recs = append(r.recs[:i], r.recs[i+1:]...)
	if wasBuiltin {
		r.hidden[strings.ToLower(name)] = true
		if err := r.saveHiddenLocked(); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := r.saveCustomsLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// Reload re-fetches a target's CIDRs from its upstream feed and persists them.
// For built-in CDNs with the original API URL, FetchRanges is used (official→backup
// per opts). Built-ins with a user-overridden API URL, and all customs, are scraped
// via ScrapeCIDRs. The refreshed record is returned.
func (r *Registry) Reload(ctx context.Context, c *http.Client, name string, opts providers.FetchOptions) (Record, error) {
	rec, ok := r.Get(name)
	if !ok {
		return Record{}, fmt.Errorf("unknown target %q", name)
	}

	var cidrs []string
	var err error

	if entry, isBuiltin := providers.GetEntry(name); isBuiltin && rec.APIURL == entry.APIURL {
		// Unmodified built-in feed: use full FetchRanges (official→backup per opts).
		cidrs, _, err = providers.FetchRanges(ctx, c, entry, opts)
	} else {
		// Custom target or user-overridden API URL: JSON-aware fetch (accepts a
		// RangeFile JSON, a bare JSON array, or a plain-text feed).
		if strings.TrimSpace(rec.APIURL) == "" {
			return Record{}, fmt.Errorf("%s has no API URL to reload from", name)
		}
		cidrs, err = providers.FetchCIDRs(ctx, c, rec.APIURL)
	}
	if err != nil {
		return Record{}, err
	}
	cidrs = iprange.FilterV4(cidrs)
	sort.Strings(cidrs)
	rec.CIDRs = cidrs
	return r.Upsert(rec)
}

// indexOf returns the position of name (case-insensitive) or -1. Caller holds mu.
func (r *Registry) indexOf(name string) int {
	name = strings.TrimSpace(name)
	for i := range r.recs {
		if strings.EqualFold(r.recs[i].Name, name) {
			return i
		}
	}
	return -1
}

// persistLocked writes a record to the right place via the store. Caller holds mu.
func (r *Registry) persistLocked(rec Record) error {
	if rec.Builtin {
		return r.store.SaveRanges(&providers.RangeFile{
			CDN:       rec.Name,
			FetchedAt: time.Now().UTC().Format(time.RFC3339),
			Count:     len(rec.CIDRs),
			CIDRs:     rec.CIDRs,
		})
	}
	return r.saveCustomsLocked()
}

// saveCustomsLocked rewrites custom storage from the current custom records.
// Caller holds mu.
func (r *Registry) saveCustomsLocked() error {
	var customs []storage.CustomTarget
	for _, rec := range r.recs {
		if !rec.Builtin {
			customs = append(customs, storage.CustomTarget{Name: rec.Name, CIDRs: rec.CIDRs, APIURL: rec.APIURL})
		}
	}
	return r.store.SaveCustoms(customs)
}

// saveHiddenLocked persists the set of deleted built-in names. Caller holds mu.
func (r *Registry) saveHiddenLocked() error {
	names := make([]string, 0, len(r.hidden))
	for name := range r.hidden {
		names = append(names, name)
	}
	sort.Strings(names)
	return r.store.SaveHidden(names)
}

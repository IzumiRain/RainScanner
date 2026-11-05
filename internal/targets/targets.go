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
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

// ErrStaleReload means the target changed or was deleted while its feed was fetched.
var ErrStaleReload = errors.New("target changed during reload")

// Registry is a concurrency-safe in-memory collection of targets. It is the
// source of truth during a run; mutations are flushed through the storage.Store
// (built-in range edits to ips/<name>.json, custom edits to ips/custom.json).
type Registry struct {
	store        storage.Store
	builtinNames map[string]bool // names seeded from the active manifest
	hidden       map[string]bool // built-in names the user deleted locally

	mu        sync.Mutex
	recs      []Record
	revisions map[string]uint64
	revision  uint64
}

// Open builds a Registry: built-in CDNs seeded from the active manifest (with
// cached ranges from the store), minus any the user has deleted, then user
// customs loaded from the store.
func Open(store storage.Store) (*Registry, error) {
	r := &Registry{store: store, builtinNames: map[string]bool{}, hidden: map[string]bool{}, revisions: map[string]uint64{}}

	hidden, err := store.LoadHidden()
	if err != nil {
		return nil, err
	}
	for _, name := range hidden {
		r.hidden[strings.ToLower(name)] = true
	}

	for _, entry := range providers.Entries() {
		if !providers.SafeRangeName(entry.Name) {
			continue
		}
		lower := strings.ToLower(entry.Name)
		r.builtinNames[lower] = true
		if r.hidden[lower] {
			continue // user deleted this default; don't re-seed it
		}
		rec := Record{Name: entry.Name, Builtin: true, APIURL: entry.APIURL}
		if rf, err := store.Ranges(entry.Name); err == nil {
			rec.CIDRs = rf.CIDRs
			if rf.APIURL != "" {
				rec.APIURL = rf.APIURL
			}
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

// RestoreBuiltins force-restores the built-in set from the active manifest:
// GitHub is authoritative for built-ins, so this clears the hidden set (any
// default the user deleted comes back) and adds every manifest built-in not
// currently present. Custom (user-added) targets are never touched. Built-in
// RANGES are not changed here — the caller's ReloadAll overwrites them from the
// chosen source (GitHub inside-api when prefer_backup). Call it after refreshing
// the manifest on an explicit reload-all. Returns the names restored (those that
// were hidden or freshly added), de-duplicated.
//
// Consequence: deleting a built-in is temporary — it disappears from the list
// until the next reload-all, which restores it. Deleted customs stay deleted.
func (r *Registry) RestoreBuiltins() ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	restored := map[string]bool{}
	// Un-hide every previously-deleted default; GitHub owns the built-in set.
	if len(r.hidden) > 0 {
		for lower := range r.hidden {
			restored[lower] = true
		}
		if err := r.store.SaveHidden(nil); err != nil {
			return nil, err
		}
		r.hidden = map[string]bool{}
	}
	// Ensure every manifest built-in is present (re-add the un-hidden ones and any
	// newly-published upstream CDN). Existing records are left as-is; ReloadAll
	// refreshes their ranges.
	for _, entry := range providers.Entries() {
		if !providers.SafeRangeName(entry.Name) {
			// A manifest-supplied name becomes a filename on persist; never
			// ingest one that could traverse or carry an ADS suffix.
			continue
		}
		lower := strings.ToLower(entry.Name)
		r.builtinNames[lower] = true
		if r.indexOf(entry.Name) >= 0 {
			continue // already in the registry
		}
		rec := Record{Name: entry.Name, Builtin: true, APIURL: entry.APIURL}
		if rf, err := r.store.Ranges(entry.Name); err == nil {
			rec.CIDRs = rf.CIDRs
			if rf.APIURL != "" {
				rec.APIURL = rf.APIURL
			}
		}
		r.recs = append(r.recs, rec)
		r.bumpRevisionLocked(rec.Name)
		restored[lower] = true
	}

	out := make([]string, 0, len(restored))
	for name := range restored {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// List returns a copy of all stored targets, built-ins first then customs, each
// group sorted by name. A copy is returned so callers can't mutate the store's
// internal slice without going through Upsert/Delete.
func (r *Registry) List() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, len(r.recs))
	copy(out, r.recs)
	for i := range out {
		out[i].CIDRs = append([]string(nil), out[i].CIDRs...)
	}
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
		rec := r.recs[i]
		rec.CIDRs = append([]string(nil), rec.CIDRs...)
		return rec, true
	}
	return Record{}, false
}

// Upsert creates or replaces a target by name and persists it. CIDRs are
// filtered to valid IPv4/IPv6 entries first. The Builtin flag is decided by the
// registry, not the caller: a name that matches a compiled-in CDN is always
// treated as that built-in (so editing cloudflare's ranges in the GUI updates
// the built-in's cache file), and any other name is a custom. The persisted
// record is returned.
func (r *Registry) Upsert(rec Record) (Record, error) {
	rec.Name = strings.TrimSpace(rec.Name)
	if rec.Name == "" {
		return Record{}, fmt.Errorf("target name is required")
	}
	rec.CIDRs = iprange.Filter(rec.CIDRs, iprange.FamilyAuto)
	rec.APIURL = strings.TrimSpace(rec.APIURL)
	apiProvided := rec.APIURL != ""
	if api := rec.APIURL; api != "" {
		// The API URL is fetched server-side on reload; only http(s) is
		// accepted so neither file:// nor exotic schemes can ever reach
		// url.Open-equivalent sinks downstream.
		if u, err := url.Parse(api); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return Record{}, fmt.Errorf("api_url must be an http(s) URL")
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	lower := strings.ToLower(rec.Name)
	isBuiltin := r.builtinNames[lower]
	rec.Builtin = isBuiltin

	if isBuiltin {
		if entry, ok := providers.GetEntry(rec.Name); ok {
			rec.Name = entry.Name
			if rec.APIURL == "" {
				rec.APIURL = entry.APIURL
			}
		}
	}

	next := append([]Record(nil), r.recs...)
	if i := r.indexOf(rec.Name); i >= 0 {
		// Names are case-insensitive identities; retain their persisted spelling.
		rec.Name = r.recs[i].Name
		rec.Builtin = r.recs[i].Builtin || isBuiltin
		// Preserve the existing APIURL if the caller didn't supply one.
		if !apiProvided {
			rec.APIURL = r.recs[i].APIURL
		}
		next[i] = rec
	} else {
		next = append(next, rec)
	}

	if err := r.persistLocked(rec, next); err != nil {
		return Record{}, err
	}
	if isBuiltin && r.hidden[lower] {
		names := make([]string, 0, len(r.hidden)-1)
		for name := range r.hidden {
			if name != lower {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		if err := r.store.SaveHidden(names); err != nil {
			return Record{}, err
		}
		delete(r.hidden, lower)
	}
	r.recs = next
	r.bumpRevisionLocked(rec.Name)
	rec.CIDRs = append([]string(nil), rec.CIDRs...)
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
	rec := r.recs[i]
	next := append([]Record(nil), r.recs[:i]...)
	next = append(next, r.recs[i+1:]...)
	if rec.Builtin {
		names := make([]string, 0, len(r.hidden)+1)
		for name := range r.hidden {
			names = append(names, name)
		}
		names = append(names, strings.ToLower(rec.Name))
		sort.Strings(names)
		if err := r.store.SaveHidden(names); err != nil {
			return false, err
		}
		r.hidden[strings.ToLower(rec.Name)] = true
	} else if err := r.saveCustomsLocked(next); err != nil {
		return false, err
	}
	r.recs = next
	delete(r.revisions, rec.Name)
	return true, nil
}

// Reload re-fetches a target's CIDRs from its upstream feed and persists them.
// For built-in CDNs with the original API URL, FetchRanges is used (official→backup
// per opts). Built-ins with a user-overridden API URL, and all customs, are scraped
// via ScrapeCIDRs. The refreshed record is returned.
func (r *Registry) Reload(ctx context.Context, c *http.Client, name string, opts providers.FetchOptions) (Record, error) {
	r.mu.Lock()
	i := r.indexOf(name)
	if i < 0 {
		r.mu.Unlock()
		return Record{}, fmt.Errorf("unknown target %q", name)
	}
	rec := r.recs[i]
	revision := r.revisions[rec.Name]
	r.mu.Unlock()

	var cidrs []string
	var err error

	if entry, isBuiltin := providers.GetEntry(rec.Name); isBuiltin && rec.Builtin && rec.APIURL == entry.APIURL {
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
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	cidrs = iprange.Filter(cidrs, iprange.FamilyAuto)
	iprange.Sort(cidrs)
	rec.CIDRs = cidrs
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	i = r.indexOf(rec.Name)
	if i < 0 || r.revisions[r.recs[i].Name] != revision {
		return Record{}, fmt.Errorf("%s: %w", rec.Name, ErrStaleReload)
	}
	next := append([]Record(nil), r.recs...)
	next[i] = rec
	if err := r.persistLocked(rec, next); err != nil {
		return Record{}, err
	}
	r.recs = next
	r.bumpRevisionLocked(rec.Name)
	rec.CIDRs = append([]string(nil), rec.CIDRs...)
	return rec, nil
}

func (r *Registry) bumpRevisionLocked(name string) {
	r.revision++
	r.revisions[name] = r.revision
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
func (r *Registry) persistLocked(rec Record, recs []Record) error {
	if rec.Builtin {
		override := rec.APIURL
		if override == providers.APIURL(rec.Name) {
			override = ""
		}
		return r.store.SaveRanges(&providers.RangeFile{
			CDN:       rec.Name,
			FetchedAt: time.Now().UTC().Format(time.RFC3339),
			Count:     len(rec.CIDRs),
			CIDRs:     rec.CIDRs,
			APIURL:    override,
		})
	}
	return r.saveCustomsLocked(recs)
}

// saveCustomsLocked rewrites custom storage from the current custom records.
// Caller holds mu.
func (r *Registry) saveCustomsLocked(recs []Record) error {
	var customs []storage.CustomTarget
	for _, rec := range recs {
		if !rec.Builtin {
			customs = append(customs, storage.CustomTarget{Name: rec.Name, CIDRs: rec.CIDRs, APIURL: rec.APIURL})
		}
	}
	return r.store.SaveCustoms(customs)
}

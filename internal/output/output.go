// Package output writes the confirmed, latency-ranked scan results for one CDN
// to results/<cdn>.json. The on-disk format is deliberately compact: the
// top-level metadata stays on its own readable lines, but every result entry is
// emitted as a single line. A confirmed scan can contain hundreds of IPs, and
// one-line-per-entry keeps the file small and easy to scan by eye or with tools
// like grep/jq, instead of exploding every field onto its own indented line.
package output

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var filesMu sync.Mutex

// Entry is one confirmed working IP: the endpoint plus the measured latency and
// how many of the probe attempts succeeded.
type Entry struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	MedianMS  int64  `json:"median_ms"`
	Successes int    `json:"successes"`
	Total     int    `json:"total"`
}

// ResultFile is the logical structure written to results/<cdn>.json. It is not
// marshalled directly (see Write) because we hand-render the body to control the
// compact, one-entry-per-line layout.
type ResultFile struct {
	CDN         string  `json:"cdn"`
	GeneratedAt string  `json:"generated_at"`
	Count       int     `json:"count"`
	Results     []Entry `json:"results"`
}

// Write sorts entries by latency (lowest first), then renders and saves
// results/<cdn>.json. It returns the path written. The fastest confirmed IPs end
// up at the top of the file, which is exactly the order a user wants to try them.
func Write(dir, cdn string, entries []Entry) (string, error) {
	return WriteContext(context.Background(), dir, cdn, entries)
}

// WriteContext is Write with cancellation checked before work and publication.
func WriteContext(ctx context.Context, dir, cdn string, entries []Entry) (string, error) {
	filesMu.Lock()
	defer filesMu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	entries = append([]Entry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].MedianMS < entries[j].MedianMS })

	// Build the document by hand so each entry occupies a single compact line
	// while the surrounding metadata stays human-readable. We still go through
	// encoding/json for the individual values so all escaping/quoting is correct.
	var buf bytes.Buffer
	buf.WriteString("{\n")
	writeField(&buf, "cdn", cdn, true)
	writeField(&buf, "generated_at", time.Now().UTC().Format(time.RFC3339), true)
	writeRawField(&buf, "count", len(entries), true)
	buf.WriteString("  \"results\": [")
	for i, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			return "", err
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString("\n    ")
		buf.Write(b)
	}
	if len(entries) > 0 {
		buf.WriteString("\n  ")
	}
	buf.WriteString("]\n}\n")

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := Path(dir, cdn)
	// A legacy or externally-created file must never be overwritten for a
	// different identity, even on a case-insensitive filesystem.
	if _, err := readPath(path, cdn); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".results-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return "", err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return path, os.Rename(f.Name(), path)
}

// writeField appends a quoted string field ("key": "value") at two-space indent,
// with a trailing comma when more fields follow.
func writeField(buf *bytes.Buffer, key, val string, more bool) {
	kb, _ := json.Marshal(key)
	vb, _ := json.Marshal(val)
	buf.WriteString("  ")
	buf.Write(kb)
	buf.WriteString(": ")
	buf.Write(vb)
	if more {
		buf.WriteByte(',')
	}
	buf.WriteByte('\n')
}

// writeRawField appends a non-string field ("key": value), e.g. an int.
func writeRawField(buf *bytes.Buffer, key string, val int, more bool) {
	kb, _ := json.Marshal(key)
	vb, _ := json.Marshal(val)
	buf.WriteString("  ")
	buf.Write(kb)
	buf.WriteString(": ")
	buf.Write(vb)
	if more {
		buf.WriteByte(',')
	}
	buf.WriteByte('\n')
}

// sanitizeName makes an arbitrary target name (e.g. a user-supplied custom-range
// name) safe to use as a filename: it lowercases the input and collapses any run
// of non-alphanumeric characters into a single '-'. Empty input yields "custom".
// This prevents a name like "My CDN!" from producing an invalid or surprising
// path such as results/My CDN!.json.
func sanitizeName(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "custom"
	}
	return out
}

// Path preserves ordinary canonical ASCII names. Other names use a stable hash
// namespace so lossy sanitization, Windows casing and device names cannot alias.
func Path(dir, name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	slug := sanitizeName(key)
	canonical := key == slug && len(key) <= 64 && !strings.Contains(key, "--") && !reservedName(key)
	if !canonical {
		if len(slug) > 48 {
			slug = slug[:48]
		}
		sum := sha256.Sum256([]byte(key))
		slug = fmt.Sprintf("target-%s--%x", slug, sum[:16])
	}
	return filepath.Join(dir, slug+".json")
}

func reservedName(name string) bool {
	switch name {
	case "con", "prn", "aux", "nul":
		return true
	}
	return len(name) == 4 && (strings.HasPrefix(name, "com") || strings.HasPrefix(name, "lpt")) && name[3] >= '1' && name[3] <= '9'
}

// Read loads a previously written results/<name>.json. A missing file returns
// an error the caller can treat as "no results yet".
func Read(dir, name string) (*ResultFile, error) {
	filesMu.Lock()
	defer filesMu.Unlock()
	path := Path(dir, name)
	rf, err := readPath(path, name)
	if !os.IsNotExist(err) {
		return rf, err
	}
	// Historical sanitized filenames are read only when their embedded identity
	// matches. A colliding target's results are never a valid fallback.
	legacyName := sanitizeName(name)
	// Opening CON.json (and other DOS devices) can access a device rather than
	// a file on Windows. Such names were never portable legacy result files.
	if reservedName(legacyName) {
		return nil, err
	}
	legacy := filepath.Join(dir, legacyName+".json")
	if legacy != path {
		return readPath(legacy, name)
	}
	return nil, err
}

func readPath(path, name string) (*ResultFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf ResultFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("%s: parse: %w", path, err)
	}
	if !strings.EqualFold(strings.TrimSpace(rf.CDN), strings.TrimSpace(name)) {
		return nil, fmt.Errorf("%s: results belong to target %q, not %q", path, rf.CDN, name)
	}
	return &rf, nil
}

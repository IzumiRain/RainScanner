// Package output writes the confirmed, latency-ranked scan results for one CDN
// to results/<cdn>.json. The on-disk format is deliberately compact: the
// top-level metadata stays on its own readable lines, but every result entry is
// emitted as a single line. A confirmed scan can contain hundreds of IPs, and
// one-line-per-entry keeps the file small and easy to scan by eye or with tools
// like grep/jq, instead of exploding every field onto its own indented line.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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
	return path, os.WriteFile(path, buf.Bytes(), 0o644)
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

// Path returns the on-disk path results/<sanitized-name>.json for a target,
// using the same sanitisation Write applies, so readers and writers agree.
func Path(dir, name string) string {
	return filepath.Join(dir, sanitizeName(name)+".json")
}

// Read loads a previously written results/<name>.json. A missing file returns
// an error the caller can treat as "no results yet".
func Read(dir, name string) (*ResultFile, error) {
	b, err := os.ReadFile(Path(dir, name))
	if err != nil {
		return nil, err
	}
	var rf ResultFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("%s: parse: %w", Path(dir, name), err)
	}
	return &rf, nil
}

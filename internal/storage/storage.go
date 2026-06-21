// Package storage is the persistence port for RainScanner. Every on-disk format
// the app reads or writes — cached CDN ranges, user custom targets, and scan
// results — lives behind the Store interface so the engine and front-ends never
// touch files directly. FileStore is the file-based adapter (the only one);
// it reproduces the historical ips/ and results/ layout byte-for-byte.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cdnscan/internal/output"
	"cdnscan/internal/providers"
)

// CustomTarget is one user-added target as persisted in ips/custom.json.
// (Built-in CDNs are persisted separately as ips/<name>.json.)
type CustomTarget struct {
	Name    string   `json:"name"`
	CIDRs   []string `json:"cidrs"`
	APIURL  string   `json:"api_url,omitempty"`
	Builtin bool     `json:"builtin"`
}

// customFile is the on-disk shape of ips/custom.json. Hidden is the list of
// built-in CDN names the user has deleted locally; it is kept here (rather than
// a separate file) so all user-local target state lives in one place. Hidden is
// omitempty so a custom.json with no deletions is byte-identical to before.
type customFile struct {
	UpdatedAt string         `json:"updated_at"`
	Targets   []CustomTarget `json:"targets"`
	Hidden    []string       `json:"hidden,omitempty"`
}

// Store abstracts all of RainScanner's persistence.
type Store interface {
	// Ranges returns the cached ranges for a built-in CDN (ips/<cdn>.json).
	Ranges(cdn string) (*providers.RangeFile, error)
	// SaveRanges writes ips/<cdn>.json.
	SaveRanges(rf *providers.RangeFile) error
	// LoadCustoms returns all user custom targets (ips/custom.json); a missing
	// file yields (nil, nil).
	LoadCustoms() ([]CustomTarget, error)
	// SaveCustoms rewrites ips/custom.json (preserving the hidden list).
	SaveCustoms(customs []CustomTarget) error
	// LoadHidden returns the names of built-in CDNs the user has deleted; a
	// missing file yields (nil, nil).
	LoadHidden() ([]string, error)
	// SaveHidden rewrites the hidden built-in list (preserving custom targets).
	SaveHidden(hidden []string) error
	// Results returns the saved results for a target (results/<cdn>.json).
	Results(cdn string) (*output.ResultFile, error)
	// SaveResults writes results/<cdn>.json and returns the path.
	SaveResults(cdn string, entries []output.Entry) (string, error)
}

// FileStore is the file-based Store adapter.
type FileStore struct {
	ipsDir     string
	resultsDir string
	customPath string
}

// NewFileStore builds a FileStore over the given ips/ and results/ directories.
func NewFileStore(ipsDir, resultsDir string) *FileStore {
	return &FileStore{
		ipsDir:     ipsDir,
		resultsDir: resultsDir,
		customPath: filepath.Join(ipsDir, "custom.json"),
	}
}

func (f *FileStore) Ranges(cdn string) (*providers.RangeFile, error) {
	return providers.Load(f.ipsDir, cdn)
}

func (f *FileStore) SaveRanges(rf *providers.RangeFile) error {
	return providers.Save(f.ipsDir, rf)
}

// loadEnvelope reads ips/custom.json; a missing file yields a zero envelope.
func (f *FileStore) loadEnvelope() (customFile, error) {
	b, err := os.ReadFile(f.customPath)
	if err != nil {
		if os.IsNotExist(err) {
			return customFile{}, nil
		}
		return customFile{}, err
	}
	var cf customFile
	if err := json.Unmarshal(b, &cf); err != nil {
		return customFile{}, fmt.Errorf("%s: parse: %w", f.customPath, err)
	}
	return cf, nil
}

// saveEnvelope rewrites ips/custom.json with a fresh timestamp.
func (f *FileStore) saveEnvelope(cf customFile) error {
	if err := os.MkdirAll(f.ipsDir, 0o755); err != nil {
		return err
	}
	cf.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	b, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(f.customPath, b, 0o644)
}

func (f *FileStore) LoadCustoms() ([]CustomTarget, error) {
	cf, err := f.loadEnvelope()
	return cf.Targets, err
}

func (f *FileStore) SaveCustoms(customs []CustomTarget) error {
	cf, err := f.loadEnvelope()
	if err != nil {
		return err
	}
	cf.Targets = customs
	return f.saveEnvelope(cf)
}

func (f *FileStore) LoadHidden() ([]string, error) {
	cf, err := f.loadEnvelope()
	return cf.Hidden, err
}

func (f *FileStore) SaveHidden(hidden []string) error {
	cf, err := f.loadEnvelope()
	if err != nil {
		return err
	}
	cf.Hidden = hidden
	return f.saveEnvelope(cf)
}

func (f *FileStore) Results(cdn string) (*output.ResultFile, error) {
	return output.Read(f.resultsDir, cdn)
}

func (f *FileStore) SaveResults(cdn string, entries []output.Entry) (string, error) {
	return output.Write(f.resultsDir, cdn, entries)
}

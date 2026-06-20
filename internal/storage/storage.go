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
	Name   string   `json:"name"`
	CIDRs  []string `json:"cidrs"`
	APIURL string   `json:"api_url,omitempty"`
}

// customFile is the on-disk shape of ips/custom.json.
type customFile struct {
	UpdatedAt string         `json:"updated_at"`
	Targets   []CustomTarget `json:"targets"`
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
	// SaveCustoms rewrites ips/custom.json.
	SaveCustoms(customs []CustomTarget) error
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

func (f *FileStore) LoadCustoms() ([]CustomTarget, error) {
	b, err := os.ReadFile(f.customPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cf customFile
	if err := json.Unmarshal(b, &cf); err != nil {
		return nil, fmt.Errorf("%s: parse: %w", f.customPath, err)
	}
	return cf.Targets, nil
}

func (f *FileStore) SaveCustoms(customs []CustomTarget) error {
	if err := os.MkdirAll(f.ipsDir, 0o755); err != nil {
		return err
	}
	cf := customFile{UpdatedAt: time.Now().UTC().Format(time.RFC3339), Targets: customs}
	b, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(f.customPath, b, 0o644)
}

func (f *FileStore) Results(cdn string) (*output.ResultFile, error) {
	return output.Read(f.resultsDir, cdn)
}

func (f *FileStore) SaveResults(cdn string, entries []output.Entry) (string, error) {
	return output.Write(f.resultsDir, cdn, entries)
}

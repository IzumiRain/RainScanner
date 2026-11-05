package xray

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func embeddedArchive(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("release/xray")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractEmbeddedConcurrent(t *testing.T) {
	payload := bytes.Repeat([]byte("in-memory executable fixture\n"), 4096)
	archive := embeddedArchive(t, payload)
	dir := t.TempDir()
	const workers = 24
	paths := make([]string, workers)
	errs := make([]error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range paths {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			paths[i], errs[i] = extractEmbedded(archive, "xray", dir)
		}(i)
	}
	close(start)
	wg.Wait()
	for i := range paths {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if paths[i] != paths[0] {
			t.Fatal("extractors returned different destinations")
		}
		got, err := os.ReadFile(paths[i])
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("worker %d read incomplete extraction: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary extraction leaked: %v %v", entries, err)
	}
	fi, err := os.Stat(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v", fi.Mode())
	}
	if _, err := extractEmbedded(archive, "xray", dir); err != nil {
		t.Fatal(err)
	}
	fi2, err := os.Stat(paths[0])
	if err != nil || !os.SameFile(fi, fi2) || !fi.ModTime().Equal(fi2.ModTime()) {
		t.Fatalf("valid cache was rewritten: %v", err)
	}
}

func TestExtractEmbeddedRejectsInvalidCache(t *testing.T) {
	payload := []byte("verified binary fixture")
	archive := embeddedArchive(t, payload)
	for _, kind := range []string{"same-size corruption", "permissions", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			if runtime.GOOS == "windows" && kind != "same-size corruption" {
				t.Skip("Unix permission/symlink semantics")
			}
			dir := t.TempDir()
			dst, err := extractEmbedded(archive, "xray", dir)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "same-size corruption":
				if err := os.WriteFile(dst, bytes.Repeat([]byte{'x'}, len(payload)), 0o755); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(dst, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(dst); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(dir, "other")
				if err := os.WriteFile(target, payload, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, dst); err != nil {
					t.Fatal(err)
				}
			}
			path, err := extractEmbedded(archive, "xray", dir)
			if err != nil {
				// Windows Rename cannot replace an existing corrupt file; failing
				// closed still guarantees it is never returned as a valid binary.
				if runtime.GOOS == "windows" {
					return
				}
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("returned corrupt cache: %v", err)
			}
			fi, err := os.Lstat(path)
			if err != nil || !fi.Mode().IsRegular() || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755) {
				t.Fatalf("unsafe extraction mode: %v %v", fi, err)
			}
		})
	}
}

func TestExtractEmbeddedInvalidArchive(t *testing.T) {
	if _, err := extractEmbedded([]byte("not a zip"), "xray", t.TempDir()); err == nil {
		t.Fatal("invalid zip accepted")
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := extractEmbedded(buf.Bytes(), "xray", t.TempDir()); err == nil {
		t.Fatal("empty archive accepted")
	}
}

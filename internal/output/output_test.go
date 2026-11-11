package output

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCollidingNamesKeepIndependentResults(t *testing.T) {
	dir := t.TempDir()
	names := []string{"A B", "A-B", "A_B", "A/B", "A:B", "\u4e2d\u6587", "\u65e5\u672c", "custom", "CON", "con.txt", "NUL", "COM1", "LPT9", "../cdn", "cdn.", strings.Repeat("long", 100)}
	paths := map[string]string{}
	for i, name := range names {
		path := Path(dir, name)
		if prev, ok := paths[strings.ToLower(path)]; ok {
			t.Fatalf("%q and %q share path %s", prev, name, path)
		}
		paths[strings.ToLower(path)] = name
		if filepath.Dir(path) != dir || len(filepath.Base(path)) > 200 {
			t.Fatalf("unsafe path %s", path)
		}
		want := []Entry{{IP: "192.0.2.1", Port: 1000 + i, MedianMS: int64(i)}}
		written, err := Write(dir, name, want)
		if err != nil || written != path {
			t.Fatalf("write %q: %s, %v", name, written, err)
		}
		got, err := Read(dir, name)
		if err != nil || got.CDN != name || !reflect.DeepEqual(got.Results, want) {
			t.Fatalf("read %q: %+v, %v", name, got, err)
		}
	}
	for i, name := range names {
		got, err := Read(dir, name)
		if err != nil || got.CDN != name || got.Results[0].Port != 1000+i {
			t.Fatalf("later read %q: %+v, %v", name, got, err)
		}
	}
}

func TestCanonicalPathsAndCaseInsensitiveIdentity(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"cloudflare", "cloudfront", "fastly", "arvan", "my-cdn"} {
		want := filepath.Join(dir, name+".json")
		if Path(dir, name) != want || Path(dir, strings.ToUpper(name)) != want {
			t.Fatalf("canonical path changed: %q", name)
		}
	}
	if Path(dir, " My CDN! ") != Path(dir, "my cdn!") {
		t.Fatal("case-insensitive identity produced different paths")
	}
	if _, err := Write(dir, "My CDN!", []Entry{{IP: "192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, "MY CDN!"); err != nil {
		t.Fatal(err)
	}
	// Hashed filenames themselves cannot be claimed by a plain custom name.
	hashed := strings.TrimSuffix(filepath.Base(Path(dir, "A B")), ".json")
	if strings.EqualFold(Path(dir, hashed), Path(dir, "A B")) {
		t.Fatal("hash namespace can be claimed by a canonical name")
	}
}

func TestReservedNamesNeverOpenLegacyDevices(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"CON", "PRN", "AUX", "NUL", "COM1", "LPT9"} {
		if _, err := Read(dir, name); !os.IsNotExist(err) {
			t.Fatalf("missing reserved target %q: %v", name, err)
		}
	}
}

func putLegacyResult(t *testing.T, dir, filename, cdn string) []byte {
	t.Helper()
	b, err := json.Marshal(ResultFile{CDN: cdn, Count: 1, Results: []Entry{{IP: "192.0.2.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLegacyReadRequiresMatchingStoredIdentity(t *testing.T) {
	dir := t.TempDir()
	legacy := putLegacyResult(t, dir, "a-b.json", "A B")
	got, err := Read(dir, "a b")
	if err != nil || got.CDN != "A B" {
		t.Fatalf("compatible legacy read: %+v, %v", got, err)
	}
	if _, err := Read(dir, "A-B"); err == nil {
		t.Fatal("read another target's legacy results")
	}
	if _, err := Write(dir, "A-B", []Entry{{IP: "198.51.100.1"}}); err == nil {
		t.Fatal("overwrote conflicting legacy results")
	}
	unchanged, err := os.ReadFile(filepath.Join(dir, "a-b.json"))
	if err != nil || string(unchanged) != string(legacy) {
		t.Fatal("conflicting write changed legacy file")
	}
	if _, err := Write(dir, "A B", []Entry{{IP: "203.0.113.1"}}); err != nil {
		t.Fatal(err)
	}
	got, err = Read(dir, "A B")
	if err != nil || got.Results[0].IP != "203.0.113.1" {
		t.Fatalf("new hashed result not preferred: %+v, %v", got, err)
	}
	// A mismatched hashed file must not be hidden by a matching legacy fallback.
	putLegacyResult(t, dir, filepath.Base(Path(dir, "A B")), "someone else")
	if _, err := Read(dir, "A B"); err == nil {
		t.Fatal("accepted mismatched hashed result")
	}
}

func TestWriteSortsWithoutMutatingCallerAndReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	entries := []Entry{{IP: "192.0.2.1", MedianMS: 30}, {IP: "192.0.2.2", MedianMS: 10}}
	want := append([]Entry(nil), entries...)
	for i := 0; i < 2; i++ {
		if _, err := Write(dir, "fastly", entries); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatal("write reordered caller's entries")
	}
	rf, err := Read(dir, "fastly")
	if err != nil || rf.Count != 2 || rf.Results[0].MedianMS != 10 {
		t.Fatalf("sorted result = %+v, %v", rf, err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("temporary files left behind: %v, %v", files, err)
	}
}

type cancelAtPublishContext struct {
	context.Context
	checks int
}

func (c *cancelAtPublishContext) Err() error {
	c.checks++
	if c.checks >= 2 {
		return context.Canceled
	}
	return nil
}

func TestCanceledWritePreservesExistingResults(t *testing.T) {
	for _, stage := range []string{"before-work", "before-publish"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := Write(dir, "fastly", []Entry{{IP: "192.0.2.1"}}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(Path(dir, "fastly"))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var writeCtx context.Context = ctx
			if stage == "before-publish" {
				writeCtx = &cancelAtPublishContext{Context: context.Background()}
			}
			if _, err := WriteContext(writeCtx, dir, "fastly", []Entry{{IP: "198.51.100.1"}}); !errors.Is(err, context.Canceled) {
				t.Fatalf("write error = %v", err)
			}
			after, err := os.ReadFile(Path(dir, "fastly"))
			if err != nil || string(after) != string(before) {
				t.Fatal("canceled write replaced results")
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 1 {
				t.Fatalf("canceled write left temporary files: %v, %v", files, err)
			}
		})
	}
}

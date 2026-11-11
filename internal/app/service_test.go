package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cdnscan/internal/providers"
	"cdnscan/internal/storage"
	"cdnscan/internal/targets"
)

func testService(t *testing.T, feed string) (*Service, *storage.FileStore) {
	t.Helper()
	installed, entries := providers.ManifestInstalled(), providers.Entries()
	providers.SetManifest(&providers.ManifestIndex{CDNs: []providers.ManifestEntry{{Name: "testcdn", APIURL: feed, Parser: "scrape"}}})
	t.Cleanup(func() {
		if installed {
			providers.SetManifest(&providers.ManifestIndex{CDNs: entries})
		} else {
			providers.SetManifest(nil)
		}
	})
	root := t.TempDir()
	ips, results := filepath.Join(root, "ips"), filepath.Join(root, "results")
	store := storage.NewFileStore(ips, results)
	s, err := New(store, ips, results)
	if err != nil {
		t.Fatal(err)
	}
	return s, store
}

func TestScanRefreshUsesRegistryFeedAndUpdatesNextScan(t *testing.T) {
	for _, kind := range []string{"custom", "builtin-override", "builtin"} {
		t.Run(kind, func(t *testing.T) {
			var officialCalls, customCalls atomic.Int32
			official := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				officialCalls.Add(1)
				fmt.Fprintln(w, "192.0.2.0/24")
			}))
			defer official.Close()
			custom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				customCalls.Add(1)
				fmt.Fprintln(w, `{"cidrs":["192.0.2.0/24"]}`)
			}))
			defer custom.Close()
			s, store := testService(t, official.URL)
			name, api := "testcdn", ""
			if kind == "custom" {
				name = "Custom Feed"
			}
			if kind != "builtin" {
				api = custom.URL
			}
			if _, err := s.Upsert(targets.Record{Name: name, APIURL: api, CIDRs: []string{"198.51.100.0/24"}}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			// The feed is IPv4-only. Selecting IPv6 avoids all candidate TCP dials.
			sums, err := s.Scan(ctx, ScanRequest{CDN: name, Refresh: true, NoBackup: true, Family: "ipv6", MaxTotal: 1}, ScanHooks{})
			if err != nil || len(sums) != 1 || sums[0].Hosts != 0 {
				t.Fatalf("refresh scan = %+v, %v", sums, err)
			}
			if kind == "builtin" {
				if officialCalls.Load() != 1 || customCalls.Load() != 0 {
					t.Fatal("builtin did not use manifest feed")
				}
			} else if officialCalls.Load() != 0 || customCalls.Load() != 1 {
				t.Fatal("refresh bypassed custom/overridden registry feed")
			}
			want := []string{"192.0.2.0/24"}
			got, ok := s.Ranges(name)
			if !ok || !reflect.DeepEqual(got.CIDRs, want) {
				t.Fatalf("registry remained stale: %+v", got)
			}
			cfg, err := s.buildConfig(ScanRequest{CDN: name})
			if err != nil || cfg.Custom == nil || !reflect.DeepEqual(cfg.Custom.CIDRs, want) {
				t.Fatalf("next config remained stale: %+v, %v", cfg.Custom, err)
			}
			reopened, err := New(store, s.ipsDir, s.resultsDir)
			if err != nil {
				t.Fatal(err)
			}
			got, ok = reopened.Ranges(name)
			if !ok || !reflect.DeepEqual(got.CIDRs, want) {
				t.Fatalf("refresh was not persisted: %+v", got)
			}
			if _, err := s.Scan(ctx, ScanRequest{CDN: name, Family: "ipv6"}, ScanHooks{}); err != nil {
				t.Fatal(err)
			}
			if officialCalls.Load()+customCalls.Load() != 1 {
				t.Fatal("next scan refetched rather than using fresh registry state")
			}
		})
	}
}

func TestScanEmptyCustomDoesNotFallBackToManifest(t *testing.T) {
	s, _ := testService(t, "http://127.0.0.1:1/unused")
	if _, err := s.Upsert(targets.Record{Name: "empty-custom"}); err != nil {
		t.Fatal(err)
	}
	sums, err := s.Scan(context.Background(), ScanRequest{CDN: "empty-custom", Family: "ipv6"}, ScanHooks{})
	if err != nil || len(sums) != 1 || sums[0].Hosts != 0 {
		t.Fatalf("empty custom = %+v, %v", sums, err)
	}
	if _, err := s.Scan(context.Background(), ScanRequest{CDN: "empty-custom", Refresh: true}, ScanHooks{}); err == nil {
		t.Fatal("refresh without a source should fail explicitly")
	}
}

func TestScanRefreshRejectsStaleRegistryFetch(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		fmt.Fprintln(w, "192.0.2.0/24")
	}))
	defer server.Close()
	defer unblock()
	s, _ := testService(t, server.URL)
	if _, err := s.Upsert(targets.Record{Name: "testcdn", CIDRs: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := s.Scan(ctx, ScanRequest{CDN: "testcdn", Refresh: true, NoBackup: true, Family: "ipv6"}, ScanHooks{})
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := s.Delete("testcdn"); err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case err := <-done:
		if !errors.Is(err, targets.ErrStaleReload) {
			t.Fatalf("stale refresh error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, ok := s.Ranges("testcdn"); ok {
		t.Fatal("scan refresh resurrected deleted target")
	}
}

func TestAdHocCustomWinsWithoutRefreshingRegistry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); fmt.Fprintln(w, "192.0.2.0/24") }))
	defer server.Close()
	s, _ := testService(t, server.URL)
	sums, err := s.Scan(context.Background(), ScanRequest{CDN: "testcdn", Refresh: true, Custom: &CustomRange{Name: "ad-hoc", CIDRs: []string{"192.0.2.0/24"}}, Family: "ipv6"}, ScanHooks{})
	if err != nil || len(sums) != 1 || sums[0].CDN != "ad-hoc" || calls.Load() != 0 {
		t.Fatalf("explicit custom lost precedence: %+v, %v, calls=%d", sums, err, calls.Load())
	}
}

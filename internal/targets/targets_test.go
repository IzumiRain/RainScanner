package targets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cdnscan/internal/providers"
	"cdnscan/internal/storage"
)

type cancelAfterFeed struct{ cancel context.CancelFunc }

func (rt cancelAfterFeed) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.cancel()
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("192.0.2.0/24")), Request: r}, nil
}

func TestCanceledReloadDoesNotPersistFetchedRanges(t *testing.T) {
	reg, store := testRegistry(t)
	before, err := reg.Upsert(Record{Name: "custom-feed", APIURL: "http://fixture.invalid/", CIDRs: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = reg.Reload(ctx, &http.Client{Transport: cancelAfterFeed{cancel}}, before.Name, providers.FetchOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reload error=%v", err)
	}
	got, _ := reg.Get(before.Name)
	if !reflect.DeepEqual(got, before) {
		t.Fatalf("cancellation changed live record: %+v", got)
	}
	reopened, err := Open(store)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = reopened.Get(before.Name)
	if !reflect.DeepEqual(got, before) {
		t.Fatalf("cancellation changed persisted record: %+v", got)
	}
}

func testRegistry(t *testing.T) (*Registry, *storage.FileStore) {
	t.Helper()
	installed, entries := providers.ManifestInstalled(), providers.Entries()
	providers.SetManifest(&providers.ManifestIndex{CDNs: []providers.ManifestEntry{{Name: "testcdn", APIURL: "https://official.invalid/ranges", Parser: "scrape"}}})
	t.Cleanup(func() {
		if installed {
			providers.SetManifest(&providers.ManifestIndex{CDNs: entries})
		} else {
			providers.SetManifest(nil)
		}
	})
	root := t.TempDir()
	store := storage.NewFileStore(filepath.Join(root, "ips"), filepath.Join(root, "results"))
	reg, err := Open(store)
	if err != nil {
		t.Fatal(err)
	}
	return reg, store
}

func TestBuiltinOverrideAndCanonicalNameSurviveRestart(t *testing.T) {
	reg, store := testRegistry(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"cidrs":["192.0.2.0/24"]}`)
	}))
	defer server.Close()
	got, err := reg.Upsert(Record{Name: " TestCDN ", APIURL: server.URL, CIDRs: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "testcdn" {
		t.Fatalf("name = %q, want manifest spelling", got.Name)
	}
	got, err = reg.Upsert(Record{Name: "TESTCDN", CIDRs: []string{"203.0.113.0/24"}})
	if err != nil || got.APIURL != server.URL {
		t.Fatalf("range-only update lost override: %+v, %v", got, err)
	}
	rf, err := store.Ranges("testcdn")
	if err != nil || rf.CDN != "testcdn" || rf.APIURL != server.URL {
		t.Fatalf("canonical cache = %+v, %v", rf, err)
	}
	reopened, err := Open(store)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get("testcdn")
	if !ok || got.APIURL != server.URL || !reflect.DeepEqual(got.CIDRs, []string{"203.0.113.0/24"}) {
		t.Fatalf("reopened override = %+v, exists=%v", got, ok)
	}
	got, err = reopened.Reload(context.Background(), server.Client(), "TESTCDN", providers.FetchOptions{NoBackup: true})
	if err != nil || !reflect.DeepEqual(got.CIDRs, []string{"192.0.2.0/24"}) {
		t.Fatalf("reload override = %+v, %v", got, err)
	}
}

func TestLegacyBuiltinCacheUsesManifestURL(t *testing.T) {
	_, store := testRegistry(t)
	if err := store.SaveRanges(&providers.RangeFile{CDN: "testcdn", Count: 1, CIDRs: []string{"192.0.2.0/24"}}); err != nil {
		t.Fatal(err)
	}
	reg, err := Open(store)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := reg.Get("testcdn")
	if got.APIURL != providers.APIURL("testcdn") || len(got.CIDRs) != 1 {
		t.Fatalf("legacy cache = %+v", got)
	}
	if _, err := reg.Upsert(Record{Name: "testcdn", CIDRs: got.CIDRs}); err != nil {
		t.Fatal(err)
	}
	rf, err := store.Ranges("testcdn")
	if err != nil || rf.APIURL != "" {
		t.Fatalf("unmodified feed should not pin manifest URL: %+v, %v", rf, err)
	}
}

func TestReloadRejectsConcurrentChanges(t *testing.T) {
	for _, name := range []string{"testcdn", "custom-feed"} {
		for _, change := range []string{"delete", "edit", "delete-recreate", "second-reload"} {
			t.Run(name+"/"+change, func(t *testing.T) {
				reg, store := testRegistry(t)
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				var requests atomic.Int32
				unblock := func() { once.Do(func() { close(release) }) }
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/slow" && requests.Add(1) == 1 {
						close(entered)
						select {
						case <-release:
						case <-r.Context().Done():
							return
						}
					}
					fmt.Fprintln(w, "192.0.2.0/24")
				}))
				defer server.Close()
				defer unblock()
				old := Record{Name: name, APIURL: server.URL + "/slow", CIDRs: []string{"198.51.100.0/24"}}
				if _, err := reg.Upsert(old); err != nil {
					t.Fatal(err)
				}
				if change == "delete-recreate" {
					var err error
					reg, err = Open(store)
					if err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					_, err := reg.Reload(ctx, server.Client(), name, providers.FetchOptions{NoBackup: true})
					done <- err
				}()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if strings.HasPrefix(change, "delete") {
					if removed, err := reg.Delete(name); err != nil || !removed {
						t.Fatalf("delete while fetching = %v, %v", removed, err)
					}
				}
				if change != "delete" && change != "second-reload" {
					newer := Record{Name: name, APIURL: server.URL + "/new", CIDRs: []string{"203.0.113.0/24"}}
					if change == "delete-recreate" {
						newer.Name = strings.ToUpper(name)
					}
					if _, err := reg.Upsert(newer); err != nil {
						t.Fatal(err)
					}
				}
				if change == "second-reload" {
					if _, err := reg.Reload(ctx, server.Client(), name, providers.FetchOptions{NoBackup: true}); err != nil {
						t.Fatal(err)
					}
				}
				want, exists := reg.Get(name)
				unblock()
				select {
				case err := <-done:
					if !errors.Is(err, ErrStaleReload) {
						t.Fatalf("stale reload error = %v", err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				reopened, err := Open(store)
				if err != nil {
					t.Fatal(err)
				}
				for _, view := range []*Registry{reg, reopened} {
					got, ok := view.Get(name)
					if ok != exists || !reflect.DeepEqual(got, want) {
						t.Fatalf("stale reload changed state: %+v/%v, want %+v/%v", got, ok, want, exists)
					}
				}
			})
		}
	}
}

type failingStore struct {
	storage.Store
	fail bool
}

var errPersist = errors.New("persist failed")

func (s *failingStore) SaveRanges(rf *providers.RangeFile) error {
	if s.fail {
		return errPersist
	}
	return s.Store.SaveRanges(rf)
}
func (s *failingStore) SaveCustoms(cs []storage.CustomTarget) error {
	if s.fail {
		return errPersist
	}
	return s.Store.SaveCustoms(cs)
}
func (s *failingStore) SaveHidden(names []string) error {
	if s.fail {
		return errPersist
	}
	return s.Store.SaveHidden(names)
}

func TestFailedPersistenceDoesNotChangeRegistry(t *testing.T) {
	_, store := testRegistry(t)
	fs := &failingStore{Store: store}
	reg, err := Open(fs)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"testcdn", "custom-feed"} {
		if _, err := reg.Upsert(Record{Name: name, CIDRs: []string{"192.0.2.0/24"}}); err != nil {
			t.Fatal(err)
		}
	}
	before := reg.List()
	fs.fail = true
	for _, name := range []string{"testcdn", "custom-feed", "new-custom"} {
		if _, err := reg.Upsert(Record{Name: name, CIDRs: []string{"198.51.100.0/24"}}); !errors.Is(err, errPersist) {
			t.Fatalf("upsert error = %v", err)
		}
		if name != "new-custom" {
			if _, err := reg.Delete(name); !errors.Is(err, errPersist) {
				t.Fatalf("delete error = %v", err)
			}
		}
		if !reflect.DeepEqual(reg.List(), before) {
			t.Fatalf("failed mutation changed registry: %+v", reg.List())
		}
	}
	fs.fail = false
	if _, err := reg.Delete("testcdn"); err != nil {
		t.Fatal(err)
	}
	before = reg.List()
	fs.fail = true
	if _, err := reg.RestoreBuiltins(); !errors.Is(err, errPersist) {
		t.Fatalf("restore error = %v", err)
	}
	if !reflect.DeepEqual(reg.List(), before) {
		t.Fatal("failed restore changed registry")
	}
}

func TestReturnedRecordsDoNotAliasRegistry(t *testing.T) {
	reg, _ := testRegistry(t)
	rec, err := reg.Upsert(Record{Name: "custom", CIDRs: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	rec.CIDRs[0] = "changed"
	rec, _ = reg.Get("custom")
	rec.CIDRs[0] = "changed"
	list := reg.List()
	for i := range list {
		if list[i].Name == "custom" {
			list[i].CIDRs[0] = "changed"
		}
	}
	got, _ := reg.Get("custom")
	if !reflect.DeepEqual(got.CIDRs, []string{"192.0.2.0/24"}) {
		t.Fatalf("mutated registry: %+v", got)
	}
}

func TestFailedReloadDoesNotChangeRegistry(t *testing.T) {
	_, store := testRegistry(t)
	fs := &failingStore{Store: store}
	reg, err := Open(fs)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "198.51.100.0/24") }))
	defer server.Close()
	for _, name := range []string{"testcdn", "custom-feed"} {
		fs.fail = false
		before, err := reg.Upsert(Record{Name: name, APIURL: server.URL, CIDRs: []string{"192.0.2.0/24"}})
		if err != nil {
			t.Fatal(err)
		}
		fs.fail = true
		if _, err := reg.Reload(context.Background(), server.Client(), name, providers.FetchOptions{}); !errors.Is(err, errPersist) {
			t.Fatalf("reload error = %v", err)
		}
		got, _ := reg.Get(name)
		if !reflect.DeepEqual(got, before) {
			t.Fatalf("failed reload changed record: %+v, want %+v", got, before)
		}
	}
}

package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type partialCancelTransport struct{ cancel context.CancelFunc }

func (rt partialCancelTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Path, "v6") {
		rt.cancel()
		return nil, context.Canceled
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("192.0.2.0/24")), Request: r}, nil
}

func TestDualFeedCancellationDoesNotReturnPartialSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &http.Client{Transport: partialCancelTransport{cancel: cancel}}
	entry := ManifestEntry{Name: "fixture", Parser: "scrape", APIURL: "http://fixture.invalid/v4", APIURLv6: "http://fixture.invalid/v6"}
	cidrs, _, err := FetchRanges(ctx, client, entry, FetchOptions{NoBackup: true})
	if !errors.Is(err, context.Canceled) || len(cidrs) != 0 {
		t.Fatalf("canceled dual feed published partial success: %v, %v", cidrs, err)
	}
}

type cancelTransport struct{ cancel context.CancelFunc }

func (rt cancelTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.cancel()
	return nil, context.Canceled
}

func TestRangeFetchPreservesCancellationAcrossFallbacks(t *testing.T) {
	for _, parser := range []string{"scrape", "manual"} {
		for _, backupFirst := range []bool{false, true} {
			t.Run(parser+"/backup="+fmt.Sprint(backupFirst), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				client := &http.Client{Transport: cancelTransport{cancel: cancel}}
				_, _, err := FetchRanges(ctx, client, ManifestEntry{Name: "fixture", APIURL: "http://fixture.invalid/", Parser: parser}, FetchOptions{PreferBackup: backupFirst})
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", err)
				}
			})
		}
	}
}

func TestRangeFileLegacyAndOverrideCompatibility(t *testing.T) {
	dir := t.TempDir()
	legacy := []byte(`{"cdn":"cloudflare","fetched_at":"2026-01-01T00:00:00Z","count":1,"cidrs":["192.0.2.0/24"],"source":"official"}`)
	if err := os.WriteFile(filepath.Join(dir, "cloudflare.json"), legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	rf, err := Load(dir, "cloudflare")
	if err != nil || rf.APIURL != "" || rf.Source != "official" {
		t.Fatalf("legacy cache = %+v, %v", rf, err)
	}
	rf.APIURL = "https://example.invalid/override"
	for i := 0; i < 2; i++ {
		if err := Save(dir, rf); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Load(dir, "cloudflare")
	if err != nil || !reflect.DeepEqual(got, rf) {
		t.Fatalf("override round trip = %+v, %v", got, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "cloudflare.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil || fields["api_url"] == nil {
		t.Fatalf("override metadata not persisted: %s, %v", b, err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("staging files left: %v, %v", files, err)
	}
}

func TestRangeNamesRejectTraversalReservedAndEnvelopeFiles(t *testing.T) {
	for _, name := range []string{"../cloudflare", "a/b", `a\b`, "a:stream", "CON", "nul.txt", "COM1", "lpt9.log", "custom", "index", "cdn.", " cdn"} {
		if SafeRangeName(name) {
			t.Errorf("accepted unsafe name %q", name)
		}
		if _, err := Load(t.TempDir(), name); err == nil {
			t.Errorf("loaded unsafe name %q", name)
		}
		if err := Save(t.TempDir(), &RangeFile{CDN: name}); err == nil {
			t.Errorf("saved unsafe name %q", name)
		}
	}
	for _, name := range []string{"cloudflare", "gcore", "my-cdn", "CDN_2"} {
		if !SafeRangeName(name) {
			t.Errorf("rejected valid name %q", name)
		}
	}
}

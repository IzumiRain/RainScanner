package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestCustomEnvelopePreservesHiddenAndCustoms(t *testing.T) {
	root := t.TempDir()
	f := NewFileStore(filepath.Join(root, "ips"), filepath.Join(root, "results"))
	customs := []CustomTarget{{Name: "Custom Feed", APIURL: "https://example.invalid/feed", CIDRs: []string{"192.0.2.0/24"}}}
	if err := f.SaveCustoms(customs); err != nil {
		t.Fatal(err)
	}
	if err := f.SaveHidden([]string{"cloudflare"}); err != nil {
		t.Fatal(err)
	}
	if err := f.SaveCustoms(customs); err != nil {
		t.Fatal(err)
	}
	got, err := f.LoadCustoms()
	if err != nil || !reflect.DeepEqual(got, customs) {
		t.Fatalf("customs = %+v, %v", got, err)
	}
	hidden, err := f.LoadHidden()
	if err != nil || !reflect.DeepEqual(hidden, []string{"cloudflare"}) {
		t.Fatalf("hidden = %v, %v", hidden, err)
	}
	files, err := os.ReadDir(f.ipsDir)
	if err != nil || len(files) != 1 || files[0].Name() != "custom.json" {
		t.Fatalf("unexpected staging files: %v, %v", files, err)
	}
}

func TestConcurrentEnvelopeUpdatesRemainValidAndPreserveFields(t *testing.T) {
	root := t.TempDir()
	f := NewFileStore(filepath.Join(root, "ips"), filepath.Join(root, "results"))
	if err := f.SaveCustoms(nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				var err error
				switch worker {
				case 0:
					err = f.SaveCustoms([]CustomTarget{{Name: fmt.Sprintf("custom-%d", i)}})
				case 1:
					err = f.SaveHidden([]string{fmt.Sprintf("hidden-%d", i)})
				case 2:
					var b []byte
					b, err = os.ReadFile(f.customPath)
					if err == nil {
						var cf customFile
						err = json.Unmarshal(b, &cf)
					}
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	customs, err := f.LoadCustoms()
	if err != nil || len(customs) != 1 || customs[0].Name != "custom-49" {
		t.Fatalf("lost custom update: %+v, %v", customs, err)
	}
	hidden, err := f.LoadHidden()
	if err != nil || !reflect.DeepEqual(hidden, []string{"hidden-49"}) {
		t.Fatalf("lost hidden update: %v, %v", hidden, err)
	}
}

func TestInvalidExistingEnvelopeIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	f := NewFileStore(dir, filepath.Join(dir, "results"))
	if err := os.WriteFile(f.customPath, []byte("invalid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.SaveCustoms(nil); err == nil {
		t.Fatal("accepted invalid envelope")
	}
	if err := f.SaveHidden(nil); err == nil {
		t.Fatal("accepted invalid envelope")
	}
	b, err := os.ReadFile(f.customPath)
	if err != nil || string(b) != "invalid" {
		t.Fatal("destroyed invalid existing envelope")
	}
}

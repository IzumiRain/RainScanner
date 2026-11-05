package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockedFlush struct {
	*httptest.ResponseRecorder
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (w *blockedFlush) Flush() {
	w.once.Do(func() { close(w.entered); <-w.release })
}

func TestStreamDoesNotLoseTerminalNotification(t *testing.T) {
	s := NewServer(nil)
	j := s.newJob()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := httptest.NewRequest(http.MethodGet, "/api/stream?id="+j.id, nil).WithContext(ctx)
	w := &blockedFlush{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { s.handleStream(w, r); close(done) }()
	select {
	case <-w.entered:
	case <-ctx.Done():
		t.Fatal("stream did not flush")
	}
	j.push(event{Type: "result", Data: map[string]int{"confirmed": 1}})
	j.finish("done")
	close(w.release)
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("terminal notification was lost")
	}
	if !strings.Contains(w.Body.String(), `"type":"done"`) || !strings.Contains(w.Body.String(), "id: 2") {
		t.Fatalf("terminal events absent: %s", w.Body.String())
	}
}

func TestStreamReconnectCursor(t *testing.T) {
	s := NewServer(nil)
	j := s.newJob()
	j.push(event{Type: "log", Line: "first"})
	j.push(event{Type: "log", Line: "second"})
	j.finish("stopped")
	for _, header := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, "/api/stream?id="+j.id+"&after=1", nil)
		if header {
			r.Header.Set("Last-Event-ID", "1")
		}
		w := httptest.NewRecorder()
		s.handleStream(w, r)
		body := w.Body.String()
		if strings.Contains(body, `"first"`) || !strings.Contains(body, `"second"`) || !strings.Contains(body, `"status":"stopped"`) {
			t.Fatalf("incorrect replay: %s", body)
		}
	}
	for _, cursor := range []string{"-1", "garbage", "999"} {
		w := httptest.NewRecorder()
		s.handleStream(w, httptest.NewRequest(http.MethodGet, "/api/stream?id="+j.id+"&after="+cursor, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("cursor %q: status %d", cursor, w.Code)
		}
	}
}

func TestScanCancellationPublishedBeforeWorker(t *testing.T) {
	s := NewServer(nil)
	ctx, cancel := s.beginScan()
	if cancel == nil {
		t.Fatal("could not claim scan")
	}
	defer cancel()
	if _, second := s.beginScan(); second != nil {
		second()
		t.Fatal("duplicate scan claimed")
	}
	w := httptest.NewRecorder()
	s.handleStop(w, httptest.NewRequest(http.MethodPost, "/api/stop", nil))
	select {
	case <-ctx.Done():
	default:
		t.Fatal("Stop did not cancel the accepted scan before its worker started")
	}
}

func TestJobRetentionStartsAtCompletion(t *testing.T) {
	s := NewServer(nil)
	j := s.newJob()
	j.createdAt = time.Now().Add(-2 * time.Hour)
	j.finish("done")
	s.mu.Lock()
	s.sweepJobsLocked()
	_, kept := s.jobs[j.id]
	j.finishedAt = time.Now().Add(-2 * time.Hour)
	s.sweepJobsLocked()
	_, expired := s.jobs[j.id]
	s.mu.Unlock()
	if !kept || expired {
		t.Fatalf("retention kept recent=%v expired old=%v", kept, expired)
	}
}

func TestMutationGuard(t *testing.T) {
	for _, origin := range []string{"http://evil.invalid", "null"} {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/stop", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		if guardMutation(w, r) || w.Code != http.StatusForbidden {
			t.Errorf("accepted origin %s", origin)
		}
	}
	w := httptest.NewRecorder()
	writeJSON(w, map[string]bool{"ok": true})
	var got map[string]bool
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !got["ok"] {
		t.Fatalf("JSON response: %s", w.Body.String())
	}
}

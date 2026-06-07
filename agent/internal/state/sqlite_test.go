package state

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentDurableClaim(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	var claims atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			ok, err := s.Claim(ctx, "request")
			if err != nil {
				t.Error(err)
			}
			if ok {
				claims.Add(1)
			}
		})
	}
	wg.Wait()
	if claims.Load() != 1 {
		t.Fatal("duplicate claims", claims.Load())
	}
	if err := s.Record(ctx, "request", AuditEvent{Kind: "validated", Digest: "hash"}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	events, err := s.Get(ctx, "request")
	if err != nil || len(events) != 2 {
		t.Fatal(events, err)
	}
}

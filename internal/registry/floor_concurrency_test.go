package registry

import (
	"path/filepath"
	"sync"
	"testing"
)

// This is a logical lost-update race in filesystem state. The Go race detector
// cannot detect it: an atomic rename does not make Read/compare/Write atomic.
func TestFloorRaiseConcurrentNeverRegresses(t *testing.T) {
	const workers = 64
	for round := range 32 {
		f := Floor{Path: filepath.Join(t.TempDir(), "floor")}
		if err := f.Raise(1); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, workers)
		var ready, done sync.WaitGroup
		ready.Add(workers)
		done.Add(workers)
		for i := range workers {
			go func(seq uint64) {
				defer done.Done()
				ready.Done()
				<-start
				errs <- f.Raise(seq)
			}(uint64(i + 2))
		}
		ready.Wait()
		close(start)
		done.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := f.Read()
		if err != nil {
			t.Fatal(err)
		}
		if got != workers+1 {
			t.Fatalf("round %d: all Raise(2..%d) succeeded, reopened floor = %d; maximum was overwritten", round, workers+1, got)
		}
	}
}

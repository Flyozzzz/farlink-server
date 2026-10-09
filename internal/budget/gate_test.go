package budget

import (
	"sync"
	"testing"
)

func TestGateCapsEachLevelAndReleasesOnce(t *testing.T) {
	g := NewGate(2, 3, 4)
	r1, ok1 := g.Take("a", "ip1", 1)
	_, ok2 := g.Take("a", "ip1", 1)
	if _, ok := g.Take("a", "ip2", 1); !ok1 || !ok2 || ok {
		t.Fatal("per-device cap")
	}
	if _, ok := g.Take("b", "ip1", 1); !ok {
		t.Fatal("under the address cap")
	}
	if _, ok := g.Take("c", "ip1", 1); ok {
		t.Fatal("per-address cap")
	}
	if _, ok := g.Take("c", "ip2", 1); !ok {
		t.Fatal("under the total cap")
	}
	if _, ok := g.Take("d", "ip3", 1); ok {
		t.Fatal("total cap")
	}
	r1()
	r1()
	if dev, ip, total := g.Held("a", "ip1"); dev != 1 || ip != 2 || total != 3 {
		t.Fatalf("after double release: %d %d %d", dev, ip, total)
	}
}

func TestGateUnderContention(t *testing.T) {
	g := NewGate(0, 0, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	held := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if release, ok := g.Take("d", "ip", 1); ok {
				mu.Lock()
				held++
				mu.Unlock()
				defer release()
			}
		}()
	}
	wg.Wait()
	if _, _, total := g.Held("", ""); total != 0 || held == 0 {
		t.Fatalf("total %d held %d", total, held)
	}
}

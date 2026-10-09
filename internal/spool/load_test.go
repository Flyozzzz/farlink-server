package spool

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// TestLoad drives whole lifecycles (create, upload, commit, list, download, ack) from many device pairs at
// once and reports throughput, latency and memory. Run it with FARLINK_LOAD=<pairs>.
func TestLoad(t *testing.T) {
	pairs, _ := strconv.Atoi(os.Getenv("FARLINK_LOAD"))
	if pairs == 0 {
		t.Skip("set FARLINK_LOAD=<device pairs> to run")
	}
	rounds := 3
	partSize := 4 << 20
	srv, s := setup(t, 64<<30)
	defer srv.Close()
	var mu sync.Mutex
	var lat []time.Duration
	var refused, failed int
	var peakHeap uint64
	stop := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				runtime.ReadMemStats(&m)
				mu.Lock()
				if m.HeapInuse > peakHeap {
					peakHeap = m.HeapInuse
				}
				mu.Unlock()
			}
		}
	}()
	timed := func(f func() int) int {
		a := time.Now()
		c := f()
		mu.Lock()
		lat = append(lat, time.Since(a))
		mu.Unlock()
		return c
	}
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < pairs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner, peer := testutil.NewDevice(), testutil.NewDevice()
			tOwner, tPeer := testutil.Login(t, srv.URL, owner), testutil.Login(t, srv.URL, peer)
			for r := 0; r < rounds; r++ {
				data := make([]byte, partSize)
				rand.Read(data)
				sum := sha256.Sum256(data)
				pid := make([]byte, 16)
				rand.Read(pid)
				part := Part{PartID: pid, Size: uint64(partSize), CiphertextSHA256: sum[:]}
				var cr CreateResponse
				if c := timed(func() int {
					return testutil.Do(t, "POST", srv.URL+"/v1/spools", tOwner, CreateRequest{Recipients: [][]byte{peer.ID}, Parts: []Part{part}}, &cr)
				}); c != 200 {
					mu.Lock()
					if c == 429 || c == 507 {
						refused++
					} else {
						failed++
					}
					mu.Unlock()
					continue
				}
				u := srv.URL + "/v1/spools/" + enc.EncodeToString(cr.SpoolID)
				pu := u + "/parts/" + enc.EncodeToString(pid)
				if c := timed(func() int { return testutil.Do(t, "PUT", pu, tOwner, data, nil) }); c != 204 {
					mu.Lock()
					failed++
					mu.Unlock()
					continue
				}
				s.mu.Lock()
				o := s.objects[string(cr.SpoolID)]
				s.mu.Unlock()
				o.mu.Lock()
				d := o.Descriptor
				o.mu.Unlock()
				d.Boxes = []Box{{Recipient: peer.ID, Box: []byte("sealed-index")}}
				msg, _ := wire.Enc.Marshal(d)
				sig := ed25519.Sign(owner.Priv, append([]byte(domain), msg...))
				timed(func() int {
					return testutil.Do(t, "POST", u+"/commit", tOwner, CommitRequest{Boxes: d.Boxes, SigningKey: owner.Pub, Signature: sig}, nil)
				})
				var list []ListItem
				timed(func() int { return testutil.Do(t, "GET", srv.URL+"/v1/spools", tPeer, nil, &list) })
				var body []byte
				if c := timed(func() int { return testutil.Do(t, "GET", pu, tPeer, nil, &body) }); c != 200 || len(body) != partSize {
					mu.Lock()
					failed++
					mu.Unlock()
				}
				timed(func() int { return testutil.Do(t, "POST", u+"/ack", tPeer, nil, nil) })
			}
		}()
	}
	wg.Wait()
	close(stop)
	el := time.Since(start)
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	moved := float64(pairs*rounds*partSize) / (1 << 20)
	t.Log(fmt.Sprintf("LOAD pairs=%d rounds=%d: %.0f MiB up + down in %.1fs = %.0f MiB/s each way; requests=%d p50=%v p99=%v max=%v; refused=%d failed=%d; peak heap %d MiB",
		pairs, rounds, moved, el.Seconds(), moved/el.Seconds(), len(lat), lat[len(lat)/2], lat[len(lat)*99/100], lat[len(lat)-1], refused, failed, peakHeap>>20))
}

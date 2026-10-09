package signal

import (
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Flyozzzz/farlink-server/internal/auth"
)

func serverWith(h *Hub) *httptest.Server {
	a := auth.New("test")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("GET /v1/signal", Handler(h, a))
	return httptest.NewServer(mux)
}

// tryDial upgrades without registering; the status tells whether admission let it through.
func tryDial(ctx context.Context, srv *httptest.Server, token string) (*websocket.Conn, int) {
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/signal"
	c, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
	if err != nil {
		if resp != nil {
			return nil, resp.StatusCode
		}
		return nil, -1
	}
	return c, 101
}

func waitHeld(t *testing.T, h *Hub, want int64) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if _, _, total := h.Conns.Held("", ""); total == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _, total := h.Conns.Held("", "")
	t.Fatalf("held connections = %d, want %d", total, want)
}

func TestConnectionFloodPerDeviceIsRefusedBeforeUpgrade(t *testing.T) {
	h := NewHub()
	srv := serverWith(h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok := login(t, srv, newDev())
	var conns []*websocket.Conn
	var mu sync.Mutex
	var wg sync.WaitGroup
	codes := map[int]int{}
	for i := 0; i < MaxConnsPerDevice+8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, code := tryDial(ctx, srv, tok)
			mu.Lock()
			defer mu.Unlock()
			codes[code]++
			if c != nil {
				conns = append(conns, c)
			}
		}()
	}
	wg.Wait()
	if codes[101] != MaxConnsPerDevice || codes[429] != 8 {
		t.Fatalf("admitted/refused = %v, want %d upgrades and 8 refusals", codes, MaxConnsPerDevice)
	}
	// Another device is not affected by this one's flood.
	if c, code := tryDial(ctx, srv, login(t, srv, newDev())); code != 101 {
		t.Fatalf("other device = %d", code)
	} else {
		c.CloseNow()
	}
	for _, c := range conns {
		c.CloseNow()
	}
	waitHeld(t, h, 0)
	if c, code := tryDial(ctx, srv, tok); code != 101 {
		t.Fatalf("slots not given back after close: %d", code)
	} else {
		c.CloseNow()
	}
}

func TestConnectionFloodPerAddressWithFreshKeys(t *testing.T) {
	h := NewHub()
	h.Conns.PerIP = 5
	srv := serverWith(h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var conns []*websocket.Conn
	for i := 0; i < 5; i++ {
		c, code := tryDial(ctx, srv, login(t, srv, newDev()))
		if code != 101 {
			t.Fatalf("connection %d = %d", i, code)
		}
		conns = append(conns, c)
	}
	if _, code := tryDial(ctx, srv, login(t, srv, newDev())); code != 429 {
		t.Fatalf("sixth fresh key from one address = %d", code)
	}
	for _, c := range conns {
		c.CloseNow()
	}
}

func TestSocketThatNeverRegistersGivesItsSlotBack(t *testing.T) {
	h := NewHub()
	h.RegisterTimeout = 100 * time.Millisecond
	srv := serverWith(h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, code := tryDial(ctx, srv, login(t, srv, newDev()))
	if code != 101 {
		t.Fatalf("dial = %d", code)
	}
	defer c.CloseNow()
	waitHeld(t, h, 0)
}

func uid(i int) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

// Send then ack frees the box at once, but its delivery id is remembered for MailboxTTL: those ids are paid
// for out of the mailbox and hub budgets, and expire from a queue.
func TestDedupIDFloodIsBoundedAndExpires(t *testing.T) {
	h := NewHub()
	h.MaxMailboxBytes = 64 * seenCost * 4 // room for a few hundred ids
	now := time.Now()
	h.Now = func() time.Time { return now }
	a, b := dev32(1), dev32(2)
	online := h.Online(b) // an online recipient: no offline fanout limit applies
	defer online()
	ctx := context.Background()
	accepted := 0
	for i := 0; i < 100_000; i++ {
		ok, err := h.Send(ctx, a, b, uid(i), nil)
		if err == ErrFull {
			break
		}
		if err != nil || !ok {
			t.Fatalf("send %d: %v %v", i, ok, err)
		}
		accepted++
		h.Ack(b, uint64(i+1))
	}
	if accepted == 0 || accepted >= 100_000 {
		t.Fatalf("accepted %d ids: not bounded by the mailbox budget", accepted)
	}
	h.mu.Lock()
	m := h.boxes[string(b)]
	seen, bytes, total := len(m.seenIDs), m.bytes, h.bytes
	h.mu.Unlock()
	if int64(seen)*seenCost > h.MaxMailboxBytes || bytes > h.MaxMailboxBytes || total != bytes {
		t.Fatalf("seen=%d bytes=%d total=%d over budget %d", seen, bytes, total, h.MaxMailboxBytes)
	}
	// Still deduplicated while remembered.
	if ok, err := h.Send(ctx, a, b, uid(0), nil); ok || err != nil {
		t.Fatalf("remembered id accepted again: %v %v", ok, err)
	}
	now = now.Add(MailboxTTL + time.Second)
	h.GC()
	h.mu.Lock()
	seen, bytes, total = len(h.boxes[string(b)].seenIDs), h.boxes[string(b)].bytes, h.bytes
	h.mu.Unlock()
	if seen != 0 || bytes != 0 || total != 0 {
		t.Fatalf("after expiry seen=%d bytes=%d total=%d", seen, bytes, total)
	}
	if ok, err := h.Send(ctx, a, b, uid(accepted+1), nil); !ok || err != nil {
		t.Fatalf("mailbox not usable after expiry: %v %v", ok, err)
	}
}

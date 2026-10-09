package turn

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	pionturn "github.com/pion/turn/v4"

	"github.com/Flyozzzz/farlink-server/internal/budget"
	"github.com/Flyozzzz/farlink-server/internal/meter"
)

// loopbackService relays to 127.0.0.1 (the test peer) and nothing else private.
func loopbackService(t *testing.T, m meter.Meter) (*Service, func()) {
	t.Helper()
	s := svc()
	s.Meter = m
	s.PeerAllowed = func(ip net.IP) bool { return ip.IsLoopback() }
	srv, err := s.Listen("127.0.0.1:0", "", nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return s, func() { srv.Close() }
}

func turnClient(t *testing.T, s *Service, device []byte) (*pionturn.Client, func()) {
	t.Helper()
	c := s.Mint(device)
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client, err := pionturn.NewClient(&pionturn.ClientConfig{STUNServerAddr: s.UDPAddr, TURNServerAddr: s.UDPAddr,
		Conn: conn, Username: c.Username, Password: c.Password, Realm: Realm})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}
	return client, func() { client.Close(); conn.Close() }
}

// devLedger stands in for billing's ledger: a flat allowance per device.
type devLedger struct {
	mu    sync.Mutex
	limit int64
	used  map[string]int64
}

func newTraffic(limit int64) (*meter.Traffic, *devLedger) {
	l := &devLedger{limit: limit, used: map[string]int64{}}
	m, _ := meter.Open("")
	m.Devices = l
	return m, l
}

func (l *devLedger) Admit(d []byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used[string(d)] < l.limit
}

func (l *devLedger) Charge(d []byte, n int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used[string(d)]+n > l.limit {
		l.used[string(d)] = l.limit // used up, as billing's ledger is once past its overdraft
		return false
	}
	l.used[string(d)] += n
	return true
}

func (l *devLedger) Paid([]byte) bool { return false }

func (l *devLedger) Used(d []byte) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used[string(d)]
}

func dev(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func readWithin(c net.PacketConn, d time.Duration) (int, error) {
	c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 2000)
	n, _, err := c.ReadFrom(buf)
	return n, err
}

func TestRelayedBytesAreChargedBothWays(t *testing.T) {
	m, l := newTraffic(1 << 20)
	s, stop := loopbackService(t, m)
	defer stop()
	d := dev(7)
	client, done := turnClient(t, s, d)
	defer done()
	relay, err := client.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer relay.Close()
	peer, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer peer.Close()

	for i := 0; i < 5; i++ { // client → peer
		if _, err := relay.WriteTo(make([]byte, 100), peer.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		if n, err := readWithin(peer, 2*time.Second); err != nil || n != 100 {
			t.Fatalf("peer got %d %v", n, err)
		}
	}
	for i := 0; i < 3; i++ { // peer → client
		if _, err := peer.WriteTo(make([]byte, 200), relay.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		if n, err := readWithin(relay, 2*time.Second); err != nil || n != 200 {
			t.Fatalf("client got %d %v", n, err)
		}
	}
	if got := l.Used(d); got != 5*100+3*200 {
		t.Fatalf("charged %d, want %d", got, 5*100+3*200)
	}
}

// Datagrams from an address the client never permitted are dropped by pion and must not drain its allowance.
func TestUnpermittedSendersAreNotCharged(t *testing.T) {
	m, l := newTraffic(1 << 20)
	s, stop := loopbackService(t, m)
	defer stop()
	d := dev(8)
	client, done := turnClient(t, s, d)
	defer done()
	relay, err := client.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	stranger, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer stranger.Close()
	for i := 0; i < 20; i++ {
		stranger.WriteTo(make([]byte, 500), relay.LocalAddr())
	}
	if _, err := readWithin(relay, 300*time.Millisecond); err == nil {
		t.Fatal("unpermitted datagram relayed")
	}
	if got := l.Used(d); got != 0 {
		t.Fatalf("unpermitted datagrams charged %d", got)
	}
}

// The address budget holds for TURN too: fresh keys from one address stop together.
func TestTURNChargesTheClientAddress(t *testing.T) {
	m, _ := meter.Open("")
	m.IPLimit = 1000
	s, stop := loopbackService(t, m)
	defer stop()
	peer, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer peer.Close()
	for i, want := range []bool{true, false} {
		client, done := turnClient(t, s, dev(byte(20+i)))
		relay, err := client.Allocate()
		if err != nil {
			done()
			if want {
				t.Fatal(err)
			}
			continue // refused up front: fine
		}
		relay.WriteTo(make([]byte, 600), peer.LocalAddr())
		_, err = readWithin(peer, 500*time.Millisecond)
		if (err == nil) != want {
			t.Fatalf("key %d relayed = %v, want %v", i, err == nil, want)
		}
		relay.Close()
		done()
	}
	if used := m.IPUsed("127.0.0.1"); used != 1000 { // 600, then pinned to the cap by the refused datagram
		t.Fatalf("address charged %d", used)
	}
}

func TestAllocationStopsWhenAllowanceRunsOut(t *testing.T) {
	m, l := newTraffic(1000)
	s, stop := loopbackService(t, m)
	defer stop()
	d := dev(9)
	client, done := turnClient(t, s, d)
	defer done()
	relay, err := client.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	peer, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer peer.Close()
	relay.WriteTo(make([]byte, 600), peer.LocalAddr())
	if n, err := readWithin(peer, 2*time.Second); err != nil || n != 600 {
		t.Fatalf("within allowance: %d %v", n, err)
	}
	relay.WriteTo(make([]byte, 600), peer.LocalAddr())
	if _, err := readWithin(peer, 300*time.Millisecond); err == nil {
		t.Fatal("datagram over the allowance was relayed")
	}
	// The allocation is gone: the peer can't reach the client through it either.
	peer.WriteTo(make([]byte, 10), relay.LocalAddr())
	if _, err := readWithin(relay, 300*time.Millisecond); err == nil {
		t.Fatal("allocation kept relaying after the allowance ran out")
	}
	if _, _, total := s.Allocations.Held("", ""); total != 0 {
		t.Fatalf("stopped allocation still holds a slot: %d", total)
	}
	// And a new one is refused up front (486).
	again, done2 := turnClient(t, s, d)
	defer done2()
	if _, err := again.Allocate(); err == nil {
		t.Fatal("allocation granted with no allowance left")
	}
	if u := l.Used(d); u > 1000 {
		t.Fatalf("charged past the limit: %d", u)
	}
}

// -quotas off: nothing is metered, but allocations are still bounded per device.
func TestAllocationCapWithoutQuotas(t *testing.T) {
	s := svc()
	s.Allocations = budget.NewGate(2, 0, 0)
	srv, err := s.Listen("127.0.0.1:0", "", nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	d := dev(10)
	var relays []net.PacketConn
	for i := 0; i < 2; i++ {
		c, done := turnClient(t, s, d)
		defer done()
		r, err := c.Allocate()
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		relays = append(relays, r)
	}
	c, done := turnClient(t, s, d)
	defer done()
	if _, err := c.Allocate(); err == nil {
		t.Fatal("third allocation for one device granted")
	}
	other, done3 := turnClient(t, s, dev(11))
	defer done3()
	if r, err := other.Allocate(); err != nil {
		t.Fatalf("other device refused: %v", err)
	} else {
		r.Close()
	}
	relays[0].Close() // refresh with lifetime 0: pion deletes it, the slot comes back
	for i := 0; i < 200; i++ {
		if held, _, _ := s.Allocations.Held(string(d), ""); held == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r, err := c.Allocate(); err != nil {
		t.Fatalf("slot not given back: %v", err)
	} else {
		r.Close()
	}
	relays[1].Close()
}

func (l *devLedger) ChargeOnce(d []byte, _ string, n int64) bool { return l.Charge(d, n) }

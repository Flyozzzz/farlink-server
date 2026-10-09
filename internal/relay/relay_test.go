package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/meter"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

type countingMeter struct {
	used  atomic.Int64
	limit int64
}

func (m *countingMeter) Charge(_ []byte, _ string, n int64) bool  { return m.used.Add(n) <= m.limit }
func (m *countingMeter) Admit([]byte, string) bool                { return m.used.Load() < m.limit }
func (m *countingMeter) ChargeAccount([]byte, string, int64) bool { return true }
func (m *countingMeter) ChargeTransit([]byte, string, int64) bool { return true }

// refuse admits every device but one.
type refuse struct {
	meter.Off
	id []byte
}

func (m refuse) Admit(d []byte, _ string) bool { return string(d) != string(m.id) }

func setup(meter meter.Meter) (*httptest.Server, *Service) {
	a := auth.New("test")
	s := New(a)
	if meter != nil {
		s.Meter = meter
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("POST /v1/relay/sessions", s.HandleCreate)
	mux.HandleFunc("GET /v1/relay/{id}", s.HandleConnect)
	return httptest.NewServer(mux), s
}

func connect(t *testing.T, ctx context.Context, srv *httptest.Server, token string, id []byte) (*websocket.Conn, error) {
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/relay/" + EncodeID(id)
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
	return c, err
}

func TestTwoPeersExchangeFrames(t *testing.T) {
	srv, _ := setup(nil)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, air := testutil.NewDevice(), testutil.NewDevice()
	tm, ta := testutil.Login(t, srv.URL, mac), testutil.Login(t, srv.URL, air)
	var cr CreateResponse
	if testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", tm, CreateRequest{Peer: air.ID}, &cr) != 200 {
		t.Fatal("create failed")
	}
	type res struct {
		c   *websocket.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := connect(t, ctx, srv, tm, cr.RelayID); ch <- res{c, err} }()
	ca, err := connect(t, ctx, srv, ta, cr.RelayID)
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	cm := r.c
	cm.Write(ctx, websocket.MessageBinary, []byte("ciphertext-from-mac"))
	if _, b, err := ca.Read(ctx); err != nil || string(b) != "ciphertext-from-mac" {
		t.Fatalf("air got %q %v", b, err)
	}
	ca.Write(ctx, websocket.MessageBinary, []byte("reply"))
	if _, b, err := cm.Read(ctx); err != nil || string(b) != "reply" {
		t.Fatalf("mac got %q %v", b, err)
	}
}

func TestStrangerCannotJoin(t *testing.T) {
	srv, _ := setup(nil)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, air, eve := testutil.NewDevice(), testutil.NewDevice(), testutil.NewDevice()
	var cr CreateResponse
	testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", testutil.Login(t, srv.URL, mac), CreateRequest{Peer: air.ID}, &cr)
	if _, err := connect(t, ctx, srv, testutil.Login(t, srv.URL, eve), cr.RelayID); err == nil {
		t.Fatal("stranger joined a relay session")
	}
}

func TestQuotaStopsForwarding(t *testing.T) {
	m := &countingMeter{limit: 10}
	srv, _ := setup(m)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, air := testutil.NewDevice(), testutil.NewDevice()
	tm, ta := testutil.Login(t, srv.URL, mac), testutil.Login(t, srv.URL, air)
	var cr CreateResponse
	testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", tm, CreateRequest{Peer: air.ID}, &cr)
	done := make(chan *websocket.Conn, 1)
	go func() { c, _ := connect(t, ctx, srv, tm, cr.RelayID); done <- c }()
	ca, _ := connect(t, ctx, srv, ta, cr.RelayID)
	cm := <-done
	cm.Write(ctx, websocket.MessageBinary, []byte("12345678901234567890"))
	if _, _, err := ca.Read(ctx); err == nil {
		t.Fatal("frame over quota was forwarded")
	}
}

func openPair(t *testing.T, srv *httptest.Server) (tm, ta string, id []byte) {
	mac, air := testutil.NewDevice(), testutil.NewDevice()
	tm, ta = testutil.Login(t, srv.URL, mac), testutil.Login(t, srv.URL, air)
	var cr CreateResponse
	if testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", tm, CreateRequest{Peer: air.ID}, &cr) != 200 {
		t.Fatal("create failed")
	}
	return tm, ta, cr.RelayID
}

func TestConcurrentDuplicateConnectTakesOneSlot(t *testing.T) {
	srv, s := setup(nil)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tm, ta, id := openPair(t, srv)
	const n = 8
	conns := make(chan *websocket.Conn, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, err := connect(t, ctx, srv, tm, id); err == nil {
				conns <- c
			}
		}()
	}
	wg.Wait()
	close(conns)
	var owner *websocket.Conn
	for c := range conns {
		if owner != nil {
			t.Fatal("two connections took the owner slot")
		}
		owner = c
	}
	if owner == nil {
		t.Fatal("no owner connection")
	}
	ca, err := connect(t, ctx, srv, ta, id)
	if err != nil {
		t.Fatal(err)
	}
	owner.Write(ctx, websocket.MessageBinary, []byte("hi"))
	if _, b, err := ca.Read(ctx); err != nil || string(b) != "hi" {
		t.Fatalf("peer got %q %v", b, err)
	}
	ca.CloseNow()
	if _, _, err := owner.Read(ctx); err == nil {
		t.Fatal("owner still connected after the peer left")
	}
	waitEmpty(t, s)
	if _, err := connect(t, ctx, srv, ta, id); err == nil {
		t.Fatal("rejoined an ended session")
	}
}

func waitEmpty(t *testing.T, s *Service) {
	t.Helper()
	for i := 0; i < 200; i++ {
		s.mu.Lock()
		n := len(s.sessions)
		s.mu.Unlock()
		_, _, o := s.Open.Held("", "")
		if n == 0 && o == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("relay session not cleaned up")
}

func TestHalfOpenSessionIsCleanedUp(t *testing.T) {
	srv, s := setup(nil)
	defer srv.Close()
	s.JoinTimeout = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tm, ta, id := openPair(t, srv)
	c, err := connect(t, ctx, srv, tm, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Read(ctx); err == nil {
		t.Fatal("lonely side not closed")
	}
	waitEmpty(t, s)
	if _, err := connect(t, ctx, srv, ta, id); err == nil {
		t.Fatal("joined a timed-out session")
	}
}

func TestRelayLifetimeIsBoundByAuthSession(t *testing.T) {
	a := auth.New("test")
	a.TTL = 700 * time.Millisecond
	s := New(a)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("POST /v1/relay/sessions", s.HandleCreate)
	mux.HandleFunc("GET /v1/relay/{id}", s.HandleConnect)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, air := testutil.NewDevice(), testutil.NewDevice()
	tm, ta := testutil.Login(t, srv.URL, mac), testutil.Login(t, srv.URL, air)
	var cr CreateResponse
	start := time.Now()
	testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", tm, CreateRequest{Peer: air.ID}, &cr)
	if time.UnixMilli(int64(cr.ExpiresAt)).After(start.Add(time.Second)) {
		t.Fatalf("relay outlives the auth session: %v", time.UnixMilli(int64(cr.ExpiresAt)).Sub(start))
	}
	done := make(chan *websocket.Conn, 1)
	go func() { c, _ := connect(t, ctx, srv, tm, cr.RelayID); done <- c }()
	ca, err := connect(t, ctx, srv, ta, cr.RelayID)
	if err != nil {
		t.Fatal(err)
	}
	cm := <-done
	if _, _, err := ca.Read(ctx); err == nil {
		t.Fatal("relay kept running after the auth session expired")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("relay was not cut at the auth expiry")
	}
	cm.CloseNow()
	waitEmpty(t, s)
}

func TestRelayCreateBodyIsSmallAndSessionsPerOwnerAreCapped(t *testing.T) {
	srv, _ := setup(nil)
	defer srv.Close()
	mac := testutil.NewDevice()
	tm := testutil.Login(t, srv.URL, mac)
	if code := testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", tm, make([]byte, 64<<10), nil); code != 413 {
		t.Fatalf("oversized create = %d", code)
	}
	peer := testutil.NewDevice().ID
	for i := 0; i < MaxPerOwner; i++ {
		if code := testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", tm, CreateRequest{Peer: peer}, nil); code != 200 {
			t.Fatalf("create %d = %d", i, code)
		}
	}
	if code := testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", tm, CreateRequest{Peer: peer}, nil); code != 429 {
		t.Fatalf("over per-owner cap = %d", code)
	}
}

// An exhausted device can't open new relay sessions; the peer's quota is not its business.
func TestAdmitGatesNewSessions(t *testing.T) {
	mac, air := testutil.NewDevice(), testutil.NewDevice()
	srv, _ := setup(refuse{id: mac.ID})
	defer srv.Close()
	if code := testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", testutil.Login(t, srv.URL, mac), CreateRequest{Peer: air.ID}, nil); code != 429 {
		t.Fatalf("exhausted device = %d", code)
	}
	if code := testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", testutil.Login(t, srv.URL, air), CreateRequest{Peer: mac.ID}, nil); code != 200 {
		t.Fatalf("device with quota = %d", code)
	}
}

// Fresh keys from one address share its budget, and stop when it runs out mid-session.
func TestFreshKeysCannotBypassTheAddressBudget(t *testing.T) {
	m, _ := meter.Open("")
	m.IPLimit = 30
	srv, s := setup(m)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relayOnce := func(n int) bool {
		tm, ta, id := openPair(t, srv)
		done := make(chan *websocket.Conn, 1)
		go func() { c, _ := connect(t, ctx, srv, tm, id); done <- c }()
		ca, err := connect(t, ctx, srv, ta, id)
		if err != nil {
			t.Fatal(err)
		}
		defer ca.CloseNow()
		cm := <-done
		defer cm.CloseNow()
		cm.Write(ctx, websocket.MessageBinary, make([]byte, n))
		rctx, rcancel := context.WithTimeout(ctx, time.Second)
		defer rcancel()
		_, _, err = ca.Read(rctx)
		return err == nil
	}
	if !relayOnce(20) {
		t.Fatal("within the address budget not forwarded")
	}
	waitEmpty(t, s)
	if relayOnce(20) {
		t.Fatal("a fresh key relayed past its address's budget")
	}
	waitEmpty(t, s)
	mac, air := testutil.NewDevice(), testutil.NewDevice()
	if code := testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", testutil.Login(t, srv.URL, mac), CreateRequest{Peer: air.ID}, nil); code != 429 {
		t.Fatalf("new session on a used-up address = %d", code)
	}
}

func TestFailedUpgradeReleasesTheSlot(t *testing.T) {
	srv, _ := setup(nil)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tm, ta, id := openPair(t, srv)
	if code := testutil.Do(t, "GET", srv.URL+"/v1/relay/"+EncodeID(id), tm, nil, nil); code == 101 || code == 200 {
		t.Fatalf("plain GET upgraded: %d", code)
	}
	done := make(chan error, 1)
	go func() { _, err := connect(t, ctx, srv, tm, id); done <- err }()
	if _, err := connect(t, ctx, srv, ta, id); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("owner locked out after a failed upgrade: %v", err)
	}
}

// pair opens a session between two fresh devices and returns their connections.
func pair(t *testing.T, ctx context.Context, srv *httptest.Server) (mac, air *websocket.Conn) {
	t.Helper()
	m, a := testutil.NewDevice(), testutil.NewDevice()
	tm, ta := testutil.Login(t, srv.URL, m), testutil.Login(t, srv.URL, a)
	var cr CreateResponse
	if testutil.Do(t, "POST", srv.URL+"/v1/relay/sessions", tm, CreateRequest{Peer: a.ID}, &cr) != 200 {
		t.Fatal("create failed")
	}
	type res struct {
		c   *websocket.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := connect(t, ctx, srv, tm, cr.RelayID); ch <- res{c, err} }()
	ca, err := connect(t, ctx, srv, ta, cr.RelayID)
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.c, ca
}

func TestFramesAreHeldOnlyWhileTheyMoveAndTheBudgetIsGivenBack(t *testing.T) {
	srv, s := setup(nil)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mac, air := pair(t, ctx, srv)
	air.SetReadLimit(-1)
	frame := make([]byte, 3<<20+17)
	for i := 0; i < 5; i++ {
		if err := mac.Write(ctx, websocket.MessageBinary, frame); err != nil {
			t.Fatal(err)
		}
		if _, b, err := air.Read(ctx); err != nil || len(b) != len(frame) {
			t.Fatalf("frame %d: %d bytes, %v", i, len(b), err)
		}
	}
	for i := 0; i < 100; i++ {
		s.Inflight.mu.Lock()
		used := s.Inflight.used
		s.Inflight.mu.Unlock()
		if used == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("bytes still held after every frame was delivered")
}

func TestAFrameThatDoesNotFitTheSharedBudgetEndsItsSession(t *testing.T) {
	srv, s := setup(nil)
	defer srv.Close()
	s.Inflight = NewInflight(1 << 20)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mac, air := pair(t, ctx, srv)
	mac.SetReadLimit(-1)
	air.SetReadLimit(-1)
	// Small frames pass; a big one is turned away before it is all held, and nothing stays reserved.
	if err := mac.Write(ctx, websocket.MessageBinary, []byte("small")); err != nil {
		t.Fatal(err)
	}
	if _, b, err := air.Read(ctx); err != nil || string(b) != "small" {
		t.Fatalf("%q %v", b, err)
	}
	mac.Write(ctx, websocket.MessageBinary, make([]byte, 4<<20))
	if _, _, err := air.Read(ctx); err == nil {
		t.Fatal("a frame over the budget was forwarded")
	}
	for i := 0; i < 100; i++ {
		s.Inflight.mu.Lock()
		used := s.Inflight.used
		s.Inflight.mu.Unlock()
		if used == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("budget not given back after the session ended")
}

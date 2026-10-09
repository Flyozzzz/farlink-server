package turn

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	pionturn "github.com/pion/turn/v4"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

func svc() *Service {
	return &Service{Secret: []byte("0123456789abcdef0123456789abcdef"), Now: time.Now, URLs: []string{"turn:127.0.0.1:3478"}}
}

func TestMintedCredentialsAuthenticate(t *testing.T) {
	s := svc()
	c := s.Mint(make([]byte, 32))
	key, ok := s.AuthKey(c.Username, Realm, nil)
	if !ok || string(key) != string(pionturn.GenerateAuthKey(c.Username, Realm, c.Password)) {
		t.Fatal("fresh credentials rejected")
	}
}

func TestExpiredOrForgedUsernameRejected(t *testing.T) {
	s := svc()
	c := s.Mint(make([]byte, 32))
	s.Now = func() time.Time { return time.Now().Add(CredentialTTL + time.Minute) }
	if _, ok := s.AuthKey(c.Username, Realm, nil); ok {
		t.Fatal("expired credentials accepted")
	}
	s.Now = time.Now
	if _, ok := s.AuthKey("garbage", Realm, nil); ok {
		t.Fatal("malformed username accepted")
	}
	// A client that edits the expiry gets a different HMAC key than the one it holds a password for.
	forged := "9999999999:" + c.Username[len("0000000000:"):]
	key, _ := s.AuthKey(forged, Realm, nil)
	if string(key) == string(pionturn.GenerateAuthKey(forged, Realm, c.Password)) {
		t.Fatal("forged expiry would authenticate")
	}
}

// End-to-end: a real TURN allocation over UDP on localhost with minted credentials.
func TestAllocateOverUDP(t *testing.T) {
	s := svc()
	srv, err := s.Listen("127.0.0.1:0", "", nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := s.UDPAddr
	c := s.Mint(make([]byte, 32))
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer conn.Close()
	client, err := pionturn.NewClient(&pionturn.ClientConfig{STUNServerAddr: addr, TURNServerAddr: addr,
		Conn: conn, Username: c.Username, Password: c.Password, Realm: Realm})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}
	relay, err := client.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	relay.Close()
}

// A firewall can only open what the server promises to use: relayed traffic stays inside -turn-relay-ports.
func TestRelayStaysInConfiguredPorts(t *testing.T) {
	s := svc()
	s.RelayPorts = [2]uint16{47100, 47199}
	srv, err := s.Listen("127.0.0.1:0", "", nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c := s.Mint(make([]byte, 32))
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer conn.Close()
	client, err := pionturn.NewClient(&pionturn.ClientConfig{STUNServerAddr: s.UDPAddr, TURNServerAddr: s.UDPAddr,
		Conn: conn, Username: c.Username, Password: c.Password, Realm: Realm})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}
	relay, err := client.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer relay.Close()
	if port := relay.LocalAddr().(*net.UDPAddr).Port; port < 47100 || port > 47199 {
		t.Fatalf("relay port %d outside 47100-47199", port)
	}
}

// Hole punching asks the TURN listener "how do you see me" with a plain STUN Binding, no credentials.
func TestBindingWithoutCredentials(t *testing.T) {
	s := svc()
	srv, err := s.Listen("127.0.0.1:0", "", nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer conn.Close()
	server, _ := net.ResolveUDPAddr("udp4", s.UDPAddr)
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.WriteTo(req.Raw, server); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no binding response: %v", err)
	}
	res := &stun.Message{Raw: buf[:n]}
	var addr stun.XORMappedAddress
	if err := res.Decode(); err != nil || res.Type != stun.BindingSuccess || addr.GetFrom(res) != nil {
		t.Fatalf("bad binding response: %v %v", err, res.Type)
	}
	if addr.Port != conn.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("mapped port %d, local %s", addr.Port, conn.LocalAddr())
	}
}

func TestCredentialsNeedAuthAndAllow(t *testing.T) {
	a := auth.New("test")
	s := svc()
	s.Auth = a
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("POST /v1/turn/credentials", s.HandleCredentials)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if code := testutil.Do(t, "POST", srv.URL+"/v1/turn/credentials", "", nil, nil); code != 401 {
		t.Fatalf("anonymous credentials = %d", code)
	}
	good, bad := testutil.NewDevice(), testutil.NewDevice()
	s.Meter = onlyMeter{good.ID}
	var c Credentials
	if code := testutil.Do(t, "POST", srv.URL+"/v1/turn/credentials", testutil.Login(t, srv.URL, good), nil, &c); code != 200 || c.Password == "" {
		t.Fatalf("allowed device = %d", code)
	}
	if code := testutil.Do(t, "POST", srv.URL+"/v1/turn/credentials", testutil.Login(t, srv.URL, bad), nil, nil); code != 429 {
		t.Fatalf("refused device = %d", code)
	}
}

// onlyMeter lets one device through.
type onlyMeter struct{ id []byte }

func (m onlyMeter) Charge(d []byte, _ string, _ int64) bool        { return bytes.Equal(d, m.id) }
func (m onlyMeter) Admit(d []byte, _ string) bool                  { return bytes.Equal(d, m.id) }
func (m onlyMeter) ChargeAccount(d []byte, _ string, _ int64) bool { return bytes.Equal(d, m.id) }
func (m onlyMeter) ChargeTransit([]byte, string, int64) bool       { return true }

type hookMeter struct {
	admit  func(device []byte) bool
	charge func(device []byte, n int64) bool
}

func (m hookMeter) Admit(d []byte, _ string) bool                  { return m.admit(d) }
func (m hookMeter) Charge(d []byte, _ string, n int64) bool        { return m.charge(d, n) }
func (m hookMeter) ChargeAccount(d []byte, _ string, n int64) bool { return m.charge(d, n) }
func (m hookMeter) ChargeTransit([]byte, string, int64) bool       { return true }

func TestInternalPeersAreRefused(t *testing.T) {
	s := svc()
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "224.0.0.1"} {
		if s.permit(nil, net.ParseIP(ip)) {
			t.Errorf("relay to %s allowed", ip)
		}
	}
	for _, ip := range []string{"203.0.113.5", "8.8.8.8", "2001:4860::8888"} {
		if !s.permit(nil, net.ParseIP(ip)) {
			t.Errorf("relay to %s refused", ip)
		}
	}
}

// Relayed bytes are billed to the device in the username, both ways; a refused device gets no allocation.
func TestRelayedBytesAreMetered(t *testing.T) {
	s := svc()
	var mu sync.Mutex
	billed := map[string]int64{}
	var refused atomic.Bool
	s.Meter = hookMeter{admit: func([]byte) bool { return !refused.Load() },
		charge: func(d []byte, n int64) bool { mu.Lock(); billed[string(d)] += n; mu.Unlock(); return true }}
	s.PeerAllowed = func(net.IP) bool { return true }
	srv, err := s.Listen("127.0.0.1:0", "", nil, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	dev := bytes.Repeat([]byte{7}, 32)
	c := s.Mint(dev)
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer conn.Close()
	client, err := pionturn.NewClient(&pionturn.ClientConfig{STUNServerAddr: s.UDPAddr, TURNServerAddr: s.UDPAddr,
		Conn: conn, Username: c.Username, Password: c.Password, Realm: Realm})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}
	relay, err := client.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	peer, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer peer.Close()
	if _, err := relay.WriteTo(make([]byte, 1000), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := peer.ReadFrom(buf)
	if err != nil || n != 1000 {
		t.Fatalf("peer got %d, %v", n, err)
	}
	peer.WriteTo(make([]byte, 500), from)
	relay.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _, err := relay.ReadFrom(buf); err != nil || n != 500 {
		t.Fatalf("client got %d, %v", n, err)
	}
	mu.Lock()
	got := billed[string(dev)]
	mu.Unlock()
	if got != 1500 {
		t.Fatalf("billed %d, want 1500", got)
	}

	refused.Store(true)
	conn2, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer conn2.Close()
	client2, _ := pionturn.NewClient(&pionturn.ClientConfig{STUNServerAddr: s.UDPAddr, TURNServerAddr: s.UDPAddr,
		Conn: conn2, Username: c.Username, Password: c.Password, Realm: Realm})
	defer client2.Close()
	client2.Listen()
	if r, err := client2.Allocate(); err == nil {
		r.Close()
		t.Fatal("allocation past the quota")
	}
}

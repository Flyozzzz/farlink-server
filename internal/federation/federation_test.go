package federation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/registry"
)

type node struct {
	id   string
	cert tls.Certificate
	pin  []byte
	srv  *httptest.Server
	fed  *Server
	got  chan Request
	mu   sync.Mutex
	seen map[string]bool
}

func mkCert(t *testing.T, name string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, SPKIPin(leaf)
}

func mesh(t *testing.T, ids ...string) map[string]*node {
	t.Helper()
	nodes := map[string]*node{}
	for _, id := range ids {
		n := &node{id: id, got: make(chan Request, 8), seen: map[string]bool{}}
		n.cert, n.pin = mkCert(t, id)
		n.srv = httptest.NewUnstartedServer(nil)
		n.srv.TLS = &tls.Config{Certificates: []tls.Certificate{n.cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
		nodes[id] = n
	}
	var reg registry.Registry
	for _, id := range ids {
		n := nodes[id]
		n.srv.StartTLS()
		t.Cleanup(n.srv.Close)
		reg.Servers = append(reg.Servers, registry.Server{ServerID: id, APIOrigin: n.srv.URL,
			FederationIdentity: PinString(n.pin), TLSSPKIPins: [][]byte{n.pin}})
	}
	dir, err := NewDirectory(reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n := nodes[id]
		n.fed = &Server{Self: id, Dir: dir, Client: &Client{Self: id, Dir: dir, Cert: n.cert},
			Sink: SinkFunc(func(_ context.Context, _ Peer, r Request) error {
				n.mu.Lock()
				defer n.mu.Unlock()
				k := string(r.DeliveryID)
				if !n.seen[k] {
					n.seen[k] = true
					n.got <- r
				}
				return nil
			})}
		mux := http.NewServeMux()
		mux.HandleFunc("POST "+forwardPath, n.fed.HandleForward)
		n.srv.Config.Handler = mux
	}
	return nodes
}

func newReq(self string, id byte, ttl time.Duration) Request {
	did := make([]byte, 16)
	did[0] = id
	return NewRequest(self, did, make([]byte, 32), make([]byte, 32), "spool-hint", uint64(time.Now().Add(ttl).UnixMilli()), []byte("sealed"))
}

func refusal(t *testing.T, err error, code string) {
	t.Helper()
	e, ok := codeOf(err)
	if !ok || e.Code != code {
		t.Fatalf("want refusal %s, got %v", code, err)
	}
}

func TestForwardDeliversOverMutualTLS(t *testing.T) {
	m := mesh(t, "a", "b")
	if err := m["a"].fed.Client.Send(context.Background(), "b", newReq("a", 1, time.Hour)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-m["b"].got:
		if r.Origin != "a" || r.Kind != "spool-hint" || string(r.Envelope) != "sealed" {
			t.Fatalf("bad request %+v", r)
		}
	default:
		t.Fatal("nothing delivered")
	}
}

func TestDuplicateDeliveryIsHandledOnceByTheSink(t *testing.T) {
	m := mesh(t, "a", "b")
	for i := 0; i < 3; i++ {
		if err := m["a"].fed.Client.Send(context.Background(), "b", newReq("a", 7, time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if len(m["b"].got) != 1 {
		t.Fatalf("sink saw %d, want 1", len(m["b"].got))
	}
}

func TestUnknownCertificateIsRefused(t *testing.T) {
	m := mesh(t, "a", "b")
	stranger, _ := mkCert(t, "evil")
	dir, _ := NewDirectory(registry.Registry{Servers: []registry.Server{{ServerID: "b", APIOrigin: m["b"].srv.URL,
		FederationIdentity: PinString(m["b"].pin), TLSSPKIPins: [][]byte{m["b"].pin}}}})
	c := &Client{Self: "evil", Dir: dir, Cert: stranger}
	err := c.Send(context.Background(), "b", newReq("evil", 2, time.Hour))
	refusal(t, err, "PEER_UNAUTHORIZED")
	if len(m["b"].got) != 0 {
		t.Fatal("stranger reached the sink")
	}
}

func TestClientRejectsServerWithWrongPinnedKey(t *testing.T) {
	m := mesh(t, "a", "b")
	other, otherPin := mkCert(t, "x")
	_ = other
	dir, _ := NewDirectory(registry.Registry{Servers: []registry.Server{{ServerID: "b", APIOrigin: m["b"].srv.URL,
		FederationIdentity: PinString(m["b"].pin), TLSSPKIPins: [][]byte{otherPin}}}})
	c := &Client{Self: "a", Dir: dir, Cert: m["a"].cert}
	if err := c.Send(context.Background(), "b", newReq("a", 3, time.Hour)); err == nil {
		t.Fatal("connected to a server that does not match the registry pin")
	}
}

func TestSenderMustBeTheLastVisitedServer(t *testing.T) {
	m := mesh(t, "a", "b", "c")
	r := newReq("a", 4, time.Hour) // claims origin a, but c is the one connecting
	refusal(t, m["c"].fed.Client.Send(context.Background(), "b", r), "PEER_UNAUTHORIZED")
}

func TestLoopExpiryAndHopLimitAreRefused(t *testing.T) {
	m := mesh(t, "a", "b", "c")
	ctx := context.Background()

	loop := newReq("a", 5, time.Hour)
	loop.Visited = []string{"a", "b", "c"}
	loop.Origin = "a"
	refusal(t, m["c"].fed.Client.Send(ctx, "b", loop), "FEDERATION_LOOP")

	refusal(t, m["a"].fed.Client.Send(ctx, "b", newReq("a", 6, -time.Second)), "EXPIRED")

	long := newReq("a", 8, 30*24*time.Hour)
	refusal(t, m["a"].fed.Client.Send(ctx, "b", long), "INVALID_ENCODING")

	spent := newReq("a", 9, time.Hour)
	spent.HopLimit = 0
	refusal(t, m["a"].fed.Client.Send(ctx, "b", spent), "HOP_LIMIT")

	dup := newReq("a", 10, time.Hour)
	dup.Visited = []string{"a", "a"}
	refusal(t, m["a"].fed.Client.Send(ctx, "b", dup), "INVALID_ENCODING")

	bad := newReq("a", 11, time.Hour)
	bad.Envelope = make([]byte, MaxEnvelope+1)
	refusal(t, m["a"].fed.Client.Send(ctx, "b", bad), "INVALID_ENCODING")

	if len(m["b"].got) != 0 {
		t.Fatal("a refused envelope reached the sink")
	}
}

func TestRouterForwardsToTheRightServerAndSpendsAHop(t *testing.T) {
	m := mesh(t, "a", "b", "c")
	m["b"].fed.Next = func(Request) string { return "c" }
	if err := m["a"].fed.Client.Send(context.Background(), "b", newReq("a", 12, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(m["b"].got) != 0 {
		t.Fatal("router kept a message meant for c")
	}
	r := <-m["c"].got
	if r.HopLimit != HopLimit-1 || len(r.Visited) != 2 || r.Visited[1] != "b" {
		t.Fatalf("bad onward request: hop=%d visited=%v", r.HopLimit, r.Visited)
	}
}

func TestRouterStopsWhenHopsAreSpent(t *testing.T) {
	m := mesh(t, "a", "b", "c")
	m["b"].fed.Next = func(Request) string { return "c" }
	r := newReq("a", 13, time.Hour)
	r.HopLimit = 1
	refusal(t, m["a"].fed.Client.Send(context.Background(), "b", r), "HOP_LIMIT")
}

func TestRouterLoopBetweenTwoServersTerminates(t *testing.T) {
	m := mesh(t, "a", "b")
	m["a"].fed.Next = func(Request) string { return "b" }
	m["b"].fed.Next = func(Request) string { return "a" }
	err := m["a"].fed.Client.Send(context.Background(), "b", newReq("a", 14, time.Hour))
	refusal(t, err, "FEDERATION_LOOP")
}

func TestDirectoryRejectsMalformedIdentityAndSkipsServersWithoutOne(t *testing.T) {
	if _, err := NewDirectory(registry.Registry{Servers: []registry.Server{{ServerID: "x", FederationIdentity: "not-a-pin"}}}); err == nil {
		t.Fatal("malformed federation_identity accepted")
	}
	d, err := NewDirectory(registry.Registry{Servers: []registry.Server{{ServerID: "plain"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Peer("plain"); ok {
		t.Fatal("server without federation_identity became a peer")
	}
}

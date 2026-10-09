package drop

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/contacts"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/mailbox"
	"github.com/Flyozzzz/farlink-server/internal/outbox"
	"github.com/Flyozzzz/farlink-server/internal/registry"
	"github.com/Flyozzzz/farlink-server/internal/spool"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

type node struct {
	id       string
	srv      *httptest.Server
	box      *mailbox.Store
	out      *outbox.Outbox
	drop     *Service
	con      *contacts.Store
	cli      *federation.Client
	rt       *contacts.Router
	api      *contacts.API
	accounts *accounts.Registry
	resolver *accounts.Resolver
}

var spoolID = []byte("spool-object-001")

type fakeSpool struct {
	owner []byte
	info  spool.Info
}

func (f fakeSpool) Info(id, owner []byte) (spool.Info, bool) {
	return f.info, string(id) == string(spoolID) && bytes.Equal(owner, f.owner)
}

func cert(t *testing.T, name string) (tls.Certificate, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, federation.SPKIPin(leaf)
}

// mesh starts one server per id, all in one registry.
func mesh(t *testing.T, ids ...string) map[string]*node {
	nodes, certs, pins := map[string]*node{}, map[string]tls.Certificate{}, map[string][]byte{}
	var reg registry.Registry
	for _, id := range ids {
		certs[id], pins[id] = cert(t, id)
		n := &node{id: id}
		n.srv = httptest.NewUnstartedServer(nil)
		n.srv.TLS = &tls.Config{Certificates: []tls.Certificate{certs[id]}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
		n.srv.StartTLS()
		t.Cleanup(n.srv.Close)
		nodes[id] = n
		reg.Servers = append(reg.Servers, registry.Server{ServerID: id, APIOrigin: n.srv.URL,
			FederationIdentity: federation.PinString(pins[id]), TLSSPKIPins: [][]byte{pins[id]}})
	}
	dir, err := federation.NewDirectory(reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		n := nodes[id]
		a := auth.New(id)
		n.box, _ = mailbox.Open(t.TempDir())
		client := &federation.Client{Self: id, Dir: dir, Cert: certs[id]}
		n.accounts, err = accounts.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		n.resolver, err = accounts.OpenResolver(n.accounts, t.TempDir(), client.AccountReplicas)
		if err != nil {
			t.Fatal(err)
		}
		n.con, _ = contacts.Open(t.TempDir())
		n.cli = client
		n.rt = &contacts.Router{Self: id, Store: n.con, Client: client, Accounts: n.resolver}
		n.out, err = outbox.Open(t.TempDir(), id, client, n.rt.Guard(n.box.Sink()))
		if err != nil {
			t.Fatal(err)
		}
		n.drop = &Service{Auth: a, Self: id, Dir: dir, Outbox: n.out, Accounts: n.resolver}
		n.drop.Authority = n.rt
		fed := &federation.Server{Self: id, Dir: dir, Sink: n.rt.Guard(n.box.Sink()), Client: client}
		api := &mailbox.API{Auth: a, Store: n.box, Accounts: n.resolver}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /v1/accounts/{id}", (&accounts.API{Reg: n.accounts}).HandleGet)
		mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
		mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
		mux.HandleFunc("POST /v1/mailbox/drop", n.drop.HandleDrop)
		mux.HandleFunc("GET /v1/mailbox", api.HandleList)
		mux.HandleFunc("POST /v1/mailbox/{id}/ack", api.HandleAck)
		mux.HandleFunc("POST /v1/federation/forward", fed.HandleForward)
		contactFederation := &contacts.Federation{Dir: dir, Router: n.rt}
		mux.HandleFunc("POST "+contacts.AdmitPath, contactFederation.HandleAdmit)
		mux.HandleFunc("POST "+contacts.ExportPath, contactFederation.HandleExport)
		mux.HandleFunc("POST "+contacts.ImportPath, contactFederation.HandleImport)
		n.api = &contacts.API{Auth: a, Store: n.con, Accounts: n.resolver, Self: id, Client: client}
		mux.HandleFunc("POST /v1/contacts/state", n.api.HandleState)
		n.srv.Config.Handler = mux
	}
	return nodes
}

func insecureLogin(t *testing.T, n *node, d testutil.Device) string {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return testutil.Login(t, n.srv.URL, d)
}

func did(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

func list(t *testing.T, n *node, d testutil.Device) []mailbox.Entry {
	var out []mailbox.Entry
	if testutil.Do(t, "GET", n.srv.URL+"/v1/mailbox", insecureLogin(t, n, d), nil, &out) != 200 {
		t.Fatal("list failed")
	}
	return out
}

func TestMessageReachesBothMailboxServersAndSurvivesOneBeingDown(t *testing.T) {
	m := mesh(t, "a", "b", "c")
	sender, recipient := testutil.NewDevice(), testutil.NewDevice()
	tok := insecureLogin(t, m["a"], sender)
	req := Request{DeliveryID: did(1), Destination: recipient.ID, Kind: KindMessage, MailboxServers: []string{"b", "c"}, Envelope: []byte("sealed")}
	var resp Response
	if code := testutil.Do(t, "POST", m["a"].srv.URL+"/v1/mailbox/drop", tok, req, &resp); code != 202 || resp.Accepted != 2 {
		t.Fatalf("drop = %d %+v", code, resp)
	}
	m["b"].srv.Close() // a mailbox server is down when the origin delivers
	if n := m["a"].out.Process(context.Background()); n != 1 {
		t.Fatalf("delivered %d, want 1 (only c is up)", n)
	}
	if m["a"].out.Pending() != 1 {
		t.Fatal("the delivery to b must stay queued")
	}
	got := list(t, m["c"], recipient)
	if len(got) != 1 || got[0].Origin != "a" || string(got[0].Envelope) != "sealed" || !bytes.Equal(got[0].Sender, sender.ID) {
		t.Fatalf("c holds %+v", got)
	}
	if other := list(t, m["c"], testutil.NewDevice()); len(other) != 0 {
		t.Fatal("a stranger sees the recipient's mailbox")
	}
}

func TestOriginCanBeOneOfTheMailboxServers(t *testing.T) {
	m := mesh(t, "a", "b")
	sender, recipient := testutil.NewDevice(), testutil.NewDevice()
	tok := insecureLogin(t, m["a"], sender)
	req := Request{DeliveryID: did(2), Destination: recipient.ID, Kind: KindMessage, MailboxServers: []string{"a", "b"}, Envelope: []byte("x")}
	if code := testutil.Do(t, "POST", m["a"].srv.URL+"/v1/mailbox/drop", tok, req, nil); code != 202 {
		t.Fatal(code)
	}
	if m["a"].out.Process(context.Background()) != 2 || len(list(t, m["a"], recipient)) != 1 || len(list(t, m["b"], recipient)) != 1 {
		t.Fatal("both the local and the remote mailbox must hold it")
	}
}

func TestSpoolHintUsesTheServersOwnNumbersAndRecipientCheck(t *testing.T) {
	m := mesh(t, "a", "b")
	sender, recipient, stranger := testutil.NewDevice(), testutil.NewDevice(), testutil.NewDevice()
	exp := uint64(time.Now().Add(2 * time.Hour).UnixMilli())
	m["a"].drop.Spool = fakeSpool{owner: sender.ID, info: spool.Info{Bytes: 4242, ExpiresAt: exp, Recipients: [][]byte{recipient.ID}}}
	tok := insecureLogin(t, m["a"], sender)
	url := m["a"].srv.URL + "/v1/mailbox/drop"
	hint := Request{DeliveryID: did(3), Destination: recipient.ID, Kind: KindSpoolHint, SpoolID: spoolID,
		MailboxServers: []string{"b"}, ExpiresAt: 1, Envelope: []byte("x")}
	if code := testutil.Do(t, "POST", url, tok, hint, nil); code != 202 {
		t.Fatalf("hint = %d", code)
	}
	m["a"].out.Process(context.Background())
	got := list(t, m["b"], recipient)
	if len(got) != 1 || got[0].Bytes != 4242 || got[0].ExpiresAt != exp || string(got[0].SpoolID) != string(spoolID) {
		t.Fatalf("hint stored %+v: size and expiry must come from the spool, not the client", got)
	}
	hint.DeliveryID, hint.Destination = did(4), stranger.ID
	if code := testutil.Do(t, "POST", url, tok, hint, nil); code != 404 {
		t.Fatalf("hint for a non-recipient = %d", code)
	}
	other := insecureLogin(t, m["a"], testutil.NewDevice())
	hint.DeliveryID, hint.Destination = did(5), recipient.ID
	if code := testutil.Do(t, "POST", url, other, hint, nil); code != 404 {
		t.Fatalf("hint for someone else's spool = %d", code)
	}
}

func TestRefusals(t *testing.T) {
	m := mesh(t, "a", "b")
	sender, recipient := testutil.NewDevice(), testutil.NewDevice()
	tok := insecureLogin(t, m["a"], sender)
	url := m["a"].srv.URL + "/v1/mailbox/drop"
	ok := Request{DeliveryID: did(6), Destination: recipient.ID, Kind: KindMessage, MailboxServers: []string{"b"}, Envelope: []byte("x")}
	cases := map[string]func(r *Request){
		"unknown server":    func(r *Request) { r.MailboxServers = []string{"evil"} },
		"same server twice": func(r *Request) { r.MailboxServers = []string{"b", "b"} },
		"three servers":     func(r *Request) { r.MailboxServers = []string{"a", "b", "a"} },
		"no servers":        func(r *Request) { r.MailboxServers = nil },
		"empty envelope":    func(r *Request) { r.Envelope = nil },
		"huge envelope":     func(r *Request) { r.Envelope = make([]byte, MaxEnvelope+1) },
		"short delivery":    func(r *Request) { r.DeliveryID = []byte{1} },
		"bad kind":          func(r *Request) { r.Kind = "gossip" },
		"message + spool":   func(r *Request) { r.SpoolID = []byte("s") },
		"already expired":   func(r *Request) { r.ExpiresAt = uint64(time.Now().Add(-time.Hour).UnixMilli()) },
	}
	for name, mut := range cases {
		r := ok
		mut(&r)
		if code := testutil.Do(t, "POST", url, tok, r, nil); code < 400 || code >= 500 {
			t.Errorf("%s: status %d", name, code)
		}
	}
	if code := testutil.Do(t, "POST", url, tok, Request{DeliveryID: did(7), Destination: recipient.ID, Kind: KindSpoolHint,
		SpoolID: spoolID, MailboxServers: []string{"b"}, Envelope: []byte("x")}, nil); code != 501 {
		t.Errorf("spool hint without a spool = %d", code)
	}
	if code := testutil.Do(t, "POST", url, "", ok, nil); code != 401 {
		t.Errorf("no session = %d", code)
	}
	if m["a"].out.Pending() != 0 {
		t.Fatal("a refused drop left queue entries")
	}
}

func TestLifetimeIsClampedToSevenDays(t *testing.T) {
	m := mesh(t, "a", "b")
	sender, recipient := testutil.NewDevice(), testutil.NewDevice()
	tok := insecureLogin(t, m["a"], sender)
	r := Request{DeliveryID: did(8), Destination: recipient.ID, Kind: KindMessage, MailboxServers: []string{"b"}, Envelope: []byte("x"),
		ExpiresAt: uint64(time.Now().Add(90 * 24 * time.Hour).UnixMilli())}
	testutil.Do(t, "POST", m["a"].srv.URL+"/v1/mailbox/drop", tok, r, nil)
	m["a"].out.Process(context.Background())
	got := list(t, m["b"], recipient)
	if len(got) != 1 || got[0].ExpiresAt > uint64(time.Now().Add(7*24*time.Hour+time.Minute).UnixMilli()) {
		t.Fatalf("lifetime not clamped: %+v", got)
	}
}

func TestPerDeviceRateLimit(t *testing.T) {
	m := mesh(t, "a", "b")
	sender, recipient := testutil.NewDevice(), testutil.NewDevice()
	tok := insecureLogin(t, m["a"], sender)
	now := time.Now()
	m["a"].drop.Now = func() time.Time { return now }
	url := m["a"].srv.URL + "/v1/mailbox/drop"
	var last int
	for i := 0; i <= PerHour; i++ {
		id := make([]byte, 16)
		id[0], id[1] = byte(i), byte(i>>8)
		last = testutil.Do(t, "POST", url, tok, Request{DeliveryID: id, Destination: recipient.ID, Kind: KindMessage, MailboxServers: []string{"b"}, Envelope: []byte("x")}, nil)
	}
	if last != 429 {
		t.Fatalf("drop %d = %d, want 429", PerHour+1, last)
	}
	now = now.Add(time.Hour + time.Second)
	if code := testutil.Do(t, "POST", url, tok, Request{DeliveryID: did(9), Destination: recipient.ID, Kind: KindMessage, MailboxServers: []string{"b"}, Envelope: []byte("x")}, nil); code != 202 {
		t.Fatalf("after the window = %d", code)
	}
}

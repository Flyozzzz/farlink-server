package billing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/meter"
	"github.com/Flyozzzz/farlink-server/internal/registry"
)

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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, federation.SPKIPin(leaf)
}

func TestTheAuthorityIsReachedOverPinnedMutualTLSAndRefusesStrangers(t *testing.T) {
	nodeCert, nodePin := mkCert(t, "ru1")
	authCert, authPin := mkCert(t, "us")
	strangerCert, _ := mkCert(t, "stranger")

	ledger := NewLedger(buckets(100))
	mux := http.NewServeMux()
	authority := &Authority{Ledger: ledger, Limits: Limits{FreeRelay: 100, RelayRelay: 1000, TeamsPerPerson: 200}}
	mux.HandleFunc("POST "+GrantPath, authority.HandleGrant)
	mux.HandleFunc("POST "+UsedPath, authority.HandleUsed)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{authCert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	reg := registry.Registry{Servers: []registry.Server{
		{ServerID: "ru1", FederationIdentity: federation.PinString(nodePin)},
		{ServerID: "us", FederationIdentity: federation.PinString(authPin), APIOrigin: srv.URL, TLSSPKIPins: [][]byte{authPin}},
	}}
	dir, err := federation.NewDirectory(reg)
	if err != nil {
		t.Fatal(err)
	}
	authority.Dir = dir

	node := &FedRemote{Client: &federation.Client{Self: "ru1", Dir: dir, Cert: nodeCert}, Authority: "us"}
	ctx := context.Background()
	month := meter.Month(time.Now())
	grant := func(id string, limit, want int64, overdraft, exact bool, key string) (GrantResponse, error) {
		return node.Grant(ctx, GrantRequest{ID: id, Month: month, Key: key, Limit: limit, Want: want, Overdraft: overdraft, Exact: exact})
	}
	got, err := grant("a", 100, 30, false, false, account)
	if err != nil || got.Granted != 30 || got.Month != month {
		t.Fatalf("grant = %+v, %#v", got, err)
	}
	// The same request again (its reply was lost) is answered with the same grant, not a second one.
	if again, _ := grant("a", 100, 30, false, false, account); again.Granted != 30 {
		t.Fatalf("repeated grant = %+v", again)
	}
	if used, m, err := node.Used(ctx, account); err != nil || used != 30 || m != month {
		t.Fatalf("used = %d (month %d), %v", used, m, err)
	}
	// The limit is the fleet's, not the peer's; an invented one is refused. Another month grants nothing.
	if _, err := grant("b", 1<<40, 10, false, false, account); err == nil {
		t.Fatal("a peer chose its own limit")
	}
	if g, err := node.Grant(ctx, GrantRequest{ID: "c", Month: month - 1, Key: account, Limit: 100, Want: 10}); err != nil || g.Granted != 0 || g.Month != month {
		t.Fatalf("grant for last month = %+v %v", g, err)
	}
	if got, _ := grant("d", 100, 500, false, false, account); got.Granted != 70 {
		t.Fatalf("grant up to the limit = %+v", got)
	}
	if got, _ := grant("e", 100, 500, true, false, account); got.Granted != 100 {
		t.Fatalf("overdraft grant = %+v", got)
	}
	if got, _ := grant("f", 100, 5, true, true, account); got.Granted != 0 {
		t.Fatalf("an exact grant past twice the limit = %+v", got)
	}
	// A Teams pool is granted too: its limit must be seats times the per-seat pool of a pack on sale.
	teams := teamsBucketPrefix + hex.EncodeToString(bytes.Repeat([]byte{4}, 32))
	if g, err := grant("g", 600, 50, false, false, teams); err != nil || g.Granted != 50 {
		t.Fatalf("teams grant = %+v, %v", g, err)
	}
	if _, err := grant("h", 601, 50, false, false, teams); err == nil {
		t.Fatal("a Teams limit that is no pack was accepted")
	}

	// A bucket that is not an account bucket, and a certificate the registry does not know.
	if _, _, err := node.Used(ctx, "free:AAAA"); err == nil {
		t.Fatal("the authority answered for a device bucket")
	}
	if _, _, err := node.Used(ctx, accountBucketPrefix+"short"); err == nil {
		t.Fatal("the authority answered for a key that is not an account id")
	}
	stranger := &FedRemote{Client: &federation.Client{Self: "ru1", Dir: dir, Cert: strangerCert}, Authority: "us"}
	if _, err := stranger.Grant(ctx, GrantRequest{ID: "x", Month: month, Key: account, Limit: 100, Want: 1}); err == nil {
		t.Fatal("a peer the registry does not list got a lease")
	}
}

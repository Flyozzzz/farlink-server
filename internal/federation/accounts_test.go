package federation

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/registry"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

func TestAccountResolverReadsPeerOverPinnedMutualTLS(t *testing.T) {
	data, err := os.ReadFile("../accounts/testdata/swift-chain.cbor")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AccountID []byte   `cbor:"account_id"`
		Links     [][]byte `cbor:"links"`
	}
	if err := wire.Lenient(data, &fixture); err != nil {
		t.Fatal(err)
	}
	local, err := accounts.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	remote, err := accounts.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := local.Submit(fixture.Links[0]); err != nil {
		t.Fatal(err)
	}
	for _, raw := range fixture.Links {
		if _, _, err := remote.Submit(raw); err != nil {
			t.Fatal(err)
		}
	}
	clientCert, clientPin := mkCert(t, "self")
	serverCert, serverPin := mkCert(t, "peer")
	api := &accounts.API{Reg: remote}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/accounts/{id}", api.HandleGet)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	reg := registry.Registry{Servers: []registry.Server{
		{ServerID: "self", FederationIdentity: PinString(clientPin)},
		{ServerID: "peer", FederationIdentity: PinString(serverPin), APIOrigin: srv.URL, TLSSPKIPins: [][]byte{serverPin}},
	}}
	dir, err := NewDirectory(reg)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{Self: "self", Dir: dir, Cert: clientCert}
	resolver, err := accounts.OpenResolver(local, t.TempDir(), client.AccountReplicas)
	if err != nil {
		t.Fatal(err)
	}
	current, err := resolver.Current(context.Background(), fixture.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Head().Number != uint64(len(fixture.Links)-1) {
		t.Fatal("did not observe peer's recovery")
	}
	old, err := accounts.ParseLink(fixture.Links[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := current.ActiveDevice(old.State.Devices[0].DeviceID); ok {
		t.Fatal("pre-recovery device authorized")
	}
	// A different server key cannot furnish a quorum even with a valid checkpoint.
	reg.Servers[1].TLSSPKIPins = [][]byte{clientPin}
	if err := dir.Update(reg); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Current(context.Background(), fixture.AccountID); !errors.Is(err, accounts.ErrUnreachable) {
		t.Fatalf("wrong pin: %v", err)
	}
	// Expiry of the mesh must not fall back to an apparently standalone quorum.
	if err := dir.Update(registry.Registry{}); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Current(context.Background(), fixture.AccountID); !errors.Is(err, accounts.ErrUnreachable) {
		t.Fatalf("expired directory: %v", err)
	}
}

func TestAccountReplicaRefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("account replica followed redirect outside its peer snapshot")
		wire.Write(w, [][]byte{})
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	client := &Client{HTTP: origin.Client()}
	if _, err := client.accountPage(context.Background(), Peer{APIOrigin: origin.URL}, make([]byte, 32), 0); !errors.Is(err, accounts.ErrUnreachable) {
		t.Fatalf("redirect: %v", err)
	}
}

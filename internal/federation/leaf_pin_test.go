package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/registry"
)

// The peer presents a genuine leaf/intermediate/root chain, not just an
// unrelated certificate pasted after the leaf. Only the leaf key is proved.
func pinTestChain(t *testing.T) tls.Certificate {
	t.Helper()
	var parent *x509.Certificate
	var signer *ecdsa.PrivateKey
	var chain [][]byte
	var leafKey *ecdsa.PrivateKey
	for i, name := range []string{"root", "intermediate", "leaf"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: i < 2, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
		if tpl.IsCA {
			tpl.KeyUsage |= x509.KeyUsageCertSign
		}
		if parent == nil {
			parent, signer = tpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		parent, err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		signer, leafKey = key, key
		chain = append([][]byte{der}, chain...)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: leafKey, Leaf: parent}
}

func chainPin(t *testing.T, cert tls.Certificate, index int) []byte {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[index])
	if err != nil {
		t.Fatal(err)
	}
	return SPKIPin(parsed)
}

func TestAuthenticatePeerPinsOnlyLeaf(t *testing.T) {
	cert := pinTestChain(t)
	for index, name := range []string{"leaf", "intermediate", "root"} {
		t.Run(name, func(t *testing.T) {
			dir, err := NewDirectory(registry.Registry{Servers: []registry.Server{{ServerID: "peer", FederationIdentity: PinString(chainPin(t, cert, index))}}})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				peer, ok := AuthenticatePeer(dir, r)
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				io.WriteString(w, peer.ServerID)
			}))
			srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
			srv.StartTLS()
			defer srv.Close()
			client := srv.Client()
			tr := client.Transport.(*http.Transport)
			tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
			defer tr.CloseIdleConnections()
			resp, err := client.Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			want := http.StatusUnauthorized
			if index == 0 {
				want = http.StatusOK
			}
			if resp.StatusCode != want {
				t.Fatalf("pinned %s: status = %d, want %d", name, resp.StatusCode, want)
			}
			if index == 0 && string(body) != "peer" {
				t.Fatalf("authenticated identity = %q", body)
			}
		})
	}
}

func TestFederationClientPinsOnlyLeaf(t *testing.T) {
	cert := pinTestChain(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "delivered") }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	for index, name := range []string{"leaf", "intermediate", "root"} {
		t.Run(name, func(t *testing.T) {
			client := (&Client{}).httpFor(Peer{TLSPins: [][]byte{chainPin(t, cert, index)}})
			defer client.CloseIdleConnections()
			resp, err := client.Get(srv.URL)
			if index != 0 {
				if err == nil {
					resp.Body.Close()
					t.Fatalf("accepted pinned %s instead of leaf", name)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != 200 || string(body) != "delivered" {
				t.Fatalf("leaf request = %v, %d, %q", err, resp.StatusCode, body)
			}
		})
	}
}

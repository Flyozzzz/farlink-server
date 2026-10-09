package appstore_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/appstore"
	"github.com/Flyozzzz/farlink-server/internal/appstore/storetest"
)

const bundle = "com.flyoz.farlink"

func verifier(ca *storetest.CA) *appstore.Verifier {
	v := appstore.NewVerifier(bundle, "Production")
	v.Roots = [][32]byte{ca.Fingerprint()}
	return v
}

func TestValidSubscription(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	tx, err := verifier(ca).VerifyTransaction(ca.Sign(storetest.Subscription(bundle, "relay.monthly", "1000")))
	if err != nil {
		t.Fatal(err)
	}
	if tx.OriginalTransactionID != "1000" || tx.ProductID != "relay.monthly" || tx.Expires().Before(time.Now()) {
		t.Fatalf("%+v", tx)
	}
}

func TestRejections(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	other := storetest.New(storetest.Options{})
	sub := func(edit func(storetest.Transaction)) storetest.Transaction {
		tx := storetest.Subscription(bundle, "relay.monthly", "1000")
		edit(tx)
		return tx
	}
	cases := []struct {
		name string
		jws  string
		want error
	}{
		{"wrong root", other.Sign(sub(func(storetest.Transaction) {})), appstore.ErrUntrusted},
		{"wrong bundle", ca.Sign(sub(func(t storetest.Transaction) { t["bundleId"] = "com.example.other" })), appstore.ErrBundle},
		{"sandbox not accepted", ca.Sign(sub(func(t storetest.Transaction) { t["environment"] = "Sandbox" })), appstore.ErrEnvironment},
		{"revoked", ca.Sign(sub(func(t storetest.Transaction) { t["revocationDate"] = storetest.Ms(time.Now()) })), appstore.ErrRevoked},
		{"subscription expired", ca.Sign(sub(func(t storetest.Transaction) {
			t["expiresDate"] = storetest.Ms(time.Now().Add(-time.Minute))
		})), appstore.ErrExpired},
		{"signed in the future", ca.Sign(sub(func(t storetest.Transaction) {
			t["signedDate"] = storetest.Ms(time.Now().Add(time.Hour))
		})), appstore.ErrFuture},
		{"not a jws", "abc.def", appstore.ErrMalformed},
	}
	for _, c := range cases {
		if _, err := verifier(ca).VerifyTransaction(c.jws); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestExpiredCertificate(t *testing.T) {
	// The leaf had expired when the transaction was signed.
	ca := storetest.New(storetest.Options{NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)})
	if _, err := verifier(ca).VerifyTransaction(ca.Sign(storetest.Subscription(bundle, "p", "1"))); !errors.Is(err, appstore.ErrChain) {
		t.Fatal(err)
	}
	// Signed while the leaf was valid: still fine after it expires (as of the signing date).
	tx := storetest.Subscription(bundle, "p", "1")
	tx["signedDate"] = storetest.Ms(time.Now().Add(-36 * time.Hour))
	if _, err := verifier(ca).VerifyTransaction(ca.Sign(tx)); err != nil {
		t.Fatal(err)
	}
}

func TestMissingAppleExtensions(t *testing.T) {
	for _, o := range []storetest.Options{{SkipLeafOID: true}, {SkipInterOID: true}} {
		ca := storetest.New(o)
		if _, err := verifier(ca).VerifyTransaction(ca.Sign(storetest.Subscription(bundle, "p", "1"))); !errors.Is(err, appstore.ErrChain) {
			t.Errorf("%+v: %v", o, err)
		}
	}
}

func TestTamperedAndForgedHeaders(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	jws := ca.Sign(storetest.Subscription(bundle, "relay.monthly", "1000"))
	parts := strings.Split(jws, ".")
	// Payload swapped for another product: signature no longer matches.
	forged := storetest.Subscription(bundle, "teams50.yearly", "1000")
	p, _ := json.Marshal(forged)
	if _, err := verifier(ca).VerifyTransaction(parts[0] + "." + base64.RawURLEncoding.EncodeToString(p) + "." + parts[2]); !errors.Is(err, appstore.ErrSignature) {
		t.Fatal(err)
	}
	// alg other than ES256.
	var h map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	json.Unmarshal(hb, &h)
	h["alg"] = "none"
	hb, _ = json.Marshal(h)
	if _, err := verifier(ca).VerifyTransaction(base64.RawURLEncoding.EncodeToString(hb) + "." + parts[1] + "." + parts[2]); !errors.Is(err, appstore.ErrAlgorithm) {
		t.Fatal(err)
	}
	// Leaf signed straight by the root, intermediate dropped from x5c.
	h["alg"] = "ES256"
	h["x5c"] = h["x5c"].([]any)[:2]
	hb, _ = json.Marshal(h)
	if _, err := verifier(ca).VerifyTransaction(base64.RawURLEncoding.EncodeToString(hb) + "." + parts[1] + "." + parts[2]); !errors.Is(err, appstore.ErrChain) {
		t.Fatal(err)
	}
}

func TestAppleRootPinned(t *testing.T) {
	v := appstore.NewVerifier(bundle, "Production")
	if len(v.Roots) != 1 || v.Roots[0] != appstore.AppleRootCAG3 {
		t.Fatal("the default verifier must trust exactly Apple Root CA - G3")
	}
	ca := storetest.New(storetest.Options{})
	if _, err := v.VerifyTransaction(ca.Sign(storetest.Subscription(bundle, "p", "1"))); !errors.Is(err, appstore.ErrUntrusted) {
		t.Fatal(err)
	}
}

func TestNotification(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	tx := storetest.Subscription(bundle, "relay.monthly", "1000")
	tx["revocationDate"] = storetest.Ms(time.Now())
	n := map[string]any{"notificationType": "REFUND", "notificationUUID": "u1", "signedDate": storetest.Ms(time.Now()),
		"data": map[string]any{"bundleId": bundle, "environment": "Production", "signedTransactionInfo": ca.Sign(tx)}}
	got, t2, err := verifier(ca).VerifyNotification(ca.Sign(n))
	if !errors.Is(err, appstore.ErrRevoked) || got.NotificationType != "REFUND" || t2.OriginalTransactionID != "1000" {
		t.Fatal(got, t2, err)
	}
	n["data"].(map[string]any)["bundleId"] = "com.example.other"
	if _, _, err := verifier(ca).VerifyNotification(ca.Sign(n)); !errors.Is(err, appstore.ErrBundle) {
		t.Fatal(err)
	}
}

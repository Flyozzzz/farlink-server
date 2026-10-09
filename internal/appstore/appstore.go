// Package appstore verifies StoreKit 2 signed data (JWS) offline: the x5c chain must end in a pinned Apple
// root, the leaf and intermediate must carry Apple's App Store receipt-signing extensions, and the ES256
// signature must verify with the leaf key. No network call: the chain is checked as of the signing date, the
// way Apple's own server library does without online checks.
package appstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

// AppleRootCAG3 is the SHA-256 of the DER of "Apple Root CA - G3" (www.apple.com/certificateauthority), the
// root every App Store JWS chains to.
var AppleRootCAG3 = mustFingerprint("63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179")

var (
	oidReceiptSigner = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1} // leaf
	oidWWDRG6        = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}  // intermediate
)

var (
	ErrMalformed   = errors.New("appstore: malformed JWS")
	ErrAlgorithm   = errors.New("appstore: unsupported algorithm")
	ErrUntrusted   = errors.New("appstore: chain does not end in a trusted root")
	ErrChain       = errors.New("appstore: certificate chain invalid")
	ErrSignature   = errors.New("appstore: signature invalid")
	ErrBundle      = errors.New("appstore: wrong bundle id")
	ErrEnvironment = errors.New("appstore: environment not accepted")
	ErrRevoked     = errors.New("appstore: transaction revoked")
	ErrExpired     = errors.New("appstore: subscription expired")
	ErrFuture      = errors.New("appstore: signed in the future")
)

// Transaction is JWSTransactionDecodedPayload (the fields we use). Dates are Unix milliseconds.
type Transaction struct {
	TransactionID         string `json:"transactionId"`
	OriginalTransactionID string `json:"originalTransactionId"`
	BundleID              string `json:"bundleId"`
	ProductID             string `json:"productId"`
	SubscriptionGroupID   string `json:"subscriptionGroupIdentifier,omitempty"`
	PurchaseDate          int64  `json:"purchaseDate"`
	OriginalPurchaseDate  int64  `json:"originalPurchaseDate"`
	ExpiresDate           int64  `json:"expiresDate,omitempty"`
	Type                  string `json:"type"`
	AppAccountToken       string `json:"appAccountToken,omitempty"`
	OwnershipType         string `json:"inAppOwnershipType"`
	SignedDate            int64  `json:"signedDate"`
	RevocationDate        int64  `json:"revocationDate,omitempty"`
	RevocationReason      *int   `json:"revocationReason,omitempty"`
	IsUpgraded            bool   `json:"isUpgraded,omitempty"`
	Environment           string `json:"environment"`
}

// Expires is the subscription's end, zero for purchases that don't expire.
func (t *Transaction) Expires() time.Time {
	if t.ExpiresDate == 0 {
		return time.Time{}
	}
	return time.UnixMilli(t.ExpiresDate)
}

type Verifier struct {
	// Roots are SHA-256 fingerprints of acceptable root certificates: AppleRootCAG3, plus the local StoreKit
	// testing root when a developer tests against Xcode transactions.
	Roots        [][32]byte
	BundleID     string
	Environments map[string]bool // "Production", "Sandbox", "Xcode"
	Now          func() time.Time
	// ClockSkew tolerates a device clock or signing time slightly ahead of ours.
	ClockSkew time.Duration
}

func NewVerifier(bundleID string, environments ...string) *Verifier {
	env := map[string]bool{}
	for _, e := range environments {
		env[e] = true
	}
	return &Verifier{Roots: [][32]byte{AppleRootCAG3}, BundleID: bundleID, Environments: env, Now: time.Now, ClockSkew: 5 * time.Minute}
}

// VerifyTransaction checks a signed transaction and returns it if it currently grants something: signed by
// Apple for our bundle and an accepted environment, not revoked, and (for subscriptions) not expired.
func (v *Verifier) VerifyTransaction(jws string) (*Transaction, error) {
	var t Transaction
	if err := v.Verify(jws, &t, func() int64 { return t.SignedDate }); err != nil {
		return nil, err
	}
	if t.OriginalTransactionID == "" || t.ProductID == "" {
		return nil, ErrMalformed
	}
	if err := v.checkApp(t.BundleID, t.Environment); err != nil {
		return nil, err
	}
	if t.RevocationDate != 0 {
		return &t, ErrRevoked
	}
	if e := t.Expires(); !e.IsZero() && !e.After(v.Now()) {
		return &t, ErrExpired
	}
	return &t, nil
}

func (v *Verifier) checkApp(bundle, env string) error {
	if bundle != v.BundleID {
		return ErrBundle
	}
	if !v.Environments[env] {
		return ErrEnvironment
	}
	return nil
}

type header struct {
	Alg string   `json:"alg"`
	X5c []string `json:"x5c"`
}

// Verify checks the compact JWS and decodes its payload into out. signedAt reads the signing date (Unix ms)
// from the decoded payload: the chain is validated as of that moment, and it may not be in the future.
func (v *Verifier) Verify(jws string, out any, signedAt func() int64) error {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || len(jws) > 64<<10 {
		return ErrMalformed
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return ErrMalformed
	}
	var h header
	if json.Unmarshal(hb, &h) != nil {
		return ErrMalformed
	}
	if h.Alg != "ES256" {
		return ErrAlgorithm
	}
	if len(h.X5c) != 3 {
		return ErrChain
	}
	var certs [3]*x509.Certificate
	for i, c := range h.X5c {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return ErrMalformed
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return ErrChain
		}
	}
	leaf, inter, root := certs[0], certs[1], certs[2]
	if !v.trusted(root) {
		return ErrUntrusted
	}
	if json.Unmarshal(pb, out) != nil {
		return ErrMalformed
	}
	at := time.UnixMilli(signedAt())
	if signedAt() <= 0 {
		return ErrMalformed
	}
	if at.After(v.Now().Add(v.ClockSkew)) {
		return ErrFuture
	}
	if !hasExtension(leaf, oidReceiptSigner) || !hasExtension(inter, oidWWDRG6) {
		return ErrChain
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inters.AddCert(inter)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return ErrChain
	}
	// The leaf must hang off this intermediate, not straight off the root.
	through := false
	for _, c := range chains {
		if len(c) == 3 && c[1].Equal(inter) {
			through = true
		}
	}
	if !through {
		return ErrChain
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || len(sig) != 64 {
		return ErrSignature
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrSignature
	}
	return nil
}

func (v *Verifier) trusted(root *x509.Certificate) bool {
	fp := sha256.Sum256(root.Raw)
	for _, r := range v.Roots {
		if r == fp {
			return true
		}
	}
	return false
}

func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// Fingerprint is the pin of a certificate DER, for trusting an extra root (Xcode StoreKit testing).
func Fingerprint(der []byte) [32]byte { return sha256.Sum256(der) }

func mustFingerprint(h string) [32]byte {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		panic("appstore: bad fingerprint")
	}
	var f [32]byte
	copy(f[:], b)
	return f
}

// Notification is an App Store Server Notification v2 (responseBodyV2DecodedPayload), the fields we use.
type Notification struct {
	NotificationType string `json:"notificationType"`
	Subtype          string `json:"subtype,omitempty"`
	NotificationUUID string `json:"notificationUUID"`
	SignedDate       int64  `json:"signedDate"`
	Data             struct {
		BundleID              string `json:"bundleId"`
		Environment           string `json:"environment"`
		SignedTransactionInfo string `json:"signedTransactionInfo,omitempty"`
	} `json:"data"`
}

// VerifyNotification checks a notification's signedPayload and the transaction inside it. The transaction is
// returned even when it is revoked or expired (that is usually the news); err is then ErrRevoked/ErrExpired.
func (v *Verifier) VerifyNotification(signedPayload string) (*Notification, *Transaction, error) {
	var n Notification
	if err := v.Verify(signedPayload, &n, func() int64 { return n.SignedDate }); err != nil {
		return nil, nil, err
	}
	if err := v.checkApp(n.Data.BundleID, n.Data.Environment); err != nil {
		return nil, nil, err
	}
	if n.Data.SignedTransactionInfo == "" {
		return &n, nil, nil
	}
	t, err := v.VerifyTransaction(n.Data.SignedTransactionInfo)
	if t == nil {
		return nil, nil, err
	}
	return &n, t, err
}

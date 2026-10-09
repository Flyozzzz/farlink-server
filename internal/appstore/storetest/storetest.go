// Package storetest signs StoreKit-shaped JWS with a throwaway root → intermediate → leaf chain that mirrors
// Apple's (same extensions, ES256), for tests of everything that consumes App Store transactions.
package storetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"
)

type CA struct {
	Root, Inter, Leaf *x509.Certificate
	leafKey           *ecdsa.PrivateKey
}

// Options shape a chain for negative tests.
type Options struct {
	NotBefore, NotAfter time.Time // leaf validity (default: a year around now)
	SkipLeafOID         bool
	SkipInterOID        bool
}

func New(opts Options) *CA {
	now := time.Now()
	if opts.NotBefore.IsZero() {
		opts.NotBefore = now.Add(-180 * 24 * time.Hour)
	}
	if opts.NotAfter.IsZero() {
		opts.NotAfter = now.Add(180 * 24 * time.Hour)
	}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ext := func(oid asn1.ObjectIdentifier) pkix.Extension { return pkix.Extension{Id: oid, Value: []byte{5, 0}} }
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root CA - G3"},
		NotBefore: now.Add(-10 * 365 * 24 * time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	inter := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test WWDR CA - G6"},
		NotBefore: now.Add(-5 * 365 * 24 * time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if !opts.SkipInterOID {
		inter.ExtraExtensions = []pkix.Extension{ext(asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1})}
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Test Prod ECC Mac App Store"},
		NotBefore: opts.NotBefore, NotAfter: opts.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	if !opts.SkipLeafOID {
		leaf.ExtraExtensions = []pkix.Extension{ext(asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1})}
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	interDER, _ := x509.CreateCertificate(rand.Reader, inter, rootCert, &interKey.PublicKey, rootKey)
	interCert, _ := x509.ParseCertificate(interDER)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, interCert, &leafKey.PublicKey, interKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	return &CA{Root: rootCert, Inter: interCert, Leaf: leafCert, leafKey: leafKey}
}

// Fingerprint is what a Verifier pins to trust this CA.
func (c *CA) Fingerprint() [32]byte { return sha256.Sum256(c.Root.Raw) }

// Sign returns a compact ES256 JWS of payload with this chain in x5c.
func (c *CA) Sign(payload any) string {
	x5c := []string{}
	for _, cert := range []*x509.Certificate{c.Leaf, c.Inter, c.Root} {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	h, _ := json.Marshal(map[string]any{"alg": "ES256", "x5c": x5c})
	p, _ := json.Marshal(payload)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	d := sha256.Sum256([]byte(in))
	r, s, _ := ecdsa.Sign(rand.Reader, c.leafKey, d[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Transaction is a JWSTransactionDecodedPayload for Sign; Ms converts times.
type Transaction map[string]any

func Ms(t time.Time) int64 { return t.UnixMilli() }

// Subscription is an active auto-renewable transaction for product, signed now, renewing in a month.
func Subscription(bundle, product, original string) Transaction {
	now := time.Now()
	return Transaction{"transactionId": original + "-1", "originalTransactionId": original, "bundleId": bundle,
		"productId": product, "purchaseDate": Ms(now.Add(-time.Hour)), "originalPurchaseDate": Ms(now.Add(-time.Hour)),
		"expiresDate": Ms(now.Add(30 * 24 * time.Hour)), "type": "Auto-Renewable Subscription",
		"inAppOwnershipType": "PURCHASED", "signedDate": Ms(now), "environment": "Production"}
}

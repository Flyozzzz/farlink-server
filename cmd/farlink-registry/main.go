// Command farlink-registry makes the operator key and signs servers.json (protocol v1 §12).
//
//	farlink-registry keygen -out key.pem           # prints the key id and public key for the apps
//	farlink-registry sign -key key.pem -in registry.json -out servers.json
//	farlink-registry sign -key old.pem,new.pem ...  # during a rotation (next_keys), signed by both
//	farlink-registry pin -cert cert.pem            # SPKI SHA-256 pin, base64, for tls_spki_pins
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Flyozzzz/farlink-server/internal/registry"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: farlink-registry keygen|sign|pin ...")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	out := fs.String("out", "", "output file")
	keyFile := fs.String("key", "", "operator key (PEM); several, comma-separated, sign together")
	in := fs.String("in", "", "registry JSON (unsigned)")
	certFile := fs.String("cert", "", "server certificate (PEM)")
	fs.Parse(os.Args[2:])
	switch os.Args[1] {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		check(err)
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		check(err)
		check(os.WriteFile(*out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
		// For the apps' pinned keys, and for a next_keys entry announcing this key in a catalog signed by the
		// current one: {"key_id": …, "public_key": …, "activate_sequence": <a later sequence>}.
		fmt.Printf("key_id=%s\npublic_key=%s\n", keyID(pub), base64.StdEncoding.EncodeToString(pub))
	case "sign":
		var signers []registry.Signer
		for _, f := range strings.Split(*keyFile, ",") {
			priv := loadKey(f)
			signers = append(signers, registry.Signer{KeyID: keyID(priv.Public().(ed25519.PublicKey)), Key: priv})
		}
		data, err := os.ReadFile(*in)
		check(err)
		var r registry.Registry
		check(json.Unmarshal(data, &r))
		signed, err := registry.SignWith(&r, signers...)
		check(err)
		check(os.WriteFile(*out, signed, 0o644))
	case "pin":
		data, err := os.ReadFile(*certFile)
		check(err)
		b, _ := pem.Decode(data)
		if b == nil {
			fail("no PEM certificate")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		check(err)
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		fmt.Println(base64.StdEncoding.EncodeToString(sum[:]))
	default:
		fail("unknown command " + os.Args[1])
	}
}

// keyID names a key by its own hash, so a rotated key can't be confused with the old one.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "op-" + base64.RawURLEncoding.EncodeToString(sum[:8])
}

func loadKey(path string) ed25519.PrivateKey {
	data, err := os.ReadFile(path)
	check(err)
	b, _ := pem.Decode(data)
	if b == nil {
		fail("no PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	check(err)
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		fail("not an Ed25519 key")
	}
	return priv
}

func check(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) { fmt.Fprintln(os.Stderr, msg); os.Exit(1) }

package billing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// A request signed by the Swift client (Core/Tests/FarlinkNetTests/AccountBillingTests.swift, seed 7): the two
// sides must agree on the byte layout of the signed body, or no real device could ever bind a key.
func TestTheSwiftClientsSignatureVerifiesHere(t *testing.T) {
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pub := ed25519.PublicKey(mustHex("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"))
	body := BindBody{Protocol: 1, AccountID: bytes.Repeat([]byte{1}, 32),
		AccountDevice: mustHex("fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889"),
		Transport:     bytes.Repeat([]byte{2}, 32), RequestID: bytes.Repeat([]byte{3}, 16), ExpiresAt: 301000,
		Audience: "https://us.farlink.test:8443"}
	sig := mustHex("89cc7390855f27456a35dbb3c944f03b2b8f7aded97a442252acfd3daec1d59ccdb9e963d3965d04672b71a5094304241e6851ab87b59bfae14f8bf0d219200e")
	raw, err := wire.Enc.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, append([]byte(BindDomain), raw...), sig) {
		t.Fatal("the Swift signature does not verify over the Go encoding of the same body")
	}
	body.Audience = "https://ru1.farlink.test:8443"
	raw, _ = wire.Enc.Marshal(body)
	if ed25519.Verify(pub, append([]byte(BindDomain), raw...), sig) {
		t.Fatal("a changed field still verifies")
	}
}

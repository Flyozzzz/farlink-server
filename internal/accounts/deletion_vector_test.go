package accounts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// A request signed by the Swift client (Core/Tests/FarlinkNetTests/AccountDeletionTests.swift, seed 7): both sides must
// agree on the bytes of the signed body, or no device could ever delete its account.
func TestTheSwiftClientsDeletionSignatureVerifiesHere(t *testing.T) {
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pub := mustHex("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
	req := DeleteRequest{
		DeleteBody: DeleteBody{Protocol: 1, AccountID: bytes.Repeat([]byte{1}, 32), Device: mustHex("fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889"),
			HeadHash: bytes.Repeat([]byte{4}, 32), ExpiresAt: 1_000 + 5*60*1000},
		Signature: mustHex("b7d00565353bc1321a20a44f9f816392b5a0611898e301b7625976eb86e1311fb806a0b9b64204966bf2fa0b5b9c9bfcc9cc8cde3df3ddca208718173a95a007"),
	}
	if !req.signatureOK(ed25519.PublicKey(pub)) {
		t.Fatal("the Swift signature does not verify over the Go encoding of the same body")
	}
	req.HeadHash = bytes.Repeat([]byte{5}, 32)
	if req.signatureOK(ed25519.PublicKey(pub)) {
		t.Fatal("a changed field still verifies")
	}
}

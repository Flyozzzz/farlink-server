// Package testutil logs devices into a test server the way real clients do.
package testutil

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"net/http"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

type Device struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
	ID   []byte
}

func NewDevice() Device {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := sha256.Sum256(pub)
	return Device{priv, pub, s[:]}
}

// Do sends a CBOR request (body may be nil) and decodes a CBOR response into out; returns the status.
func Do(t *testing.T, method, url, token string, body any, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		if raw, ok := body.([]byte); ok {
			rd = bytes.NewReader(raw)
		} else {
			b, _ := wire.Enc.Marshal(body)
			rd = bytes.NewReader(b)
		}
	}
	req, _ := http.NewRequest(method, url, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil {
		if raw, ok := out.(*[]byte); ok {
			*raw = data
		} else if resp.StatusCode < 300 {
			if err := wire.Lenient(data, out); err != nil {
				t.Fatalf("%s %s: decode: %v", method, url, err)
			}
		}
	}
	return resp.StatusCode
}

func Login(t *testing.T, base string, d Device) string {
	t.Helper()
	var ch auth.ChallengeResponse
	if Do(t, "POST", base+"/v1/auth/challenges", "", auth.ChallengeRequest{DeviceID: d.ID}, &ch) != 200 {
		t.Fatal("challenge failed")
	}
	msg, _ := wire.Enc.Marshal(auth.SignedChallenge{ChallengeID: ch.ChallengeID, Nonce: ch.Nonce, Audience: ch.Audience, ExpiresAt: ch.ExpiresAt, DeviceID: d.ID})
	var sr auth.SessionResponse
	if Do(t, "POST", base+"/v1/auth/sessions", "", auth.SessionRequest{ChallengeID: ch.ChallengeID, SigningKey: d.Pub,
		Signature: ed25519.Sign(d.Priv, append([]byte("farlink/server-auth/v1"), msg...))}, &sr) != 200 {
		t.Fatal("session failed")
	}
	return sr.Token
}

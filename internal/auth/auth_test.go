package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

type device struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   []byte
}

func newDevice() device {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sum := sha256.Sum256(pub)
	return device{pub, priv, sum[:]}
}

func post(t *testing.T, h http.HandlerFunc, body any) *httptest.ResponseRecorder {
	b, _ := wire.Enc.Marshal(body)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/", bytes.NewReader(b)))
	return rec
}

// Login runs the full challenge/response and returns the bearer token (used by other packages' tests too).
func Login(t *testing.T, s *Service, d device) (string, int) {
	rec := post(t, s.HandleChallenge, ChallengeRequest{DeviceID: d.id})
	var ch ChallengeResponse
	if err := wire.Lenient(rec.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	msg, _ := wire.Enc.Marshal(SignedChallenge{ch.ChallengeID, ch.Nonce, ch.Audience, ch.ExpiresAt, d.id})
	sig := ed25519.Sign(d.priv, append([]byte(domain), msg...))
	rec = post(t, s.HandleSession, SessionRequest{ChallengeID: ch.ChallengeID, SigningKey: d.pub, Signature: sig})
	var sr SessionResponse
	wire.Lenient(rec.Body.Bytes(), &sr)
	return sr.Token, rec.Code
}

func TestLoginAndAuthenticate(t *testing.T) {
	s := New("fi1")
	d := newDevice()
	tok, code := Login(t, s, d)
	if code != 200 || tok == "" {
		t.Fatalf("login failed: %d", code)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	sess, ok := s.Authenticate(r)
	if !ok || !bytes.Equal(sess.DeviceID, d.id) {
		t.Fatal("token not accepted")
	}
	r.Header.Set("Authorization", "Bearer "+tok+"x")
	if _, ok := s.Authenticate(r); ok {
		t.Fatal("wrong token accepted")
	}
}

func TestWrongKeyForDeviceID(t *testing.T) {
	s := New("fi1")
	victim, attacker := newDevice(), newDevice()
	rec := post(t, s.HandleChallenge, ChallengeRequest{DeviceID: victim.id})
	var ch ChallengeResponse
	wire.Lenient(rec.Body.Bytes(), &ch)
	msg, _ := wire.Enc.Marshal(SignedChallenge{ch.ChallengeID, ch.Nonce, ch.Audience, ch.ExpiresAt, victim.id})
	sig := ed25519.Sign(attacker.priv, append([]byte(domain), msg...))
	rec = post(t, s.HandleSession, SessionRequest{ChallengeID: ch.ChallengeID, SigningKey: attacker.pub, Signature: sig})
	if rec.Code != 401 {
		t.Fatalf("attacker got a session: %d", rec.Code)
	}
}

func TestChallengeIsOneTimeAndExpires(t *testing.T) {
	s := New("fi1")
	d := newDevice()
	rec := post(t, s.HandleChallenge, ChallengeRequest{DeviceID: d.id})
	var ch ChallengeResponse
	wire.Lenient(rec.Body.Bytes(), &ch)
	msg, _ := wire.Enc.Marshal(SignedChallenge{ch.ChallengeID, ch.Nonce, ch.Audience, ch.ExpiresAt, d.id})
	sig := ed25519.Sign(d.priv, append([]byte(domain), msg...))
	req := SessionRequest{ChallengeID: ch.ChallengeID, SigningKey: d.pub, Signature: sig}
	if post(t, s.HandleSession, req).Code != 200 {
		t.Fatal("first use should work")
	}
	if post(t, s.HandleSession, req).Code != 401 {
		t.Fatal("replayed challenge accepted")
	}

	rec = post(t, s.HandleChallenge, ChallengeRequest{DeviceID: d.id})
	wire.Lenient(rec.Body.Bytes(), &ch)
	msg, _ = wire.Enc.Marshal(SignedChallenge{ch.ChallengeID, ch.Nonce, ch.Audience, ch.ExpiresAt, d.id})
	sig = ed25519.Sign(d.priv, append([]byte(domain), msg...))
	s.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if post(t, s.HandleSession, SessionRequest{ch.ChallengeID, d.pub, sig}).Code != 401 {
		t.Fatal("expired challenge accepted")
	}
}

func TestAudienceIsBound(t *testing.T) {
	a, b := New("fi1"), New("am1")
	d := newDevice()
	rec := post(t, a.HandleChallenge, ChallengeRequest{DeviceID: d.id})
	var ch ChallengeResponse
	wire.Lenient(rec.Body.Bytes(), &ch)
	// Signature made for fi1 must not open a session on am1, even with the same challenge id.
	b.challenges[string(ch.ChallengeID)] = a.challenges[string(ch.ChallengeID)]
	msg, _ := wire.Enc.Marshal(SignedChallenge{ch.ChallengeID, ch.Nonce, "fi1", ch.ExpiresAt, d.id})
	sig := ed25519.Sign(d.priv, append([]byte(domain), msg...))
	if post(t, b.HandleSession, SessionRequest{ch.ChallengeID, d.pub, sig}).Code != 401 {
		t.Fatal("cross-server replay accepted")
	}
}

func postFrom(h http.HandlerFunc, ip string, body any) *httptest.ResponseRecorder {
	b, _ := wire.Enc.Marshal(body)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(b))
	req.RemoteAddr = ip + ":4242"
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestChallengeFloodIsCappedPerIPAndGlobally(t *testing.T) {
	s := New("fi1")
	now := time.Now()
	s.Now = func() time.Time { return now }
	s.MaxChallengesPerIP, s.MaxChallenges = 4, 6
	d := newDevice()
	for i := 0; i < 4; i++ {
		if c := postFrom(s.HandleChallenge, "198.51.100.1", ChallengeRequest{DeviceID: d.id}).Code; c != 200 {
			t.Fatalf("challenge %d = %d", i, c)
		}
	}
	if c := postFrom(s.HandleChallenge, "198.51.100.1", ChallengeRequest{DeviceID: d.id}).Code; c != 429 {
		t.Fatalf("over per-ip cap = %d", c)
	}
	// Addresses of one IPv6 /64 share a bucket.
	postFrom(s.HandleChallenge, "[2001:db8::1]", ChallengeRequest{DeviceID: d.id})
	postFrom(s.HandleChallenge, "[2001:db8::2]", ChallengeRequest{DeviceID: d.id})
	if c := postFrom(s.HandleChallenge, "198.51.100.9", ChallengeRequest{DeviceID: d.id}).Code; c != 429 {
		t.Fatalf("over global cap = %d", c)
	}
	now = now.Add(challengeTTL + time.Second)
	if c := postFrom(s.HandleChallenge, "198.51.100.1", ChallengeRequest{DeviceID: d.id}).Code; c != 200 {
		t.Fatalf("expired challenges still count: %d", c)
	}
	if len(s.challenges) != 1 || len(s.challengesAt) != 1 {
		t.Fatalf("expired challenges kept: %d, %v", len(s.challenges), s.challengesAt)
	}
}

func TestUsedChallengesFreeTheirSlotAndQueueStaysBounded(t *testing.T) {
	s := New("fi1")
	s.MaxChallengesPerIP = 2
	d := newDevice()
	for i := 0; i < 5000; i++ {
		rec := postFrom(s.HandleChallenge, "198.51.100.1", ChallengeRequest{DeviceID: d.id})
		if rec.Code != 200 {
			t.Fatalf("challenge %d = %d", i, rec.Code)
		}
		var ch ChallengeResponse
		wire.Lenient(rec.Body.Bytes(), &ch)
		postFrom(s.HandleSession, "198.51.100.1", SessionRequest{ChallengeID: ch.ChallengeID, SigningKey: d.pub, Signature: make([]byte, 64)})
	}
	if len(s.challenges) != 0 || len(s.challengeQ.keys) > 1024+2 {
		t.Fatalf("challenges %d, queue %d", len(s.challenges), len(s.challengeQ.keys))
	}
}

func TestSessionsAreCappedPerIP(t *testing.T) {
	s := New("fi1")
	s.MaxSessionsPerIP = 2
	for i := 0; i < 2; i++ {
		if _, code := Login(t, s, newDevice()); code != 200 {
			t.Fatalf("login %d = %d", i, code)
		}
	}
	if _, code := Login(t, s, newDevice()); code != 429 {
		t.Fatalf("over session cap = %d", code)
	}
}

func TestAuthBodiesAreSmall(t *testing.T) {
	s := New("fi1")
	big := bytes.Repeat([]byte{0}, wire.ControlBody+1)
	for _, h := range []http.HandlerFunc{s.HandleChallenge, s.HandleSession} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest("POST", "/", bytes.NewReader(big)))
		if rec.Code != 413 {
			t.Fatalf("oversized auth body = %d", rec.Code)
		}
	}
}

func TestChallengeCarriesConfiguredAudience(t *testing.T) {
	s := New("fi1")
	var ch ChallengeResponse
	wire.Lenient(post(t, s.HandleChallenge, ChallengeRequest{DeviceID: newDevice().id}).Body.Bytes(), &ch)
	if ch.Audience != "fi1" {
		t.Fatalf("audience = %q", ch.Audience)
	}
}

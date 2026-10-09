// Package auth proves a device holds its Ed25519 key (protocol v1 §10.1): one-time challenge, signature,
// short-lived bearer session. It proves key possession only — not membership, entitlements or spool rights.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	challengeTTL = 60 * time.Second
	SessionTTL   = 15 * time.Minute
	domain       = "farlink/server-auth/v1"

	// Admission caps: anyone may create a key, so outstanding challenges and sessions are bounded per client
	// address and in total.
	MaxChallenges      = 100_000
	MaxChallengesPerIP = 64
	MaxSessions        = 200_000
	MaxSessionsPerIP   = 1024
)

type challenge struct {
	deviceID  []byte
	nonce     []byte
	expiresAt uint64
	ip        string
}

type Session struct {
	DeviceID  []byte
	ExpiresAt time.Time
	ip        string
}

// expiring is a FIFO of keys in expiry order (every entry of one kind gets the same TTL), so expiring the
// oldest entries costs nothing when none are due, instead of a scan of the whole map on every request.
type expiring[K comparable] struct {
	keys []K
	at   []time.Time
}

func (q *expiring[K]) push(k K, at time.Time) { q.keys, q.at = append(q.keys, k), append(q.at, at) }

// pop removes and returns the oldest key if it expired by now.
func (q *expiring[K]) pop(now time.Time) (K, bool) {
	var zero K
	if len(q.keys) == 0 || !now.After(q.at[0]) {
		return zero, false
	}
	k := q.keys[0]
	q.keys, q.at = q.keys[1:], q.at[1:]
	return k, true
}

// compact drops keys that are no longer live once they outnumber live ones, so used entries can't pile up.
func (q *expiring[K]) compact(live int, alive func(K) bool) {
	if len(q.keys) <= 2*live+1024 {
		return
	}
	keys, at := make([]K, 0, live), make([]time.Time, 0, live)
	for i, k := range q.keys {
		if alive(k) {
			keys, at = append(keys, k), append(at, q.at[i])
		}
	}
	q.keys, q.at = keys, at
}

type Service struct {
	Audience string // this server's stable id (-id), exactly as listed in servers.json; clients compare it
	Now      func() time.Time
	TTL      time.Duration // session lifetime (SessionTTL unless configured)

	MaxChallenges, MaxChallengesPerIP, MaxSessions, MaxSessionsPerIP int

	// Blocked says a device belongs to an account that was deleted: it signs in nowhere and no session of it works. The
	// answer is 410 DEVICE_ACCOUNT_DELETED, which a client takes to mean its own account is gone (unlike ACCOUNT_DELETED,
	// which says someone else's is).
	Blocked func(deviceID []byte) bool

	mu           sync.Mutex
	challenges   map[string]challenge // challenge_id → challenge
	sessions     map[[32]byte]Session // sha256(token) → session; tokens themselves are never stored
	challengeQ   expiring[string]
	sessionQ     expiring[[32]byte]
	challengesAt map[string]int // client ip → outstanding challenges
	sessionsAt   map[string]int // client ip → live sessions
}

func New(audience string) *Service {
	return &Service{Audience: audience, Now: time.Now, TTL: SessionTTL,
		MaxChallenges: MaxChallenges, MaxChallengesPerIP: MaxChallengesPerIP, MaxSessions: MaxSessions, MaxSessionsPerIP: MaxSessionsPerIP,
		challenges: map[string]challenge{}, sessions: map[[32]byte]Session{}, challengesAt: map[string]int{}, sessionsAt: map[string]int{}}
}

type ChallengeRequest struct {
	DeviceID []byte `cbor:"device_id"`
}

type ChallengeResponse struct {
	ChallengeID []byte `cbor:"challenge_id"`
	Nonce       []byte `cbor:"nonce"`
	Audience    string `cbor:"audience"`
	ExpiresAt   uint64 `cbor:"expires_at"`
}

// SignedChallenge is the exact structure the device signs.
type SignedChallenge struct {
	ChallengeID []byte `cbor:"challenge_id"`
	Nonce       []byte `cbor:"nonce"`
	Audience    string `cbor:"audience"`
	ExpiresAt   uint64 `cbor:"expires_at"`
	DeviceID    []byte `cbor:"device_id"`
}

type SessionRequest struct {
	ChallengeID []byte `cbor:"challenge_id"`
	SigningKey  []byte `cbor:"signing_key"`
	Signature   []byte `cbor:"signature"`
}

type SessionResponse struct {
	Token     string `cbor:"token"`
	ExpiresAt uint64 `cbor:"expires_at"`
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func (s *Service) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	var req ChallengeRequest
	if err := wire.ReadLimit(r, &req, wire.ControlBody); err != nil {
		wire.WriteReadError(w, err)
		return
	}
	if len(req.DeviceID) != 32 {
		wire.WriteError(w, 400, "INVALID_ENCODING", false)
		return
	}
	ip := wire.ClientIP(r)
	id, nonce := random(16), random(32)
	now := s.Now()
	until := now.Add(challengeTTL)
	exp := uint64(until.UnixMilli())
	s.mu.Lock()
	s.gc(now)
	if len(s.challenges) >= s.MaxChallenges || s.challengesAt[ip] >= s.MaxChallengesPerIP {
		s.mu.Unlock()
		wire.WriteError(w, 429, "RATE_LIMITED", true)
		return
	}
	s.challenges[string(id)] = challenge{deviceID: req.DeviceID, nonce: nonce, expiresAt: exp, ip: ip}
	s.challengesAt[ip]++
	s.challengeQ.push(string(id), until)
	s.mu.Unlock()
	wire.Write(w, ChallengeResponse{ChallengeID: id, Nonce: nonce, Audience: s.Audience, ExpiresAt: exp})
}

func (s *Service) HandleSession(w http.ResponseWriter, r *http.Request) {
	var req SessionRequest
	if err := wire.ReadLimit(r, &req, wire.ControlBody); err != nil {
		wire.WriteReadError(w, err)
		return
	}
	if len(req.SigningKey) != ed25519.PublicKeySize {
		wire.WriteError(w, 400, "INVALID_ENCODING", false)
		return
	}
	s.mu.Lock()
	c, ok := s.challenges[string(req.ChallengeID)]
	if ok { // one-time, even when the proof fails
		s.dropChallenge(string(req.ChallengeID), c)
	}
	s.mu.Unlock()
	now := s.Now()
	if !ok || uint64(now.UnixMilli()) > c.expiresAt {
		wire.WriteError(w, 401, "AUTH_FAILED", true)
		return
	}
	sum := sha256.Sum256(req.SigningKey)
	if string(sum[:]) != string(c.deviceID) {
		wire.WriteError(w, 401, "AUTH_FAILED", false)
		return
	}
	if s.Blocked != nil && s.Blocked(c.deviceID) {
		wire.WriteError(w, 410, "DEVICE_ACCOUNT_DELETED", false)
		return
	}
	msg, _ := wire.Enc.Marshal(SignedChallenge{ChallengeID: req.ChallengeID, Nonce: c.nonce, Audience: s.Audience, ExpiresAt: c.expiresAt, DeviceID: c.deviceID})
	if !ed25519.Verify(req.SigningKey, append([]byte(domain), msg...), req.Signature) {
		wire.WriteError(w, 401, "AUTH_FAILED", false)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(random(32))
	exp := now.Add(s.TTL)
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	s.gc(now)
	if len(s.sessions) >= s.MaxSessions || s.sessionsAt[c.ip] >= s.MaxSessionsPerIP {
		s.mu.Unlock()
		wire.WriteError(w, 429, "RATE_LIMITED", true)
		return
	}
	s.sessions[key] = Session{DeviceID: c.deviceID, ExpiresAt: exp, ip: c.ip}
	s.sessionsAt[c.ip]++
	s.sessionQ.push(key, exp)
	s.mu.Unlock()
	wire.Write(w, SessionResponse{Token: token, ExpiresAt: uint64(exp.UnixMilli())})
}

// Authenticate resolves the bearer token of a request.
func (s *Service) Authenticate(r *http.Request) (Session, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return Session{}, false
	}
	key := sha256.Sum256([]byte(strings.TrimPrefix(h, "Bearer ")))
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[key]
	if !ok {
		return Session{}, false
	}
	if s.Now().After(sess.ExpiresAt) {
		s.dropSession(key, sess)
		return Session{}, false
	}
	return sess, true
}

// IsBlocked says whether a device belongs to an account that was deleted.
func (s *Service) IsBlocked(deviceID []byte) bool { return s.Blocked != nil && s.Blocked(deviceID) }

// Require wraps a handler so it only runs for an authenticated device.
func (s *Service) Require(next func(http.ResponseWriter, *http.Request, Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.Authenticate(r)
		if !ok {
			wire.WriteError(w, 401, "AUTH_FAILED", true)
			return
		}
		if s.Blocked != nil && s.Blocked(sess.DeviceID) {
			wire.WriteError(w, 410, "DEVICE_ACCOUNT_DELETED", false)
			return
		}
		next(w, r, sess)
	}
}

func (s *Service) dropChallenge(id string, c challenge) {
	delete(s.challenges, id)
	if s.challengesAt[c.ip]--; s.challengesAt[c.ip] <= 0 {
		delete(s.challengesAt, c.ip)
	}
}

func (s *Service) dropSession(key [32]byte, v Session) {
	delete(s.sessions, key)
	if s.sessionsAt[v.ip]--; s.sessionsAt[v.ip] <= 0 {
		delete(s.sessionsAt, v.ip)
	}
}

// gc drops what expired from the front of the queues; used or already dropped keys are skipped.
func (s *Service) gc(now time.Time) {
	for {
		id, ok := s.challengeQ.pop(now)
		if !ok {
			break
		}
		if c, live := s.challenges[id]; live && uint64(now.UnixMilli()) > c.expiresAt {
			s.dropChallenge(id, c)
		}
	}
	s.challengeQ.compact(len(s.challenges), func(id string) bool { _, ok := s.challenges[id]; return ok })
	for {
		key, ok := s.sessionQ.pop(now)
		if !ok {
			break
		}
		if v, live := s.sessions[key]; live && now.After(v.ExpiresAt) {
			s.dropSession(key, v)
		}
	}
	s.sessionQ.compact(len(s.sessions), func(k [32]byte) bool { _, ok := s.sessions[k]; return ok })
}

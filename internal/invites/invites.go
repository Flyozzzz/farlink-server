// Package invites lets a device find a pairing invite by a short code typed on another device. The server
// stores only an opaque blob sealed under a key derived from the code, keyed by SHA-256 of the code; it hands
// each blob out once, keeps it at most 10 minutes, lets its issuer withdraw it and rate-limits lookups per
// client address.
package invites

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	TTL           = 10 * time.Minute
	MaxBlob       = 8 << 10
	LookupsPerMin = 10
	MaxPerIssuer  = 5
	PerIssuerHour = 10     // codes one device may create per hour
	MaxEntries    = 20_000 // all issuers together (fresh keys are free)

	// KindContact marks a code for exchanging contacts. A device has one live: a new one replaces the old, so a
	// code that was shown and forgotten cannot pile up.
	KindContact = "contact"
)

type entry struct {
	blob    []byte
	owner   string
	kind    string
	expires time.Time
	account []byte
}

type Service struct {
	Auth     *auth.Service
	Accounts *accounts.Resolver
	Now      func() time.Time

	mu      sync.Mutex
	entries map[string]entry       // lookup id → invite
	hits    map[string][]time.Time // client ip → recent lookups
	made    map[string][]time.Time // issuer device → creations within the last hour
}

func New(a *auth.Service) *Service {
	return &Service{Auth: a, Now: time.Now, entries: map[string]entry{}, hits: map[string][]time.Time{}, made: map[string][]time.Time{}}
}

type PutRequest struct {
	LookupID  []byte `cbor:"lookup_id"`
	Blob      []byte `cbor:"blob"`
	Kind      string `cbor:"kind,omitempty"`
	AccountID []byte `cbor:"account_id,omitempty"`
}

// HandlePut: POST /v1/invites (authenticated issuer).
func (s *Service) HandlePut(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		var req PutRequest
		if err := wire.ReadLimit(r, &req, wire.ControlBody); err != nil {
			wire.WriteReadError(w, err)
			return
		}
		if len(req.LookupID) != 32 || len(req.Blob) == 0 || len(req.Blob) > MaxBlob || (req.Kind != "" && req.Kind != KindContact) {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		if req.Kind == KindContact && !s.active(w, r, req.AccountID, sess.DeviceID) {
			return
		}
		owner := string(sess.DeviceID)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.Auth.IsBlocked(sess.DeviceID) { // checked under the lock the erasing of a deleted account takes
			wire.WriteError(w, 410, "DEVICE_ACCOUNT_DELETED", false)
			return
		}
		s.gc()
		if _, taken := s.entries[string(req.LookupID)]; taken {
			wire.WriteError(w, 409, "INVITE_USED", false)
			return
		}
		n := 0
		var previous string
		for k, e := range s.entries {
			if e.owner == owner {
				n++
				if req.Kind == KindContact && e.kind == KindContact {
					previous = k
				}
			}
		}
		if previous != "" {
			n-- // replaced below, once the new one is accepted
		}
		if n >= MaxPerIssuer || len(s.entries)-btoi(previous != "") >= MaxEntries {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		now := s.Now()
		recent := s.made[owner][:0]
		for _, t := range s.made[owner] {
			if now.Sub(t) < time.Hour {
				recent = append(recent, t)
			}
		}
		if len(recent) >= PerIssuerHour {
			s.made[owner] = recent
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		s.made[owner] = append(recent, now)
		if previous != "" {
			delete(s.entries, previous)
		}
		s.entries[string(req.LookupID)] = entry{blob: req.Blob, owner: owner, kind: req.Kind, expires: now.Add(TTL), account: req.AccountID}
		w.WriteHeader(204)
	})(w, r)
}

// HandleGet: GET /v1/invites/{lookup} — no login (the new device isn't anyone yet); one-time and rate-limited.
func (s *Service) HandleGet(w http.ResponseWriter, r *http.Request) {
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("lookup"))
	if err != nil || len(id) != 32 {
		wire.WriteError(w, 400, "INVALID_ENCODING", false)
		return
	}
	ip := wire.ClientIP(r)
	s.mu.Lock()
	now := s.Now()
	recent := s.hits[ip][:0]
	for _, at := range s.hits[ip] {
		if now.Sub(at) < time.Minute {
			recent = append(recent, at)
		}
	}
	if len(recent) >= LookupsPerMin {
		s.hits[ip] = recent
		s.mu.Unlock()
		wire.WriteError(w, 429, "RATE_LIMITED", true)
		return
	}
	s.hits[ip] = append(recent, now)
	s.gc()
	e, ok := s.entries[string(id)]
	s.mu.Unlock()
	if !ok {
		wire.WriteError(w, 404, "INVITE_EXPIRED", false)
		return
	}
	consume := func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		current, ok := s.entries[string(id)]
		if !ok || !s.Now().Before(current.expires) || current.owner != e.owner {
			wire.WriteError(w, 404, "INVITE_EXPIRED", false)
			return
		}
		delete(s.entries, string(id))
		wire.Write(w, map[string][]byte{"blob": current.blob})
	}
	if e.kind != KindContact {
		consume(w, r)
		return
	}
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		account, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("account_id"))
		if err != nil || len(account) != 32 {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		if !s.active(w, r, account, sess.DeviceID) || !s.active(w, r, e.account, []byte(e.owner)) {
			return
		}
		consume(w, r)
	})(w, r)
}

// HandleDelete: DELETE /v1/invites/{lookup} — the issuer withdraws its invite (Cancel in Add Device).
// Only the device that stored it may; an unknown or already used lookup is fine (204), so it reveals nothing.
func (s *Service) HandleDelete(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		id, err := base64.RawURLEncoding.DecodeString(r.PathValue("lookup"))
		if err != nil || len(id) != 32 {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		s.mu.Lock()
		e, found := s.entries[string(id)]
		s.mu.Unlock()
		if found && e.kind == KindContact && e.owner == string(sess.DeviceID) && !s.active(w, r, e.account, sess.DeviceID) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if e, ok := s.entries[string(id)]; ok && e.owner == string(sess.DeviceID) {
			delete(s.entries, string(id))
		}
		w.WriteHeader(204)
	})(w, r)
}

func (s *Service) active(w http.ResponseWriter, r *http.Request, account, device []byte) bool {
	if len(account) != 32 {
		wire.WriteError(w, 400, "INVALID_ENCODING", false)
		return false
	}
	if s.Accounts == nil {
		wire.WriteError(w, 503, "ACCOUNT_UNAVAILABLE", true)
		return false
	}
	current, err := s.Accounts.Current(r.Context(), account)
	if errors.Is(err, accounts.ErrDeleted) {
		wire.WriteError(w, 410, "ACCOUNT_DELETED", false)
		return false
	}
	if err != nil {
		log.Printf("invites: account lookup failed: %v", err)
		wire.WriteError(w, 503, "ACCOUNT_UNAVAILABLE", true)
		return false
	}
	if _, active := current.ActiveDevice(device); !active {
		wire.WriteError(w, 403, "REVOKED_DEVICE", false)
		return false
	}
	return true
}

func (s *Service) gc() {
	now := s.Now()
	for k, e := range s.entries {
		if now.After(e.expires) {
			delete(s.entries, k)
		}
	}
	for id, ts := range s.made {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > time.Hour {
			delete(s.made, id)
		}
	}
	for ip, ts := range s.hits {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > time.Minute {
			delete(s.hits, ip)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// PurgeAccount forgets the codes of an account that was deleted and of its devices.
func (s *Service) PurgeAccount(account []byte, devs [][]byte) error {
	set := map[string]bool{}
	for _, d := range devs {
		set[string(d)] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.entries {
		if set[e.owner] || (len(e.account) > 0 && string(e.account) == string(account)) {
			delete(s.entries, id)
		}
	}
	for d := range s.made {
		if set[d] {
			delete(s.made, d)
		}
	}
	return nil
}

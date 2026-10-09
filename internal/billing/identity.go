package billing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// This file binds a transport key (the key a device or a network identity signs in to a server with) to the
// Farlink account it belongs to. A binding is proven by an account device that is active right now: it signs the
// transport key. Billing identities on the account principal, never on a caller-supplied account ID, build on
// it. Nothing here changes a quota: it only records who a transport key belongs to.

const (
	// BindDomain separates the signature from every other signature an account device makes.
	BindDomain = "farlink/billing-identity-bind/v1"
	// BindLifetime is how long a signed binding request stays acceptable after it was made.
	BindLifetime = 10 * time.Minute
	// MaxTransportsPerAccount bounds what one account can bind: its devices times the networks they follow.
	MaxTransportsPerAccount = 256
	// MaxBindings bounds the file this server keeps.
	MaxBindings = 2_000_000
	bindBody    = 4 << 10
)

var (
	ErrBindExpired  = errors.New("billing: binding request expired")
	ErrBindProof    = errors.New("billing: binding proof invalid")
	ErrBindConflict = errors.New("billing: transport key is bound to another account")
	ErrBindFull     = errors.New("billing: too many bindings")
)

// BindBody is what the account device signs.
type BindBody struct {
	Protocol      uint64 `cbor:"protocol"`
	AccountID     []byte `cbor:"account_id"`
	AccountDevice []byte `cbor:"account_device"`
	Transport     []byte `cbor:"transport_device"`
	RequestID     []byte `cbor:"request_id"`
	ExpiresAt     uint64 `cbor:"expires_at"` // milliseconds since the epoch
	Audience      string `cbor:"audience"`   // the billing authority's server ID
}

// BindRequest is POST /v2/billing/identities/bind.
type BindRequest struct {
	BindBody
	Signature []byte `cbor:"signature"`
}

// BindResponse answers both the bind and the lookup.
type BindResponse struct {
	Bound     bool   `cbor:"bound"`
	AccountID []byte `cbor:"account_id,omitempty"`
}

func (b BindBody) valid() bool {
	return b.Protocol == 1 && len(b.AccountID) == 32 && len(b.AccountDevice) == 32 && len(b.Transport) == 32 &&
		len(b.RequestID) == 16 && b.Audience != ""
}

func (b BindBody) digest() [32]byte {
	raw, _ := wire.Enc.Marshal(b)
	return sha256.Sum256(raw)
}

// SignBind is what a client (and the tests) run: the signature an active account device puts on the body.
func SignBind(key ed25519.PrivateKey, body BindBody) BindRequest {
	raw, _ := wire.Enc.Marshal(body)
	return BindRequest{BindBody: body, Signature: ed25519.Sign(key, append([]byte(BindDomain), raw...))}
}

// Bindings is the durable transport-key -> account table: an append-only log of fixed-size rows, one per key, ever
// added, so a bind costs one small write and nothing is rewritten. A row is written and synced before an answer goes
// out, so a restart never forgets a binding a client has been told about; a row is never changed or removed, so a
// key never moves to another account. Binding an already bound key to the same account writes nothing.
type Bindings struct {
	path    string
	mu      sync.Mutex
	f       *os.File
	account map[string][32]byte // transport key -> account
	count   map[[32]byte]int    // account -> bound keys
}

const (
	bindingMagic = "FLBND1\n\x00"
	bindingRow   = 64 // transport (32) + account (32)
)

// OpenBindings reads dir/billing-bindings.log, or starts it when it does not exist yet. A row cut short by a crash
// while it was being appended was never acknowledged, so it is dropped.
func OpenBindings(dir string) (*Bindings, error) {
	b := &Bindings{path: filepath.Join(dir, "billing-bindings.log"), account: map[string][32]byte{}, count: map[[32]byte]int{}}
	raw, err := readFileIfExists(b.path)
	if err != nil {
		return nil, err
	}
	good := len(bindingMagic)
	switch {
	case raw == nil:
	case len(raw) < len(bindingMagic) || string(raw[:len(bindingMagic)]) != bindingMagic:
		return nil, errors.New("billing: unreadable bindings file")
	default:
		for off := len(bindingMagic); off+bindingRow <= len(raw); off += bindingRow {
			var acct [32]byte
			copy(acct[:], raw[off+32:off+bindingRow])
			b.account[string(raw[off:off+32])] = acct
			b.count[acct]++
			good = off + bindingRow
		}
	}
	f, err := os.OpenFile(b.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		if _, err := f.Write([]byte(bindingMagic)); err != nil {
			f.Close()
			return nil, err
		}
	} else if int64(good) != int64(len(raw)) {
		if err := f.Truncate(int64(good)); err != nil {
			f.Close()
			return nil, err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 2); err != nil {
		f.Close()
		return nil, err
	}
	if err := durable.SyncDir(dir); err != nil {
		f.Close()
		return nil, err
	}
	b.f = f
	return b, nil
}

// Close releases the file.
func (b *Bindings) Close() error { return b.f.Close() }

// Lookup returns the account a transport key is bound to (a copy: callers may keep it).
func (b *Bindings) Lookup(transport []byte) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.account[string(transport)]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), v[:]...), true
}

// Bind records the binding the proof backs. Repeating it, with any request ID, answers the same and writes nothing;
// the same transport key under another account is refused.
func (b *Bindings) Bind(req BindRequest) error {
	_, err := b.BindNew(req)
	return err
}

// BindNew is Bind that also says whether the key was bound just now (not before).
func (b *Bindings) BindNew(req BindRequest) (added bool, err error) {
	var acct [32]byte
	if len(req.AccountID) != 32 || len(req.Transport) != 32 {
		return false, ErrBindProof
	}
	copy(acct[:], req.AccountID)
	b.mu.Lock()
	defer b.mu.Unlock()
	if old, ok := b.account[string(req.Transport)]; ok {
		if old != acct {
			return false, ErrBindConflict
		}
		return false, nil
	}
	if len(b.account) >= MaxBindings || b.count[acct] >= MaxTransportsPerAccount {
		return false, ErrBindFull
	}
	row := make([]byte, 0, bindingRow)
	row = append(append(row, req.Transport...), req.AccountID...)
	if _, err := b.f.Write(row); err != nil {
		b.fail()
		return false, err
	}
	if err := b.f.Sync(); err != nil {
		b.fail()
		return false, err
	}
	b.account[string(req.Transport)] = acct
	b.count[acct]++
	return true, nil
}

// fail cuts a half-written row off, so the next bind starts at a row boundary.
func (b *Bindings) fail() {
	end := int64(len(bindingMagic) + len(b.account)*bindingRow)
	_ = b.f.Truncate(end)
	_, _ = b.f.Seek(end, 0)
}

// AccountResolver is the part of accounts.Resolver the billing identity needs.
type AccountResolver interface {
	Current(ctx context.Context, id []byte) (accounts.VerifiedAccount, error)
}

// Verify checks a binding request against the account as it is now: the signer is an active device of the
// account, the signature covers this transport key, the request is for this authority and has not expired.
func Verify(ctx context.Context, resolver AccountResolver, req BindRequest, self string, now time.Time) error {
	if !req.BindBody.valid() || len(req.Signature) != ed25519.SignatureSize || req.Audience != self {
		return ErrBindProof
	}
	if req.ExpiresAt <= uint64(now.UnixMilli()) || req.ExpiresAt > uint64(now.Add(BindLifetime).UnixMilli()) {
		return ErrBindExpired
	}
	if resolver == nil {
		return accounts.ErrUnreachable
	}
	account, err := resolver.Current(ctx, req.AccountID)
	if err != nil {
		return err
	}
	device, active := account.ActiveDevice(req.AccountDevice)
	if !active {
		return ErrBindProof
	}
	raw, err := wire.Enc.Marshal(req.BindBody)
	if err != nil || !ed25519.Verify(device.SigningKey, append([]byte(BindDomain), raw...), req.Signature) {
		return ErrBindProof
	}
	return nil
}

// Identity serves the binding endpoints. With Bindings nil the feature is off and both routes answer 404.
type Identity struct {
	Auth     *auth.Service
	Accounts AccountResolver
	Bindings *Bindings
	Self     string // this billing authority's server ID, the audience every request must name
	Now      func() time.Time
	// OnNewBinding runs after a key was bound for the first time (for example to recount queues by account).
	OnNewBinding func()
}

func (s *Identity) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// HandleBind: POST /v2/billing/identities/bind. The session's own key is the transport key being bound.
func (s *Identity) HandleBind(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		if s.Bindings == nil {
			wire.WriteError(w, 404, "NOT_FOUND", false)
			return
		}
		var req BindRequest
		if err := wire.ReadLimit(r, &req, bindBody); err != nil {
			wire.WriteReadError(w, err)
			return
		}
		if !req.BindBody.valid() {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		// The connection proves the transport key (it signed in); the account device proves it belongs to the account.
		if !bytes.Equal(req.Transport, sess.DeviceID) {
			wire.WriteError(w, 403, "FORBIDDEN", false)
			return
		}
		switch err := Verify(r.Context(), s.Accounts, req, s.Self, s.now()); {
		case err == nil:
		case errors.Is(err, ErrBindExpired):
			wire.WriteError(w, 400, "EXPIRED", false)
			return
		case errors.Is(err, ErrBindProof), errors.Is(err, accounts.ErrUnknown), errors.Is(err, accounts.ErrRevoked):
			wire.WriteError(w, 403, "FORBIDDEN", false)
			return
		case errors.Is(err, accounts.ErrFork):
			wire.WriteError(w, 409, "ACCOUNT_FORK", false)
			return
		case errors.Is(err, accounts.ErrDeleted):
			wire.WriteError(w, 410, "ACCOUNT_DELETED", false)
			return
		default:
			wire.WriteError(w, 503, "ACCOUNT_UNAVAILABLE", true)
			return
		}
		added, err := s.Bindings.BindNew(req)
		switch {
		case err == nil:
			if added && s.OnNewBinding != nil {
				s.OnNewBinding()
			}
			wire.Write(w, BindResponse{Bound: true, AccountID: req.AccountID})
		case errors.Is(err, ErrBindConflict):
			wire.WriteError(w, 409, "CONFLICT", false)
		case errors.Is(err, ErrBindFull):
			wire.WriteError(w, 429, "RATE_LIMITED", false)
		default:
			wire.WriteError(w, 503, "UNAVAILABLE", true)
		}
	})(w, r)
}

// HandleLookup: GET /v2/billing/identities/me — which account this session's key is bound to.
func (s *Identity) HandleLookup(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		if s.Bindings == nil {
			wire.WriteError(w, 404, "NOT_FOUND", false)
			return
		}
		account, ok := s.Bindings.Lookup(sess.DeviceID)
		wire.Write(w, BindResponse{Bound: ok, AccountID: account})
	})(w, r)
}

func readFileIfExists(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

// TransportsOf lists the transport keys bound to an account.
func (b *Bindings) TransportsOf(account []byte) [][]byte {
	var acct [32]byte
	copy(acct[:], account)
	b.mu.Lock()
	defer b.mu.Unlock()
	var out [][]byte
	for k, v := range b.account {
		if v == acct {
			out = append(out, []byte(k))
		}
	}
	return out
}

// Remove erases every binding of an account (it was deleted): the file is rewritten without them and replaced
// atomically. Their keys stay refused through the deletion's own device tombstones. The new file is opened and written
// before it replaces the old one, so a failure leaves the old file and its descriptor in use, and a failure after the
// replacement still switches to the new file.
func (b *Bindings) Remove(account []byte) error {
	var acct [32]byte
	copy(acct[:], account)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.count[acct] == 0 {
		return nil
	}
	out := []byte(bindingMagic)
	kept := map[string][32]byte{}
	for k, v := range b.account {
		if v == acct {
			continue
		}
		kept[k] = v
		out = append(append(out, k...), v[:]...)
	}
	dir := filepath.Dir(b.path)
	tmp, err := os.CreateTemp(dir, ".tmp-bindings-")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if _, err := tmp.Seek(0, 2); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), b.path); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	// From here the new file is the file: switch to it whatever else happens.
	b.f.Close()
	b.f, b.account = tmp, kept
	delete(b.count, acct)
	return durable.SyncDir(dir)
}

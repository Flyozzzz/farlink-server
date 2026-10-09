package contacts

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const AdmitPath = "/v1/federation/admit"

var (
	errForbidden      = &federation.Error{Status: 403, Code: "FORBIDDEN"}
	errNotAuthority   = &federation.Error{Status: 409, Code: "NOT_AUTHORITY"}
	errMailboxMissing = &federation.Error{Status: 400, Code: "MAILBOX_MISMATCH"}
)

// AdmitRequest carries the device's signature over the concrete delivery; an
// origin cannot change the recipient, kind, payload hash, size, or expiration.
type AdmitRequest struct {
	Proof ContactDeliveryProof `cbor:"proof"`
}

type Authority interface {
	Admit(ctx context.Context, server string, req AdmitRequest) error
}

type Router struct {
	Self     string
	Store    *Store
	Accounts *accounts.Resolver
	Client   *federation.Client
	Now      func() time.Time
}

func (r *Router) now() uint64 {
	if r.Now != nil {
		return uint64(r.Now().UnixMilli())
	}
	return uint64(time.Now().UnixMilli())
}

func (r *Router) Authorize(ctx context.Context, req AdmitRequest) error {
	p := req.Proof
	current, err := p.Check(ctx, r.Accounts, r.now())
	if err != nil {
		return err
	}
	if p.Authority != r.Self {
		return errNotAuthority
	}
	if err := r.ensure(ctx, p.RecipientAccount, current.ContactRoutes()); err != nil {
		return err
	}
	current, err = p.Check(ctx, r.Accounts, r.now())
	if err != nil {
		return err
	}
	routes := current.ContactRoutes()
	if len(routes) == 0 {
		return ErrMigration
	}
	epoch := routes[len(routes)-1].Head
	if p.Kind == "contact-control" {
		return r.Store.AdmitControl(p.RecipientAccount, p.SenderAccount, epoch)
	}
	return r.Store.Admit(p.RecipientAccount, p.SenderAccount, p.LogicalID, p.Bytes, p.ExpiresAt, epoch)
}

func (r *Router) Admit(ctx context.Context, server string, req AdmitRequest) error {
	if req.Proof.Authority != server {
		return errNotAuthority
	}
	if server == r.Self {
		return r.Authorize(ctx, req)
	}
	if r.Client == nil {
		return &federation.Error{Status: 503, Code: "AUTHORITY_UNAVAILABLE", Retryable: true}
	}
	err := r.Client.Post(ctx, server, AdmitPath, req)
	if err == nil {
		return nil
	}
	if e, ok := err.(*federation.Error); ok && e.Status < 500 {
		return e
	}
	return &federation.Error{Status: 503, Code: "AUTHORITY_UNAVAILABLE", Retryable: true}
}

func IsContact(kind string) bool { return strings.HasPrefix(kind, "contact-") }

// Guard is required for local outbox delivery too, not only federation ingress:
// revocation may happen after the origin accepted a queued delivery.
func (r *Router) Guard(next federation.Sink) federation.Sink {
	return federation.SinkFunc(func(ctx context.Context, from federation.Peer, req federation.Request) error {
		if !IsContact(req.Kind) {
			return next.Receive(ctx, from, req)
		}
		var p ContactDeliveryProof
		if len(req.Admission) == 0 || len(req.Admission) > MaxAdmission || wire.Lenient(req.Admission, &p) != nil || !p.Matches(req) {
			return errForbidden
		}
		if _, err := p.Check(ctx, r.Accounts, r.now()); err != nil {
			return err
		}
		if !slices.Contains(p.Mailboxes, r.Self) {
			return errMailboxMissing
		}
		if err := r.Admit(ctx, p.Authority, AdmitRequest{Proof: p}); err != nil {
			return err
		}
		return next.Receive(ctx, from, req)
	})
}

type Federation struct {
	Dir    *federation.Directory
	Router *Router
}

func (f *Federation) HandleAdmit(w http.ResponseWriter, r *http.Request) {
	if _, ok := federation.AuthenticatePeer(f.Dir, r); !ok {
		wire.WriteError(w, 401, "PEER_UNAUTHORIZED", false)
		return
	}
	var req AdmitRequest
	if err := wire.ReadLimit(r, &req, MaxAdmission+1024); err != nil {
		wire.WriteReadError(w, err)
		return
	}
	if err := f.Router.Authorize(r.Context(), req); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(204)
}

func writeErr(w http.ResponseWriter, err error) {
	if e, ok := err.(*federation.Error); ok {
		wire.WriteError(w, e.Status, e.Code, e.Retryable)
		return
	}
	wire.WriteError(w, 503, "INTERNAL", true)
}

type StateRequest struct {
	Recipient []byte `cbor:"recipient_account"`
	Sender    []byte `cbor:"sender_account,omitempty"`
	Action    string `cbor:"action"`
	Expected  uint64 `cbor:"expected_generation,omitempty"`
	Cursor    []byte `cbor:"cursor,omitempty"`
	Limit     uint64 `cbor:"limit,omitempty"`
}

type StateResponse struct {
	Records []Record `cbor:"records"`
	Next    []byte   `cbor:"next,omitempty"`
}

const StatePerMinute = 120

type API struct {
	Auth     *auth.Service
	Store    *Store
	Accounts *accounts.Resolver
	Self     string
	Client   *federation.Client
	Now      func() time.Time
	mu       sync.Mutex
	rates    map[string]*stateWindow
}

type stateWindow struct {
	start time.Time
	n     int
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) allow(account []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rates == nil {
		a.rates = map[string]*stateWindow{}
	}
	now := a.now()
	w := a.rates[string(account)]
	if w == nil || now.Sub(w.start) >= time.Minute {
		if len(a.rates) > 50000 {
			for k, v := range a.rates {
				if now.Sub(v.start) >= time.Minute {
					delete(a.rates, k)
				}
			}
		}
		w = &stateWindow{start: now}
		a.rates[string(account)] = w
	}
	w.n++
	return w.n <= StatePerMinute
}

func writeState(w http.ResponseWriter, resp StateResponse) { wire.Write(w, resp) }

func (a *API) HandleState(w http.ResponseWriter, r *http.Request) {
	a.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		// Charge the authenticated device and source before any registry/peer I/O,
		// including unknown recipients and accounts this device does not belong to.
		if !a.allow([]byte("ip:"+wire.ClientIP(r))) || !a.allow(append([]byte("device:"), sess.DeviceID...)) {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		var req StateRequest
		if err := wire.ReadLimit(r, &req, 4<<10); err != nil {
			wire.WriteReadError(w, err)
			return
		}
		if len(req.Recipient) != 32 {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		if a.Accounts == nil {
			writeErr(w, AccountError(accounts.ErrUnreachable))
			return
		}
		current, err := a.Accounts.Current(r.Context(), req.Recipient)
		if err != nil {
			writeErr(w, AccountError(err))
			return
		}
		if _, active := current.ActiveDevice(sess.DeviceID); !active {
			writeErr(w, errForbidden)
			return
		}
		authority := current.ContactAuthority()
		if authority == "" || authority != a.Self {
			writeErr(w, errNotAuthority)
			return
		}
		router := Router{Self: a.Self, Store: a.Store, Accounts: a.Accounts, Client: a.Client}
		if err := router.ensure(r.Context(), req.Recipient, current.ContactRoutes()); err != nil {
			writeErr(w, err)
			return
		}
		current, err = a.Accounts.Current(r.Context(), req.Recipient)
		if err != nil {
			writeErr(w, AccountError(err))
			return
		}
		authority = current.ContactAuthority()
		if _, active := current.ActiveDevice(sess.DeviceID); !active || authority != a.Self {
			writeErr(w, errForbidden)
			return
		}
		routes := current.ContactRoutes()
		epoch := routes[len(routes)-1].Head
		if !a.allow(req.Recipient) {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		if req.Action == "list" {
			if len(req.Cursor) != 0 && len(req.Cursor) != 32 {
				wire.WriteError(w, 400, "INVALID_ENCODING", false)
				return
			}
			page, next, err := a.Store.List(req.Recipient, req.Cursor, int(min(req.Limit, MaxPageSize)), epoch)
			if err != nil {
				writeErr(w, err)
				return
			}
			writeState(w, StateResponse{Records: page, Next: next})
			return
		}
		if len(req.Sender) != 32 || string(req.Sender) == string(req.Recipient) {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		record, err := a.Store.Apply(req.Recipient, req.Sender, Action(req.Action), req.Expected, epoch)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeState(w, StateResponse{Records: []Record{record}})
	})(w, r)
}

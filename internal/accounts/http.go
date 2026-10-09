package accounts

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// SubmitsPerMin is how many links one address may send in a minute: creating accounts costs the server a file each.
const SubmitsPerMin = 30

// API serves the account chain endpoints. They carry no bearer token: every link proves itself by its signature,
// and the chain is public data.
type API struct {
	Reg *Registry
	Now func() time.Time
	// IsPeer says whether a request came from another server of the fleet: only they may read a deleted account's chain
	// (they check a deletion against it).
	IsPeer func(*http.Request) bool

	mu   sync.Mutex
	hits map[string][]time.Time
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) allow(r *http.Request) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.hits == nil {
		a.hits = map[string][]time.Time{}
	}
	ip, now := wire.ClientIP(r), a.now()
	recent := a.hits[ip][:0]
	for _, t := range a.hits[ip] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= SubmitsPerMin {
		a.hits[ip] = recent
		return false
	}
	a.hits[ip] = append(recent, now)
	if len(a.hits) > 4096 {
		for k, v := range a.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > time.Minute {
				delete(a.hits, k)
			}
		}
	}
	return true
}

type receipt struct {
	Number   uint64 `cbor:"number"`
	HeadHash []byte `cbor:"head_hash"`
}

func status(err error) (int, string) {
	switch {
	case errors.Is(err, ErrDeleted):
		return 410, err.Error()
	case errors.Is(err, ErrMalformed), errors.Is(err, ErrBadSignature):
		return 400, err.Error()
	case errors.Is(err, ErrNotAuthorized), errors.Is(err, ErrRevoked):
		return 403, err.Error()
	case errors.Is(err, ErrUnknown):
		return 404, err.Error()
	case errors.Is(err, ErrTooLong):
		return 413, err.Error()
	case errors.Is(err, ErrWrongAccount), errors.Is(err, ErrSync), errors.Is(err, ErrFork), errors.Is(err, ErrDeviceLimit),
		errors.Is(err, ErrLastDevice), errors.Is(err, ErrDeviceTaken), errors.Is(err, ErrExists):
		return 409, err.Error()
	}
	return 500, "INTERNAL"
}

func (a *API) submit(w http.ResponseWriter, r *http.Request) {
	if !a.allow(r) {
		wire.WriteError(w, 429, "RATE_LIMITED", true)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxLinkBytes+1))
	if err != nil || len(raw) > MaxLinkBytes {
		wire.WriteError(w, 413, "LIMIT_EXCEEDED", false)
		return
	}
	n, h, err := a.Reg.Submit(raw)
	if err != nil {
		st, code := status(err)
		wire.WriteError(w, st, code, st == 500)
		return
	}
	wire.Write(w, receipt{Number: n, HeadHash: h})
}

// HandleCreate: POST /v1/accounts, the body is the first link.
func (a *API) HandleCreate(w http.ResponseWriter, r *http.Request) { a.submit(w, r) }

// HandleLink: POST /v1/accounts/{id}/links, the body is the next link.
func (a *API) HandleLink(w http.ResponseWriter, r *http.Request) { a.submit(w, r) }

// HandleGet: GET /v1/accounts/{id}, the whole chain as an array of links.
func (a *API) HandleGet(w http.ResponseWriter, r *http.Request) {
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil || len(id) != 32 {
		wire.WriteError(w, 400, "INVALID_ENCODING", false)
		return
	}
	if a.Reg.IsDeleted(id) && (a.IsPeer == nil || !a.IsPeer(r)) {
		wire.WriteError(w, 410, "ACCOUNT_DELETED", false)
		return
	}
	if value := r.URL.Query().Get("journal_from"); value != "" {
		from, err := strconv.ParseUint(value, 10, 62)
		if err != nil {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		page, found := a.Reg.JournalPage(id, from)
		if !found {
			wire.WriteError(w, 404, "NOT_FOUND", false)
			return
		}
		wire.Write(w, page)
		return
	}
	// ?after=N: only the links after number N; ?from=N: the links from number N on (from=0 is the whole chain). Both are bounded
	// pages: the caller continues from the last number it got.
	if q := r.URL.Query(); q.Get("after") != "" || q.Get("from") != "" {
		var from uint64
		if v := q.Get("after"); v != "" {
			after, perr := strconv.ParseUint(v, 10, 62)
			if perr != nil {
				wire.WriteError(w, 400, "INVALID_ENCODING", false)
				return
			}
			from = after + 1
		} else {
			f, perr := strconv.ParseUint(q.Get("from"), 10, 62)
			if perr != nil {
				wire.WriteError(w, 400, "INVALID_ENCODING", false)
				return
			}
			from = f
		}
		links, found := a.Reg.Page(id, from)
		if !found {
			wire.WriteError(w, 404, "NOT_FOUND", false)
			return
		}
		wire.Write(w, links)
		return
	}
	chain, ok := a.Reg.Chain(id)
	if !ok {
		wire.WriteError(w, 404, "NOT_FOUND", false)
		return
	}
	wire.Write(w, chain)
}

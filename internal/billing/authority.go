package billing

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// One allowance per account, however many of our servers its devices use: the counters of account buckets live on one
// server, the billing authority. The other servers ask it for blocks of bytes, spend them locally and ask again, so no
// frame costs a round trip and the account still cannot spend more than its limit. A request has an ID and the authority
// keeps the answer to each ID next to the counters (Ledger.GrantOnce), so a lost reply is repeated, never granted twice.
// Nothing is given back: what a server holds when it stops is spent (at most one block). If the authority cannot be
// reached a server spends what it holds and then refuses; it never invents an allowance of its own.

const (
	// GrantPath and UsedPath are the authority's federation routes.
	GrantPath = "/v1/federation/billing/grant"
	UsedPath  = "/v1/federation/billing/used"

	callTimeout = 3 * time.Second
	// DefaultBlock is how much a server asks for at a time: small enough that what a stopped server forgets does not matter.
	DefaultBlock = 8 << 20
)

type UsedRequest struct {
	Key string `cbor:"key"`
}

type UsedResponse struct {
	Used  int64 `cbor:"used"`
	Month int   `cbor:"month"`
}

// Remote is the billing authority as a server that is not it sees it.
type Remote interface {
	Grant(ctx context.Context, req GrantRequest) (GrantResponse, error)
	Used(ctx context.Context, key string) (used int64, month int, err error)
}

// FedRemote reaches the authority over the pinned federation transport.
type FedRemote struct {
	Client    *federation.Client
	Authority string // the authority's server ID
}

func (f *FedRemote) Grant(ctx context.Context, req GrantRequest) (GrantResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out GrantResponse
	err := f.Client.Call(ctx, f.Authority, GrantPath, req, &out)
	return out, err
}

func (f *FedRemote) Used(ctx context.Context, key string) (int64, int, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out UsedResponse
	if err := f.Client.Call(ctx, f.Authority, UsedPath, UsedRequest{Key: key}, &out); err != nil {
		return 0, 0, err
	}
	return out.Used, out.Month, nil
}

// Authority serves the other servers out of this server's ledger. It decides the limit itself (a peer can only name one
// of the allowances this fleet has) and refuses anything that is not a well-formed account or Teams bucket.
type Authority struct {
	Dir    *federation.Directory
	Ledger *Ledger
	// Limits are the fleet's allowances: a request for any other limit is refused.
	Limits Limits
}

const (
	authorityBody = 4 << 10
	maxKey        = 128
	maxID         = 160
)

func (a *Authority) peer(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := federation.AuthenticatePeer(a.Dir, r); !ok {
		wire.WriteError(w, 401, "PEER_UNAUTHORIZED", false)
		return false
	}
	return true
}

// validKey: an account bucket named by a canonical 32-byte account id, or a Teams pool named by a network's 32-byte
// billing tag in hex; nothing else.
func validKey(k string) bool {
	if len(k) > maxKey {
		return false
	}
	if rest, ok := strings.CutPrefix(k, accountBucketPrefix); ok {
		raw, err := b64.DecodeString(rest)
		return err == nil && len(raw) == 32 && b64.EncodeToString(raw) == rest
	}
	if rest, ok := strings.CutPrefix(k, teamsBucketPrefix); ok {
		raw, err := hex.DecodeString(rest)
		return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == rest
	}
	return false
}

// validLimit is the allowance a key may be held against: Free or Relay for an account; for a Teams pool seats times the
// per-seat pool of a pack that is on sale.
func (a *Authority) validLimit(key string, limit int64) bool {
	if strings.HasPrefix(key, teamsBucketPrefix) {
		for _, seats := range TeamsSizes {
			if limit == int64(seats)*a.Limits.TeamsPerPerson {
				return true
			}
		}
		return false
	}
	return limit == a.Limits.FreeRelay || limit == a.Limits.RelayRelay || (a.Limits.RelayMaxRelay > 0 && limit == a.Limits.RelayMaxRelay)
}

func (a *Authority) HandleGrant(w http.ResponseWriter, r *http.Request) {
	if !a.peer(w, r) {
		return
	}
	var req GrantRequest
	if err := wire.ReadLimit(r, &req, authorityBody); err != nil {
		wire.WriteReadError(w, err)
		return
	}
	if !validKey(req.Key) || req.ID == "" || len(req.ID) > maxID || req.Want <= 0 || !a.validLimit(req.Key, req.Limit) {
		wire.WriteError(w, 400, "INVALID_ENCODING", false)
		return
	}
	resp, err := a.Ledger.GrantOnce(req)
	if err != nil {
		wire.WriteError(w, 503, "UNAVAILABLE", true) // asking again with the same ID gets the same grant
		return
	}
	wire.Write(w, resp)
}

func (a *Authority) HandleUsed(w http.ResponseWriter, r *http.Request) {
	if !a.peer(w, r) {
		return
	}
	var req UsedRequest
	if err := wire.ReadLimit(r, &req, authorityBody); err != nil {
		wire.WriteReadError(w, err)
		return
	}
	if !validKey(req.Key) {
		wire.WriteError(w, 400, "INVALID_ENCODING", false)
		return
	}
	used, month := a.Ledger.UsedOf(req.Key)
	wire.Write(w, UsedResponse{Used: used, Month: month})
}

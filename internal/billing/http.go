package billing

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	MaxTransactions = 32
	// A membership slice is normally the one head link; after a gap it runs from the server's head, and the
	// first time from genesis.
	verifyBody = 4 << 20
)

// Service serves the entitlement endpoints. With Store nil (quotas off, self-hosting) every device is
// unlimited and nothing is verified: there is nothing to grant.
type Service struct {
	Auth   *auth.Service
	Store  *Store
	Ledger *Ledger
}

type VerifyRequest struct {
	Transactions []string `cbor:"transactions"`      // StoreKit 2 jwsRepresentation of current entitlements
	Network      []byte   `cbor:"network,omitempty"` // billing tag of the device's network (32 bytes)
	// Membership: contiguous SignedMembership.encoded links of that network's chain, ending at the device's
	// head, starting at genesis, at the server's head or right after it (see ChainResult).
	Membership [][]byte `cbor:"membership,omitempty"`
}

type VerifyResponse struct {
	Results    []Result     `cbor:"results"`
	Quota      Balance      `cbor:"quota"`
	Membership *ChainResult `cbor:"membership,omitempty"`
}

// HandleVerify: POST /v1/entitlements/verify. Sent on purchase and at every login; idempotent.
func (s *Service) HandleVerify(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		var req VerifyRequest
		if err := wire.ReadLimit(r, &req, verifyBody); err != nil {
			wire.WriteReadError(w, err)
			return
		}
		if len(req.Transactions) > MaxTransactions || (len(req.Network) != 0 && len(req.Network) != 32) || len(req.Membership) > MaxLinks {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		if s.Store == nil {
			wire.Write(w, VerifyResponse{Results: []Result{}, Quota: Balance{Unlimited: true}})
			return
		}
		res, cr, err := s.Store.Apply(sess.DeviceID, req.Network, req.Membership, req.Transactions)
		if err != nil {
			log.Printf("billing: %v", err)
			wire.WriteError(w, 503, "RATE_LIMITED", true)
			return
		}
		out := VerifyResponse{Results: res, Quota: s.Ledger.Balance(sess.DeviceID)}
		if len(req.Network) == 32 {
			out.Membership = &cr
		}
		wire.Write(w, out)
	})(w, r)
}

// HandleQuota: GET /v1/quota.
func (s *Service) HandleQuota(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		if s.Ledger == nil {
			wire.Write(w, Balance{Unlimited: true})
			return
		}
		wire.Write(w, s.Ledger.Balance(sess.DeviceID))
	})(w, r)
}

// HandleNotification: POST /v1/appstore/notifications, App Store Server Notifications v2 (JSON
// {"signedPayload"}). Apple retries anything but 200, so a payload that fails verification gets 400 and is
// dropped; refunds, revocations and renewals of subscriptions we know are applied.
func (s *Service) HandleNotification(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SignedPayload string `json:"signedPayload"`
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
	if err != nil || json.Unmarshal(b, &body) != nil || s.Store == nil {
		http.Error(w, "bad request", 400)
		return
	}
	_, tx, err := s.Store.Verifier.VerifyNotification(body.SignedPayload)
	if tx == nil {
		if err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		w.WriteHeader(200) // e.g. TEST notifications carry no transaction
		return
	}
	if err := s.Store.Notify(tx); err != nil {
		log.Printf("billing: notification: %v", err)
		http.Error(w, "retry", 500)
		return
	}
	w.WriteHeader(200)
}

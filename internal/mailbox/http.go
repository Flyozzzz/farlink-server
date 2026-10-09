package mailbox

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/contacts"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

var b64 = base64.RawURLEncoding

// Entry is what a device sees: the item plus the handle it acknowledges by.
type Entry struct {
	ItemID     []byte `cbor:"item_id"`
	DeliveryID []byte `cbor:"delivery_id"`
	Origin     string `cbor:"origin_server"`
	Sender     []byte `cbor:"sender_device"`
	ExpiresAt  uint64 `cbor:"expires_at"`
	Kind       string `cbor:"kind"`
	SpoolID    []byte `cbor:"spool_id,omitempty"`
	Bytes      uint64 `cbor:"bytes,omitempty"`
	Envelope   []byte `cbor:"envelope"`
	Admission  []byte `cbor:"admission,omitempty"`
}

type API struct {
	Auth     *auth.Service
	Store    *Store
	Accounts *accounts.Resolver
}

func (a *API) authorize(w http.ResponseWriter, r *http.Request, it Item, device []byte) bool {
	if !contacts.IsContact(it.Kind) {
		return true
	}
	var proof contacts.ContactDeliveryProof
	if wire.Lenient(it.Admission, &proof) != nil || !bytes.Equal(proof.RecipientDevice, device) {
		wire.WriteError(w, 403, "FORBIDDEN", false)
		return false
	}
	if a.Accounts == nil {
		wire.WriteError(w, 503, "ACCOUNT_UNAVAILABLE", true)
		return false
	}
	current, err := a.Accounts.Current(r.Context(), proof.RecipientAccount)
	if errors.Is(err, accounts.ErrDeleted) {
		wire.WriteError(w, 410, "ACCOUNT_DELETED", false)
		return false
	}
	if err != nil {
		wire.WriteError(w, 503, "ACCOUNT_UNAVAILABLE", true)
		return false
	}
	if _, active := current.ActiveDevice(device); !active {
		wire.WriteError(w, 403, "REVOKED_DEVICE", false)
		return false
	}
	return true
}

// HandleList: GET /v1/mailbox — the caller's waiting hints.
func (a *API) HandleList(w http.ResponseWriter, r *http.Request) {
	a.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		items := a.Store.List(sess.DeviceID)
		out := make([]Entry, 0, len(items))
		for _, it := range items {
			if !a.authorize(w, r, it, sess.DeviceID) {
				return
			}
			out = append(out, Entry{ItemID: it.id(), DeliveryID: it.DeliveryID, Origin: it.Origin, Sender: it.Sender,
				ExpiresAt: it.ExpiresAt, Kind: it.Kind, SpoolID: it.SpoolID, Bytes: it.Bytes, Envelope: it.Envelope, Admission: it.Admission})
		}
		wire.Write(w, out)
	})(w, r)
}

// HandleAck: POST /v1/mailbox/{id}/ack — the device processed the item durably.
func (a *API) HandleAck(w http.ResponseWriter, r *http.Request) {
	a.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		id, err := b64.DecodeString(r.PathValue("id"))
		if err != nil || len(id) != 32 {
			wire.WriteError(w, 404, "NOT_FOUND", false)
			return
		}
		item, found := a.Store.Get(sess.DeviceID, id)
		if !found {
			wire.WriteError(w, 404, "NOT_FOUND", false)
			return
		}
		if !a.authorize(w, r, item, sess.DeviceID) {
			return
		}
		if !a.Store.Ack(sess.DeviceID, id) {
			wire.WriteError(w, 404, "NOT_FOUND", false)
			return
		}
		w.WriteHeader(204)
	})(w, r)
}

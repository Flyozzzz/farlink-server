// Package drop accepts small encrypted deliveries and queues each selected mailbox.
package drop

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/contacts"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/outbox"
	"github.com/Flyozzzz/farlink-server/internal/spool"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	KindSpoolHint      = "spool-hint"
	KindMessage        = "message"
	KindContactOffer   = "contact-offer"
	KindContactMessage = "contact-message"
	KindContactFile    = "contact-file"
	KindContactBatch   = "contact-batch"
	KindContactControl = "contact-control"
	MaxBatchFiles      = 10
	MaxEnvelope        = 32 << 10
	MaxLifetime        = 7 * 24 * time.Hour
	PerHour            = 600
)

type Request struct {
	DeliveryID     []byte                         `cbor:"delivery_id"`
	Destination    []byte                         `cbor:"destination_device"`
	Kind           string                         `cbor:"kind"`
	MailboxServers []string                       `cbor:"mailbox_servers"`
	SpoolID        []byte                         `cbor:"spool_id,omitempty"`
	SpoolIDs       [][]byte                       `cbor:"spool_ids,omitempty"`
	ExpiresAt      uint64                         `cbor:"expires_at,omitempty"`
	Envelope       []byte                         `cbor:"envelope"`
	Proof          *contacts.ContactDeliveryProof `cbor:"proof,omitempty"`
}

type Response struct {
	Accepted uint64 `cbor:"accepted"`
}

type SpoolInfo interface {
	Info(id, owner []byte) (spool.Info, bool)
}

type Service struct {
	Auth      *auth.Service
	Self      string
	Dir       *federation.Directory
	Spool     SpoolInfo
	Outbox    *outbox.Outbox
	Authority contacts.Authority
	Accounts  *accounts.Resolver
	Now       func() time.Time
	mu        sync.Mutex
	rates     map[string]*window
}

type logicalSend struct {
	recipient  string
	deliveries map[string]string
}
type window struct {
	start   time.Time
	n       int
	logical map[string]*logicalSend
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Account sends consume one slot per logical ID, never one per HPKE envelope or
// mailbox retry. A logical send cannot be reused for another account or >15 devices.
func (s *Service) allow(key string, proof *contacts.ContactDeliveryProof) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rates == nil {
		s.rates = map[string]*window{}
	}
	now := s.now()
	w := s.rates[key]
	if w == nil || now.Sub(w.start) >= time.Hour {
		if len(s.rates) > 50000 {
			for k, v := range s.rates {
				if now.Sub(v.start) >= time.Hour {
					delete(s.rates, k)
				}
			}
		}
		w = &window{start: now, logical: map[string]*logicalSend{}}
		s.rates[key] = w
	}
	if proof != nil {
		logical := w.logical[string(proof.LogicalID)]
		if logical != nil {
			if logical.recipient != string(proof.RecipientAccount) {
				return false
			}
			device := string(proof.RecipientDevice)
			if old, ok := logical.deliveries[device]; ok {
				return old == string(proof.Signature)
			}
			if len(logical.deliveries) >= accounts.MaxDevices {
				return false
			}
			logical.deliveries[device] = string(proof.Signature)
			return true
		}
		if w.n >= PerHour {
			return false
		}
		w.logical[string(proof.LogicalID)] = &logicalSend{recipient: string(proof.RecipientAccount), deliveries: map[string]string{string(proof.RecipientDevice): string(proof.Signature)}}
	}
	if w.n >= PerHour {
		return false
	}
	w.n++
	return true
}

func (s *Service) knows(server string) bool {
	if server == s.Self {
		return true
	}
	if s.Dir == nil {
		return false
	}
	_, ok := s.Dir.Peer(server)
	return ok
}

func (s *Service) HandleDrop(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		var req Request
		if err := wire.ReadLimit(r, &req, MaxEnvelope+contacts.MaxAdmission+4<<10); err != nil {
			wire.WriteReadError(w, err)
			return
		}
		bad := func() { wire.WriteError(w, 400, "INVALID_ENCODING", false) }
		if len(req.DeliveryID) != 16 || len(req.Destination) != 32 || len(req.Envelope) == 0 || len(req.Envelope) > MaxEnvelope ||
			len(req.MailboxServers) == 0 || len(req.MailboxServers) > 2 {
			bad()
			return
		}
		for i, mailbox := range req.MailboxServers {
			if slices.Contains(req.MailboxServers[:i], mailbox) {
				bad()
				return
			}
			if !s.knows(mailbox) {
				wire.WriteError(w, 400, "UNKNOWN_SERVER", false)
				return
			}
		}
		contact := contacts.IsContact(req.Kind)
		if contact != (req.Proof != nil) {
			bad()
			return
		}
		if contact && (s.Authority == nil || s.Accounts == nil) {
			wire.WriteError(w, 503, "ACCOUNT_UNAVAILABLE", true)
			return
		}
		if len(req.SpoolIDs) != 0 && req.Kind != KindContactBatch {
			bad()
			return
		}
		now := uint64(s.now().UnixMilli())
		expires := req.ExpiresAt
		if !contact && (expires == 0 || expires > now+uint64(MaxLifetime.Milliseconds())) {
			expires = now + uint64(MaxLifetime.Milliseconds())
		}
		size := uint64(len(req.Envelope))
		spools := req.SpoolIDs
		switch req.Kind {
		case KindSpoolHint, KindContactFile:
			if len(req.SpoolID) != 16 {
				bad()
				return
			}
			spools = [][]byte{req.SpoolID}
		case KindContactBatch:
			if len(req.SpoolID) != 0 || len(spools) > MaxBatchFiles {
				bad()
				return
			}
		case KindMessage, KindContactOffer, KindContactMessage, KindContactControl:
			if len(req.SpoolID) != 0 {
				bad()
				return
			}
		default:
			bad()
			return
		}
		if len(spools) != 0 {
			if s.Spool == nil {
				wire.WriteError(w, 501, "NOT_SUPPORTED", false)
				return
			}
			size = 0
			for i, id := range spools {
				if len(id) != 16 || slices.ContainsFunc(spools[:i], func(other []byte) bool { return bytes.Equal(other, id) }) {
					bad()
					return
				}
				info, ok := s.Spool.Info(id, sess.DeviceID)
				if !ok || !hasRecipient(info.Recipients, req.Destination) {
					wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
					return
				}
				if contact && (info.Contact == nil || !bytes.Equal(info.Contact.SenderAccount, req.Proof.SenderAccount) || !bytes.Equal(info.Contact.RecipientAccount, req.Proof.RecipientAccount)) {
					wire.WriteError(w, 403, "FORBIDDEN", false)
					return
				}
				if info.Bytes > uint64(1<<63-1)-size {
					wire.WriteError(w, 413, "LIMIT_EXCEEDED", false)
					return
				}
				size += info.Bytes
				if req.Kind == KindSpoolHint || req.Kind == KindContactFile {
					expires = info.ExpiresAt
				} else {
					expires = min(expires, info.ExpiresAt)
				}
			}
		}
		if expires <= now {
			wire.WriteError(w, 410, "EXPIRED", false)
			return
		}
		fr := federation.NewRequest(s.Self, req.DeliveryID, sess.DeviceID, req.Destination, req.Kind, expires, req.Envelope)
		fr.SpoolID, fr.SpoolIDs, fr.Bytes = req.SpoolID, req.SpoolIDs, size
		if contact {
			p := req.Proof
			if !p.Matches(fr) || !slices.Equal(p.Mailboxes, req.MailboxServers) {
				wire.WriteError(w, 403, "FORBIDDEN", false)
				return
			}
			if _, err := p.Check(r.Context(), s.Accounts, now); err != nil {
				writeFed(w, err)
				return
			}
			if !s.allow("account:"+string(p.SenderAccount), p) || !s.allow("ip:"+wire.ClientIP(r), p) {
				wire.WriteError(w, 429, "RATE_LIMITED", true)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			err := s.Authority.Admit(ctx, p.Authority, contacts.AdmitRequest{Proof: *p})
			cancel()
			if err != nil {
				writeFed(w, err)
				return
			}
			fr.Admission, _ = wire.Enc.Marshal(p)
		} else if !s.allow("device:"+string(sess.DeviceID), nil) {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		if s.Auth.IsBlocked(sess.DeviceID) { // the account was deleted while the body was being read
			wire.WriteError(w, 410, "DEVICE_ACCOUNT_DELETED", false)
			return
		}
		for _, mailbox := range req.MailboxServers {
			if err := s.Outbox.Enqueue(mailbox, fr); err != nil {
				wire.WriteError(w, 503, "QUOTA_EXCEEDED", true)
				return
			}
		}
		body, _ := wire.Enc.Marshal(Response{Accepted: uint64(len(req.MailboxServers))})
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(202)
		w.Write(body)
	})(w, r)
}

func writeFed(w http.ResponseWriter, err error) {
	if e, ok := err.(*federation.Error); ok {
		wire.WriteError(w, e.Status, e.Code, e.Retryable)
		return
	}
	wire.WriteError(w, 503, "AUTHORITY_UNAVAILABLE", true)
}

func hasRecipient(list [][]byte, dev []byte) bool {
	return slices.ContainsFunc(list, func(id []byte) bool { return bytes.Equal(id, dev) })
}

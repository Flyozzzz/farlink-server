package contacts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const deliveryDomain = "farlink/contact-delivery/v2"
const MaxAdmission = 8 << 10
const MaxEnvelope = 32 << 10

// Delivery binds a device signature to one encrypted delivery. LogicalID is shared
// by the <=15 device envelopes of a logical send; DeliveryID names one envelope.
type Delivery struct {
	Protocol         uint64           `cbor:"protocol"`
	SenderAccount    []byte           `cbor:"sender_account"`
	SenderHead       accounts.HeadRef `cbor:"sender_head"`
	SenderDevice     []byte           `cbor:"sender_device"`
	RecipientAccount []byte           `cbor:"recipient_account"`
	RecipientHead    accounts.HeadRef `cbor:"recipient_head"`
	RecipientDevice  []byte           `cbor:"recipient_device"`
	LogicalID        []byte           `cbor:"logical_id"`
	DeliveryID       []byte           `cbor:"delivery_id"`
	Kind             string           `cbor:"kind"`
	Origin           string           `cbor:"origin_server"`
	Authority        string           `cbor:"authority_server"`
	Mailboxes        []string         `cbor:"mailbox_servers"`
	SpoolIDs         [][]byte         `cbor:"spool_ids"`
	Bytes            uint64           `cbor:"bytes"`
	ExpiresAt        uint64           `cbor:"expires_at"`
	EnvelopeHash     []byte           `cbor:"envelope_hash"`
}

type ContactDeliveryProof struct {
	Delivery
	Signature []byte `cbor:"signature"`
}

func SignDeliveryProof(key ed25519.PrivateKey, delivery Delivery) ContactDeliveryProof {
	body, _ := wire.Enc.Marshal(delivery)
	return ContactDeliveryProof{Delivery: delivery, Signature: ed25519.Sign(key, append([]byte(deliveryDomain), body...))}
}

func (p ContactDeliveryProof) valid(now uint64) bool {
	if p.Protocol != 2 || len(p.SenderAccount) != 32 || len(p.RecipientAccount) != 32 || bytes.Equal(p.SenderAccount, p.RecipientAccount) ||
		len(p.SenderDevice) != 32 || len(p.RecipientDevice) != 32 || len(p.SenderHead.Hash) != 32 || len(p.RecipientHead.Hash) != 32 ||
		len(p.LogicalID) != 16 || len(p.DeliveryID) != 16 || len(p.EnvelopeHash) != 32 || len(p.Signature) != ed25519.SignatureSize ||
		p.ExpiresAt <= now || p.ExpiresAt-now > uint64((7*24*time.Hour).Milliseconds()) ||
		p.Origin == "" || len(p.Origin) > accounts.MaxMailboxIDBytes || len(p.Mailboxes) == 0 || len(p.Mailboxes) > accounts.MaxContactMailboxes ||
		p.Authority != p.Mailboxes[0] || len(p.SpoolIDs) > 10 {
		return false
	}
	for i, mailbox := range p.Mailboxes {
		if mailbox == "" || len(mailbox) > accounts.MaxMailboxIDBytes || slices.Contains(p.Mailboxes[:i], mailbox) {
			return false
		}
	}
	for i, id := range p.SpoolIDs {
		if len(id) != 16 || slices.ContainsFunc(p.SpoolIDs[:i], func(other []byte) bool { return bytes.Equal(other, id) }) {
			return false
		}
	}
	switch p.Kind {
	case "contact-offer", "contact-message", "contact-control":
		return len(p.SpoolIDs) == 0 && p.Bytes > 0 && p.Bytes <= MaxEnvelope
	case "contact-file":
		return len(p.SpoolIDs) == 1
	case "contact-batch":
		return true // The authority applies the first-request byte quota.
	default:
		return false
	}
}

// AccountError preserves fail-closed unavailability rather than turning missing
// fresh data into permission or a permanent contact decision.
func AccountError(err error) error {
	if errors.Is(err, accounts.ErrDeleted) {
		return &federation.Error{Status: 410, Code: "ACCOUNT_DELETED"}
	}
	if errors.Is(err, accounts.ErrFork) {
		return &federation.Error{Status: 409, Code: "ACCOUNT_FORK"}
	}
	if errors.Is(err, accounts.ErrUnknown) || errors.Is(err, accounts.ErrRevoked) {
		return errForbidden
	}
	return &federation.Error{Status: 503, Code: "ACCOUNT_UNAVAILABLE", Retryable: true}
}

func (p ContactDeliveryProof) Check(ctx context.Context, resolver *accounts.Resolver, now uint64) (accounts.VerifiedAccount, error) {
	if !p.valid(now) {
		return accounts.VerifiedAccount{}, errForbidden
	}
	if resolver == nil {
		return accounts.VerifiedAccount{}, AccountError(accounts.ErrUnreachable)
	}
	sender, err := resolver.Current(ctx, p.SenderAccount)
	if err != nil {
		return accounts.VerifiedAccount{}, AccountError(err)
	}
	device, active := sender.ActiveDevice(p.SenderDevice)
	if !active || !sender.Contains(p.SenderHead) {
		return accounts.VerifiedAccount{}, errForbidden
	}
	body, err := wire.Enc.Marshal(p.Delivery)
	if err != nil || !ed25519.Verify(device.SigningKey, append([]byte(deliveryDomain), body...), p.Signature) {
		return accounts.VerifiedAccount{}, errForbidden
	}
	recipient, err := resolver.Current(ctx, p.RecipientAccount)
	if err != nil {
		return accounts.VerifiedAccount{}, AccountError(err)
	}
	if _, active := recipient.ActiveDevice(p.RecipientDevice); !active || !recipient.Contains(p.RecipientHead) {
		return accounts.VerifiedAccount{}, errForbidden
	}
	mailboxes := recipient.Head().ContactMailboxes
	if len(p.Mailboxes) > len(mailboxes) || !slices.Equal(p.Mailboxes, mailboxes[:len(p.Mailboxes)]) {
		return accounts.VerifiedAccount{}, errMailboxMissing
	}
	return recipient, nil
}

// Matches checks the actual bytes and transport metadata at origin and every
// forward/local-sink boundary; a valid signature on some other delivery is useless.
func (p ContactDeliveryProof) Matches(req federation.Request) bool {
	hash := sha256.Sum256(req.Envelope)
	spools := req.SpoolIDs
	if len(req.SpoolID) != 0 {
		spools = [][]byte{req.SpoolID}
	}
	return bytes.Equal(p.SenderDevice, req.Sender) && bytes.Equal(p.RecipientDevice, req.Destination) &&
		bytes.Equal(p.DeliveryID, req.DeliveryID) && p.Kind == req.Kind && p.Origin == req.Origin &&
		p.Bytes == req.Bytes && p.ExpiresAt == req.ExpiresAt && bytes.Equal(p.EnvelopeHash, hash[:]) &&
		slices.EqualFunc(p.SpoolIDs, spools, bytes.Equal)
}

package spool

import (
	"bytes"
	"errors"
	"net/http"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// ContactBinding is signed as part of the descriptor. Network spools use their
// existing membership grants; contact spools must carry both account histories.
type ContactBinding struct {
	SenderAccount    []byte           `cbor:"sender_account"`
	SenderHead       accounts.HeadRef `cbor:"sender_head"`
	RecipientAccount []byte           `cbor:"recipient_account"`
	RecipientHead    accounts.HeadRef `cbor:"recipient_head"`
}

// authorizeContact does no network I/O under an object/store lock. The binding,
// owner and recipients are fixed at reservation and never changed by commit.
func (s *Service) authorizeContact(w http.ResponseWriter, r *http.Request, d Descriptor, sess auth.Session, allRecipients bool) bool {
	binding := d.Contact
	if binding == nil {
		return true
	}
	fail := func(status int, code string, retryable bool) bool {
		if w != nil {
			wire.WriteError(w, status, code, retryable)
		}
		return false
	}
	deny := func() bool { return fail(403, "REVOKED_DEVICE", false) }
	if s.Accounts == nil {
		return fail(503, "ACCOUNT_UNAVAILABLE", true)
	}
	if len(binding.SenderAccount) != 32 || len(binding.RecipientAccount) != 32 || bytes.Equal(binding.SenderAccount, binding.RecipientAccount) ||
		len(d.Recipients) == 0 || len(d.Recipients) > accounts.MaxDevices {
		return deny()
	}
	sender, err := s.Accounts.Current(r.Context(), binding.SenderAccount)
	if errors.Is(err, accounts.ErrDeleted) {
		return fail(410, "ACCOUNT_DELETED", false)
	}
	if err != nil {
		return fail(503, "ACCOUNT_UNAVAILABLE", true)
	}
	if !sender.Contains(binding.SenderHead) {
		return deny()
	}
	if _, active := sender.ActiveDevice(d.OwnerDeviceID); !active {
		return deny()
	}
	recipient, err := s.Accounts.Current(r.Context(), binding.RecipientAccount)
	if errors.Is(err, accounts.ErrDeleted) {
		return fail(410, "ACCOUNT_DELETED", false)
	}
	if err != nil {
		return fail(503, "ACCOUNT_UNAVAILABLE", true)
	}
	if !recipient.Contains(binding.RecipientHead) {
		return deny()
	}
	if allRecipients {
		for _, id := range d.Recipients {
			if _, active := recipient.ActiveDevice(id); !active {
				return deny()
			}
		}
	}
	if !bytes.Equal(sess.DeviceID, d.OwnerDeviceID) {
		if _, active := recipient.ActiveDevice(sess.DeviceID); !active {
			return deny()
		}
	}
	return true
}

func (s *Service) authorizeObject(w http.ResponseWriter, r *http.Request, o *object, sess auth.Session, allRecipients bool) bool {
	o.mu.Lock()
	d := o.Descriptor
	o.mu.Unlock()
	return s.authorizeContact(w, r, d, sess, allRecipients)
}

// Cleanup is a recipient's right even after the sender is revoked. It grants no
// descriptor/chunk access and cannot drop another device's grant.
func (s *Service) authorizeCleanup(w http.ResponseWriter, r *http.Request, o *object, sess auth.Session) bool {
	o.mu.Lock()
	d := o.Descriptor
	isRecipient := o.isRecipient(sess.DeviceID)
	o.mu.Unlock()
	if d.Contact == nil || bytes.Equal(d.OwnerDeviceID, sess.DeviceID) {
		return s.authorizeContact(w, r, d, sess, false)
	}
	if !isRecipient || s.Accounts == nil {
		wire.WriteError(w, 403, "REVOKED_DEVICE", false)
		return false
	}
	current, err := s.Accounts.Current(r.Context(), d.Contact.RecipientAccount)
	if errors.Is(err, accounts.ErrDeleted) {
		wire.WriteError(w, 410, "ACCOUNT_DELETED", false)
		return false
	}
	if err != nil {
		wire.WriteError(w, 503, "ACCOUNT_UNAVAILABLE", true)
		return false
	}
	if _, active := current.ActiveDevice(sess.DeviceID); !active || !current.Contains(d.Contact.RecipientHead) {
		wire.WriteError(w, 403, "REVOKED_DEVICE", false)
		return false
	}
	return true
}

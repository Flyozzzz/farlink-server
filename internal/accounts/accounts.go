// Package accounts is the server side of Farlink accounts (spec 2026-10-04 §12): an account is a signed chain of
// device lists, each link signed by a device of the previous one or by the account's recovery key. The server only
// verifies and stores the public chain; its one extra job is the registry that says which account a device key
// belongs to, so a key is never enrolled twice.
package accounts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	Domain       = "farlink/account/v1"
	MaxDevices   = 15
	MaxNickname  = 64
	MaxDevName   = 64
	MaxLinkBytes = 16 << 10
	MaxLinks     = 4096
	// Fork evidence has a separate budget so rejected branches cannot consume
	// the selected chain's remaining device/recovery updates.
	MaxForkEvents    = 256
	MaxSiblings      = 16 // includes one reserved selected-state slot
	MaxJournalEvents = MaxLinks + MaxForkEvents
	// MaxContactMailboxes servers carry an account's contact traffic: the first decides who may write to it.
	MaxContactMailboxes = 2
	MaxMailboxIDBytes   = 256
)

var (
	ErrMalformed     = errors.New("INVALID_ENCODING")
	ErrBadSignature  = errors.New("BAD_SIGNATURE")
	ErrNotAuthorized = errors.New("NOT_AUTHORIZED")
	ErrWrongAccount  = errors.New("WRONG_ACCOUNT")
	ErrRevoked       = errors.New("REVOKED_DEVICE")
	ErrSync          = errors.New("SYNC_REQUIRED")
	ErrFork          = errors.New("FORK")
	ErrDeviceLimit   = errors.New("DEVICE_LIMIT")
	ErrLastDevice    = errors.New("LAST_DEVICE")
	ErrDeviceTaken   = errors.New("DEVICE_ENROLLED_ELSEWHERE")
	ErrExists        = errors.New("ACCOUNT_EXISTS")
	ErrUnknown       = errors.New("NOT_FOUND")
	ErrTooLong       = errors.New("LIMIT_EXCEEDED")
)

// Device is one device of an account: its two public keys; its id is the SHA-256 of the signing key.
type Device struct {
	DeviceID      []byte `cbor:"device_id"`
	SigningKey    []byte `cbor:"signing_key"`
	EncryptionKey []byte `cbor:"encryption_key"`
	Name          string `cbor:"name"`
	AddedAt       uint64 `cbor:"added_at"`
}

// State is one state of the account, as the clients sign it.
type State struct {
	Protocol     uint64   `cbor:"protocol"`
	AccountID    []byte   `cbor:"account_id"`
	Number       uint64   `cbor:"number"`
	PrevHash     []byte   `cbor:"prev_hash"`
	Nickname     string   `cbor:"nickname"`
	Devices      []Device `cbor:"devices"`
	RecoverySign []byte   `cbor:"recovery_signing_key"`
	RecoveryEnc  []byte   `cbor:"recovery_encryption_key"`
	Revoked      [][]byte `cbor:"revoked"`
	Signer       []byte   `cbor:"signer"`
	CreatedAt    uint64   `cbor:"created_at"`
	// ContactMailboxes: where contacts reach this account (canonical server ids); empty means contacts are off.
	ContactMailboxes []string `cbor:"contact_mailboxes"`
	GenesisNonce     []byte   `cbor:"genesis_nonce,omitempty"`
}

// Link is a state with its signature: the two-element array the clients send, kept as received.
type Link struct {
	Raw       []byte // the envelope exactly as received; its hash names the link
	Bytes     []byte // the signed state
	Signature []byte
	State     State
}

// Hash names the link.
func (l Link) Hash() []byte { h := sha256.Sum256(l.Raw); return h[:] }

func keyID(signing []byte) []byte { h := sha256.Sum256(signing); return h[:] }

func (s State) recoveryID() []byte { return keyID(s.RecoverySign) }

func (s State) device(id []byte) (Device, bool) {
	for _, d := range s.Devices {
		if bytes.Equal(d.DeviceID, id) {
			return d, true
		}
	}
	return Device{}, false
}

func (s State) revoked(id []byte) bool {
	for _, r := range s.Revoked {
		if bytes.Equal(r, id) {
			return true
		}
	}
	return false
}

// ParseLink decodes an envelope and its state, and checks everything that needs no history.
func ParseLink(raw []byte) (Link, error) {
	if len(raw) == 0 || len(raw) > MaxLinkBytes {
		return Link{}, ErrMalformed
	}
	var env [][]byte
	if wire.Unmarshal(raw, &env) != nil || len(env) != 2 || len(env[1]) != ed25519.SignatureSize {
		return Link{}, ErrMalformed
	}
	var st State
	if wire.Unmarshal(env[0], &st) != nil {
		return Link{}, ErrMalformed
	}
	if st.Protocol != 1 || len(st.AccountID) != 32 || len(st.PrevHash) != 32 || len(st.Signer) != 32 ||
		len(st.RecoverySign) != ed25519.PublicKeySize || len(st.RecoveryEnc) != 32 ||
		len(st.Nickname) > MaxNickname*4 || len(st.Devices) == 0 || len(st.Devices) > MaxDevices {
		return Link{}, ErrMalformed
	}
	if len(st.ContactMailboxes) > MaxContactMailboxes {
		return Link{}, ErrMalformed
	}
	for i, m := range st.ContactMailboxes {
		if m == "" || len(m) > MaxMailboxIDBytes {
			return Link{}, ErrMalformed
		}
		for _, o := range st.ContactMailboxes[:i] {
			if o == m {
				return Link{}, ErrMalformed
			}
		}
	}
	for i, d := range st.Devices {
		if len(d.SigningKey) != ed25519.PublicKeySize || len(d.EncryptionKey) != 32 || !bytes.Equal(d.DeviceID, keyID(d.SigningKey)) ||
			len(d.Name) > MaxDevName*4 {
			return Link{}, ErrMalformed
		}
		if i > 0 && bytes.Compare(st.Devices[i-1].DeviceID, d.DeviceID) >= 0 {
			return Link{}, ErrMalformed
		}
	}
	for i, r := range st.Revoked {
		if len(r) != 32 || (i > 0 && bytes.Compare(st.Revoked[i-1], r) >= 0) {
			return Link{}, ErrMalformed
		}
		if _, ok := st.device(r); ok {
			return Link{}, ErrRevoked
		}
	}
	return Link{Raw: append([]byte(nil), raw...), Bytes: env[0], Signature: env[1], State: st}, nil
}

func verify(pub, signed, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub), append([]byte(Domain), signed...), sig)
}

// CheckGenesis validates the first link of an account.
func CheckGenesis(l Link) error {
	s := l.State
	if s.Number != 0 || !bytes.Equal(s.PrevHash, make([]byte, 32)) || len(s.Devices) != 1 || len(s.Revoked) != 0 ||
		!bytes.Equal(s.Signer, s.Devices[0].DeviceID) || len(s.GenesisNonce) != 16 || bytes.Equal(s.Devices[0].DeviceID, s.recoveryID()) {
		return ErrMalformed
	}
	h := sha256.New()
	h.Write([]byte("farlink/account-id/v1"))
	h.Write(s.Devices[0].SigningKey)
	h.Write(s.RecoverySign)
	h.Write(s.GenesisNonce)
	if !bytes.Equal(h.Sum(nil), s.AccountID) {
		return ErrMalformed
	}
	if !verify(s.Devices[0].SigningKey, l.Bytes, l.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Check validates `next` as the successor of `prev` (whose link hash is prevHash): the same rules the devices apply.
func Check(next Link, prev State, prevHash []byte) error {
	n := next.State
	if !bytes.Equal(n.AccountID, prev.AccountID) {
		return ErrWrongAccount
	}
	if n.Number != prev.Number+1 || !bytes.Equal(n.PrevHash, prevHash) {
		return ErrSync
	}
	if len(n.GenesisNonce) != 0 {
		return ErrMalformed
	}
	var signerKey []byte
	if d, ok := prev.device(n.Signer); ok {
		signerKey = d.SigningKey
	} else if bytes.Equal(n.Signer, prev.recoveryID()) {
		signerKey = prev.RecoverySign
	} else {
		return ErrNotAuthorized
	}
	if !verify(signerKey, next.Bytes, next.Signature) {
		return ErrBadSignature
	}
	for _, r := range prev.Revoked {
		if !n.revoked(r) {
			return ErrRevoked
		}
	}
	for _, d := range n.Devices {
		if n.revoked(d.DeviceID) {
			return ErrRevoked
		}
		if bytes.Equal(d.DeviceID, n.recoveryID()) {
			return ErrMalformed
		}
		if old, ok := prev.device(d.DeviceID); ok && (!bytes.Equal(old.SigningKey, d.SigningKey) || !bytes.Equal(old.EncryptionKey, d.EncryptionKey)) {
			return ErrMalformed
		}
	}
	if len(n.Devices) == 0 {
		return ErrLastDevice
	}
	if len(n.Devices) > MaxDevices {
		return ErrDeviceLimit
	}
	for _, old := range prev.Devices {
		if _, ok := n.device(old.DeviceID); !ok && !n.revoked(old.DeviceID) {
			return ErrMalformed
		}
	}
	return nil
}

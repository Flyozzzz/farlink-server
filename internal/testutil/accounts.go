package testutil

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// Account signs real chain links for integration tests using ordinary device keys.
type Account struct {
	State    accounts.State
	Links    [][]byte
	Recovery Device
}

func AccountDevice(d Device) accounts.Device {
	key := make([]byte, 32)
	rand.Read(key)
	return accounts.Device{DeviceID: d.ID, SigningKey: d.Pub, EncryptionKey: key, Name: "Device", AddedAt: 1}
}

func NewAccount(t *testing.T, devices []Device, mailboxes ...string) *Account {
	t.Helper()
	rk := NewDevice()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	h := sha256.New()
	h.Write([]byte("farlink/account-id/v1"))
	h.Write(devices[0].Pub)
	h.Write(rk.Pub)
	h.Write(nonce)
	a := &Account{Recovery: rk, State: accounts.State{Protocol: 1, AccountID: h.Sum(nil), PrevHash: make([]byte, 32),
		Nickname: "Account", Devices: []accounts.Device{AccountDevice(devices[0])}, RecoverySign: rk.Pub, RecoveryEnc: make([]byte, 32),
		Revoked: [][]byte{}, Signer: devices[0].ID, CreatedAt: 1, ContactMailboxes: mailboxes, GenesisNonce: nonce}}
	if a.State.ContactMailboxes == nil {
		a.State.ContactMailboxes = []string{}
	}
	a.sign(t, devices[0])
	if len(devices) > 1 {
		a.Update(t, devices[0], func(state *accounts.State) {
			for _, d := range devices[1:] {
				state.Devices = append(state.Devices, AccountDevice(d))
			}
		})
	}
	return a
}

func (a *Account) sign(t *testing.T, signer Device) {
	t.Helper()
	slices.SortFunc(a.State.Devices, func(a, b accounts.Device) int { return bytes.Compare(a.DeviceID, b.DeviceID) })
	slices.SortFunc(a.State.Revoked, bytes.Compare)
	body, err := wire.Enc.Marshal(a.State)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := wire.Enc.Marshal([][]byte{body, ed25519.Sign(signer.Priv, append([]byte(accounts.Domain), body...))})
	if err != nil {
		t.Fatal(err)
	}
	a.Links = append(a.Links, raw)
}

func (a *Account) HeadRef() accounts.HeadRef {
	hash := sha256.Sum256(a.Links[len(a.Links)-1])
	return accounts.HeadRef{Number: a.State.Number, Hash: hash[:]}
}

func (a *Account) Update(t *testing.T, signer Device, change func(*accounts.State)) {
	t.Helper()
	a.State.PrevHash = a.HeadRef().Hash
	a.State.Number++
	a.State.GenesisNonce = nil
	a.State.Signer = signer.ID
	a.State.Devices = slices.Clone(a.State.Devices)
	a.State.Revoked = slices.Clone(a.State.Revoked)
	if a.State.Revoked == nil {
		a.State.Revoked = [][]byte{}
	}
	change(&a.State)
	a.sign(t, signer)
}

func (a *Account) Publish(t *testing.T, registries ...*accounts.Registry) {
	t.Helper()
	for _, registry := range registries {
		for _, raw := range a.Links {
			if _, _, err := registry.Submit(raw); err != nil {
				t.Fatal(err)
			}
		}
	}
}

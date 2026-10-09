package contacts

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

func TestDeliveryProofBindsConcreteEnvelopeAndFreshAccountDevices(t *testing.T) {
	sender, receiver := testutil.NewDevice(), testutil.NewDevice()
	from := testutil.NewAccount(t, []testutil.Device{sender}, "origin")
	to := testutil.NewAccount(t, []testutil.Device{receiver}, "mailbox")
	reg, err := accounts.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	from.Publish(t, reg)
	to.Publish(t, reg)
	resolver, err := accounts.OpenResolver(reg, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixMilli())
	fr := federation.NewRequest("origin", did(1), sender.ID, receiver.ID, "contact-message", now+60000, []byte("sealed"))
	fr.Bytes = uint64(len(fr.Envelope))
	hash := sha256.Sum256(fr.Envelope)
	proof := SignDeliveryProof(sender.Priv, Delivery{Protocol: 2, SenderAccount: from.State.AccountID, SenderHead: from.HeadRef(),
		SenderDevice: sender.ID, RecipientAccount: to.State.AccountID, RecipientHead: to.HeadRef(), RecipientDevice: receiver.ID,
		LogicalID: did(1), DeliveryID: fr.DeliveryID, Kind: fr.Kind, Origin: fr.Origin, Authority: "mailbox", Mailboxes: []string{"mailbox"},
		SpoolIDs: [][]byte{}, Bytes: fr.Bytes, ExpiresAt: fr.ExpiresAt, EnvelopeHash: hash[:]})
	// Exercise exactly the CBOR form forwarded by the origin, not just a Go struct.
	raw, err := wire.Enc.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var parsed ContactDeliveryProof
	if err := wire.Lenient(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Matches(fr) {
		t.Fatal("transport rejected signed delivery")
	}
	if _, err := parsed.Check(context.Background(), resolver, now); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*ContactDeliveryProof){
		"account":      func(p *ContactDeliveryProof) { p.SenderAccount = to.State.AccountID },
		"device":       func(p *ContactDeliveryProof) { p.SenderDevice = receiver.ID },
		"logical send": func(p *ContactDeliveryProof) { p.LogicalID = did(2) },
		"delivery":     func(p *ContactDeliveryProof) { p.DeliveryID = did(2) },
		"kind":         func(p *ContactDeliveryProof) { p.Kind = "contact-control" },
		"origin":       func(p *ContactDeliveryProof) { p.Origin = "other" },
		"expiry":       func(p *ContactDeliveryProof) { p.ExpiresAt++ },
		"payload":      func(p *ContactDeliveryProof) { p.EnvelopeHash = id(8) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := parsed
			mutate(&changed)
			if _, err := changed.Check(context.Background(), resolver, now); err == nil {
				t.Fatal("substituted delivery accepted")
			}
		})
	}
	changed := fr
	changed.Envelope = []byte("different ciphertext")
	if parsed.Matches(changed) {
		t.Fatal("signed hash accepted another payload")
	}
	if _, err := parsed.Check(context.Background(), resolver, proof.ExpiresAt); err == nil {
		t.Fatal("expired delivery accepted")
	}
	fresh := testutil.NewDevice()
	from.Update(t, from.Recovery, func(state *accounts.State) {
		state.Devices = []accounts.Device{testutil.AccountDevice(fresh)}
		state.Revoked = [][]byte{sender.ID}
	})
	from.Publish(t, reg)
	if _, err := parsed.Check(context.Background(), resolver, now); err == nil {
		t.Fatal("previously valid delivery survived sender revocation")
	}
}

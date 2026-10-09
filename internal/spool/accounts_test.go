package spool

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

type contactSpool struct {
	f        *fixture
	from, to *testutil.Account
	registry *accounts.Registry
	request  CreateRequest
	created  CreateResponse
	other    testutil.Device
}

func newContactSpool(t *testing.T) *contactSpool {
	t.Helper()
	f := &fixture{owner: testutil.NewDevice(), peer: testutil.NewDevice()}
	f.srv, f.s = setup(t, 1<<30)
	t.Cleanup(f.srv.Close)
	f.tOwner, f.tPeer = testutil.Login(t, f.srv.URL, f.owner), testutil.Login(t, f.srv.URL, f.peer)
	c := &contactSpool{f: f, other: testutil.NewDevice()}
	c.from = testutil.NewAccount(t, []testutil.Device{f.owner}, "test")
	c.to = testutil.NewAccount(t, []testutil.Device{f.peer, c.other}, "test")
	var err error
	c.registry, err = accounts.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.from.Publish(t, c.registry)
	c.to.Publish(t, c.registry)
	f.s.Accounts, err = accounts.OpenResolver(c.registry, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.data = bytes.Repeat([]byte("ciphertext"), 100)
	hash := sha256.Sum256(f.data)
	f.part = Part{PartID: bytes.Repeat([]byte{1}, 16), Size: uint64(len(f.data)), CiphertextSHA256: hash[:]}
	c.request = CreateRequest{Recipients: [][]byte{f.peer.ID}, Parts: []Part{f.part}, Contact: &ContactBinding{
		SenderAccount: c.from.State.AccountID, SenderHead: c.from.HeadRef(), RecipientAccount: c.to.State.AccountID, RecipientHead: c.to.HeadRef()}}
	if status := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", f.tOwner, c.request, &c.created); status != 200 {
		t.Fatalf("create: %d", status)
	}
	f.id = c.created.SpoolID
	return c
}

func (c *contactSpool) commit(t *testing.T) int {
	f := c.f
	d := Descriptor{Protocol: 1, SpoolID: c.created.SpoolID, OwnerDeviceID: f.owner.ID, Recipients: c.request.Recipients,
		OriginServer: c.created.OriginServer, CreatedAt: c.created.CreatedAt, ExpiresAt: c.created.ExpiresAt, Parts: c.request.Parts,
		Boxes: []Box{{Recipient: f.peer.ID, Box: []byte("sealed")}}, Contact: c.request.Contact}
	body, err := wire.Enc.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return testutil.Do(t, "POST", f.url("commit"), f.tOwner, CommitRequest{Boxes: d.Boxes, SigningKey: f.owner.Pub, Signature: ed25519.Sign(f.owner.Priv, append([]byte(domain), body...))}, nil)
}

func (c *contactSpool) revokeSender(t *testing.T) {
	fresh := testutil.NewDevice()
	c.from.Update(t, c.from.Recovery, func(state *accounts.State) {
		state.Devices = []accounts.Device{testutil.AccountDevice(fresh)}
		state.Revoked = [][]byte{c.f.owner.ID}
	})
	c.from.Publish(t, c.registry)
}
func (c *contactSpool) revokeRecipient(t *testing.T) {
	c.to.Update(t, c.other, func(state *accounts.State) {
		for _, device := range state.Devices {
			if bytes.Equal(device.DeviceID, c.other.ID) {
				state.Devices = []accounts.Device{device}
				break
			}
		}
		state.Revoked = [][]byte{c.f.peer.ID}
	})
	c.to.Publish(t, c.registry)
}

func TestContactSpoolRevocationBetweenReservationUploadAndCommit(t *testing.T) {
	for _, who := range []string{"sender", "recipient"} {
		t.Run(who, func(t *testing.T) {
			c := newContactSpool(t)
			f := c.f
			if status := testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, f.data, nil); status != 204 {
				t.Fatal(status)
			}
			if who == "sender" {
				c.revokeSender(t)
			} else {
				c.revokeRecipient(t)
			}
			if status := c.commit(t); status != 403 {
				t.Fatalf("commit after %s revoke: %d", who, status)
			}
			if status := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", f.tOwner, c.request, nil); status != 403 {
				t.Fatalf("new reservation after %s revoke: %d", who, status)
			}
			if who == "sender" {
				if status := testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, f.data, nil); status != 403 {
					t.Fatalf("upload after revoke: %d", status)
				}
			}
		})
	}
}

func TestContactSpoolRechecksEveryReadAndACKAfterRevocation(t *testing.T) {
	c := newContactSpool(t)
	f := c.f
	if status := testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, f.data, nil); status != 204 {
		t.Fatal(status)
	}
	if status := c.commit(t); status != 204 {
		t.Fatalf("commit: %d", status)
	}
	var descriptor GetResponse
	if status := testutil.Do(t, "GET", f.url(), f.tPeer, nil, &descriptor); status != 200 {
		t.Fatalf("descriptor before revoke: %d", status)
	}
	if descriptor.Descriptor.Contact == nil || !bytes.Equal(descriptor.Descriptor.Contact.RecipientAccount, c.to.State.AccountID) {
		t.Fatal("descriptor lost account binding")
	}
	c.revokeRecipient(t)
	var visible []ListItem
	if status := testutil.Do(t, "GET", f.srv.URL+"/v1/spools", f.tPeer, nil, &visible); status != 200 || len(visible) != 0 {
		t.Fatalf("revoked recipient list: %d %+v", status, visible)
	}
	for _, request := range []struct{ method, url string }{{"GET", f.url()}, {"GET", f.url("parts", enc.EncodeToString(f.part.PartID))}, {"POST", f.url("ack")}} {
		if status := testutil.Do(t, request.method, request.url, f.tPeer, nil, nil); status != 403 {
			t.Fatalf("%s %s after revoke: %d", request.method, request.url, status)
		}
	}
	req, err := http.NewRequest("GET", f.url("parts", enc.EncodeToString(f.part.PartID)), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+f.tPeer)
	req.Header.Set("Range", "bytes=0-9")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 403 || bytes.Equal(body, f.data[:10]) {
		t.Fatal("Range leaked revoked recipient's bytes")
	}
	// A revoked recipient does not gain access again when the spool is reopened.
	reopened, err := New(f.s.Auth, f.s.Dir, f.s.TTL, f.s.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Accounts = f.s.Accounts
	request, _ := http.NewRequest("GET", f.url(), nil)
	request.SetPathValue("id", enc.EncodeToString(f.id))
	request.Header.Set("Authorization", "Bearer "+f.tPeer)
	recorder := httptest.NewRecorder()
	reopened.HandleGet(recorder, request)
	if recorder.Code != 403 {
		t.Fatalf("restart restored revoked recipient access: %d", recorder.Code)
	}
}

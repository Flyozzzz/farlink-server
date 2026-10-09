package drop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/contacts"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/spool"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

func post(t *testing.T, url, token string, body any) (int, string) {
	t.Helper()
	var raw []byte
	status := testutil.Do(t, "POST", url, token, body, &raw)
	var failure wire.Error
	if status >= 300 {
		wire.Lenient(raw, &failure)
	}
	return status, failure.Code
}

type contactSetup struct {
	m                        map[string]*node
	sender, recipent, second testutil.Device
	from, to                 *testutil.Account
	senderTok                string
	expires                  uint64
}

func setup(t *testing.T, ids ...string) contactSetup {
	c := contactSetup{m: mesh(t, ids...), sender: testutil.NewDevice(), recipent: testutil.NewDevice(), second: testutil.NewDevice(),
		expires: uint64(time.Now().Add(time.Hour).UnixMilli())}
	c.from = testutil.NewAccount(t, []testutil.Device{c.sender}, "a")
	mailboxes := ids[1:]
	if len(mailboxes) == 0 {
		mailboxes = ids
	}
	c.to = testutil.NewAccount(t, []testutil.Device{c.recipent, c.second}, mailboxes...)
	c.publish(t, c.from)
	c.publish(t, c.to)
	c.senderTok = insecureLogin(t, c.m["a"], c.sender)
	return c
}

func (c contactSetup) publish(t *testing.T, account *testutil.Account) {
	for _, n := range c.m {
		account.Publish(t, n.accounts)
	}
}

func (c contactSetup) binding() *spool.ContactBinding {
	return &spool.ContactBinding{SenderAccount: c.from.State.AccountID, SenderHead: c.from.HeadRef(), RecipientAccount: c.to.State.AccountID, RecipientHead: c.to.HeadRef()}
}

func (c contactSetup) sign(r Request) Request {
	size := uint64(len(r.Envelope))
	ids := r.SpoolIDs
	if len(r.SpoolID) != 0 {
		ids = [][]byte{r.SpoolID}
	}
	if len(ids) != 0 && c.m["a"].drop.Spool != nil {
		size = 0
		for _, id := range ids {
			info, ok := c.m["a"].drop.Spool.Info(id, c.sender.ID)
			if ok {
				size += info.Bytes
				r.ExpiresAt = min(r.ExpiresAt, info.ExpiresAt)
			}
		}
	}
	if ids == nil {
		ids = [][]byte{}
	}
	hash := sha256.Sum256(r.Envelope)
	p := contacts.SignDeliveryProof(c.sender.Priv, contacts.Delivery{Protocol: 2, SenderAccount: c.from.State.AccountID, SenderHead: c.from.HeadRef(), SenderDevice: c.sender.ID,
		RecipientAccount: c.to.State.AccountID, RecipientHead: c.to.HeadRef(), RecipientDevice: r.Destination, LogicalID: r.DeliveryID, DeliveryID: r.DeliveryID,
		Kind: r.Kind, Origin: "a", Authority: r.MailboxServers[0], Mailboxes: r.MailboxServers, SpoolIDs: ids, Bytes: size, ExpiresAt: r.ExpiresAt, EnvelopeHash: hash[:]})
	r.Proof = &p
	return r
}

func (c contactSetup) offer(id byte, servers ...string) Request {
	return c.sign(Request{DeliveryID: did(id), Destination: c.recipent.ID, Kind: KindContactOffer, MailboxServers: servers, ExpiresAt: c.expires, Envelope: []byte("sealed offer")})
}
func (c contactSetup) batch(id byte, spools ...[]byte) Request {
	r := c.offer(id, "b")
	r.Kind, r.SpoolIDs = KindContactBatch, spools
	return c.sign(r)
}
func (c contactSetup) control(id byte) Request {
	r := c.offer(id, "b")
	r.Kind = KindContactControl
	return c.sign(r)
}
func (c contactSetup) drop(t *testing.T, r Request) (int, string) {
	return post(t, c.m["a"].srv.URL+"/v1/mailbox/drop", c.senderTok, r)
}
func (c contactSetup) state(t *testing.T, server string, dev testutil.Device, req contacts.StateRequest) (int, string, contacts.StateResponse) {
	t.Helper()
	req.Recipient = c.to.State.AccountID
	var raw []byte
	status := testutil.Do(t, "POST", c.m[server].srv.URL+"/v1/contacts/state", insecureLogin(t, c.m[server], dev), req, &raw)
	var response contacts.StateResponse
	var failure wire.Error
	if status == 200 {
		wire.Lenient(raw, &response)
	} else {
		wire.Lenient(raw, &failure)
	}
	return status, failure.Code, response
}
func (c contactSetup) decide(t *testing.T, authority, action string, generation uint64) (int, string, contacts.Record) {
	status, failure, response := c.state(t, authority, c.recipent, contacts.StateRequest{Sender: c.from.State.AccountID, Action: action, Expected: generation})
	var record contacts.Record
	if len(response.Records) == 1 {
		record = response.Records[0]
	}
	return status, failure, record
}
func (c contactSetup) held(server string) []contacts.Record {
	records, _, _ := c.m[server].con.List(c.to.State.AccountID, nil, 0)
	return records
}

func TestFirstContactIsHeldPendingAtTheAuthorityAndDeliveredToBothMailboxes(t *testing.T) {
	c := setup(t, "a", "b", "c")
	first := c.offer(1, "b", "c")
	if status, err := c.drop(t, first); status != 202 {
		t.Fatalf("first: %d %s", status, err)
	}
	c.m["a"].out.Process(context.Background())
	if len(list(t, c.m["b"], c.recipent)) != 1 || len(list(t, c.m["c"], c.recipent)) != 1 {
		t.Fatal("both mailboxes must receive")
	}
	if records := c.held("b"); len(records) != 1 || records[0].State != contacts.Pending {
		t.Fatalf("authority: %+v", records)
	}
	if len(c.held("c")) != 0 {
		t.Fatal("secondary mailbox became authority")
	}
	if status, err := c.drop(t, first); status != 202 {
		t.Fatalf("retry: %d %s", status, err)
	}
	if status, err := c.drop(t, c.offer(2, "b", "c")); status != 409 || err != "CONTACT_PENDING" {
		t.Fatalf("second batch: %d %s", status, err)
	}
	// The other device's envelope belongs to the same logical request.
	second := first
	second.Destination, second.DeliveryID = c.second.ID, did(3)
	second = c.sign(second)
	second.Proof.LogicalID = first.Proof.LogicalID
	p := contacts.SignDeliveryProof(c.sender.Priv, second.Proof.Delivery)
	second.Proof = &p
	if status, err := c.drop(t, second); status != 202 {
		t.Fatalf("device fanout: %d %s", status, err)
	}
	c.m["a"].out.Process(context.Background())
	if len(list(t, c.m["b"], c.second)) != 1 {
		t.Fatal("second active device did not receive")
	}
}

func TestAcceptDeclineRemoveAndRestoreDecideWhatTheSenderMaySend(t *testing.T) {
	c := setup(t, "a", "b")
	if status, _ := c.drop(t, c.offer(1, "b")); status != 202 {
		t.Fatal(status)
	}
	pending := c.held("b")[0]
	status, _, accepted := c.decide(t, "b", "accept", pending.Generation)
	if status != 200 || accepted.State != contacts.Accepted {
		t.Fatal("accept failed")
	}
	r := c.offer(2, "b")
	r.Kind = KindContactMessage
	r = c.sign(r)
	if status, err := c.drop(t, r); status != 202 {
		t.Fatalf("accepted send: %d %s", status, err)
	}
	if status, err, _ := c.decide(t, "b", "remove", pending.Generation); status != 409 || err != "STALE_GENERATION" {
		t.Fatalf("stale CAS: %d %s", status, err)
	}
	status, _, removed := c.decide(t, "b", "remove", accepted.Generation)
	if status != 200 || removed.State != contacts.Removed {
		t.Fatal("remove failed")
	}
	if status, err := c.drop(t, c.offer(3, "b")); status != 403 || err != "CONTACT_REMOVED" {
		t.Fatalf("blocked send: %d %s", status, err)
	}
	if status, _, rec := c.decide(t, "b", "accept", removed.Generation); status != 200 || rec.State != contacts.Accepted {
		t.Fatal("restore failed")
	}
}

func TestDeclineBlocksTheSenderUntilTheRetryWindowPasses(t *testing.T) {
	c := setup(t, "a", "b")
	now := time.Now()
	c.m["b"].con.Now = func() time.Time { return now }
	c.drop(t, c.offer(1, "b"))
	if status, _, rec := c.decide(t, "b", "decline", c.held("b")[0].Generation); status != 200 || rec.State != contacts.Declined {
		t.Fatal("decline failed")
	}
	if status, err := c.drop(t, c.offer(2, "b")); status != 403 || err != "CONTACT_DECLINED" {
		t.Fatalf("declined send: %d %s", status, err)
	}
	now = now.Add(contacts.RetryAfter + time.Minute)
	if status, err := c.drop(t, c.offer(3, "b")); status != 202 {
		t.Fatalf("after window: %d %s", status, err)
	}
}

func TestForgetLiftsABlockAndOnlyABlock(t *testing.T) {
	c := setup(t, "a", "b")
	c.drop(t, c.offer(1, "b"))
	pending := c.held("b")[0]
	if status, err, _ := c.decide(t, "b", "forget", pending.Generation); status != 409 || err != "INVALID_STATE" {
		t.Fatal("forgot pending")
	}
	_, _, declined := c.decide(t, "b", "decline", pending.Generation)
	if status, _, gone := c.decide(t, "b", "forget", declined.Generation); status != 200 || gone.State != contacts.None {
		t.Fatal("forget failed")
	}
	if status, err := c.drop(t, c.offer(2, "b")); status != 202 {
		t.Fatalf("after forget: %d %s", status, err)
	}
	if c.held("b")[0].Generation <= declined.Generation {
		t.Fatal("generation reused after forget")
	}
}

func TestAnUnreachableAuthorityFailsClosedAndQueuesNothing(t *testing.T) {
	c := setup(t, "a", "b", "c")
	c.m["b"].srv.Close()
	if status, err := c.drop(t, c.offer(1, "b", "c")); status != 503 || err != "AUTHORITY_UNAVAILABLE" {
		t.Fatalf("authority unavailable: %d %s", status, err)
	}
	if c.m["a"].out.Pending() != 0 {
		t.Fatal("queued without authority")
	}
}

func TestOriginCanBeTheAuthorityItself(t *testing.T) {
	c := setup(t, "a")
	if status, err := c.drop(t, c.offer(1, "a")); status != 202 {
		t.Fatalf("local authority: %d %s", status, err)
	}
	if len(c.held("a")) != 1 {
		t.Fatal("no local state")
	}
}

func TestDeliverySubstitutionCannotChangeWhatSenderSigned(t *testing.T) {
	c := setup(t, "a", "b")
	for name, change := range map[string]func(*Request){
		"payload":   func(r *Request) { r.Envelope = []byte("other") },
		"device":    func(r *Request) { r.Destination = c.second.ID },
		"delivery":  func(r *Request) { r.DeliveryID = did(8) },
		"kind":      func(r *Request) { r.Kind = KindContactControl },
		"signature": func(r *Request) { r.Proof.Signature = make([]byte, 64) },
		"expiry":    func(r *Request) { r.ExpiresAt++ },
	} {
		t.Run(name, func(t *testing.T) {
			r := c.offer(1, "b")
			change(&r)
			if status, _ := c.drop(t, r); status != 403 {
				t.Fatalf("substitution: %d", status)
			}
		})
	}
	if len(c.held("b")) != 0 || c.m["a"].out.Pending() != 0 {
		t.Fatal("forgery left state")
	}
}

func TestCurrentAccountDecidesRecipientAndMailboxOrder(t *testing.T) {
	c := setup(t, "a", "b", "c")
	wrong := c.offer(1, "c", "b")
	if status, err := c.drop(t, wrong); status != 400 || err != "MAILBOX_MISMATCH" {
		t.Fatalf("wrong order: %d %s", status, err)
	}
	wrong = c.offer(2, "b", "c")
	wrong.Destination = testutil.NewDevice().ID
	wrong = c.sign(wrong)
	if status, _ := c.drop(t, wrong); status != 403 {
		t.Fatal("unknown device accepted")
	}
	if status, err := c.drop(t, c.offer(3, "b")); status != 202 {
		t.Fatalf("mailbox prefix: %d %s", status, err)
	}
	old := c.offer(4, "b", "c")
	c.to.Update(t, c.recipent, func(state *accounts.State) { state.ContactMailboxes = []string{"c", "b"} })
	c.publish(t, c.to)
	if status, err := c.drop(t, old); status != 400 || err != "MAILBOX_MISMATCH" {
		t.Fatalf("old authority after route migration: %d %s", status, err)
	}
	if status, err := c.drop(t, c.offer(5, "c", "b")); status != 409 || err != "CONTACT_PENDING" {
		t.Fatalf("new authority lost pending snapshot: %d %s", status, err)
	}
	status, failure, state := c.state(t, "c", c.recipent, contacts.StateRequest{Action: "list"})
	if status != 200 || len(state.Records) != 1 || !bytes.Equal(state.Records[0].PendingDelivery, did(3)) {
		t.Fatalf("migrated state: %d %s %+v", status, failure, state)
	}
	if status, failure, _ := c.decide(t, "c", "accept", state.Records[0].Generation); status != 200 {
		t.Fatalf("accept after migration: %d %s", status, failure)
	}
	c.to.Update(t, c.recipent, func(state *accounts.State) { state.ContactMailboxes = []string{"b", "c"} })
	c.publish(t, c.to)
	if status, failure := c.drop(t, c.offer(6, "b", "c")); status != 202 {
		t.Fatalf("return authority lost acceptance: %d %s", status, failure)
	}
	c.to.Update(t, c.recipent, func(state *accounts.State) { state.ContactMailboxes = []string{} })
	c.publish(t, c.to)
	c.to.Update(t, c.recipent, func(state *accounts.State) { state.ContactMailboxes = []string{"b", "c"} })
	c.publish(t, c.to)
	if status, failure := c.drop(t, c.offer(7, "b", "c")); status != 202 {
		t.Fatalf("disable-enable lost acceptance: %d %s", status, failure)
	}
}

func TestNothingReachesAMailboxAroundTheAuthority(t *testing.T) {
	c := setup(t, "a", "b", "c")
	r := c.offer(1, "b", "c")
	fr := federation.NewRequest("a", r.DeliveryID, c.sender.ID, r.Destination, r.Kind, r.ExpiresAt, r.Envelope)
	fr.Bytes = r.Proof.Bytes
	if err := c.m["a"].cli.Send(context.Background(), "b", fr); err == nil {
		t.Fatal("missing proof admitted")
	}
	fr.Admission, _ = wire.Enc.Marshal(r.Proof)
	bad := fr
	bad.Envelope = []byte("other")
	if err := c.m["a"].cli.Send(context.Background(), "b", bad); err == nil {
		t.Fatal("substituted forward admitted")
	}
	if err := c.m["a"].cli.Send(context.Background(), "b", fr); err != nil {
		t.Fatal(err)
	}
	_, _, accepted := c.decide(t, "b", "accept", c.held("b")[0].Generation)
	c.decide(t, "b", "remove", accepted.Generation)
	if err := c.m["a"].cli.Send(context.Background(), "c", fr); err == nil {
		t.Fatal("secondary bypassed removed state")
	}
	if len(list(t, c.m["c"], c.recipent)) != 0 {
		t.Fatal("refused delivery stored")
	}
}

func TestOnlyActiveRecipientDeviceCanDecide(t *testing.T) {
	c := setup(t, "a", "b")
	c.drop(t, c.offer(1, "b"))
	if status, _, _ := c.state(t, "b", c.sender, contacts.StateRequest{Sender: c.from.State.AccountID, Action: "accept", Expected: c.held("b")[0].Generation}); status != 403 {
		t.Fatal("sender accepted itself")
	}
	revoke(t, c.to, c.recipent, c.second.ID)
	c.publish(t, c.to)
	if status, _, _ := c.state(t, "b", c.second, contacts.StateRequest{Action: "list"}); status != 403 {
		t.Fatal("revoked recipient device read state")
	}
}

func TestListPagesAndTheStateAPIIsRateLimited(t *testing.T) {
	c := setup(t, "a", "b")
	for i := range 5 {
		if err := c.m["b"].con.Admit(c.to.State.AccountID, append(make([]byte, 31), byte(i+1)), did(1), 1, c.expires); err != nil {
			t.Fatal(err)
		}
	}
	status, _, first := c.state(t, "b", c.recipent, contacts.StateRequest{Action: "list", Limit: 2})
	if status != 200 || len(first.Records) != 2 || len(first.Next) != 32 {
		t.Fatal("first page")
	}
	_, _, second := c.state(t, "b", c.second, contacts.StateRequest{Action: "list", Cursor: first.Next, Limit: 200})
	if len(second.Records) != 3 || second.Next != nil {
		t.Fatal("second page")
	}
	if status, _, _ := c.state(t, "b", c.recipent, contacts.StateRequest{Action: "list", Cursor: []byte{1}}); status != 400 {
		t.Fatal("bad cursor")
	}
	now := time.Now()
	c.m["b"].api.Now = func() time.Time { return now }
	for range contacts.StatePerMinute {
		status, _, _ = c.state(t, "b", c.second, contacts.StateRequest{Action: "list"})
	}
	if status != 429 {
		t.Fatal("state rate limit not shared by account")
	}
	now = now.Add(time.Minute + time.Second)
	if status, _, _ := c.state(t, "b", c.recipent, contacts.StateRequest{Action: "list"}); status != 200 {
		t.Fatal("state window did not reset")
	}
}

type batchSpool struct {
	owner []byte
	infos map[string]spool.Info
}

func (f batchSpool) Info(id, owner []byte) (spool.Info, bool) {
	info, ok := f.infos[string(id)]
	return info, ok && bytes.Equal(owner, f.owner)
}
func sid(n byte) []byte { return append(bytes.Repeat([]byte{0xA0}, 15), n) }

func TestABatchIsOneRequestSizedByAllFilesWithEarliestExpiry(t *testing.T) {
	c := setup(t, "a", "b")
	expires := c.expires - 1000
	info := func(size, expiry uint64) spool.Info {
		return spool.Info{Bytes: size, ExpiresAt: expiry, Recipients: [][]byte{c.recipent.ID}, Contact: c.binding()}
	}
	c.m["a"].drop.Spool = batchSpool{c.sender.ID, map[string]spool.Info{string(sid(1)): info(30<<20, c.expires), string(sid(2)): info(40<<20, expires), string(sid(3)): info(40<<20, c.expires)}}
	if status, _ := c.drop(t, c.batch(1, sid(1), sid(2), sid(3))); status != 413 {
		t.Fatalf("oversized batch: %d", status)
	}
	valid := c.batch(2, sid(1), sid(2))
	if status, err := c.drop(t, valid); status != 202 {
		t.Fatalf("valid batch: %d %s", status, err)
	}
	c.m["a"].out.Process(context.Background())
	got := list(t, c.m["b"], c.recipent)
	if len(got) != 1 || got[0].Bytes != 70<<20 || got[0].ExpiresAt != expires {
		t.Fatalf("batch: %+v", got)
	}
	if status, err := c.drop(t, valid); status != 202 {
		t.Fatalf("retry: %d %s", status, err)
	}
	if status, err := c.drop(t, c.batch(3, sid(1))); status != 409 || err != "CONTACT_PENDING" {
		t.Fatalf("second pending: %d %s", status, err)
	}
}

func TestABatchRefusesInvalidOrForeignSpools(t *testing.T) {
	c := setup(t, "a", "b")
	infos := map[string]spool.Info{string(sid(1)): {Bytes: 5, ExpiresAt: c.expires, Recipients: [][]byte{c.recipent.ID}, Contact: c.binding()}, string(sid(4)): {Bytes: 5, ExpiresAt: c.expires, Recipients: [][]byte{c.second.ID}, Contact: c.binding()}}
	c.m["a"].drop.Spool = batchSpool{c.sender.ID, infos}
	many := make([][]byte, MaxBatchFiles+1)
	for i := range many {
		many[i] = sid(byte(i + 10))
	}
	for _, tc := range []struct {
		ids    [][]byte
		status int
	}{{[][]byte{sid(1), sid(1)}, 400}, {[][]byte{[]byte("short")}, 400}, {many, 400}, {[][]byte{sid(9)}, 404}, {[][]byte{sid(1), sid(4)}, 404}} {
		if status, _ := c.drop(t, c.batch(1, tc.ids...)); status != tc.status {
			t.Fatalf("invalid spools: %d want %d", status, tc.status)
		}
	}
	foreign := infos[string(sid(1))]
	foreign.Contact = nil
	infos[string(sid(1))] = foreign
	if status, _ := c.drop(t, c.batch(2, sid(1))); status != 403 {
		t.Fatal("network spool reused as contact attachment")
	}
	if c.m["a"].out.Pending() != 0 || len(c.held("b")) != 0 {
		t.Fatal("refused spools left state")
	}
}

func TestATextOnlyBatchNeedsNoSpoolAndControlRequiresAcceptance(t *testing.T) {
	c := setup(t, "a", "b")
	if status, err := c.drop(t, c.control(1)); status != 403 || err != "CONTACT_NOT_ACCEPTED" {
		t.Fatalf("unknown control: %d %s", status, err)
	}
	if len(c.held("b")) != 0 {
		t.Fatal("control opened request")
	}
	r := c.batch(2)
	if status, err := c.drop(t, r); status != 202 {
		t.Fatalf("text batch: %d %s", status, err)
	}
	if status, _ := c.drop(t, c.control(3)); status != 403 {
		t.Fatal("pending permits control")
	}
	_, _, accepted := c.decide(t, "b", "accept", c.held("b")[0].Generation)
	if status, err := c.drop(t, c.control(4)); status != 202 {
		t.Fatalf("accepted control: %d %s", status, err)
	}
	c.m["a"].out.Process(context.Background())
	if got := list(t, c.m["b"], c.recipent); len(got) != 2 || got[0].Bytes != uint64(len(r.Envelope)) {
		t.Fatal("batch/control delivery")
	}
	c.decide(t, "b", "remove", accepted.Generation)
	if status, err := c.drop(t, c.control(5)); status != 403 || err != "CONTACT_REMOVED" {
		t.Fatalf("removed control: %d %s", status, err)
	}
}

func revoke(t *testing.T, account *testutil.Account, signer testutil.Device, id []byte) {
	account.Update(t, signer, func(state *accounts.State) {
		kept := make([]accounts.Device, 0, len(state.Devices)-1)
		for _, device := range state.Devices {
			if !bytes.Equal(device.DeviceID, id) {
				kept = append(kept, device)
			}
		}
		state.Devices = kept
		state.Revoked = append(state.Revoked, id)
	})
}

func TestRevocationBetweenQueueAndSinkStateMailboxAndACK(t *testing.T) {
	c := setup(t, "a", "b")
	r := c.offer(1, "b")
	r.Destination = c.second.ID
	r = c.sign(r)
	if status, err := c.drop(t, r); status != 202 {
		t.Fatalf("before revoke: %d %s", status, err)
	}
	c.m["a"].out.Process(context.Background())
	items := list(t, c.m["b"], c.second)
	if len(items) != 1 {
		t.Fatal("missing pre-revocation delivery")
	}
	revoke(t, c.to, c.recipent, c.second.ID)
	c.publish(t, c.to)
	if status, _, _ := c.state(t, "b", c.second, contacts.StateRequest{Action: "list"}); status != 403 {
		t.Fatal("revoked device read state")
	}
	token := insecureLogin(t, c.m["b"], c.second)
	if status := testutil.Do(t, "GET", c.m["b"].srv.URL+"/v1/mailbox", token, nil, nil); status != 403 {
		t.Fatalf("revoked mailbox: %d", status)
	}
	if status, _ := post(t, c.m["b"].srv.URL+"/v1/mailbox/"+base64.RawURLEncoding.EncodeToString(items[0].ItemID)+"/ack", token, nil); status != 403 {
		t.Fatal("revoked ACK accepted")
	}
	if status, _ := c.drop(t, r); status != 403 {
		t.Fatal("old recipient proof accepted")
	}
	// A queued delivery to a local mailbox must also recheck the sender.
	c = setup(t, "a")
	local := c.offer(2, "a")
	if status, err := c.drop(t, local); status != 202 {
		t.Fatalf("local queue: %d %s", status, err)
	}
	fresh := testutil.NewDevice()
	c.from.Update(t, c.from.Recovery, func(state *accounts.State) {
		state.Devices = []accounts.Device{testutil.AccountDevice(fresh)}
		state.Revoked = [][]byte{c.sender.ID}
	})
	c.publish(t, c.from)
	c.m["a"].out.Process(context.Background())
	if len(c.m["a"].box.List(c.recipent.ID)) != 0 {
		t.Fatal("local sink accepted revoked sender")
	}
	if status, _ := c.drop(t, local); status != 403 {
		t.Fatal("revoked sender sent again")
	}
}

func TestRateLimitCountsLogicalSendsAcrossAccountDevicesNotFanout(t *testing.T) {
	c := setup(t, "a")
	secondSender := testutil.NewDevice()
	c.from.Update(t, c.sender, func(state *accounts.State) {
		state.Devices = append(state.Devices, testutil.AccountDevice(secondSender))
	})
	c.publish(t, c.from)
	if status, _, _ := c.decide(t, "a", "accept", 0); status != 200 {
		t.Fatal("recipient did not accept")
	}
	other := c
	other.sender = secondSender
	other.senderTok = insecureLogin(t, c.m["a"], secondSender)
	var last Request
	for i := range PerHour {
		sender := c
		if i%2 != 0 {
			sender = other
		}
		r := sender.offer(0, "a")
		r.DeliveryID = make([]byte, 16)
		r.DeliveryID[0], r.DeliveryID[1] = byte(i), byte(i>>8)
		r = sender.sign(r)
		if status, err := sender.drop(t, r); status != 202 {
			t.Fatalf("logical send %d: %d %s", i, status, err)
		}
		last = r
	}
	if status, err := other.drop(t, last); status != 202 {
		t.Fatalf("retry at limit: %d %s", status, err)
	}
	fanout := last
	fanout.Destination, fanout.DeliveryID = c.second.ID, did(99)
	fanout = other.sign(fanout)
	fanout.Proof.LogicalID = last.Proof.LogicalID
	proof := contacts.SignDeliveryProof(secondSender.Priv, fanout.Proof.Delivery)
	fanout.Proof = &proof
	if status, err := other.drop(t, fanout); status != 202 {
		t.Fatalf("second HPKE envelope consumed logical-send quota: %d %s", status, err)
	}
	if status, err := c.drop(t, c.offer(101, "a")); status != 429 || err != "RATE_LIMITED" {
		t.Fatalf("601st logical send across two devices: %d %s", status, err)
	}
}

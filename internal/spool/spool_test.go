package spool

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

var enc = base64.RawURLEncoding

func setup(t *testing.T, maxBytes int64) (*httptest.Server, *Service) {
	a := auth.New("test")
	s, err := New(a, t.TempDir(), 7*24*time.Hour, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("POST /v1/spools", s.HandleCreate)
	mux.HandleFunc("GET /v1/spools", s.HandleList)
	mux.HandleFunc("GET /v1/spools/{id}", s.HandleGet)
	mux.HandleFunc("PUT /v1/spools/{id}/parts/{part}", s.HandlePutPart)
	mux.HandleFunc("GET /v1/spools/{id}/parts/{part}", s.HandleGetPart)
	mux.HandleFunc("POST /v1/spools/{id}/commit", s.HandleCommit)
	mux.HandleFunc("POST /v1/spools/{id}/ack", s.HandleAck)
	mux.HandleFunc("DELETE /v1/spools/{id}", s.HandleDelete)
	return httptest.NewServer(mux), s
}

type fixture struct {
	srv           *httptest.Server
	s             *Service
	owner, peer   testutil.Device
	tOwner, tPeer string
	part          Part
	data          []byte
	id            []byte
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{owner: testutil.NewDevice(), peer: testutil.NewDevice()}
	f.srv, f.s = setup(t, 1<<30)
	f.tOwner, f.tPeer = testutil.Login(t, f.srv.URL, f.owner), testutil.Login(t, f.srv.URL, f.peer)
	f.data = make([]byte, 1000)
	rand.Read(f.data)
	sum := sha256.Sum256(f.data)
	pid := make([]byte, 16)
	rand.Read(pid)
	f.part = Part{PartID: pid, Size: 1000, CiphertextSHA256: sum[:]}
	var cr CreateResponse
	if testutil.Do(t, "POST", f.srv.URL+"/v1/spools", f.tOwner, CreateRequest{Recipients: [][]byte{f.peer.ID}, Parts: []Part{f.part}}, &cr) != 200 {
		t.Fatal("create failed")
	}
	f.id = cr.SpoolID
	return f
}

func (f *fixture) url(parts ...string) string {
	u := f.srv.URL + "/v1/spools/" + enc.EncodeToString(f.id)
	for _, p := range parts {
		u += "/" + p
	}
	return u
}

func (f *fixture) commit(t *testing.T) int {
	f.s.mu.Lock()
	o := f.s.objects[string(f.id)]
	f.s.mu.Unlock()
	if o == nil {
		return testutil.Do(t, "POST", f.url("commit"), f.tOwner, CommitRequest{SigningKey: f.owner.Pub}, nil)
	}
	o.mu.Lock()
	d := o.Descriptor
	o.mu.Unlock()
	d.Boxes = []Box{{Recipient: f.peer.ID, Box: []byte("sealed-index")}}
	msg, _ := wire.Enc.Marshal(d)
	sig := ed25519.Sign(f.owner.Priv, append([]byte(domain), msg...))
	return testutil.Do(t, "POST", f.url("commit"), f.tOwner, CommitRequest{Boxes: d.Boxes, SigningKey: f.owner.Pub, Signature: sig}, nil)
}

func TestFullSpoolLifecycle(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	pu := f.url("parts", enc.EncodeToString(f.part.PartID))
	if code := f.commit(t); code != 409 {
		t.Fatalf("commit before upload = %d", code)
	}
	if code := testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil); code != 204 {
		t.Fatalf("put = %d", code)
	}
	if code := testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil); code != 204 {
		t.Fatalf("idempotent put = %d", code)
	}
	var list []ListItem
	testutil.Do(t, "GET", f.srv.URL+"/v1/spools", f.tPeer, nil, &list)
	if len(list) != 0 {
		t.Fatal("uncommitted object visible to recipient")
	}
	if code := f.commit(t); code != 204 {
		t.Fatalf("commit = %d", code)
	}
	testutil.Do(t, "GET", f.srv.URL+"/v1/spools", f.tPeer, nil, &list)
	if len(list) != 1 {
		t.Fatalf("list = %+v", list)
	}
	var got GetResponse
	testutil.Do(t, "GET", f.url(), f.tPeer, nil, &got)
	if string(got.Box) != "sealed-index" {
		t.Fatalf("box = %q", got.Box)
	}
	var body []byte
	testutil.Do(t, "GET", pu, f.tPeer, nil, &body)
	if string(body) != string(f.data) {
		t.Fatal("part bytes differ")
	}
	if code := testutil.Do(t, "POST", f.url("ack"), f.tPeer, nil, nil); code != 204 {
		t.Fatalf("ack = %d", code)
	}
	if code := testutil.Do(t, "GET", f.url(), f.tPeer, nil, nil); code != 404 {
		t.Fatal("object still there after all recipients acked")
	}
}

func TestPartMustMatchReservation(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	bad := append([]byte{}, f.data...)
	bad[0] ^= 1
	if code := testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, bad, nil); code != 409 {
		t.Fatalf("tampered part = %d", code)
	}
}

func TestStrangersAndOwnerCannotReadAsRecipient(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, f.data, nil)
	f.commit(t)
	eve := testutil.Login(t, f.srv.URL, testutil.NewDevice())
	if code := testutil.Do(t, "GET", f.url(), eve, nil, nil); code != 404 {
		t.Fatalf("stranger read = %d", code)
	}
	if code := testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tPeer, f.data, nil); code != 404 {
		t.Fatalf("recipient could upload = %d", code)
	}
}

func TestForgedCommitRejected(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, f.data, nil)
	other := testutil.NewDevice()
	o := f.s.objects[string(f.id)]
	msg, _ := wire.Enc.Marshal(o.Descriptor)
	sig := ed25519.Sign(other.Priv, append([]byte(domain), msg...))
	if code := testutil.Do(t, "POST", f.url("commit"), f.tOwner, CommitRequest{SigningKey: other.Pub, Signature: sig}, nil); code != 401 {
		t.Fatalf("foreign key commit = %d", code)
	}
}

func TestExpiryAndRangeAndRestart(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	pu := f.url("parts", enc.EncodeToString(f.part.PartID))
	testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil)
	f.commit(t)

	req, _ := http.NewRequest("GET", pu, nil)
	req.Header.Set("Authorization", "Bearer "+f.tPeer)
	req.Header.Set("Range", "bytes=500-")
	resp, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 206 || string(b) != string(f.data[500:]) {
		t.Fatalf("range = %d, %d bytes", resp.StatusCode, len(b))
	}

	again, err := New(f.s.Auth, f.s.Dir, f.s.TTL, f.s.MaxBytes)
	if err != nil || again.objects[string(f.id)] == nil || again.objects[string(f.id)].State != Available {
		t.Fatal("state lost across restart")
	}

	f.s.Now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	if code := testutil.Do(t, "GET", f.url(), f.tPeer, nil, nil); code != 404 {
		t.Fatal("expired object still readable")
	}
}

func TestOwnerQuota(t *testing.T) {
	srv, _ := setup(t, 1000+objectOverhead+64+32+500) // one 1000-byte part with its metadata, not two
	defer srv.Close()
	owner := testutil.NewDevice()
	tok := testutil.Login(t, srv.URL, owner)
	part := func() Part {
		id := make([]byte, 16)
		rand.Read(id)
		return Part{PartID: id, Size: 1000, CiphertextSHA256: make([]byte, 32)}
	}
	peer := testutil.NewDevice().ID
	if testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{peer}, Parts: []Part{part()}}, nil) != 200 {
		t.Fatal("first reservation should fit")
	}
	if code := testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{peer}, Parts: []Part{part()}}, nil); code != 507 {
		t.Fatalf("over quota = %d", code)
	}
}

// Quota hooks: the tier's allowance replaces the flat per-owner cap, an exhausted owner reserves nothing new,
// and downloads of what is already committed are billed to the owner, and stop when the meter refuses.
func TestQuotaHooks(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	pu := f.url("parts", enc.EncodeToString(f.part.PartID))
	testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil)
	if code := f.commit(t); code != 204 {
		t.Fatalf("commit = %d", code)
	}
	var billed int64
	hooks := &hookMeter{charge: func(owner []byte, n int64) bool {
		if string(owner) == string(f.owner.ID) {
			billed += n
		}
		return true
	}}
	f.s.Meter = hooks
	var got []byte
	// An exhausted meter refuses the first download before any byte goes out.
	allow := hooks.charge
	hooks.charge = func([]byte, int64) bool { return false }
	if code := testutil.Do(t, "GET", pu, f.tPeer, nil, nil); code != 429 {
		t.Fatalf("download on an exhausted meter = %d", code)
	}
	hooks.charge = allow
	if code := testutil.Do(t, "GET", pu, f.tPeer, nil, &got); code != 200 || len(got) != 1000 || billed != 1000 {
		t.Fatalf("download = %d, %d bytes, billed %d", code, len(got), billed)
	}
	// Billed once: the same object is served again without asking the meter.
	hooks.charge = func([]byte, int64) bool { return false }
	if code := testutil.Do(t, "GET", pu, f.tPeer, nil, nil); code != 200 {
		t.Fatalf("second download of a billed object = %d", code)
	}
	req := CreateRequest{Recipients: [][]byte{f.peer.ID}, Parts: []Part{f.part}}
	f.s.OwnerMaxBytes = func([]byte) int64 { return 2000 }
	if code := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", f.tOwner, req, nil); code != 507 {
		t.Fatalf("over the tier's spool allowance = %d", code)
	}
	f.s.OwnerMaxBytes = func([]byte) int64 { return 1 << 30 }
	hooks.admit = func(owner []byte) bool { return string(owner) != string(f.owner.ID) }
	if code := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", f.tOwner, req, nil); code != 429 {
		t.Fatalf("exhausted owner reserved = %d", code)
	}
}

type hookMeter struct {
	admit  func(device []byte) bool
	charge func(device []byte, n int64) bool
}

func (m *hookMeter) Admit(d []byte, _ string) bool { return m.admit == nil || m.admit(d) }
func (m *hookMeter) Charge(d []byte, _ string, n int64) bool {
	return m.charge == nil || m.charge(d, n)
}
func (m *hookMeter) ChargeAccount(d []byte, _ string, n int64) bool {
	return m.charge == nil || m.charge(d, n)
}
func (m *hookMeter) ChargeTransit([]byte, string, int64) bool { return true }

func TestDescriptorNamesItsOriginServerAndSignatureCoversIt(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, f.data, nil)
	o := f.s.objects[string(f.id)]
	if o.Descriptor.OriginServer != "test" {
		t.Fatalf("origin_server = %q", o.Descriptor.OriginServer)
	}
	d := o.Descriptor
	d.Boxes = []Box{{Recipient: f.peer.ID, Box: []byte("x")}}
	d.OriginServer = "https://other.example"
	msg, _ := wire.Enc.Marshal(d)
	sig := ed25519.Sign(f.owner.Priv, append([]byte(domain), msg...))
	if code := testutil.Do(t, "POST", f.url("commit"), f.tOwner, CommitRequest{Boxes: d.Boxes, SigningKey: f.owner.Pub, Signature: sig}, nil); code != 400 {
		t.Fatalf("signature over a different origin_server = %d, want 400", code)
	}
	if code := f.commit(t); code != 204 {
		t.Fatalf("commit = %d", code)
	}
	var got GetResponse
	testutil.Do(t, "GET", f.url(), f.tPeer, nil, &got)
	if got.Descriptor.OriginServer != "test" {
		t.Fatalf("served origin_server = %q", got.Descriptor.OriginServer)
	}
}

func TestInfoOnlyForTheOwnerOfACommittedLiveObject(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	if _, ok := f.s.Info(f.id, f.owner.ID); ok {
		t.Fatal("uncommitted object has info")
	}
	testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, f.data, nil)
	if f.commit(t) != 204 {
		t.Fatal("commit")
	}
	info, ok := f.s.Info(f.id, f.owner.ID)
	if !ok || info.Bytes != 1000 || len(info.Recipients) != 1 || info.ExpiresAt == 0 {
		t.Fatalf("info = %+v %v", info, ok)
	}
	if _, ok := f.s.Info(f.id, f.peer.ID); ok {
		t.Fatal("the recipient must not pass as the owner")
	}
	if _, ok := f.s.Info([]byte("nope"), f.owner.ID); ok {
		t.Fatal("unknown id")
	}
}

// A box is bounded by the object's own parts, so the descriptor cannot be used to move payload for free.
func TestABoxLargerThanTheObjectCanNeedIsRefused(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, f.data, nil)
	f.s.mu.Lock()
	o := f.s.objects[string(f.id)]
	f.s.mu.Unlock()
	o.mu.Lock()
	d := o.Descriptor
	o.mu.Unlock()
	d.Boxes = []Box{{Recipient: f.peer.ID, Box: make([]byte, maxBoxBytes(len(d.Parts))+1)}}
	msg, _ := wire.Enc.Marshal(d)
	sig := ed25519.Sign(f.owner.Priv, append([]byte(domain), msg...))
	if code := testutil.Do(t, "POST", f.url("commit"), f.tOwner, CommitRequest{Boxes: d.Boxes, SigningKey: f.owner.Pub, Signature: sig}, nil); code != 400 {
		t.Fatalf("oversized box = %d", code)
	}
}

// An account's keys share one queue allowance; unrelated keys do not.
func TestKeysOfOneAccountShareTheQueueAllowance(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	second := testutil.NewDevice()
	tSecond := testutil.Login(t, f.srv.URL, second)
	req := CreateRequest{Recipients: [][]byte{f.peer.ID}, Parts: []Part{f.part}}
	f.s.OwnerMaxBytes = func([]byte) int64 { return 6000 } // room for one object and its overhead, not two
	if code := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", tSecond, req, nil); code != 200 {
		t.Fatalf("an unrelated key shares nobody's queue: %d", code)
	}
	f.s.SetOwnerKey(func(owner []byte) string {
		if string(owner) == string(f.owner.ID) || string(owner) == string(second.ID) {
			return "a:one"
		}
		return "d:" + string(owner)
	})
	third := testutil.NewDevice()
	tThird := testutil.Login(t, f.srv.URL, third)
	if code := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", tThird, req, nil); code != 200 {
		t.Fatalf("a key of nobody: %d", code)
	}
	// The second key of the account has already used the allowance with its first object: the same account's
	// next one is refused, whichever of its keys asks.
	if code := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", tSecond, req, nil); code != 507 {
		t.Fatalf("second object of the account = %d", code)
	}
	if code := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", f.tOwner, req, nil); code != 507 {
		t.Fatalf("the account's other key = %d", code)
	}
}

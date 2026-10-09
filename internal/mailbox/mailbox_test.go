package mailbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"net/http"
	"net/http/httptest"
)

func rnd(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func item(store *Store, sender, dest []byte) Item {
	return Item{DeliveryID: rnd(16), Origin: "https://a.example", Sender: sender, Dest: dest,
		ExpiresAt: uint64(store.Now().Add(time.Hour).UnixMilli()), Kind: "contact_offer", Envelope: []byte("sealed")}
}

func open(t *testing.T) *Store {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutIsIdempotentAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	sender, dest := rnd(32), rnd(32)
	it := item(s, sender, dest)
	if isNew, err := s.Put(it); !isNew || err != nil {
		t.Fatalf("first put = %v %v", isNew, err)
	}
	if isNew, err := s.Put(it); isNew || err != nil {
		t.Fatalf("duplicate put = %v %v", isNew, err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l := again.List(dest); len(l) != 1 || !bytes.Equal(l[0].DeliveryID, it.DeliveryID) {
		t.Fatalf("after restart: %+v", l)
	}
	if isNew, _ := again.Put(it); isNew {
		t.Fatal("duplicate accepted after restart")
	}
}

func TestAckedItemStaysAsDuplicateRecordUntilExpiry(t *testing.T) {
	s := open(t)
	now := time.Now()
	s.Now = func() time.Time { return now }
	sender, dest := rnd(32), rnd(32)
	it := item(s, sender, dest)
	s.Put(it)
	if !s.Ack(dest, ID(sender, dest, it.DeliveryID)) {
		t.Fatal("ack refused")
	}
	if len(s.List(dest)) != 0 {
		t.Fatal("acked item still listed")
	}
	if isNew, _ := s.Put(it); isNew {
		t.Fatal("late retry of an acked delivery became a new item")
	}
	now = now.Add(2 * time.Hour)
	if isNew, err := s.Put(Item{DeliveryID: it.DeliveryID, Origin: it.Origin, Sender: sender, Dest: dest,
		ExpiresAt: uint64(now.Add(time.Hour).UnixMilli()), Kind: "x", Envelope: []byte("y")}); !isNew || err != nil {
		t.Fatalf("after expiry the id is free again: %v %v", isNew, err)
	}
}

func TestLifetimeIsCappedAndExpiredRefused(t *testing.T) {
	s := open(t)
	it := item(s, rnd(32), rnd(32))
	it.ExpiresAt = uint64(s.Now().Add(30 * 24 * time.Hour).UnixMilli())
	s.Put(it)
	l := s.List(it.Dest)
	if len(l) != 1 || l[0].ExpiresAt > uint64(s.Now().Add(MaxLifetime+time.Minute).UnixMilli()) {
		t.Fatalf("lifetime not capped: %+v", l)
	}
	old := item(s, rnd(32), rnd(32))
	old.ExpiresAt = uint64(s.Now().Add(-time.Second).UnixMilli())
	if _, err := s.Put(old); err != ErrExpired {
		t.Fatalf("expired put = %v", err)
	}
}

func TestLimitsPerSenderDeviceAndTotal(t *testing.T) {
	s := open(t)
	s.MaxPerSender, s.MaxPerDevice = 3, 5
	dest := rnd(32)
	a, b := rnd(32), rnd(32)
	for i := 0; i < 3; i++ {
		if _, err := s.Put(item(s, a, dest)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Put(item(s, a, dest)); err != ErrFull {
		t.Fatalf("4th from one sender = %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Put(item(s, b, dest)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Put(item(s, rnd(32), dest)); err != ErrFull {
		t.Fatalf("device cap = %v", err)
	}
	big := item(s, rnd(32), rnd(32))
	big.Envelope = make([]byte, MaxEnvelope+1)
	if _, err := s.Put(big); err != ErrTooBig {
		t.Fatalf("oversize = %v", err)
	}
}

func TestExpiryReleasesTheBudget(t *testing.T) {
	s := open(t)
	now := time.Now()
	s.Now = func() time.Time { return now }
	dest := rnd(32)
	s.Put(item(s, rnd(32), dest))
	if s.Held() == 0 {
		t.Fatal("nothing charged")
	}
	now = now.Add(2 * time.Hour)
	s.GC()
	if s.Held() != 0 || len(s.List(dest)) != 0 {
		t.Fatalf("held %d after expiry", s.Held())
	}
}

func TestHTTPListAndAckOnlyForTheAddressee(t *testing.T) {
	a := auth.New("test")
	s := open(t)
	api := &API{Auth: a, Store: s}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("GET /v1/mailbox", api.HandleList)
	mux.HandleFunc("POST /v1/mailbox/{id}/ack", api.HandleAck)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	me, other := testutil.NewDevice(), testutil.NewDevice()
	tMe, tOther := testutil.Login(t, srv.URL, me), testutil.Login(t, srv.URL, other)
	it := item(s, rnd(32), me.ID)
	s.Put(it)
	var mine, theirs []Entry
	testutil.Do(t, "GET", srv.URL+"/v1/mailbox", tMe, nil, &mine)
	testutil.Do(t, "GET", srv.URL+"/v1/mailbox", tOther, nil, &theirs)
	if len(mine) != 1 || len(theirs) != 0 {
		t.Fatalf("mine=%d theirs=%d", len(mine), len(theirs))
	}
	url := srv.URL + "/v1/mailbox/" + b64.EncodeToString(mine[0].ItemID) + "/ack"
	if code := testutil.Do(t, "POST", url, tOther, nil, nil); code != 404 {
		t.Fatalf("stranger ack = %d", code)
	}
	if code := testutil.Do(t, "POST", url, tMe, nil, nil); code != 204 {
		t.Fatalf("ack = %d", code)
	}
	testutil.Do(t, "GET", srv.URL+"/v1/mailbox", tMe, nil, &mine)
	if len(mine) != 0 {
		t.Fatal("acked item listed")
	}
}

func TestFederationSinkStoresAndMapsRefusals(t *testing.T) {
	s, _ := Open(t.TempDir())
	sink := s.Sink()
	req := federation.Request{DeliveryID: make([]byte, 16), Origin: "o", Sender: make([]byte, 32), Destination: bytes.Repeat([]byte{9}, 32),
		ExpiresAt: uint64(time.Now().Add(time.Hour).UnixMilli()), Kind: "spool-hint", Envelope: []byte("x")}
	if err := sink.Receive(context.Background(), federation.Peer{}, req); err != nil {
		t.Fatal(err)
	}
	if got := s.List(req.Destination); len(got) != 1 || got[0].Origin != "o" {
		t.Fatalf("stored %+v", got)
	}
	if err := sink.Receive(context.Background(), federation.Peer{}, req); err != nil || len(s.List(req.Destination)) != 1 {
		t.Fatal("duplicate must be accepted and not stored twice")
	}
	req.DeliveryID = bytes.Repeat([]byte{1}, 16)
	req.Envelope = make([]byte, MaxEnvelope+1)
	var fe *federation.Error
	if err := sink.Receive(context.Background(), federation.Peer{}, req); !errors.As(err, &fe) || fe.Code != "LIMIT_EXCEEDED" {
		t.Fatalf("want LIMIT_EXCEEDED, got %v", err)
	}
}

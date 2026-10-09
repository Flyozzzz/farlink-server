package accounts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

type dev struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	enc  []byte
}

func newDev() dev {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	enc := make([]byte, 32)
	rand.Read(enc)
	return dev{pub, priv, enc}
}

func (d dev) id() []byte { h := sha256.Sum256(d.pub); return h[:] }

func (d dev) entry(name string) Device {
	return Device{DeviceID: d.id(), SigningKey: d.pub, EncryptionKey: d.enc, Name: name, AddedAt: 1}
}

func sortDevices(ds []Device) {
	sort.Slice(ds, func(i, j int) bool { return bytes.Compare(ds[i].DeviceID, ds[j].DeviceID) < 0 })
}

func sortIDs(ids [][]byte) {
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i], ids[j]) < 0 })
}

// sign makes the envelope exactly as a client would: [signed bytes, signature].
func sign(t *testing.T, s State, by dev) []byte {
	t.Helper()
	sortDevices(s.Devices)
	sortIDs(s.Revoked)
	if s.Revoked == nil {
		s.Revoked = [][]byte{}
	}
	if s.ContactMailboxes == nil {
		s.ContactMailboxes = []string{}
	}
	b, err := wire.Enc.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(by.priv, append([]byte(Domain), b...))
	env, err := wire.Enc.Marshal([][]byte{b, sig})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func genesis(t *testing.T, first, rk dev) (State, []byte) {
	t.Helper()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	h := sha256.New()
	h.Write([]byte("farlink/account-id/v1"))
	h.Write(first.pub)
	h.Write(rk.pub)
	h.Write(nonce)
	s := State{Protocol: 1, AccountID: h.Sum(nil), Number: 0, PrevHash: make([]byte, 32), Nickname: "Denis",
		Devices: []Device{first.entry("Mac")}, RecoverySign: rk.pub, RecoveryEnc: make([]byte, 32), Revoked: [][]byte{},
		Signer: first.id(), CreatedAt: 1, GenesisNonce: nonce}
	return s, sign(t, s, first)
}

func next(prev State, prevRaw []byte, by dev) State {
	n := prev
	n.Number++
	h := sha256.Sum256(prevRaw)
	n.PrevHash = h[:]
	n.Signer = by.id()
	n.GenesisNonce = nil
	n.Devices = append([]Device(nil), prev.Devices...)
	n.Revoked = append([][]byte(nil), prev.Revoked...)
	return n
}

func TestChainRulesAndRegistry(t *testing.T) {
	dir := t.TempDir()
	reg, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, rk, phone := newDev(), newDev(), newDev()
	g, graw := genesis(t, first, rk)
	if _, _, err := reg.Submit(graw); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	// Sending it again is harmless.
	if _, _, err := reg.Submit(graw); err != nil {
		t.Fatalf("repeat: %v", err)
	}

	// A device adds another.
	s1 := next(g, graw, first)
	s1.Devices = append(s1.Devices, phone.entry("iPhone"))
	raw1 := sign(t, s1, first)
	if n, _, err := reg.Submit(raw1); err != nil || n != 1 {
		t.Fatalf("add: %d %v", n, err)
	}
	if id, ok := reg.AccountOf(phone.id()); !ok || !bytes.Equal(id, g.AccountID) {
		t.Fatal("device not indexed")
	}

	// A stranger's signature is refused.
	s2 := next(s1, raw1, newDev())
	if _, _, err := reg.Submit(sign(t, s2, newDev())); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("stranger: %v", err)
	}

	// A different link for number 1 is a fork.
	alt := next(g, graw, first)
	alt.Nickname = "Other"
	if _, _, err := reg.Submit(sign(t, alt, first)); !errors.Is(err, ErrFork) {
		t.Fatalf("fork: %v", err)
	}

	// Only recovery can unfreeze the fork while revoking the phone.
	s2 = next(s1, raw1, rk)
	s2.Devices = []Device{first.entry("Mac")}
	s2.Revoked = [][]byte{phone.id()}
	raw2 := sign(t, s2, rk)
	if _, _, err := reg.Submit(raw2); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := reg.AccountOf(phone.id()); ok {
		t.Fatal("revoked device still indexed")
	}

	// The dead key cannot be enrolled in another account either.
	other := newDev()
	g2, graw2 := genesis(t, phone, other)
	_ = g2
	if _, _, err := reg.Submit(graw2); !errors.Is(err, ErrDeviceTaken) {
		t.Fatalf("dead key: %v", err)
	}

	// An active device cannot be taken by a second account.
	g3, graw3 := genesis(t, first, newDev())
	_ = g3
	if _, _, err := reg.Submit(graw3); !errors.Is(err, ErrDeviceTaken) {
		t.Fatalf("second account: %v", err)
	}

	// The last device cannot go, and the limit is enforced.
	s3 := next(s2, raw2, first)
	s3.Devices = nil
	s3.Revoked = append(s3.Revoked, first.id())
	if _, _, err := reg.Submit(sign(t, s3, first)); !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrLastDevice) {
		t.Fatalf("last device: %v", err)
	}
	s4 := next(s2, raw2, first)
	for i := 0; i < MaxDevices; i++ {
		s4.Devices = append(s4.Devices, newDev().entry("x"))
	}
	if _, _, err := reg.Submit(sign(t, s4, first)); err == nil {
		t.Fatal("more than 15 devices accepted")
	}

	// The recovery key replaces everything.
	fresh := newDev()
	s5 := next(s2, raw2, rk)
	s5.Revoked = append(s5.Revoked, first.id())
	s5.Devices = []Device{fresh.entry("New Mac")}
	raw5 := sign(t, s5, rk)
	if _, _, err := reg.Submit(raw5); err != nil {
		t.Fatalf("recovery: %v", err)
	}

	// Everything survives a restart, including who is dead.
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := again.AccountOf(fresh.id()); !ok || !bytes.Equal(id, g.AccountID) {
		t.Fatal("index lost on restart")
	}
	if _, ok := again.AccountOf(first.id()); ok {
		t.Fatal("revoked device back after restart")
	}
	if _, _, err := again.Submit(graw3); !errors.Is(err, ErrDeviceTaken) {
		t.Fatalf("dead key after restart: %v", err)
	}
	links, ok := again.Chain(g.AccountID)
	if !ok || len(links) != 4 {
		t.Fatalf("chain = %d links", len(links))
	}
}

func TestHTTPAndRateLimit(t *testing.T) {
	reg, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	api := &API{Reg: reg, Now: func() time.Time { return now }}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/accounts", api.HandleCreate)
	mux.HandleFunc("POST /v1/accounts/{id}/links", api.HandleLink)
	mux.HandleFunc("GET /v1/accounts/{id}", api.HandleGet)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	first, rk := newDev(), newDev()
	g, graw := genesis(t, first, rk)
	post := func(path string, body []byte) int {
		resp, err := http.Post(srv.URL+path, "application/cbor", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post("/v1/accounts", graw); c != 200 {
		t.Fatalf("create = %d", c)
	}
	if c := post("/v1/accounts", []byte("junk")); c != 400 {
		t.Fatalf("junk = %d", c)
	}
	if c := post("/v1/accounts", append(bytes.Repeat([]byte{0}, MaxLinkBytes), 1)); c != 413 {
		t.Fatalf("oversized = %d", c)
	}
	id := base64Raw(g.AccountID)
	resp, err := http.Get(srv.URL + "/v1/accounts/" + id)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("get: %v %v", resp, err)
	}
	resp.Body.Close()
	if r, _ := http.Get(srv.URL + "/v1/accounts/" + base64Raw(make([]byte, 32))); r.StatusCode != 404 {
		t.Fatalf("unknown = %d", r.StatusCode)
	}
	limited := false
	for i := 0; i < SubmitsPerMin+2; i++ {
		if post("/v1/accounts", []byte("x")) == 429 {
			limited = true
		}
	}
	if !limited {
		t.Fatal("no rate limit")
	}
}

func base64Raw(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestContactMailboxesAreBoundedAndOrdered(t *testing.T) {
	first, rk := newDev(), newDev()
	g, raw := genesis(t, first, rk)
	reg, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.Submit(raw); err != nil {
		t.Fatal(err)
	}
	gl, _ := ParseLink(raw)
	next := func(boxes []string) error {
		s := g
		s.Number, s.PrevHash, s.GenesisNonce, s.ContactMailboxes = 1, gl.Hash(), nil, boxes
		_, _, err := reg.Submit(sign(t, s, first))
		return err
	}
	for _, bad := range [][]string{{"a", "b", "c"}, {"a", "a"}, {""}} {
		if err := next(bad); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%v: %v", bad, err)
		}
	}
	if err := next([]string{"https://us.farlink.pro:8443", "https://ru1.farlink.pro:8443"}); err != nil {
		t.Fatal(err)
	}
	head, _ := reg.Head(g.AccountID)
	if len(head.ContactMailboxes) != 2 || head.ContactMailboxes[0] != "https://us.farlink.pro:8443" {
		t.Fatalf("head = %+v", head.ContactMailboxes)
	}
}

func TestSuffixIsBoundedAndHeadRefNamesTheNewest(t *testing.T) {
	first, rk := newDev(), newDev()
	g, raw := genesis(t, first, rk)
	reg, _ := Open(t.TempDir())
	reg.Submit(raw)
	prev, _ := ParseLink(raw)
	for i := 1; i <= 20; i++ {
		s := g
		s.Number, s.PrevHash, s.GenesisNonce, s.Nickname = uint64(i), prev.Hash(), nil, "n"+string(rune('a'+i))
		env := sign(t, s, first)
		if _, _, err := reg.Submit(env); err != nil {
			t.Fatal(err)
		}
		prev, _ = ParseLink(env)
	}
	n, h, ok := reg.HeadRef(g.AccountID)
	if !ok || n != 20 || !bytes.Equal(h, prev.Hash()) {
		t.Fatalf("head ref %d %x", n, h)
	}
	links, _ := reg.Suffix(g.AccountID, 0)
	if len(links) != MaxSuffixLinks {
		t.Fatalf("page = %d", len(links))
	}
	rest, _ := reg.Suffix(g.AccountID, uint64(MaxSuffixLinks))
	if len(rest) != 20-MaxSuffixLinks {
		t.Fatalf("rest = %d", len(rest))
	}
	if none, ok := reg.Suffix(g.AccountID, 20); !ok || len(none) != 0 {
		t.Fatalf("current caller gets nothing: %d %v", len(none), ok)
	}
	// Over HTTP: ?after=N
	api := &API{Reg: reg}
	req := httptest.NewRequest("GET", "/v1/accounts/x?after=18", nil)
	req.SetPathValue("id", base64.RawURLEncoding.EncodeToString(g.AccountID))
	rec := httptest.NewRecorder()
	api.HandleGet(rec, req)
	var got [][]byte
	if rec.Code != 200 || wire.Lenient(rec.Body.Bytes(), &got) != nil || len(got) != 2 {
		t.Fatalf("http: %d %d", rec.Code, len(got))
	}
}

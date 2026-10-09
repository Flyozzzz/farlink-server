package billing

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/appstore/storetest"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

const authority = "https://us.farlink.test:8443"

type identityRig struct {
	srv      *httptest.Server
	svc      *Identity
	registry *accounts.Registry
	now      time.Time
}

func newIdentityRig(t *testing.T, dir string, on bool) *identityRig {
	t.Helper()
	registry, err := accounts.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := accounts.OpenResolver(registry, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := auth.New("test")
	rig := &identityRig{registry: registry, now: time.Now()}
	rig.svc = &Identity{Auth: a, Accounts: resolver, Self: authority, Now: func() time.Time { return rig.now }}
	if on {
		b, err := OpenBindings(dir)
		if err != nil {
			t.Fatal(err)
		}
		rig.svc.Bindings = b
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("POST /v2/billing/identities/bind", rig.svc.HandleBind)
	mux.HandleFunc("GET /v2/billing/identities/me", rig.svc.HandleLookup)
	rig.srv = httptest.NewServer(mux)
	t.Cleanup(rig.srv.Close)
	return rig
}

func makeBind(account *testutil.Account, signer, transport testutil.Device, id byte, now time.Time) BindBody {
	return BindBody{Protocol: 1, AccountID: account.State.AccountID, AccountDevice: signer.ID, Transport: transport.ID,
		RequestID: bytes.Repeat([]byte{id}, 16), ExpiresAt: uint64(now.Add(5 * time.Minute).UnixMilli()), Audience: authority}
}

func (r *identityRig) bind(t *testing.T, token string, req BindRequest) int {
	t.Helper()
	return testutil.Do(t, "POST", r.srv.URL+"/v2/billing/identities/bind", token, req, nil)
}

func (r *identityRig) lookup(t *testing.T, token string) BindResponse {
	t.Helper()
	var out BindResponse
	if code := testutil.Do(t, "GET", r.srv.URL+"/v2/billing/identities/me", token, nil, &out); code != 200 {
		t.Fatalf("lookup = %d", code)
	}
	return out
}

func TestAnActiveAccountDeviceBindsItsTransportKey(t *testing.T) {
	rig := newIdentityRig(t, t.TempDir(), true)
	phone, mac := testutil.NewDevice(), testutil.NewDevice()
	account := testutil.NewAccount(t, []testutil.Device{phone, mac})
	account.Publish(t, rig.registry)
	// A shared network signs in with its own key, not the account device's.
	network := testutil.NewDevice()
	tok := testutil.Login(t, rig.srv.URL, network)
	if rig.lookup(t, tok).Bound {
		t.Fatal("bound before anything was proved")
	}
	req := SignBind(mac.Priv, makeBind(account, mac, network, 1, rig.now))
	if code := rig.bind(t, tok, req); code != 200 {
		t.Fatalf("bind = %d", code)
	}
	if got := rig.lookup(t, tok); !got.Bound || !bytes.Equal(got.AccountID, account.State.AccountID) {
		t.Fatalf("lookup = %+v", got)
	}
	// The same request again answers the same way and changes nothing.
	if code := rig.bind(t, tok, req); code != 200 {
		t.Fatalf("repeat = %d", code)
	}
}

func TestBindingRefusesForgeriesAndStaleSigners(t *testing.T) {
	rig := newIdentityRig(t, t.TempDir(), true)
	phone, mac, stranger := testutil.NewDevice(), testutil.NewDevice(), testutil.NewDevice()
	account := testutil.NewAccount(t, []testutil.Device{phone, mac})
	account.Publish(t, rig.registry)
	transport := testutil.NewDevice()
	tok := testutil.Login(t, rig.srv.URL, transport)

	// Signed by a key that is not a device of the account.
	if code := rig.bind(t, tok, SignBind(stranger.Priv, makeBind(account, stranger, transport, 1, rig.now))); code != 403 {
		t.Errorf("stranger = %d", code)
	}
	// An account device named, but signed by another key.
	if code := rig.bind(t, tok, SignBind(stranger.Priv, makeBind(account, mac, transport, 2, rig.now))); code != 403 {
		t.Errorf("forged signature = %d", code)
	}
	// Somebody else's transport key: the session is not the key being bound.
	other := testutil.NewDevice()
	if code := rig.bind(t, tok, SignBind(mac.Priv, makeBind(account, mac, other, 3, rig.now))); code != 403 {
		t.Errorf("another transport = %d", code)
	}
	// An account the server does not know.
	ghost := testutil.NewAccount(t, []testutil.Device{stranger})
	if code := rig.bind(t, tok, SignBind(stranger.Priv, makeBind(ghost, stranger, transport, 4, rig.now))); code != 403 {
		t.Errorf("unknown account = %d", code)
	}
	// Wrong audience, and a request that has already expired.
	wrong := makeBind(account, mac, transport, 5, rig.now)
	wrong.Audience = "https://ru1.farlink.test:8443"
	if code := rig.bind(t, tok, SignBind(mac.Priv, wrong)); code != 403 {
		t.Errorf("audience = %d", code)
	}
	old := makeBind(account, mac, transport, 6, rig.now)
	old.ExpiresAt = uint64(rig.now.Add(-time.Minute).UnixMilli())
	if code := rig.bind(t, tok, SignBind(mac.Priv, old)); code != 400 {
		t.Errorf("expired = %d", code)
	}
	far := makeBind(account, mac, transport, 7, rig.now)
	far.ExpiresAt = uint64(rig.now.Add(time.Hour).UnixMilli())
	if code := rig.bind(t, tok, SignBind(mac.Priv, far)); code != 400 {
		t.Errorf("a request valid for an hour = %d", code)
	}
	if rig.lookup(t, tok).Bound {
		t.Fatal("a refused request bound the key")
	}

	// A device the account has since revoked cannot sign any more.
	account.Update(t, mac, func(s *accounts.State) {
		s.Devices = slices.DeleteFunc(s.Devices, func(d accounts.Device) bool { return bytes.Equal(d.DeviceID, phone.ID) })
		s.Revoked = append(s.Revoked, phone.ID)
	})
	account.Publish(t, rig.registry)
	if code := rig.bind(t, tok, SignBind(phone.Priv, makeBind(account, phone, transport, 8, rig.now))); code != 403 {
		t.Errorf("revoked device = %d", code)
	}
	if code := rig.bind(t, tok, SignBind(mac.Priv, makeBind(account, mac, transport, 9, rig.now))); code != 200 {
		t.Errorf("the device that is still active = %d", code)
	}
}

func TestATransportKeyNeverMovesToAnotherAccount(t *testing.T) {
	rig := newIdentityRig(t, t.TempDir(), true)
	first, second := testutil.NewDevice(), testutil.NewDevice()
	one := testutil.NewAccount(t, []testutil.Device{first})
	two := testutil.NewAccount(t, []testutil.Device{second})
	one.Publish(t, rig.registry)
	two.Publish(t, rig.registry)
	transport := testutil.NewDevice()
	tok := testutil.Login(t, rig.srv.URL, transport)
	if code := rig.bind(t, tok, SignBind(first.Priv, makeBind(one, first, transport, 1, rig.now))); code != 200 {
		t.Fatalf("first bind = %d", code)
	}
	if code := rig.bind(t, tok, SignBind(second.Priv, makeBind(two, second, transport, 2, rig.now))); code != 409 {
		t.Fatalf("a second account took the key: %d", code)
	}
	if got := rig.lookup(t, tok); !bytes.Equal(got.AccountID, one.State.AccountID) {
		t.Fatalf("the key moved: %+v", got)
	}
}

func TestBindingsSurviveARestartAndFeatureOffAnswers404(t *testing.T) {
	dir := t.TempDir()
	rig := newIdentityRig(t, dir, true)
	device := testutil.NewDevice()
	account := testutil.NewAccount(t, []testutil.Device{device})
	account.Publish(t, rig.registry)
	transport := testutil.NewDevice()
	tok := testutil.Login(t, rig.srv.URL, transport)
	if code := rig.bind(t, tok, SignBind(device.Priv, makeBind(account, device, transport, 1, rig.now))); code != 200 {
		t.Fatalf("bind = %d", code)
	}
	reopened, err := OpenBindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reopened.Lookup(transport.ID); !ok || !bytes.Equal(got, account.State.AccountID) {
		t.Fatalf("lost across a restart: %x %v", got, ok)
	}

	off := newIdentityRig(t, t.TempDir(), false)
	tok = testutil.Login(t, off.srv.URL, transport)
	if code := off.bind(t, tok, SignBind(device.Priv, makeBind(account, device, transport, 1, off.now))); code != 404 {
		t.Fatalf("off: bind = %d", code)
	}
	if code := testutil.Do(t, "GET", off.srv.URL+"/v2/billing/identities/me", tok, nil, nil); code != 404 {
		t.Fatalf("off: lookup = %d", code)
	}
	if code := testutil.Do(t, "GET", off.srv.URL+"/v2/billing/identities/me", "", nil, nil); code != 401 {
		t.Fatalf("anonymous = %d", code)
	}
}

func TestOneAccountCannotBindWithoutLimit(t *testing.T) {
	dir := t.TempDir()
	b, err := OpenBindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	account := bytes.Repeat([]byte{7}, 32)
	for i := 0; i < MaxTransportsPerAccount; i++ {
		req := BindRequest{BindBody: BindBody{Protocol: 1, AccountID: account, Transport: bytes.Repeat([]byte{byte(i), byte(i >> 8)}, 16), RequestID: bytes.Repeat([]byte{1}, 16)}}
		if err := b.Bind(req); err != nil {
			t.Fatalf("bind %d: %v", i, err)
		}
	}
	over := BindRequest{BindBody: BindBody{Protocol: 1, AccountID: account, Transport: bytes.Repeat([]byte{0xff}, 32), RequestID: bytes.Repeat([]byte{1}, 16)}}
	if err := b.Bind(over); err != ErrBindFull {
		t.Fatalf("over the cap: %v", err)
	}
	// Another account is unaffected.
	over.AccountID = bytes.Repeat([]byte{8}, 32)
	if err := b.Bind(over); err != nil {
		t.Fatalf("other account: %v", err)
	}
}

func TestDevicesOfOneAccountShareTheFreeAllowance(t *testing.T) {
	s := newStore(t, storetest.New(storetest.Options{}), false, "")
	bindings, err := OpenBindings(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.AccountOf = bindings.Lookup
	account, other := bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	for _, d := range []struct {
		device  byte
		account []byte
	}{{1, account}, {2, account}, {3, other}} {
		if err := bindings.Bind(BindRequest{BindBody: BindBody{Protocol: 1, AccountID: d.account, Transport: dev(d.device), RequestID: bytes.Repeat([]byte{d.device}, 16)}}); err != nil {
			t.Fatal(err)
		}
	}
	l := NewLedger(s.Buckets)
	// Free is 100 bytes in these tests: 60 from one device and 40 from the other use it up together.
	if !l.Charge(dev(1), 60) || !l.Charge(dev(2), 40) {
		t.Fatal("charges inside the allowance refused")
	}
	if l.Admit(dev(1)) || l.Admit(dev(2)) {
		t.Fatal("a second device of the account still has a fresh allowance")
	}
	if !l.Admit(dev(3)) {
		t.Fatal("another account lost its allowance")
	}
	// A key that is not bound to any account keeps a bucket of its own, until accounts are required.
	if !l.Admit(dev(9)) {
		t.Fatal("an unbound key has no allowance")
	}
	s.RequireAccount = true
	if l.Admit(dev(9)) || l.Charge(dev(9), 1) || l.SpoolLimit(dev(9)) != 0 || !l.Exhausted(dev(9)) {
		t.Fatal("a fresh unbound key still gets a free allowance once accounts are required")
	}
	if !l.Admit(dev(3)) {
		t.Fatal("requiring accounts took a bound key's allowance")
	}
	s.RequireAccount = false
	if got := l.Balance(dev(2)); got.Used != 100 || got.Limit != 100 {
		t.Fatalf("balance of the second device = %+v", got)
	}
}

func TestTheDefaultsAreGiBPerAccount(t *testing.T) {
	d := DefaultLimits()
	if d.FreeRelay != 10*1024*1024*1024 || d.RelayRelay != 200*1024*1024*1024 {
		t.Fatalf("defaults = %d / %d", d.FreeRelay, d.RelayRelay)
	}
}

func TestTheBindingsLogIsAppendOnlyAndSurvivesATornTail(t *testing.T) {
	dir := t.TempDir()
	b, err := OpenBindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	account, transport := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32)
	req := BindRequest{BindBody: BindBody{Protocol: 1, AccountID: account, Transport: transport, RequestID: bytes.Repeat([]byte{1}, 16)}}
	if err := b.Bind(req); err != nil {
		t.Fatal(err)
	}
	size := func() int64 {
		st, err := os.Stat(filepath.Join(dir, "billing-bindings.log"))
		if err != nil {
			t.Fatal(err)
		}
		return st.Size()
	}
	before := size()
	// Binding it again, with another request ID, is an answer, not a write.
	req.RequestID = bytes.Repeat([]byte{2}, 16)
	if err := b.Bind(req); err != nil || size() != before {
		t.Fatalf("rebind: %v, log %d -> %d", err, before, size())
	}
	// A returned account ID is a copy.
	got, _ := b.Lookup(transport)
	got[0] ^= 0xff
	if again, _ := b.Lookup(transport); !bytes.Equal(again, account) {
		t.Fatal("Lookup handed out the table's own bytes")
	}
	b.Close()
	// A crash in the middle of appending the next row leaves a stub that was never acknowledged.
	f, err := os.OpenFile(filepath.Join(dir, "billing-bindings.log"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(bytes.Repeat([]byte{9}, 40))
	f.Close()
	reopened, err := OpenBindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if a, ok := reopened.Lookup(transport); !ok || !bytes.Equal(a, account) {
		t.Fatal("the acknowledged row was lost")
	}
	if _, ok := reopened.Lookup(bytes.Repeat([]byte{9}, 32)); ok {
		t.Fatal("a torn row became a binding")
	}
	if size() != before {
		t.Fatalf("the stub was not cut off: %d bytes, want %d", size(), before)
	}
	// The log must be readable by the next process too, and appendable.
	other := BindRequest{BindBody: BindBody{Protocol: 1, AccountID: account, Transport: bytes.Repeat([]byte{6}, 32), RequestID: bytes.Repeat([]byte{3}, 16)}}
	if err := reopened.Bind(other); err != nil {
		t.Fatal(err)
	}
	if size() != before+bindingRow {
		t.Fatalf("log size %d, want %d", size(), before+bindingRow)
	}
}

func TestAnUnreadableBindingsFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "billing-bindings.log"), []byte("not a bindings log at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBindings(dir); err == nil {
		t.Fatal("a file with the wrong header was accepted")
	}
}

func TestARelaySubscriptionBelongsToTheAccountAndReplacesFree(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	s := newStore(t, ca, false, "")
	bindings, err := OpenBindings(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.AccountOf, s.RequireAccount = bindings.Lookup, true
	mine, other := bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32)
	for _, d := range []struct {
		device  byte
		account []byte
	}{{1, mine}, {2, mine}, {3, other}} {
		if err := bindings.Bind(BindRequest{BindBody: BindBody{Protocol: 1, AccountID: d.account, Transport: dev(d.device), RequestID: bytes.Repeat([]byte{d.device}, 16)}}); err != nil {
			t.Fatal(err)
		}
	}
	tx := ca.Sign(storetest.Subscription(bundle, relayM, "77"))
	// A key that is bound to nobody may not present a subscription at all.
	if res, _, err := s.Apply(dev(9), nil, nil, []string{tx}); err != nil || res[0].Code != "ACCOUNT_REQUIRED" {
		t.Fatalf("unbound key presented a subscription: %+v %v", res, err)
	}
	if res, _, err := s.Apply(dev(1), nil, nil, []string{tx}); err != nil || res[0].Code != "" {
		t.Fatalf("the account's device was refused: %+v %v", res, err)
	}
	// The other device of the account never presented it and still has it, as one pool replacing the free one.
	bs := s.Buckets(dev(2))
	if len(bs) != 1 || bs[0].Tier != KindRelay || bs[0].Limit != limits.RelayRelay || bs[0].Key != accountBucketPrefix+b64.EncodeToString(mine) {
		t.Fatalf("buckets of the second device = %+v", bs)
	}
	// Another account cannot take the same (copyable) receipt, and gets no pool from it.
	if res, _, _ := s.Apply(dev(3), nil, nil, []string{tx}); res[0].Code != "OWNED_BY_ANOTHER_ACCOUNT" {
		t.Fatalf("a second account claimed the subscription: %+v", res)
	}
	if bs := s.Buckets(dev(3)); len(bs) != 1 || bs[0].Tier != "" || bs[0].Key == bs[0].Key[:0] {
		t.Fatalf("buckets of the other account = %+v", bs)
	}
	if !NewLedger(s.Buckets).Paid(dev(2)) {
		t.Fatal("a paid account is not Paid")
	}
}

func TestOnNewBindingRunsOnlyForANewKey(t *testing.T) {
	rig := newIdentityRig(t, t.TempDir(), true)
	calls := 0
	rig.svc.OnNewBinding = func() { calls++ }
	device, transport := testutil.NewDevice(), testutil.NewDevice()
	account := testutil.NewAccount(t, []testutil.Device{device})
	account.Publish(t, rig.registry)
	tok := testutil.Login(t, rig.srv.URL, transport)
	for i := byte(1); i <= 3; i++ {
		if code := rig.bind(t, tok, SignBind(device.Priv, makeBind(account, device, transport, i, rig.now))); code != 200 {
			t.Fatalf("bind %d = %d", i, code)
		}
	}
	if calls != 1 {
		t.Fatalf("OnNewBinding ran %d times for one new key", calls)
	}
}

func TestRemovingAnAccountsBindingsKeepsTheOthersAndSurvivesAReopen(t *testing.T) {
	dir := t.TempDir()
	b, err := OpenBindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(transport, account byte) BindRequest {
		return BindRequest{BindBody: BindBody{Transport: bytes.Repeat([]byte{transport}, 32), AccountID: bytes.Repeat([]byte{account}, 32)}}
	}
	for _, r := range []BindRequest{mk(1, 10), mk(2, 10), mk(3, 11)} {
		if _, err := b.BindNew(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Remove(bytes.Repeat([]byte{10}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Lookup(bytes.Repeat([]byte{1}, 32)); ok {
		t.Fatal("a removed binding is still there")
	}
	if _, err := b.BindNew(mk(4, 11)); err != nil { // the file still takes new rows after the rewrite
		t.Fatal(err)
	}
	b.Close()
	again, err := OpenBindings(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if _, ok := again.Lookup(bytes.Repeat([]byte{3}, 32)); !ok {
		t.Fatal("another account's binding was lost")
	}
	if _, ok := again.Lookup(bytes.Repeat([]byte{4}, 32)); !ok {
		t.Fatal("a binding added after the rewrite was lost")
	}
	if _, ok := again.Lookup(bytes.Repeat([]byte{2}, 32)); ok {
		t.Fatal("a removed binding came back")
	}
}

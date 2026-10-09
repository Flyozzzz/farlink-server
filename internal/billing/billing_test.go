package billing

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/appstore"
	"github.com/Flyozzzz/farlink-server/internal/appstore/storetest"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

const (
	bundle   = "com.flyoz.farlink"
	relayM   = bundle + ".relay.monthly"
	relayMax = bundle + ".relaymax.monthly"
)

// Small limits so tests move a handful of bytes.
var limits = Limits{FreeRelay: 100, FreeSpool: 10, RelayRelay: 1000, RelayMaxRelay: 10000, RelaySpool: 50, TeamsPerPerson: 200, TeamsSpool: 60}

func newStore(t *testing.T, ca *storetest.CA, teams bool, path string) *Store {
	v := appstore.NewVerifier(bundle, "Production")
	v.Roots = [][32]byte{ca.Fingerprint()}
	s, err := NewStore(v, Catalog(bundle, teams), limits, path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func dev(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestFreeTierPerDevice(t *testing.T) {
	s := newStore(t, storetest.New(storetest.Options{}), false, "")
	l := NewLedger(s.Buckets)
	a, b := dev(1), dev(2)
	if !l.Charge(a, 100) || l.Admit(a) || !l.Admit(b) {
		t.Fatal("free allowance is 100 bytes per device")
	}
	if bal := l.Balance(a); bal.Tier != "free" || !bal.Exhausted || bal.Used != 100 || bal.Limit != 100 || bal.SpoolLimit != 10 {
		t.Fatalf("%+v", bal)
	}
}

// Admitted sessions finish into an overdraft of one more limit, and no further.
func TestOverdraftLetsTheCurrentFileFinish(t *testing.T) {
	s := newStore(t, storetest.New(storetest.Options{}), false, "")
	l := NewLedger(s.Buckets)
	a := dev(1)
	if !l.Admit(a) || !l.Charge(a, 90) || !l.Charge(a, 60) {
		t.Fatal("a transfer admitted with room left must not be cut at the limit")
	}
	if l.Admit(a) {
		t.Fatal("nothing new once the limit is passed")
	}
	if !l.Charge(a, 50) || l.Charge(a, 1) {
		t.Fatal("overdraft stops at twice the limit")
	}
}

func TestMonthRollsOver(t *testing.T) {
	s := newStore(t, storetest.New(storetest.Options{}), false, "")
	now := time.Date(2026, 9, 30, 23, 0, 0, 0, time.UTC)
	l := NewLedger(s.Buckets)
	l.Now = func() time.Time { return now }
	a := dev(1)
	l.Charge(a, 100)
	if bal := l.Balance(a); !bal.Exhausted || bal.ResetsAt != uint64(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).UnixMilli()) {
		t.Fatalf("%+v", bal)
	}
	now = now.Add(2 * time.Hour)
	if !l.Admit(a) || l.Balance(a).Used != 0 {
		t.Fatal("a new UTC month starts from zero")
	}
}

// A Relay subscription is one pool shared by every device that presents it; the free allowance stays behind it.
func TestRelaySubscriptionPooledAcrossItsDevices(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	s := newStore(t, ca, false, "")
	l := NewLedger(s.Buckets)
	jws := ca.Sign(storetest.Subscription(bundle, relayM, "500"))
	mac, phone, stranger := dev(1), dev(2), dev(3)
	for _, d := range [][]byte{mac, phone} {
		if res := apply(s, d, nil, []string{jws}); res[0].Code != "" || res[0].Kind != "relay" {
			t.Fatalf("%+v", res)
		}
	}
	if bal := l.Balance(mac); bal.Tier != "relay" || bal.Limit != 1000 || bal.SpoolLimit != 50 {
		t.Fatalf("%+v", bal)
	}
	l.Charge(mac, 700)
	l.Charge(phone, 300)
	if bal := l.Balance(phone); bal.Tier != "free" || bal.Used != 0 {
		t.Fatalf("pool used up: the free allowance comes next, got %+v", bal)
	}
	if l.Balance(stranger).Tier != "free" {
		t.Fatal("a device that never presented the subscription doesn't share it")
	}
}

// Relay Max is the same kind of pool with the large allowance; the standard one stays at its own size.
func TestRelayMaxHasTheLargeAllowance(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	s := newStore(t, ca, false, "")
	l := NewLedger(s.Buckets)
	std, big := dev(1), dev(2)
	if res := apply(s, std, nil, []string{ca.Sign(storetest.Subscription(bundle, relayM, "500"))}); res[0].Code != "" {
		t.Fatalf("%+v", res)
	}
	if res := apply(s, big, nil, []string{ca.Sign(storetest.Subscription(bundle, relayMax, "600"))}); res[0].Code != "" || res[0].Kind != "relay" {
		t.Fatalf("%+v", res)
	}
	if bal := l.Balance(std); bal.Tier != "relay" || bal.Limit != 1000 {
		t.Fatalf("standard Relay: %+v", bal)
	}
	if bal := l.Balance(big); bal.Tier != "relay" || bal.Limit != 10000 || bal.SpoolLimit != 50 {
		t.Fatalf("Relay Max: %+v", bal)
	}
}

func TestRejectedTransactionsGrantNothing(t *testing.T) {
	ca, other := storetest.New(storetest.Options{}), storetest.New(storetest.Options{})
	s := newStore(t, ca, false, "")
	expired := storetest.Subscription(bundle, relayM, "1")
	expired["expiresDate"] = storetest.Ms(time.Now().Add(-time.Hour))
	revoked := storetest.Subscription(bundle, relayM, "2")
	revoked["revocationDate"] = storetest.Ms(time.Now())
	res, _, err := s.Apply(dev(1), nil, nil, []string{
		other.Sign(storetest.Subscription(bundle, relayM, "3")),
		ca.Sign(storetest.Subscription("com.example.other", relayM, "4")),
		ca.Sign(expired), ca.Sign(revoked),
		ca.Sign(storetest.Subscription(bundle, bundle+".teams10.monthly", "5")), // Teams off on this server
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"SIGNATURE_INVALID", "WRONG_APP", "EXPIRED", "REVOKED", "UNKNOWN_PRODUCT"}
	for i, w := range want {
		if res[i].Code != w {
			t.Errorf("%d: %q, want %q", i, res[i].Code, w)
		}
	}
	if b := s.Buckets(dev(1)); len(b) != 1 || b[0].Tier != "" {
		t.Fatalf("%+v", b)
	}
}

// Teams: bound to one network by appAccountToken and by an admin of its verified chain; every member draws
// from seats × per-person, and gets Pro.
func TestTeamsPoolBoundToItsNetwork(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	s := newStore(t, ca, true, "")
	l := NewLedger(s.Buckets)
	n := newNet(t)
	member, outsider := n.add(t, false), testutil.NewDevice()
	other := newNet(t)
	jws := n.teams(ca, "700", 5)
	if res, _, _ := s.Apply(n.admin.ID, other.tag, other.links, []string{jws}); res[0].Code != "NETWORK_MISMATCH" {
		t.Fatalf("a license applied to another network: %+v", res)
	}
	if res, cr, _ := s.Apply(n.admin.ID, n.tag, n.links, []string{jws}); res[0].Code != "" || cr.Code != "" || cr.Epoch != 1 {
		t.Fatalf("%+v %+v", res, cr)
	}
	if _, cr, _ := s.Apply(member.ID, n.tag, n.links[len(n.links)-1:], nil); cr.Code != "" || !cr.Known {
		t.Fatalf("member presenting the head: %+v", cr)
	}
	s.Apply(outsider.ID, other.tag, other.links, nil)
	bal := l.Balance(member.ID)
	if bal.Tier != "teams" || bal.Limit != 5*200 || !bal.TeamsPro || bal.Seats != 5 || bal.SpoolLimit != 60 {
		t.Fatalf("%+v", bal)
	}
	l.Charge(n.admin.ID, 600)
	if l.Balance(member.ID).Used != 600 {
		t.Fatal("the pool is shared by the network")
	}
	if l.Balance(outsider.ID).TeamsPro {
		t.Fatal("another network doesn't get Pro")
	}
}

func TestNotificationRevokesAndPersists(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	path := filepath.Join(t.TempDir(), "entitlements.json")
	s := newStore(t, ca, false, path)
	apply(s, dev(1), nil, []string{ca.Sign(storetest.Subscription(bundle, relayM, "42"))})
	// Survives a restart.
	s = newStore(t, ca, false, path)
	if s.Buckets(dev(1))[0].Tier != KindRelay {
		t.Fatal("entitlement lost on restart")
	}
	refund := storetest.Subscription(bundle, relayM, "42")
	refund["revocationDate"] = storetest.Ms(time.Now())
	n := map[string]any{"notificationType": "REFUND", "notificationUUID": "u", "signedDate": storetest.Ms(time.Now()),
		"data": map[string]any{"bundleId": bundle, "environment": "Production", "signedTransactionInfo": ca.Sign(refund)}}
	svc := &Service{Store: s, Ledger: NewLedger(s.Buckets)}
	rec := httptest.NewRecorder()
	svc.HandleNotification(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{"signedPayload":"`+ca.Sign(n)+`"}`)))
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if s.Buckets(dev(1))[0].Tier != "" {
		t.Fatal("refunded subscription still grants relay")
	}
	rec = httptest.NewRecorder()
	svc.HandleNotification(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{"signedPayload":"`+storetest.New(storetest.Options{}).Sign(n)+`"}`)))
	if rec.Code != 400 {
		t.Fatal("unverified notification accepted")
	}
}

func TestCatalogAndDefaults(t *testing.T) {
	c := Catalog(bundle, true)
	for n, pool := range map[int]int64{3: 600e9, 5: 1e12, 10: 2e12, 25: 5e12, 50: 10e12} {
		for _, per := range []string{"monthly", "yearly"} {
			p, ok := c[fmt.Sprintf("%s.teams%d.%s", bundle, n, per)]
			if !ok || p.Kind != KindTeams || p.Seats != n || int64(p.Seats)*DefaultLimits().TeamsPerPerson != pool {
				t.Errorf("Teams %d %s: %+v", n, per, p)
			}
		}
	}
	if len(Catalog(bundle, false)) != 6 { // Pro, trial, Relay and Relay Max, monthly and yearly
		t.Error("teams=false still lists Teams packs")
	}
	if d := DefaultLimits(); d.FreeRelay != 10<<30 || d.FreeSpool != 2e9 || d.RelayRelay != 200<<30 || d.RelayMaxRelay != 2<<40 || d.RelaySpool != 20e9 {
		t.Errorf("%+v", d)
	}
	// The same vector is pinned in the Swift client (Billing.appAccountToken).
	if got := BillingTokenFor(bytes.Repeat([]byte{9}, 32)); got != "8dfdc34f-e2e2-8218-a346-5664273982a5" {
		t.Error(got)
	}
}

func TestEndpoints(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	a := auth.New("test")
	s := newStore(t, ca, false, "")
	for _, svc := range []*Service{{Auth: a, Store: s, Ledger: NewLedger(s.Buckets)}, {Auth: a}} {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
		mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
		mux.HandleFunc("POST /v1/entitlements/verify", svc.HandleVerify)
		mux.HandleFunc("GET /v1/quota", svc.HandleQuota)
		srv := httptest.NewServer(mux)
		d := testutil.NewDevice()
		tok := testutil.Login(t, srv.URL, d)
		if code := testutil.Do(t, "GET", srv.URL+"/v1/quota", "", nil, nil); code != 401 {
			t.Fatalf("anonymous quota = %d", code)
		}
		var vr VerifyResponse
		code := testutil.Do(t, "POST", srv.URL+"/v1/entitlements/verify", tok,
			VerifyRequest{Transactions: []string{ca.Sign(storetest.Subscription(bundle, relayM, "9"))}}, &vr)
		var bal Balance
		testutil.Do(t, "GET", srv.URL+"/v1/quota", tok, nil, &bal)
		if svc.Store == nil {
			if code != 200 || !vr.Quota.Unlimited || !bal.Unlimited {
				t.Fatalf("quotas off: %d %+v %+v", code, vr, bal)
			}
		} else if code != 200 || vr.Results[0].Code != "" || vr.Quota.Tier != "relay" || bal.Tier != "relay" {
			t.Fatalf("%d %+v %+v", code, vr, bal)
		}
		if code := testutil.Do(t, "POST", srv.URL+"/v1/entitlements/verify", tok, VerifyRequest{Network: []byte{1}}, nil); code != 400 {
			t.Fatalf("short network tag = %d", code)
		}
		srv.Close()
	}
}

// The month's usage is saved and loaded back: restarting the server must not reset anyone's quota.
func TestLedgerSurvivesARestart(t *testing.T) {
	s := newStore(t, storetest.New(storetest.Options{}), false, "")
	path := filepath.Join(t.TempDir(), "ledger.cbor")
	l, err := OpenLedger(s.Buckets, path)
	if err != nil {
		t.Fatal(err)
	}
	a := dev(1)
	if !l.Charge(a, 100) || l.Admit(a) {
		t.Fatal("free allowance is 100 bytes")
	}
	if err := l.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := OpenLedger(s.Buckets, path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Admit(a) || again.Balance(a).Used != 100 {
		t.Fatalf("restart forgave the month: %+v", again.Balance(a))
	}
	if !again.Admit(dev(2)) {
		t.Fatal("other devices unaffected")
	}
}

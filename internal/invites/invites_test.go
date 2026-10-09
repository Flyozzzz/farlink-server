package invites

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

func setup() (*httptest.Server, *Service) {
	a := auth.New("test")
	s := New(a)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("POST /v1/invites", s.HandlePut)
	mux.HandleFunc("GET /v1/invites/{lookup}", s.HandleGet)
	mux.HandleFunc("DELETE /v1/invites/{lookup}", s.HandleDelete)
	return httptest.NewServer(mux), s
}

func lookup(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestPutThenGetOnce(t *testing.T) {
	srv, _ := setup()
	defer srv.Close()
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	if code := testutil.Do(t, "POST", srv.URL+"/v1/invites", tok, PutRequest{LookupID: lookup(1), Blob: []byte("sealed")}, nil); code != 204 {
		t.Fatalf("put = %d", code)
	}
	u := srv.URL + "/v1/invites/" + base64.RawURLEncoding.EncodeToString(lookup(1))
	var got map[string][]byte
	if code := testutil.Do(t, "GET", u, "", nil, &got); code != 200 || string(got["blob"]) != "sealed" {
		t.Fatalf("get = %d %q", code, got["blob"])
	}
	if code := testutil.Do(t, "GET", u, "", nil, nil); code != 404 {
		t.Fatalf("second get = %d, want one-time", code)
	}
}

func TestExpires(t *testing.T) {
	srv, s := setup()
	defer srv.Close()
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	testutil.Do(t, "POST", srv.URL+"/v1/invites", tok, PutRequest{LookupID: lookup(2), Blob: []byte("x")}, nil)
	s.Now = func() time.Time { return time.Now().Add(TTL + time.Second) }
	if code := testutil.Do(t, "GET", srv.URL+"/v1/invites/"+base64.RawURLEncoding.EncodeToString(lookup(2)), "", nil, nil); code != 404 {
		t.Fatalf("expired invite served: %d", code)
	}
}

func TestGuessingIsRateLimited(t *testing.T) {
	srv, _ := setup()
	defer srv.Close()
	limited := false
	for i := 0; i < LookupsPerMin+2; i++ {
		code := testutil.Do(t, "GET", srv.URL+"/v1/invites/"+base64.RawURLEncoding.EncodeToString(lookup(byte(i+10))), "", nil, nil)
		if code == 429 {
			limited = true
		}
	}
	if !limited {
		t.Fatal("no rate limit on lookups")
	}
}

func TestPutNeedsLogin(t *testing.T) {
	srv, _ := setup()
	defer srv.Close()
	if code := testutil.Do(t, "POST", srv.URL+"/v1/invites", "", PutRequest{LookupID: lookup(3), Blob: []byte("x")}, nil); code != 401 {
		t.Fatalf("anonymous put = %d", code)
	}
}

func TestInviteBodyIsSmall(t *testing.T) {
	srv, _ := setup()
	defer srv.Close()
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	if code := testutil.Do(t, "POST", srv.URL+"/v1/invites", tok, make([]byte, 1<<20), nil); code != 413 {
		t.Fatalf("oversized invite body = %d", code)
	}
}

func TestIssuerCancelsInvite(t *testing.T) {
	srv, _ := setup()
	defer srv.Close()
	owner := testutil.Login(t, srv.URL, testutil.NewDevice())
	other := testutil.Login(t, srv.URL, testutil.NewDevice())
	testutil.Do(t, "POST", srv.URL+"/v1/invites", owner, PutRequest{LookupID: lookup(7), Blob: []byte("x")}, nil)
	u := srv.URL + "/v1/invites/" + base64.RawURLEncoding.EncodeToString(lookup(7))
	if code := testutil.Do(t, "DELETE", u, "", nil, nil); code != 401 {
		t.Fatalf("anonymous delete = %d", code)
	}
	if code := testutil.Do(t, "DELETE", u, other, nil, nil); code != 204 {
		t.Fatalf("other device delete = %d", code)
	}
	var got map[string][]byte
	if code := testutil.Do(t, "GET", u, "", nil, &got); code != 200 {
		t.Fatalf("someone else's delete removed the invite: %d", code)
	}
	testutil.Do(t, "POST", srv.URL+"/v1/invites", owner, PutRequest{LookupID: lookup(8), Blob: []byte("y")}, nil)
	u = srv.URL + "/v1/invites/" + base64.RawURLEncoding.EncodeToString(lookup(8))
	if code := testutil.Do(t, "DELETE", u, owner, nil, nil); code != 204 {
		t.Fatalf("owner delete = %d", code)
	}
	if code := testutil.Do(t, "GET", u, "", nil, nil); code != 404 {
		t.Fatalf("cancelled invite still served: %d", code)
	}
}

func TestIssuerMakesLimitedCodesPerHour(t *testing.T) {
	srv, s := setup()
	defer srv.Close()
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	clock := time.Now()
	s.Now = func() time.Time { return clock }
	made := func(i int) int {
		code := testutil.Do(t, "POST", srv.URL+"/v1/invites", tok, PutRequest{LookupID: lookup(byte(i)), Blob: []byte("x")}, nil)
		testutil.Do(t, "DELETE", srv.URL+"/v1/invites/"+base64.RawURLEncoding.EncodeToString(lookup(byte(i))), tok, nil, nil)
		return code
	}
	for i := 0; i < PerIssuerHour; i++ {
		if code := made(i); code != 204 {
			t.Fatalf("code %d refused: %d", i, code)
		}
	}
	if code := made(PerIssuerHour); code != 429 {
		t.Fatalf("code beyond the hourly limit = %d", code)
	}
	clock = clock.Add(time.Hour + time.Second)
	if code := made(PerIssuerHour + 1); code != 204 {
		t.Fatalf("still limited after the hour: %d", code)
	}
}

func TestANewContactCodeReplacesTheOldOneButPairingCodesStay(t *testing.T) {
	srv, service := setup()
	defer srv.Close()
	device := testutil.NewDevice()
	account := testutil.NewAccount(t, []testutil.Device{device})
	registry, err := accounts.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	account.Publish(t, registry)
	service.Accounts, err = accounts.OpenResolver(registry, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := testutil.Login(t, srv.URL, device)
	put := func(b byte, kind string) int {
		return testutil.Do(t, "POST", srv.URL+"/v1/invites", tok, PutRequest{LookupID: lookup(b), Blob: []byte("x"), Kind: kind, AccountID: account.State.AccountID}, nil)
	}
	get := func(b byte) int {
		return testutil.Do(t, "GET", srv.URL+"/v1/invites/"+base64.RawURLEncoding.EncodeToString(lookup(b))+"?account_id="+base64.RawURLEncoding.EncodeToString(account.State.AccountID), tok, nil, nil)
	}
	if put(1, "") != 204 || put(2, KindContact) != 204 || put(3, KindContact) != 204 {
		t.Fatal("put failed")
	}
	if get(2) != 404 {
		t.Fatal("the replaced contact code still answers")
	}
	if get(3) != 200 || get(1) != 200 {
		t.Fatal("the new contact code or the pairing code was lost")
	}
	if put(4, "other") != 400 {
		t.Fatal("unknown kind accepted")
	}
}

func TestContactInviteRechecksIssuerAfterRecovery(t *testing.T) {
	srv, service := setup()
	defer srv.Close()
	issuer, receiver := testutil.NewDevice(), testutil.NewDevice()
	from := testutil.NewAccount(t, []testutil.Device{issuer})
	to := testutil.NewAccount(t, []testutil.Device{receiver})
	registry, err := accounts.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	from.Publish(t, registry)
	to.Publish(t, registry)
	service.Accounts, err = accounts.OpenResolver(registry, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	issuerToken := testutil.Login(t, srv.URL, issuer)
	receiverToken := testutil.Login(t, srv.URL, receiver)
	request := PutRequest{LookupID: lookup(1), Blob: []byte("sealed"), Kind: KindContact, AccountID: from.State.AccountID}
	if status := testutil.Do(t, "POST", srv.URL+"/v1/invites", issuerToken, request, nil); status != 204 {
		t.Fatalf("create invite: %d", status)
	}
	url := srv.URL + "/v1/invites/" + base64.RawURLEncoding.EncodeToString(lookup(1)) + "?account_id=" + base64.RawURLEncoding.EncodeToString(to.State.AccountID)
	if status := testutil.Do(t, "GET", url, "", nil, nil); status != 401 {
		t.Fatalf("contact exchange without active session: %d", status)
	}
	fresh := testutil.NewDevice()
	from.Update(t, from.Recovery, func(state *accounts.State) {
		state.Devices = []accounts.Device{testutil.AccountDevice(fresh)}
		state.Revoked = [][]byte{issuer.ID}
	})
	from.Publish(t, registry)
	if status := testutil.Do(t, "GET", url, receiverToken, nil, nil); status != 403 {
		t.Fatalf("revoked issuer code redeemed: %d", status)
	}
	request.LookupID = lookup(2)
	if status := testutil.Do(t, "POST", srv.URL+"/v1/invites", issuerToken, request, nil); status != 403 {
		t.Fatalf("revoked issuer created code: %d", status)
	}
}

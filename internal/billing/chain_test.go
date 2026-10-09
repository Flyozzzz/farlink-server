package billing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/appstore"
	"github.com/Flyozzzz/farlink-server/internal/appstore/storetest"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

func apply(s *Store, device, network []byte, jws []string) []Result {
	res, _, _ := s.Apply(device, network, nil, jws)
	return res
}

// The fields Membership.cbor writes (FarlinkGroup/Membership.swift), so test chains look like real ones.
type tMember struct {
	DeviceID      []byte   `cbor:"device_id"`
	SigningKey    []byte   `cbor:"signing_key"`
	EncryptionKey []byte   `cbor:"encryption_key"`
	Admin         bool     `cbor:"admin"`
	Name          string   `cbor:"name"`
	Capabilities  []string `cbor:"capabilities"`
}

type tState struct {
	Protocol         uint64    `cbor:"protocol"`
	GroupID          []byte    `cbor:"group_id"`
	Epoch            uint64    `cbor:"epoch"`
	PrevHash         []byte    `cbor:"prev_hash"`
	Admission        string    `cbor:"admission"`
	Members          []tMember `cbor:"members"`
	Revoked          [][]byte  `cbor:"revoked"`
	PreferredServers []string  `cbor:"preferred_servers"`
	NetworkName      string    `cbor:"network_name"`
	Sharing          string    `cbor:"sharing"`
	EveryoneMax      string    `cbor:"everyone_max"`
	Groups           []string  `cbor:"groups"`
	ApprovedShares   [][]byte  `cbor:"approved_shares"`
	Author           []byte    `cbor:"author"`
	CreatedAt        uint64    `cbor:"created_at"`
}

type testNet struct {
	admin testutil.Device
	state tState
	links [][]byte
	tag   []byte
}

func tmember(d testutil.Device, admin bool) tMember {
	return tMember{DeviceID: d.ID, SigningKey: d.Pub, EncryptionKey: make([]byte, 32), Admin: admin, Name: "d", Capabilities: []string{}}
}

func sortMembers(ms []tMember) {
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && string(ms[j].DeviceID) < string(ms[j-1].DeviceID); j-- {
			ms[j], ms[j-1] = ms[j-1], ms[j]
		}
	}
}

func signLink(t *testing.T, st tState, by testutil.Device) []byte {
	body, err := wire.Enc.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := wire.Enc.Marshal([][]byte{body, ed25519.Sign(by.Priv, append([]byte(membershipDomain), body...))})
	return env
}

func newNetWith(t *testing.T, group []byte, admin testutil.Device) *testNet {
	n := &testNet{admin: admin, tag: TagFor(group)}
	n.state = tState{Protocol: 1, GroupID: group, PrevHash: make([]byte, 32), Admission: "admins",
		Members: []tMember{tmember(admin, true)}, Revoked: [][]byte{}, PreferredServers: []string{}, NetworkName: "Office",
		Sharing: "everyone", EveryoneMax: "rw", Groups: []string{}, ApprovedShares: [][]byte{}, Author: admin.ID, CreatedAt: 1}
	n.links = [][]byte{signLink(t, n.state, admin)}
	return n
}

func newNet(t *testing.T) *testNet {
	g := make([]byte, 16)
	rand.Read(g)
	return newNetWith(t, g, testutil.NewDevice())
}

// next appends the state change makes, signed by by.
func (n *testNet) next(t *testing.T, by testutil.Device, change func(*tState)) {
	prev := sha256.Sum256(n.links[len(n.links)-1])
	st := n.state
	st.Members = append([]tMember{}, st.Members...)
	st.Revoked = append([][]byte{}, st.Revoked...)
	st.Epoch++
	st.PrevHash, st.Author = prev[:], by.ID
	change(&st)
	sortMembers(st.Members)
	n.state = st
	n.links = append(n.links, signLink(t, st, by))
}

func (n *testNet) add(t *testing.T, admin bool) testutil.Device {
	d := testutil.NewDevice()
	n.next(t, n.admin, func(s *tState) { s.Members = append(s.Members, tmember(d, admin)) })
	return d
}

func (n *testNet) revoke(t *testing.T, d testutil.Device) {
	n.next(t, n.admin, func(s *tState) {
		for i, m := range s.Members {
			if string(m.DeviceID) == string(d.ID) {
				s.Members = append(s.Members[:i], s.Members[i+1:]...)
				break
			}
		}
		s.Revoked = append(s.Revoked, d.ID)
	})
}

func (n *testNet) teams(ca *storetest.CA, original string, seats int) string {
	tx := storetest.Subscription(bundle, bundle+".teams"+itoa(seats)+".monthly", original)
	tx["appAccountToken"] = strings.ToUpper(BillingTokenFor(n.tag))
	return ca.Sign(tx)
}

func itoa(n int) string {
	return map[int]string{3: "3", 5: "5", 10: "10", 25: "25", 50: "50"}[n]
}

func teamsOf(s *Store, d []byte) bool {
	for _, b := range s.Buckets(d) {
		if b.Tier == KindTeams {
			return true
		}
	}
	return false
}

// A former member knows the tag and holds the old chain; neither gets it back into the pool.
func TestFormerMemberCantDrawFromTheTeamsPool(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	s := newStore(t, ca, true, "")
	n := newNet(t)
	gone := n.add(t, false)
	stay := n.add(t, false)
	jws := n.teams(ca, "700", 5)
	if res, cr, _ := s.Apply(n.admin.ID, n.tag, n.links, []string{jws}); res[0].Code != "" || cr.Code != "" {
		t.Fatalf("%+v %+v", res, cr)
	}
	s.Apply(gone.ID, n.tag, n.links, nil)
	if !teamsOf(s, gone.ID) {
		t.Fatal("a member draws from the pool")
	}
	old := append([][]byte{}, n.links...)
	n.revoke(t, gone)
	// Any member's next connect brings the revoke; from then the pool is closed to it.
	if _, cr, _ := s.Apply(stay.ID, n.tag, n.links[len(n.links)-1:], nil); cr.Code != "" || cr.Epoch != 3 {
		t.Fatalf("a slice right after the known head: %+v", cr)
	}
	if teamsOf(s, gone.ID) || !teamsOf(s, stay.ID) {
		t.Fatal("the revoke must reach the pool")
	}
	for _, attempt := range []struct {
		name  string
		chain [][]byte
		code  string
	}{
		{"tag only", nil, ""},
		{"old chain", old, ""}, // behind the known head: proves nothing
		{"old head", old[len(old)-1:], "MEMBERSHIP_GAP"},
	} {
		if _, cr, _ := s.Apply(gone.ID, n.tag, attempt.chain, nil); cr.Code != attempt.code || teamsOf(s, gone.ID) {
			t.Fatalf("%s: %+v", attempt.name, cr)
		}
	}
	// Its own continuation of the old chain: it was never an admin, so nothing it signs verifies...
	forged := &testNet{admin: gone, state: n.state, tag: n.tag, links: old}
	forged.next(t, gone, func(s *tState) {})
	if _, cr, _ := s.Apply(gone.ID, n.tag, forged.links, nil); cr.Code != "MEMBERSHIP_INVALID" {
		t.Fatalf("forged link: %+v", cr)
	}
	// ...and a fresh genesis of the same group, with itself as admin, is another network to the server.
	fake := newNetWith(t, n.state.GroupID, gone)
	if res, cr, _ := s.Apply(gone.ID, n.tag, fake.links, []string{jws}); cr.Code != "NETWORK_MISMATCH" || res[0].Code != "NOT_ADMIN" || teamsOf(s, gone.ID) {
		t.Fatalf("fake genesis: %+v %+v", res, cr)
	}
}

// The billing tag and the pack's JWS (every member has it in the chain) don't bind the pack; an admin does.
func TestTeamsPackNeedsAnAdminOfTheChain(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	s := newStore(t, ca, true, "")
	n := newNet(t)
	member := n.add(t, false)
	jws := n.teams(ca, "700", 5)
	if res := apply(s, member.ID, n.tag, []string{jws}); res[0].Code != "MEMBERSHIP_REQUIRED" {
		t.Fatalf("tag and JWS alone: %+v", res)
	}
	if res, cr, _ := s.Apply(member.ID, n.tag, n.links, []string{jws}); res[0].Code != "NOT_ADMIN" || cr.Known {
		t.Fatalf("a member that is no admin: %+v %+v", res, cr)
	}
	if teamsOf(s, member.ID) || teamsOf(s, n.admin.ID) {
		t.Fatal("nothing is bound yet")
	}
	if res, _, _ := s.Apply(n.admin.ID, n.tag, n.links, []string{jws}); res[0].Code != "" {
		t.Fatalf("%+v", res)
	}
	s.Apply(member.ID, n.tag, nil, nil) // the server's head already lists it
	if !teamsOf(s, member.ID) {
		t.Fatal("a member of the verified head draws from the pool")
	}
}

// Only an admin of the known head can move the server to another branch (a fork an admin resolved).
func TestDivergingChainNeedsAnAdminOfTheKnownHead(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	s := newStore(t, ca, true, "")
	n := newNet(t)
	second := n.add(t, true)
	base := append([][]byte{}, n.links...)
	baseState := n.state
	n.add(t, false)
	if res, _, _ := s.Apply(n.admin.ID, n.tag, n.links, []string{n.teams(ca, "700", 5)}); res[0].Code != "" {
		t.Fatalf("%+v", res)
	}
	branch := &testNet{admin: second, state: baseState, tag: n.tag, links: base}
	branch.next(t, second, func(s *tState) { s.NetworkName = "Other" })
	member := testutil.NewDevice()
	if _, cr, _ := s.Apply(member.ID, n.tag, branch.links, nil); cr.Code != "MEMBERSHIP_FORK" || cr.Epoch != 2 {
		t.Fatalf("someone else's other branch: %+v", cr)
	}
	if _, cr, _ := s.Apply(n.admin.ID, n.tag, branch.links, nil); cr.Code != "" || cr.Epoch != 2 {
		t.Fatalf("an admin's other branch: %+v", cr)
	}
}

func TestRefundIsNotUndoneByAnOlderJWS(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	s := newStore(t, ca, false, "")
	tx := storetest.Subscription(bundle, relayM, "42")
	saved := ca.Sign(tx) // kept by the buyer before asking for a refund
	if res := apply(s, dev(1), nil, []string{saved}); res[0].Code != "" {
		t.Fatalf("%+v", res)
	}
	refund := storetest.Subscription(bundle, relayM, "42")
	refund["revocationDate"] = storetest.Ms(time.Now())
	if err := s.Notify(verified(t, s, ca.Sign(refund))); err != nil {
		t.Fatal(err)
	}
	if res := apply(s, dev(1), nil, []string{saved}); res[0].Code != "REVOKED" || s.Buckets(dev(1))[0].Tier != "" {
		t.Fatalf("the saved JWS brought the refunded subscription back: %+v", res)
	}
	// A renewal notification of the refunded transaction doesn't either.
	if err := s.Notify(verified(t, s, saved)); err != nil || s.Buckets(dev(1))[0].Tier != "" {
		t.Fatal("renewal of a refunded transaction")
	}
	// A later transaction of the subscription (resubscribed) does.
	again := storetest.Subscription(bundle, relayM, "42")
	again["transactionId"], again["purchaseDate"] = "42-2", storetest.Ms(time.Now())
	if res := apply(s, dev(1), nil, []string{ca.Sign(again)}); res[0].Code != "" || s.Buckets(dev(1))[0].Tier != KindRelay {
		t.Fatalf("resubscription: %+v", res)
	}
}

// A late refund of an earlier period buries that transaction only; the renewal in force stays.
func TestRefundOfAnEarlierPeriodDoesNotEndTheCurrentOne(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	s := newStore(t, ca, false, "")
	first := storetest.Subscription(bundle, relayM, "44")
	savedFirst := ca.Sign(first)
	second := storetest.Subscription(bundle, relayM, "44")
	second["transactionId"], second["purchaseDate"] = "44-2", storetest.Ms(time.Now().Add(time.Hour))
	if res := apply(s, dev(1), nil, []string{ca.Sign(second)}); res[0].Code != "" || s.Buckets(dev(1))[0].Tier != KindRelay {
		t.Fatalf("renewal: %+v", res)
	}
	refund := storetest.Subscription(bundle, relayM, "44")
	refund["revocationDate"] = storetest.Ms(time.Now())
	if err := s.Notify(verified(t, s, ca.Sign(refund))); err != nil {
		t.Fatal(err)
	}
	if s.Buckets(dev(1))[0].Tier != KindRelay {
		t.Fatal("the refund of the first period ended the second")
	}
	// The refunded transaction itself grants nothing, presented again.
	if res := apply(s, dev(2), nil, []string{savedFirst}); res[0].Code == "" && s.Buckets(dev(2))[0].Tier != "" {
		t.Fatalf("refunded period brought back: %+v", res)
	}
	// Refunding the current period ends it.
	cur := storetest.Subscription(bundle, relayM, "44")
	cur["transactionId"], cur["purchaseDate"], cur["revocationDate"] = "44-2", storetest.Ms(time.Now().Add(time.Hour)), storetest.Ms(time.Now())
	if err := s.Notify(verified(t, s, ca.Sign(cur))); err != nil || s.Buckets(dev(1))[0].Tier != "" {
		t.Fatalf("refund of the current period: %v", err)
	}
}

// A refund Apple reports before any device presented the subscription still sticks.
func TestRefundOfAnUnknownSubscriptionIsKept(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	path := filepath.Join(t.TempDir(), "entitlements.json")
	s := newStore(t, ca, false, path)
	tx := storetest.Subscription(bundle, relayM, "43")
	saved := ca.Sign(tx)
	tx["revocationDate"] = storetest.Ms(time.Now())
	if err := s.Notify(verified(t, s, ca.Sign(tx))); err != nil {
		t.Fatal(err)
	}
	s = newStore(t, ca, false, path)
	if res := apply(s, dev(1), nil, []string{saved}); res[0].Code != "REVOKED" || s.Buckets(dev(1))[0].Tier != "" {
		t.Fatalf("%+v", res)
	}
}

func TestNetworkHeadSurvivesARestart(t *testing.T) {
	ca := storetest.New(storetest.Options{})
	path := filepath.Join(t.TempDir(), "entitlements.json")
	s := newStore(t, ca, true, path)
	n := newNet(t)
	m := n.add(t, false)
	s.Apply(n.admin.ID, n.tag, n.links, []string{n.teams(ca, "700", 3)})
	s = newStore(t, ca, true, path)
	s.Apply(m.ID, n.tag, nil, nil)
	if !teamsOf(s, m.ID) {
		t.Fatal("head lost on restart")
	}
	n.revoke(t, m)
	if _, cr, _ := s.Apply(n.admin.ID, n.tag, n.links[len(n.links)-1:], nil); cr.Code != "" || teamsOf(s, m.ID) {
		t.Fatalf("%+v", cr)
	}
}

func verified(t *testing.T, s *Store, jws string) *appstoreTx {
	var tx appstoreTx
	if err := s.Verifier.Verify(jws, &tx, func() int64 { return tx.SignedDate }); err != nil {
		t.Fatal(err)
	}
	return &tx
}

type appstoreTx = appstore.Transaction

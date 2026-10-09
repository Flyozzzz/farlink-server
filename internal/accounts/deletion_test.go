package accounts

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fleet struct {
	t       *testing.T
	regs    map[string]*Registry
	del     map[string]*Deleter
	down    map[string]bool
	mu      sync.Mutex
	purged  map[string][][]byte
	pushes  map[string]int
	now     time.Time
	account State
	raw     []byte
	first   dev
}

// threeServers: three registries holding the same one-device account, each with a Deleter that pushes to the others.
func threeServers(t *testing.T) *fleet {
	f := &fleet{t: t, regs: map[string]*Registry{}, del: map[string]*Deleter{}, down: map[string]bool{}, purged: map[string][][]byte{}, pushes: map[string]int{}, now: time.Now()}
	f.first = newDev()
	rk := newDev()
	f.account, f.raw = genesis(t, f.first, rk)
	ids := []string{"us", "ru1", "ru2"}
	for _, id := range ids {
		reg := registryWith(t, f.raw)
		f.regs[id] = reg
	}
	for _, id := range ids {
		id := id
		resolver := resolverWith(t, f.regs[id], t.TempDir())
		d := &Deleter{Reg: f.regs[id], Resolver: resolver, Dir: t.TempDir(), Now: func() time.Time { return f.now },
			Peers: func() []string {
				var out []string
				for _, o := range ids {
					if o != id {
						out = append(out, o)
					}
				}
				return out
			},
			Push: func(ctx context.Context, peer string, p PeerDelete) error {
				f.mu.Lock()
				f.pushes[peer]++
				down := f.down[peer]
				f.mu.Unlock()
				if down {
					return ErrUnreachable
				}
				return f.del[peer].ApplyPeer(p)
			},
			Purge: []Purger{func(account []byte, devices [][]byte) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.purged[id] = devices
				return nil
			}},
		}
		if err := d.Open(); err != nil {
			t.Fatal(err)
		}
		f.del[id] = d
	}
	return f
}

func (f *fleet) request(by dev, head []byte) DeleteRequest {
	return SignDelete(by.priv, DeleteBody{Protocol: 1, AccountID: f.account.AccountID, Device: by.id(), HeadHash: head, ExpiresAt: uint64(f.now.Add(time.Minute).UnixMilli())})
}

func (f *fleet) head(server string) []byte {
	_, h, _ := f.regs[server].HeadRef(f.account.AccountID)
	return h
}

func TestOnlyAnActiveDeviceWithTheNewestLinkCanDeleteAnAccount(t *testing.T) {
	f := threeServers(t)
	ctx := context.Background()
	stranger := newDev()
	if err := f.del["us"].Start(ctx, f.request(stranger, f.head("us"))); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("a stranger's request: %v", err)
	}
	if err := f.del["us"].Start(ctx, f.request(f.first, make([]byte, 32))); !errors.Is(err, ErrSync) {
		t.Fatalf("a request for an older link: %v", err)
	}
	expired := f.request(f.first, f.head("us"))
	f.now = f.now.Add(time.Hour)
	if err := f.del["us"].Start(ctx, expired); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an expired request: %v", err)
	}
	f.now = time.Now()
	bad := f.request(f.first, f.head("us"))
	bad.Signature[0] ^= 1
	if err := f.del["us"].Start(ctx, bad); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a bad signature: %v", err)
	}
	if f.regs["us"].IsDeleted(f.account.AccountID) {
		t.Fatal("a refused request deleted the account")
	}
}

func TestDeletionRefusesTheAccountAtOnceAndReachesEveryServer(t *testing.T) {
	f := threeServers(t)
	ctx := context.Background()
	f.down["ru2"] = true
	if err := f.del["us"].Start(ctx, f.request(f.first, f.head("us"))); err != nil {
		t.Fatal(err)
	}
	if !f.regs["us"].IsDeleted(f.account.AccountID) {
		t.Fatal("not refused at once on the server that took it")
	}
	if _, err := f.del["us"].Resolver.Current(ctx, f.account.AccountID); !errors.Is(err, ErrDeleted) {
		t.Fatalf("resolver on a deleted account: %v", err)
	}
	if _, ok := f.regs["us"].AccountOf(f.first.id()); ok {
		t.Fatal("a device of a deleted account is still recognised")
	}
	if _, _, err := f.regs["us"].Submit(f.raw); !errors.Is(err, ErrDeleted) {
		t.Fatalf("making the account again: %v", err)
	}
	f.del["us"].Step(ctx)
	if !f.regs["ru1"].IsDeleted(f.account.AccountID) {
		t.Fatal("ru1 was not told")
	}
	if f.regs["ru2"].IsDeleted(f.account.AccountID) {
		t.Fatal("ru2 was down but is deleted")
	}
	if len(f.del["us"].Pending()) != 1 {
		t.Fatal("the work finished before every server was told")
	}
	if _, ok := f.regs["us"].Chain(f.account.AccountID); !ok {
		t.Fatal("the chain others need to check was dropped too early")
	}
	f.down["ru2"] = false
	f.del["us"].Step(ctx)
	if !f.regs["ru2"].IsDeleted(f.account.AccountID) {
		t.Fatal("ru2 was not told after it came back")
	}
	if len(f.del["us"].Pending()) != 1 {
		t.Fatal("the work finished before the second erasing pass")
	}
	for round := 0; round < 2; round++ { // the second pass over the stores runs a couple of minutes after the first
		f.now = f.now.Add(3 * time.Minute)
		for _, s := range []string{"us", "ru1", "ru2"} {
			f.del[s].Step(ctx)
		}
	}
	if len(f.del["us"].Pending()) != 0 {
		t.Fatal("the work did not finish")
	}
	if _, ok := f.regs["us"].Chain(f.account.AccountID); ok {
		t.Fatal("the chain was kept after every server was told")
	}
	for _, s := range []string{"us", "ru1", "ru2"} {
		f.del[s].Step(ctx)
		if _, ok := f.regs[s].Chain(f.account.AccountID); ok {
			t.Fatalf("%s kept the chain", s)
		}
		if len(f.purged[s]) == 0 {
			t.Fatalf("%s did not erase the account's data", s)
		}
		if !f.regs[s].OwnerDeleted(f.first.id()) {
			t.Fatalf("%s forgot that the device belonged to a deleted account", s)
		}
	}
}

func TestADeletionNotYetSentSurvivesARestart(t *testing.T) {
	f := threeServers(t)
	ctx := context.Background()
	f.down["ru1"], f.down["ru2"] = true, true
	if err := f.del["us"].Start(ctx, f.request(f.first, f.head("us"))); err != nil {
		t.Fatal(err)
	}
	f.del["us"].Step(ctx)
	// A restart: the same directories, a new Registry and Deleter.
	dir, regDir := f.del["us"].Dir, f.regs["us"].dir
	reg, err := Open(regDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.IsDeleted(f.account.AccountID) {
		t.Fatal("the tombstone was forgotten")
	}
	us := f.del["us"]
	again := &Deleter{Reg: reg, Resolver: us.Resolver, Dir: dir, Now: us.Now, Peers: us.Peers, Push: us.Push, Purge: us.Purge}
	if err := again.Open(); err != nil {
		t.Fatal(err)
	}
	f.down["ru1"], f.down["ru2"] = false, false
	again.Step(ctx)
	if !f.regs["ru1"].IsDeleted(f.account.AccountID) || !f.regs["ru2"].IsDeleted(f.account.AccountID) {
		t.Fatal("the other servers were not told after the restart")
	}
}

func TestAPeerDeletionIsCheckedNotTrusted(t *testing.T) {
	f := threeServers(t)
	good := f.request(f.first, f.head("us"))
	chain, _ := f.regs["us"].Chain(f.account.AccountID)
	stranger := newDev()
	if err := f.del["ru1"].ApplyPeer(PeerDelete{Request: f.request(stranger, f.head("us")), Chain: chain}); err == nil {
		t.Fatal("a request signed by a stranger was applied")
	}
	forged := good
	forged.Signature = append([]byte(nil), good.Signature...)
	forged.Signature[3] ^= 1
	if err := f.del["ru1"].ApplyPeer(PeerDelete{Request: forged, Chain: chain}); err == nil {
		t.Fatal("a forged signature was applied")
	}
	if f.regs["ru1"].IsDeleted(f.account.AccountID) {
		t.Fatal("a refused peer request deleted the account")
	}
	if err := f.del["ru1"].ApplyPeer(PeerDelete{Request: good, Chain: chain}); err != nil {
		t.Fatal(err)
	}
	if !f.regs["ru1"].IsDeleted(f.account.AccountID) {
		t.Fatal("a good peer request was not applied")
	}
}

func TestAnotherAccountsDeviceIdsAreNotTombstonedByRevokingThem(t *testing.T) {
	f := threeServers(t)
	ctx := context.Background()
	victim := newDev()
	// The account's owner writes the victim's device id into the revoked list of a valid link, then deletes.
	revoked := next(f.account, f.raw, f.first)
	revoked.Devices = []Device{f.first.entry("Mac")}
	revoked.Revoked = [][]byte{victim.id()}
	raw := sign(t, revoked, f.first)
	for _, reg := range f.regs {
		if _, _, err := reg.Submit(raw); err != nil {
			t.Fatal(err)
		}
	}
	_, head, _ := f.regs["us"].HeadRef(f.account.AccountID)
	if err := f.del["us"].Start(ctx, f.request(f.first, head)); err != nil {
		t.Fatal(err)
	}
	f.del["us"].Step(ctx)
	for s, reg := range f.regs {
		if reg.OwnerDeleted(victim.id()) {
			t.Fatalf("%s blocked a device the account never had", s)
		}
		if !reg.OwnerDeleted(f.first.id()) {
			t.Fatalf("%s did not block the account's own device", s)
		}
	}
	for _, devices := range f.purged {
		for _, d := range devices {
			if bytes.Equal(d, victim.id()) {
				t.Fatal("the stranger's data was erased with the account")
			}
		}
	}
}

func TestAPeerCannotDeleteOnAnotherBranchOfTheHistory(t *testing.T) {
	f := threeServers(t)
	// ru1 learns a newer link that revokes nobody but differs from what the sender claims as its head.
	added := next(f.account, f.raw, f.first)
	phone := newDev()
	added.Devices = append(added.Devices, phone.entry("Phone"))
	sortDevices(added.Devices)
	raw := sign(t, added, f.first)
	if _, _, err := f.regs["ru1"].Submit(raw); err != nil {
		t.Fatal(err)
	}
	chain, _ := f.regs["us"].Chain(f.account.AccountID)
	other := next(f.account, f.raw, f.first)
	other.Nickname = "other branch"
	forkRaw := sign(t, other, f.first)
	pushed := append(append([][]byte(nil), chain...), forkRaw)
	c, err := replay(pushed)
	if err != nil {
		t.Skip("the fork is not a valid chain on its own: ", err)
	}
	req := f.request(f.first, c.head().Hash())
	if err := f.del["ru1"].ApplyPeer(PeerDelete{Request: req, Chain: pushed}); err == nil {
		t.Fatal("a deletion on a branch this server does not hold was applied")
	}
}

func TestAKeyWrittenIntoAnotherAccountsDeviceListIsNotBlockedByItsDeletion(t *testing.T) {
	f := threeServers(t)
	ctx := context.Background()
	victim := newDev()
	added := next(f.account, f.raw, f.first)
	added.Devices = append(added.Devices, victim.entry("Not mine"))
	sortDevices(added.Devices)
	raw := sign(t, added, f.first)
	for _, reg := range f.regs {
		if _, _, err := reg.Submit(raw); err != nil {
			t.Fatal(err)
		}
	}
	_, head, _ := f.regs["us"].HeadRef(f.account.AccountID)
	if err := f.del["us"].Start(ctx, f.request(f.first, head)); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 3; round++ {
		f.now = f.now.Add(3 * time.Minute)
		for _, s := range []string{"us", "ru1", "ru2"} {
			f.del[s].Step(ctx)
		}
	}
	for s, reg := range f.regs {
		if reg.OwnerDeleted(victim.id()) {
			t.Fatalf("%s blocked a key that only appeared in the account's device list", s)
		}
		if !reg.OwnerDeleted(f.first.id()) {
			t.Fatalf("%s did not block the device that signed for the account", s)
		}
	}
	for _, devices := range f.purged {
		for _, d := range devices {
			if bytes.Equal(d, victim.id()) {
				t.Fatal("data of a key that never signed for the account was erased")
			}
		}
	}
}

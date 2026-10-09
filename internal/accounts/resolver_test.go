package accounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func replicaFor(id string, reg *Registry) Replica {
	return Replica{ID: id, Page: func(ctx context.Context, account []byte, from uint64) ([][]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, found := reg.JournalPage(account, from)
		if !found {
			return nil, nil
		}
		return page, nil
	}}
}

func registryWith(t *testing.T, raws ...[]byte) *Registry {
	t.Helper()
	r, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range raws {
		if _, _, err := r.Submit(raw); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func resolverWith(t *testing.T, local *Registry, dir string, peers ...Replica) *Resolver {
	t.Helper()
	r, err := OpenResolver(local, dir, func() ([]Replica, error) { return peers, nil })
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolverRevocationIsFreshWithOneReplicaUnavailable(t *testing.T) {
	first, rk, phone := newDev(), newDev(), newDev()
	g, raw := genesis(t, first, rk)
	added := next(g, raw, first)
	added.Devices = append(added.Devices, phone.entry("Phone"))
	addRaw := sign(t, added, first)
	local := registryWith(t, raw, addRaw)
	peer := registryWith(t, raw, addRaw)
	dead := Replica{ID: "dead", Page: func(ctx context.Context, _ []byte, _ uint64) ([][]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	r := resolverWith(t, local, t.TempDir(), replicaFor("peer", peer), dead)
	r.Timeout = 50 * time.Millisecond
	v, err := r.Current(context.Background(), g.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.ActiveDevice(phone.id()); !ok {
		t.Fatal("active phone denied")
	}
	// This peer and the unavailable third replica hold a published revocation;
	// the local registry deliberately stays at the preceding state.
	revoked := next(added, addRaw, first)
	revoked.Devices = []Device{first.entry("Mac")}
	revoked.Revoked = [][]byte{phone.id()}
	if _, _, err := peer.Submit(sign(t, revoked, first)); err != nil {
		t.Fatal(err)
	}
	v, err = r.Current(context.Background(), g.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.ActiveDevice(phone.id()); ok {
		t.Fatal("cached authorization survived revocation")
	}
	if _, ok := v.ActiveDevice(first.id()); !ok {
		t.Fatal("revocation denied remaining device")
	}
	if v.HeadRef().Number != 2 {
		t.Fatal("stale local registry won over peer")
	}
}

func TestResolverRequiresMajorityEvenWithCheckpoint(t *testing.T) {
	g, raw := genesis(t, newDev(), newDev())
	local, peer := registryWith(t, raw), registryWith(t, raw)
	available := true
	remote := Replica{ID: "peer", Page: func(ctx context.Context, id []byte, from uint64) ([][]byte, error) {
		if !available {
			return nil, errors.New("offline")
		}
		return replicaFor("peer", peer).Page(ctx, id, from)
	}}
	r := resolverWith(t, local, t.TempDir(), remote)
	if _, err := r.Current(context.Background(), g.AccountID); err != nil {
		t.Fatal(err)
	}
	available = false
	if _, err := r.Current(context.Background(), g.AccountID); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("cached permission: %v", err)
	}
}

func TestResolverForkAtCachedHeadRemainsFrozenAfterRestart(t *testing.T) {
	first, rk := newDev(), newDev()
	g, raw := genesis(t, first, rk)
	a := next(g, raw, first)
	a.Nickname = "A"
	b := next(g, raw, first)
	b.Nickname = "B"
	araw, braw := sign(t, a, first), sign(t, b, first)
	local := registryWith(t, raw, araw)
	peer := registryWith(t, raw, araw)
	dir := t.TempDir()
	r := resolverWith(t, local, dir, replicaFor("peer", peer))
	if _, err := r.Current(context.Background(), g.AccountID); err != nil {
		t.Fatal(err)
	}
	other := registryWith(t, raw, braw)
	r.Peers = func() ([]Replica, error) { return []Replica{replicaFor("peer", other)}, nil }
	if _, err := r.Current(context.Background(), g.AccountID); !errors.Is(err, ErrFork) {
		t.Fatalf("same-height fork: %v", err)
	}
	// Hiding the other branch and restarting cannot make the frozen account act.
	r = resolverWith(t, local, dir, replicaFor("peer", peer))
	if _, err := r.Current(context.Background(), g.AccountID); !errors.Is(err, ErrFork) {
		t.Fatalf("forgot fork: %v", err)
	}
}

func TestResolverCheckpointCannotSupplyMissingFreshEvidence(t *testing.T) {
	first, rk := newDev(), newDev()
	g, raw := genesis(t, first, rk)
	n := next(g, raw, first)
	nraw := sign(t, n, first)
	local, peer := registryWith(t, raw, nraw), registryWith(t, raw, nraw)
	dir := t.TempDir()
	r := resolverWith(t, local, dir, replicaFor("peer", peer))
	if _, err := r.Current(context.Background(), g.AccountID); err != nil {
		t.Fatal(err)
	}
	// Both answering registries roll back, while the durable checkpoint remains.
	old := registryWith(t, raw)
	r = resolverWith(t, old, dir, replicaFor("peer", old))
	if _, err := r.Current(context.Background(), g.AccountID); !errors.Is(err, ErrBehindCheckpoint) {
		t.Fatalf("rollback: %v", err)
	}
}

func TestResolverRejectsForgedHistoryWithoutFreezingValidAccount(t *testing.T) {
	first, rk := newDev(), newDev()
	g, raw := genesis(t, first, rk)
	wrong := next(g, raw, first)
	wrongRaw := sign(t, wrong, newDev())
	local := registryWith(t, raw)
	bad := Replica{ID: "bad", Page: func(context.Context, []byte, uint64) ([][]byte, error) { return [][]byte{raw, wrongRaw}, nil }}
	r := resolverWith(t, local, t.TempDir(), bad, replicaFor("good", local))
	v, err := r.Current(context.Background(), g.AccountID)
	if err != nil || v.HeadRef().Number != 0 {
		t.Fatalf("valid majority: %v", err)
	}
}

func TestResolverPagesAndStandaloneAuthorization(t *testing.T) {
	first, rk := newDev(), newDev()
	g, raw := genesis(t, first, rk)
	reg := registryWith(t, raw)
	state := g
	for range MaxSuffixLinks + 2 {
		state = next(state, raw, first)
		raw = sign(t, state, first)
		if _, _, err := reg.Submit(raw); err != nil {
			t.Fatal(err)
		}
	}
	r, err := OpenResolver(reg, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.Current(context.Background(), g.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if v.HeadRef().Number != state.Number {
		t.Fatal("pagination truncated current chain")
	}
	if _, ok := v.ActiveDevice(first.id()); !ok {
		t.Fatal("standalone active device denied")
	}
}

func TestResolverCheckpointFailureIsClosed(t *testing.T) {
	g, raw := genesis(t, newDev(), newDev())
	reg := registryWith(t, raw)
	dir := filepath.Join(t.TempDir(), "checkpoints")
	r, err := OpenResolver(reg, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Current(context.Background(), g.AccountID); err == nil {
		t.Fatal("authorized without durable checkpoint")
	}
}

func TestResolverConcurrentReadCannotRollBackNewerAuthorization(t *testing.T) {
	first, rk, fresh := newDev(), newDev(), newDev()
	g, raw := genesis(t, first, rk)
	recovery := next(g, raw, rk)
	recovery.Devices = []Device{fresh.entry("Recovered")}
	recovery.Revoked = [][]byte{first.id()}
	local := registryWith(t, raw)
	remote := registryWith(t, raw, sign(t, recovery, rk))
	type delayedKey struct{}
	started, release := make(chan struct{}), make(chan struct{})
	peer := Replica{ID: "peer", Page: func(ctx context.Context, id []byte, from uint64) ([][]byte, error) {
		if ctx.Value(delayedKey{}) == true {
			if from != 0 {
				return [][]byte{}, nil
			}
			close(started)
			select {
			case <-release:
				return [][]byte{raw}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return replicaFor("peer", remote).Page(ctx, id, from)
	}}
	r := resolverWith(t, local, t.TempDir(), peer)
	result := make(chan error, 1)
	go func() {
		_, err := r.Current(context.WithValue(context.Background(), delayedKey{}, true), g.AccountID)
		result <- err
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	current, err := r.Current(ctx, g.AccountID)
	close(release)
	if err != nil {
		t.Fatalf("independent authorization waited behind peer I/O: %v", err)
	}
	if _, ok := current.ActiveDevice(first.id()); ok {
		t.Fatal("new authorization did not observe recovery")
	}
	if err := <-result; !errors.Is(err, ErrBehindCheckpoint) {
		t.Fatalf("earlier read overwrote recovery checkpoint: %v", err)
	}
}

package accounts

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

func TestSharedRecoveryJournalSurvivesEveryRestart(t *testing.T) {
	data, err := os.ReadFile("testdata/recovery-journal.cbor")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		AccountID []byte `cbor:"account_id"`
		Genesis   []byte `cbor:"genesis"`
		Events    []struct {
			Link   []byte `cbor:"link"`
			Result string `cbor:"result"`
			Frozen bool   `cbor:"frozen"`
			Head   []byte `cbor:"head"`
		} `cbor:"events"`
	}
	if err := wire.Lenient(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		dir, checkpointDir := t.TempDir(), t.TempDir()
		reg, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := reg.Submit(fixture.Genesis); err != nil {
			t.Fatal(err)
		}
		for i, event := range fixture.Events {
			_, _, err := reg.Submit(event.Link)
			if event.Result == "fork" {
				if !errors.Is(err, ErrFork) {
					t.Fatalf("event %d: %v", i, err)
				}
			} else if err != nil {
				t.Fatalf("event %d: %v", i, err)
			}
			reg, err = Open(dir)
			if err != nil {
				t.Fatalf("restart after event %d: %v", i, err)
			}
			_, head, ok := reg.HeadRef(fixture.AccountID)
			if !ok || !bytes.Equal(head, event.Head) {
				t.Fatalf("head after event %d", i)
			}
			if _, ok := reg.Head(fixture.AccountID); ok == event.Frozen {
				t.Fatalf("authorization after event %d", i)
			}
			resolver := resolverWith(t, reg, checkpointDir)
			account, err := resolver.Current(context.Background(), fixture.AccountID)
			if event.Frozen {
				if !errors.Is(err, ErrFork) {
					t.Fatalf("resolver event %d: %v", i, err)
				}
			} else if err != nil || !bytes.Equal(account.HeadRef().Hash, event.Head) {
				t.Fatalf("resolver event %d: %v", i, err)
			}
		}
	}
}

func TestResolverRecoverySelectsOtherReplicaBranch(t *testing.T) {
	first, rk := newDev(), newDev()
	g, raw := genesis(t, first, rk)
	a := next(g, raw, first)
	a.Nickname = "a"
	b := next(g, raw, first)
	b.Nickname = "b"
	araw, braw := sign(t, a, first), sign(t, b, first)
	local, peer := registryWith(t, raw, araw), registryWith(t, raw, braw)
	dir := t.TempDir()
	resolver := resolverWith(t, local, dir, replicaFor("peer", peer))
	if _, err := resolver.Current(context.Background(), g.AccountID); !errors.Is(err, ErrFork) {
		t.Fatal(err)
	}
	resolution := next(b, braw, rk)
	resolution.Nickname = "recovered"
	if _, _, err := peer.Submit(sign(t, resolution, rk)); err != nil {
		t.Fatal(err)
	}
	resolver = resolverWith(t, local, dir, replicaFor("peer", peer))
	account, err := resolver.Current(context.Background(), g.AccountID)
	if err != nil || account.Head().Nickname != "recovered" {
		t.Fatalf("recovery: %v", err)
	}
	// The losing replica remains online and must not re-freeze a recovered checkpoint.
	resolver = resolverWith(t, local, dir, replicaFor("peer", peer))
	if _, err := resolver.Current(context.Background(), g.AccountID); err != nil {
		t.Fatal(err)
	}
}

func TestSharedNoncanonicalEnvelopesNeverEnterJournal(t *testing.T) {
	data, err := os.ReadFile("testdata/noncanonical-links.cbor")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Genesis      []byte `cbor:"genesis"`
		Canonical    []byte `cbor:"canonical"`
		Noncanonical []byte `cbor:"noncanonical"`
	}
	if err := wire.Lenient(data, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if !bytes.Equal(row.Noncanonical[2:], row.Canonical[1:]) {
			t.Fatal("signed bytes changed")
		}
		dir := t.TempDir()
		reg, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range [][]byte{row.Genesis, row.Canonical} {
			if _, _, err := reg.Submit(raw); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := reg.Submit(row.Noncanonical); !errors.Is(err, ErrMalformed) {
			t.Fatalf("noncanonical wrapper admitted: %v", err)
		}
		reg, err = Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		link, err := ParseLink(row.Canonical)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := reg.Head(link.State.AccountID); !ok {
			t.Fatal("wrapper froze account")
		}
		journal, _ := reg.JournalPage(link.State.AccountID, 0)
		if len(journal) != 2 {
			t.Fatalf("journal poisoned: %d", len(journal))
		}
	}
}

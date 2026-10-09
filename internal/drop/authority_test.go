package drop

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/contacts"
	"github.com/Flyozzzz/farlink-server/internal/federation"
)

func TestAuthorityMigrationDoesNotLetAnotherPeerExportOrImportState(t *testing.T) {
	c := setup(t, "a", "b", "c")
	if status, failure, _ := c.decide(t, "b", "remove", 0); status != 200 {
		t.Fatalf("remove: %d %s", status, failure)
	}
	c.to.Update(t, c.recipent, func(state *accounts.State) { state.ContactMailboxes = []string{"c", "b"} })
	c.publish(t, c.to)
	request := map[string]any{"account_id": c.to.State.AccountID, "transition": c.to.HeadRef()}
	// The origin is a real mTLS peer, but not the named receiving authority.
	err := c.m["a"].cli.Post(context.Background(), "b", contacts.ExportPath, request)
	if refusal, ok := err.(*federation.Error); !ok || refusal.Status != 403 {
		t.Fatalf("foreign export: %v", err)
	}
	forged := contacts.AuthoritySnapshot{Recipient: c.to.State.AccountID, Transition: c.to.HeadRef(), From: "b", To: "c", Records: []contacts.Record{}}
	err = c.m["a"].cli.Post(context.Background(), "c", contacts.ImportPath, forged)
	if refusal, ok := err.(*federation.Error); !ok || refusal.Status != 403 {
		t.Fatalf("foreign import: %v", err)
	}
	for _, route := range []string{contacts.ExportPath, contacts.ImportPath} {
		if status, _ := post(t, c.m["c"].srv.URL+route, "", forged); status != 401 {
			t.Fatalf("unauthenticated %s: %d", route, status)
		}
	}
	if status, failure := c.drop(t, c.offer(1, "c", "b")); status != 403 || failure != "CONTACT_REMOVED" {
		t.Fatalf("migration lost block: %d %s", status, failure)
	}
	if status, failure, _ := c.state(t, "b", c.recipent, contacts.StateRequest{Action: "list"}); status != 409 || failure != "NOT_AUTHORITY" {
		t.Fatalf("old authority state: %d %s", status, failure)
	}
}

func TestRecoveryForkCannotUndoExecutedAuthorityMigration(t *testing.T) {
	c := setup(t, "a", "b", "c")
	status, failure, accepted := c.decide(t, "b", "accept", 0)
	if status != 200 {
		t.Fatalf("initial acceptance: %d %s", status, failure)
	}
	// Keep the real signed predecessor so the losing migration can later be
	// removed by a fully verified device fork followed by an RK decision.
	alternative := *c.to
	alternative.Links = append([][]byte(nil), c.to.Links...)
	c.to.Update(t, c.recipent, func(state *accounts.State) { state.ContactMailboxes = []string{"c", "b"} })
	c.publish(t, c.to)
	// This invokes the pinned mTLS export/import and then commits a newer block.
	status, failure, removed := c.decide(t, "c", "remove", accepted.Generation)
	if status != 200 || removed.Generation <= accepted.Generation {
		t.Fatalf("migration and new block: %d %s", status, failure)
	}
	transition := c.to.HeadRef()
	exported := contacts.AuthoritySnapshot{Recipient: c.to.State.AccountID, Transition: transition,
		From: "b", To: "c", Clock: accepted.Generation, Records: []contacts.Record{accepted}}
	alternative.Update(t, c.recipent, func(state *accounts.State) { state.Nickname = "no migration" })
	for _, n := range c.m {
		if _, _, err := n.accounts.Submit(alternative.Links[len(alternative.Links)-1]); !errors.Is(err, accounts.ErrFork) {
			t.Fatalf("signed fork: %v", err)
		}
		if _, err := n.resolver.Current(context.Background(), c.to.State.AccountID); !errors.Is(err, accounts.ErrFork) {
			t.Fatalf("fork authorization: %v", err)
		}
	}
	alternative.Update(t, alternative.Recovery, func(state *accounts.State) { state.Nickname = "RK selected original authority" })
	for _, n := range c.m {
		if _, _, err := n.accounts.Submit(alternative.Links[len(alternative.Links)-1]); err != nil {
			t.Fatal(err)
		}
		account, err := n.resolver.Current(context.Background(), alternative.State.AccountID)
		if err != nil || !bytes.Equal(account.HeadRef().Hash, alternative.HeadRef().Hash) {
			t.Fatalf("RK resolution: %v", err)
		}
	}
	c.to = &alternative
	if status, failure, _ := c.decide(t, "b", "accept", accepted.Generation); status != 409 || failure != "AUTHORITY_MIGRATION_REQUIRED" {
		t.Fatalf("canceled handoff reopened old authority: %d %s", status, failure)
	}
	if status, failure := c.drop(t, c.offer(3, "b", "c")); status != 409 || failure != "AUTHORITY_MIGRATION_REQUIRED" {
		t.Fatalf("canceled handoff admitted sender: %d %s", status, failure)
	}
	if err := c.m["b"].cli.Post(context.Background(), "c", contacts.ImportPath, exported); err == nil {
		t.Fatal("replay of canceled snapshot succeeded")
	}
	records := c.held("c")
	if len(records) != 1 || records[0].State != contacts.Removed || records[0].Generation != removed.Generation {
		t.Fatal("RK rollback or snapshot replay lost the destination's newer block")
	}
}

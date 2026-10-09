package drop

import (
	"context"
	"errors"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/contacts"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

func TestAccountForkClosesDropAdmitForwardStateAndQueuedSinkUntilRecovery(t *testing.T) {
	c := setup(t, "a", "b")
	original := c.offer(1, "b")
	if status, failure := c.drop(t, original); status != 202 {
		t.Fatalf("queue: %d %s", status, failure)
	}
	alternate := *c.to
	alternate.Links = append([][]byte(nil), c.to.Links...)
	c.to.Update(t, c.recipent, func(s *accounts.State) { s.Nickname = "A" })
	c.publish(t, c.to)
	alternate.Update(t, c.recipent, func(s *accounts.State) { s.Nickname = "B" })
	for _, node := range c.m {
		if _, _, err := node.accounts.Submit(alternate.Links[len(alternate.Links)-1]); !errors.Is(err, accounts.ErrFork) {
			t.Fatal(err)
		}
	}
	if status, failure := c.drop(t, original); status != 409 || failure != "ACCOUNT_FORK" {
		t.Fatalf("drop: %d %s", status, failure)
	}
	if status, failure, _ := c.state(t, "b", c.recipent, contacts.StateRequest{Action: "list"}); status != 409 || failure != "ACCOUNT_FORK" {
		t.Fatalf("state: %d %s", status, failure)
	}
	err := c.m["a"].cli.Post(context.Background(), "b", contacts.AdmitPath, contacts.AdmitRequest{Proof: *original.Proof})
	if refusal, ok := err.(*federation.Error); !ok || refusal.Code != "ACCOUNT_FORK" {
		t.Fatalf("admit: %v", err)
	}
	forwarded := federation.NewRequest("a", original.DeliveryID, c.sender.ID, original.Destination, original.Kind, original.ExpiresAt, original.Envelope)
	forwarded.Bytes = original.Proof.Bytes
	forwarded.Admission, _ = wire.Enc.Marshal(original.Proof)
	if err := c.m["a"].cli.Send(context.Background(), "b", forwarded); err == nil {
		t.Fatal("forked forward accepted")
	}
	c.m["a"].out.Process(context.Background())
	if len(c.m["b"].box.List(c.recipent.ID)) != 0 {
		t.Fatal("queued sink bypassed fork")
	}
	c.to.Update(t, c.to.Recovery, func(s *accounts.State) { s.Nickname = "Recovered" })
	c.publish(t, c.to)
	if status, failure := c.drop(t, original); status != 202 {
		t.Fatalf("recovery replay: %d %s", status, failure)
	}
	// A direct retry of the exact signed delivery is authorized after RK resolution.
	if err := c.m["a"].cli.Send(context.Background(), "b", forwarded); err != nil {
		t.Fatal(err)
	}
	if len(c.m["b"].box.List(c.recipent.ID)) != 1 {
		t.Fatal("recovery did not resume delivery")
	}
}

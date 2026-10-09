package drop

import (
	"github.com/Flyozzzz/farlink-server/internal/spool"
	"testing"
)

func TestContactBatchByteAggregationCannotWrap(t *testing.T) {
	c := setup(t, "a", "b")
	c.m["a"].drop.Spool = batchSpool{c.sender.ID, map[string]spool.Info{
		string(sid(1)): {Bytes: ^uint64(0), ExpiresAt: c.expires, Recipients: [][]byte{c.recipent.ID}, Contact: c.binding()},
		string(sid(2)): {Bytes: 2, ExpiresAt: c.expires, Recipients: [][]byte{c.recipent.ID}, Contact: c.binding()},
	}}
	if status, failure := c.drop(t, c.batch(1, sid(1), sid(2))); status != 413 {
		t.Fatalf("wrapped accounting admitted: %d %s", status, failure)
	}
	if c.m["a"].out.Pending() != 0 || len(c.held("b")) != 0 {
		t.Fatal("overflow changed queue or relations")
	}
}

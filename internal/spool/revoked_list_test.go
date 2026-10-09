package spool

import (
	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"testing"
)

func TestRevokedSenderDoesNotPoisonListAndRecipientCanClean(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "uploading", true: "committed"}[committed], func(t *testing.T) {
			c := newContactSpool(t)
			f := c.f
			if committed {
				if status := testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(f.part.PartID)), f.tOwner, f.data, nil); status != 204 {
					t.Fatal(status)
				}
				if status := c.commit(t); status != 204 {
					t.Fatal(status)
				}
			}
			c.revokeSender(t)
			var list []ListItem
			if status := testutil.Do(t, "GET", f.srv.URL+"/v1/spools", f.tPeer, nil, &list); status != 200 || len(list) != 0 {
				t.Fatalf("list=%d %+v", status, list)
			}
			if status := testutil.Do(t, "DELETE", f.url(), f.tPeer, nil, nil); status != 204 {
				t.Fatalf("recipient cleanup: %d", status)
			}
		})
	}
}

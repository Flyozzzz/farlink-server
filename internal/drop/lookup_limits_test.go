package drop

import (
	"encoding/binary"
	"github.com/Flyozzzz/farlink-server/internal/contacts"
	"testing"
)

func TestUnknownAccountStateLookupsAreRateLimitedBeforeResolution(t *testing.T) {
	c := setup(t, "a", "b")
	token := insecureLogin(t, c.m["b"], c.sender)
	for i := range contacts.StatePerMinute + 1 {
		id := make([]byte, 32)
		binary.BigEndian.PutUint64(id, uint64(i+1))
		status, _ := post(t, c.m["b"].srv.URL+"/v1/contacts/state", token, contacts.StateRequest{Recipient: id, Action: "list"})
		if i == contacts.StatePerMinute && status != 429 {
			t.Fatalf("unknown recipient bypassed device/IP limit: %d", status)
		}
	}
}

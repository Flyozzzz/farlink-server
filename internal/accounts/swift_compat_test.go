package accounts

import (
	"os"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// The fixture is a chain the Swift client signed (genesis, add, add, revoke, recovery replace): the server must
// accept every link under the same rules, so the two implementations agree on the bytes.
func TestSwiftSignedChainIsAccepted(t *testing.T) {
	data, err := os.ReadFile("testdata/swift-chain.cbor")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		AccountID []byte   `cbor:"account_id"`
		Links     [][]byte `cbor:"links"`
	}
	if err := wire.Lenient(data, &f); err != nil || len(f.Links) != 6 {
		t.Fatalf("fixture: %v %d", err, len(f.Links))
	}
	reg, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i, raw := range f.Links {
		n, _, err := reg.Submit(raw)
		if err != nil || n != uint64(i) {
			t.Fatalf("link %d: n=%d err=%v", i, n, err)
		}
	}
	head, ok := reg.Head(f.AccountID)
	if !ok || head.Number != 5 || len(head.Devices) != 1 || head.Devices[0].Name != "New Mac" || len(head.Revoked) != 3 ||
		len(head.ContactMailboxes) != 2 || head.ContactMailboxes[0] != "https://a.farlink.pro:8443" {
		t.Fatalf("head = %+v", head)
	}
}

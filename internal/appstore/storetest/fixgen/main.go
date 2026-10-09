// Command fixgen writes StoreKit-shaped JWS fixtures signed by throwaway test chains, for the Swift client's
// offline license tests (Core/Tests/FarlinkGroupTests/Fixtures). Run: go run ./internal/appstore/storetest/fixgen <dir>
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/appstore/storetest"
	"github.com/Flyozzzz/farlink-server/internal/billing"
)

func main() {
	dir := os.Args[1]
	ca, other := storetest.New(storetest.Options{NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1)}), storetest.New(storetest.Options{})
	group := make([]byte, 16)
	for i := range group {
		group[i] = 7
	}
	tag := sha256.Sum256(append([]byte("farlink/billing/v1"), group...))
	teams := func(seats int, signed, expires time.Time, token string) storetest.Transaction {
		t := storetest.Subscription("com.flyoz.farlink", "com.flyoz.farlink.teams"+itoa(seats)+".yearly", "2000")
		t["purchaseDate"], t["signedDate"], t["expiresDate"] = storetest.Ms(signed), storetest.Ms(signed), storetest.Ms(expires)
		t["appAccountToken"] = token
		return t
	}
	tok := billing.BillingTokenFor(tag[:])
	fp := ca.Fingerprint()
	out := map[string]string{
		"root_sha256":   hex.EncodeToString(fp[:]),
		"group_id":      hex.EncodeToString(group),
		"teams5":        ca.Sign(teams(5, date(2026, 9, 1), date(2027, 9, 1), tok)),
		"teams5_lapsed": ca.Sign(teams(5, date(2025, 9, 1), date(2026, 9, 1), tok)),
		"teams5_other_network": ca.Sign(teams(5, date(2026, 9, 1), date(2027, 9, 1),
			billing.BillingTokenFor(make([]byte, 32)))),
		"teams5_wrong_root": other.Sign(teams(5, date(2026, 9, 1), date(2027, 9, 1), tok)),
	}
	sandbox := teams(5, date(2026, 9, 1), date(2027, 9, 1), tok)
	sandbox["environment"] = "Sandbox" // what every TestFlight purchase is
	out["teams5_sandbox"] = ca.Sign(sandbox)
	b, _ := json.MarshalIndent(out, "", "  ")
	os.WriteFile(filepath.Join(dir, "licenses.json"), append(b, '\n'), 0o644)
}

func date(y, m, d int) time.Time { return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC) }

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

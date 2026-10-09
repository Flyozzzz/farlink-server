package accounts

import (
	"github.com/Flyozzzz/farlink-server/internal/wire"
	"os"
	"strings"
	"testing"
)

func TestNegativeFixturesFromBothValidators(t *testing.T) {
	if os.Getenv("FARLINK_WRITE_NEGATIVE_FIXTURES") == "1" {
		first := newDev()
		g, _ := genesis(t, first, newDev())
		var rows [][]byte
		for _, name := range []string{strings.Repeat("a", 257), "a" + strings.Repeat("\u0301", 128)} {
			for _, deviceName := range []bool{false, true} {
				s := g
				s.Devices = append([]Device(nil), g.Devices...)
				if deviceName {
					s.Devices[0].Name = name
				} else {
					s.Nickname = name
				}
				rows = append(rows, sign(t, s, first))
			}
		}
		raw, err := wire.Enc.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("testdata/go-invalid.cbor", raw, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, producer := range []string{"go", "swift"} {
		raw, err := os.ReadFile("testdata/" + producer + "-invalid.cbor")
		if err != nil {
			t.Fatal(err)
		}
		var rows [][]byte
		if err := wire.Lenient(raw, &rows); err != nil {
			t.Fatal(err)
		}
		for i, row := range rows {
			if _, err := ParseLink(row); err == nil {
				t.Fatalf("%s fixture %d accepted", producer, i)
			}
		}
	}
}

package meter

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// flat stands in for the billing ledger: one allowance per device, used up once refused.
type flat struct {
	mu    sync.Mutex
	limit int64
	used  map[string]int64
	paid  map[string]bool
}

func newFlat(limit int64) *flat {
	return &flat{limit: limit, used: map[string]int64{}, paid: map[string]bool{}}
}

func (f *flat) Admit(d []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.used[string(d)] < f.limit
}
func (f *flat) Paid(d []byte) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.paid[string(d)] }
func (f *flat) Charge(d []byte, n int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.used[string(d)]+n > f.limit {
		return false
	}
	f.used[string(d)] += n
	return true
}

func TestDeviceAllowanceComesFromTheLedger(t *testing.T) {
	m, _ := Open("")
	m.Devices = newFlat(100)
	d, e := []byte("d"), []byte("e")
	if !m.Charge(d, "1.1.1.1", 60) || m.Charge(d, "1.1.1.1", 50) {
		t.Fatal("over-limit bytes were accepted")
	}
	if m.IPUsed("1.1.1.1") != 60 {
		t.Fatalf("bytes refused by the ledger were counted for the address: %d", m.IPUsed("1.1.1.1"))
	}
	if !m.Charge(e, "1.1.1.1", 100) {
		t.Fatal("quota is per device")
	}
}

// Fresh keys are free: the address and the server as a whole have their own budgets.
func TestFreshKeysShareTheAddressAndTotalBudget(t *testing.T) {
	m, _ := Open("")
	m.Devices, m.IPLimit, m.TotalLimit = newFlat(100), 150, 250
	if !m.Charge([]byte("a"), "ip1", 100) || !m.Charge([]byte("b"), "ip1", 40) {
		t.Fatal("within budgets refused")
	}
	if !m.Admit([]byte("fresh"), "ip1") {
		t.Fatal("address with room left refused")
	}
	if m.Charge([]byte("c"), "ip1", 20) {
		t.Fatal("address budget bypassed with a new key")
	}
	if m.Admit([]byte("fresh2"), "ip1") {
		t.Fatal("a used-up address still admits new keys")
	}
	if !m.Charge([]byte("d"), "ip2", 100) || m.Charge([]byte("e"), "ip3", 50) || m.Admit([]byte("f"), "ip4") {
		t.Fatal("total budget bypassed from other addresses")
	}
}

// A purchase can't be minted like a key: paid traffic isn't held to the per-address cap, only to the total.
func TestPaidTrafficIsNotHeldToTheAddressCap(t *testing.T) {
	f := newFlat(1 << 40)
	f.paid["office"] = true
	m, _ := Open("")
	m.Devices, m.IPLimit, m.TotalLimit = f, 100, 1000
	if !m.Charge([]byte("office"), "nat", 500) || !m.Admit([]byte("office"), "nat") {
		t.Fatal("paid device held to the address cap")
	}
	if m.IPUsed("nat") != 0 || m.Charge([]byte("office"), "nat", 600) {
		t.Fatal("paid traffic escaped the total")
	}
}

func TestCountsSurviveARestartAndRollOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.cbor")
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	m, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m.IPLimit, m.TotalLimit, m.Now = 100, 1000, func() time.Time { return now }
	if !m.Charge([]byte{0xff, 0x00}, "2001:db8::/64", 70) {
		t.Fatal("charge")
	}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	again.IPLimit, again.TotalLimit, again.Now = 100, 1000, func() time.Time { return now }
	if again.IPUsed("2001:db8::/64") != 70 || again.total != 70 {
		t.Fatalf("after restart: address %d total %d", again.IPUsed("2001:db8::/64"), again.total)
	}
	if again.Charge([]byte{1}, "2001:db8::/64", 40) {
		t.Fatal("restart forgave the month's usage")
	}
	next, _ := Open(path)
	next.IPLimit, next.Now = 100, func() time.Time { return now.AddDate(0, 1, 0) }
	if !next.Charge([]byte{1}, "2001:db8::/64", 100) {
		t.Fatal("an old month's file was not rolled over")
	}
}

func TestStoredCountsKeepRawKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.cbor")
	in := map[string]int64{string([]byte{0xff, 0xfe, 0x00}): 5, "text": 7}
	if err := StoreCounts(path, 42, in); err != nil {
		t.Fatal(err)
	}
	mo, out, err := LoadCounts(path)
	if err != nil || mo != 42 || len(out) != 2 || out[string([]byte{0xff, 0xfe, 0x00})] != 5 || out["text"] != 7 {
		t.Fatalf("round trip: %d %v %v", mo, out, err)
	}
	if _, empty, err := LoadCounts(filepath.Join(t.TempDir(), "missing")); err != nil || len(empty) != 0 {
		t.Fatal("a missing file is an empty month")
	}
}

func TestTrackedCountersAreBounded(t *testing.T) {
	m, _ := Open("")
	m.MaxTracked = 64
	for i := 0; i < 10_000; i++ {
		m.Charge(nil, string([]byte{byte(i), byte(i >> 8)}), 1)
	}
	m.mu.Lock()
	n := len(m.ips)
	m.mu.Unlock()
	if n > 64 {
		t.Fatalf("%d address counters kept", n)
	}
}

func TestConcurrentChargesAndSaves(t *testing.T) {
	m, _ := Open(filepath.Join(t.TempDir(), "t.cbor"))
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				m.Charge(nil, string(rune('a'+g)), 3)
				if i%100 == 0 {
					m.Save()
				}
			}
		}(g)
	}
	wg.Wait()
	m.Save()
	again, _ := Open(m.Path)
	if again.IPUsed("d") != 1500 || again.total != 8*1500 {
		t.Fatalf("saved %d / %d", again.IPUsed("d"), again.total)
	}
}

func TestOffCountsNothing(t *testing.T) {
	var m Meter = Off{}
	if !m.Charge([]byte("d"), "ip", 1<<62) || !m.Admit([]byte("d"), "ip") {
		t.Fatal("quotas off still metered")
	}
}

func (f *flat) ChargeOnce(d []byte, _ string, n int64) bool { return f.Charge(d, n) }

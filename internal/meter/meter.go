// Package meter is the one traffic meter every transport charges — WSS relay frames, TURN datagrams, spool
// downloads — so a device can't spend its allowance once per transport. Per-device (tier) allowances are the
// billing ledger's; this package adds what fresh keys can't get around: a monthly budget per client address
// and one for the whole server. Counts are persisted, so a restart doesn't forgive the month.
package meter

import (
	"errors"
	"github.com/Flyozzzz/farlink-server/internal/durable"
	"math"
	"os"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// Meter is what the transports call. ip is the client address bucket (wire.ClientIP) the bytes are billed to.
type Meter interface {
	// Admit reports whether device, calling from ip, may start something new (a relay session, a TURN
	// allocation or credentials, a spool reservation).
	Admit(device []byte, ip string) bool
	// Charge records n forwarded bytes; false means stop forwarding (the bytes were not recorded).
	Charge(device []byte, ip string, n int64) bool
	// ChargeAccount bills n bytes to what device's account may use this month and touches no address or server
	// counter: a queued file is billed once to its sender, however many devices download it. id names the logical
	// send: asking again with the same id (a retry after a crash or a lost answer) is answered yes and charges nothing.
	ChargeAccount(device []byte, id string, n int64) bool
	// ChargeTransit counts n physically forwarded bytes, sent for device, against the address and server caps
	// only (paid traffic is not held to the free-address cap, as in Charge).
	ChargeTransit(device []byte, ip string, n int64) bool
}

// Off is the self-hosting policy (-quotas off): nothing is metered. Connection, allocation and in-flight
// limits are separate and stay on.
type Off struct{}

func (Off) Admit([]byte, string) bool                { return true }
func (Off) Charge([]byte, string, int64) bool        { return true }
func (Off) ChargeAccount([]byte, string, int64) bool { return true }
func (Off) ChargeTransit([]byte, string, int64) bool { return true }

// Devices is the per-device allowance (billing.Ledger: tiers, pooled Teams quota, overdraft for the file in
// flight).
type Devices interface {
	Admit(device []byte) bool
	Charge(device []byte, n int64) bool
	// ChargeOnce is Charge for one logical send: the same id never charges twice.
	ChargeOnce(device []byte, id string, n int64) bool
	// Paid reports a purchased allowance. Purchases can't be minted like keys, so paid traffic is not held to
	// the per-address cap (a Teams office behind one NAT would hit it); it still counts toward the total.
	Paid(device []byte) bool
}

// MaxTracked bounds the address counters one month keeps. Past it, the smallest of a few sampled counters is
// forgotten; that can only forgive a light address, and the total budget still holds.
const MaxTracked = 1 << 20

// Traffic is the production Meter: Devices, then a hard monthly cap per client address (for free traffic)
// and for the server (calendar months, UTC). A zero limit means no cap at that level.
type Traffic struct {
	Devices    Devices // nil = no per-device allowance
	IPLimit    int64
	TotalLimit int64
	Now        func() time.Time
	Path       string // "" = memory only
	MaxTracked int

	saveMu sync.Mutex // one Save at a time, so an older snapshot never lands after a newer one
	mu     sync.Mutex
	month  int // year*12 + month of the counts below
	ips    map[string]int64
	total  int64
	dirty  bool
}

// totalKey holds the server total among the persisted counters; client address buckets never look like it.
const totalKey = "*"

// Open loads the counts saved at path, if any; an old month's file rolls over on first use.
func Open(path string) (*Traffic, error) {
	mo, counts, err := LoadCounts(path)
	if err != nil {
		return nil, err
	}
	t := &Traffic{Now: time.Now, Path: path, MaxTracked: MaxTracked, month: mo, ips: counts, total: counts[totalKey]}
	delete(t.ips, totalKey)
	return t, nil
}

// Month is the key monthly counters roll over on: calendar months in UTC.
func Month(now time.Time) int { t := now.UTC(); return t.Year()*12 + int(t.Month()) }

func (t *Traffic) roll() {
	if m := Month(t.Now()); m != t.month {
		t.month, t.ips, t.total, t.dirty = m, map[string]int64{}, 0, true
	}
}

func under(used, limit int64) bool { return limit <= 0 || used < limit }

func (t *Traffic) paid(device []byte) bool { return t.Devices != nil && t.Devices.Paid(device) }

func (t *Traffic) Admit(device []byte, ip string) bool {
	paid := t.paid(device)
	t.mu.Lock()
	t.roll()
	ok := (paid || under(t.ips[ip], t.IPLimit)) && under(t.total, t.TotalLimit)
	t.mu.Unlock()
	return ok && (t.Devices == nil || t.Devices.Admit(device))
}

// Charge refuses bytes past an address or server cap and pins that counter to its limit, so the next request
// is turned away up front. Devices is charged under the lock (it never calls back), so a refusal there leaves
// the address and total counts untouched.
func (t *Traffic) Charge(device []byte, ip string, n int64) bool {
	paid := t.paid(device)
	t.mu.Lock()
	t.roll()
	a := t.ips[ip]
	full := false
	if !paid && t.IPLimit > 0 && a+n > t.IPLimit {
		Bounded(t.ips, ip, t.MaxTracked, t.IPLimit)
		full = true
	}
	if t.TotalLimit > 0 && t.total+n > t.TotalLimit {
		t.total, full = t.TotalLimit, true
	}
	if full {
		t.dirty = true
		t.mu.Unlock()
		return false
	}
	// Counted before the device is charged, and given back if that is refused: the device's ledger may have to ask the
	// billing authority over the network, and this lock must not be held while it does.
	if !paid {
		Bounded(t.ips, ip, t.MaxTracked, a+n)
	}
	t.total += n
	t.dirty = true
	month := t.month
	t.mu.Unlock()
	if t.Devices != nil && !t.Devices.Charge(device, n) {
		t.mu.Lock()
		if t.month == month { // a rollback must not take bytes off the next month's counters
			if v, ok := t.ips[ip]; ok && !paid {
				t.ips[ip] = max(0, v-n)
			}
			t.total = max(0, t.total-n)
			t.dirty = true
		}
		t.mu.Unlock()
		return false
	}
	return true
}

// ChargeAccount bills the device's account; a refusal records nothing. No lock of this meter is held: the account's
// ledger may be asked over the network.
func (t *Traffic) ChargeAccount(device []byte, id string, n int64) bool {
	return t.Devices == nil || t.Devices.ChargeOnce(device, id, n)
}

// ChargeTransit counts n bytes the server really forwarded against the address and server caps. As in Charge,
// a counter past its limit is pinned there so the next request is turned away up front.
func (t *Traffic) ChargeTransit(device []byte, ip string, n int64) bool {
	paid := t.paid(device)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.roll()
	a := t.ips[ip]
	full := false
	if !paid && t.IPLimit > 0 && a+n > t.IPLimit {
		Bounded(t.ips, ip, t.MaxTracked, t.IPLimit)
		full = true
	}
	if t.TotalLimit > 0 && t.total+n > t.TotalLimit {
		t.total, full = t.TotalLimit, true
	}
	if full {
		t.dirty = true
		return false
	}
	if !paid {
		Bounded(t.ips, ip, t.MaxTracked, a+n)
	}
	t.total += n
	t.dirty = true
	return true
}

// Bounded stores v under k, first forgetting the smallest of a few (randomly iterated) other counters when
// counts already holds max of them.
func Bounded(counts map[string]int64, k string, max int, v int64) {
	if _, ok := counts[k]; !ok && max > 0 && len(counts) >= max {
		victim, least, seen := "", int64(math.MaxInt64), 0
		for key, used := range counts {
			if used < least {
				victim, least = key, used
			}
			if seen++; seen == 8 {
				break
			}
		}
		delete(counts, victim)
	}
	counts[k] = v
}

// IPUsed is what ip has been charged this month (tests, diagnostics).
func (t *Traffic) IPUsed(ip string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.roll()
	return t.ips[ip]
}

// Save writes the counts to Path if they changed since the last save.
func (t *Traffic) Save() error {
	t.saveMu.Lock()
	defer t.saveMu.Unlock()
	t.mu.Lock()
	if t.Path == "" || !t.dirty {
		t.mu.Unlock()
		return nil
	}
	counts := make(map[string]int64, len(t.ips)+1)
	for k, v := range t.ips {
		counts[k] = v
	}
	counts[totalKey] = t.total
	mo := t.month
	t.dirty = false
	t.mu.Unlock()
	if err := StoreCounts(t.Path, mo, counts); err != nil {
		t.mu.Lock()
		t.dirty = true
		t.mu.Unlock()
		return err
	}
	return nil
}

type entry struct {
	Key  []byte `cbor:"k"` // raw bytes: device ids are not text
	Used int64  `cbor:"n"`
}

type snapshot struct {
	Month  int     `cbor:"month"`
	Counts []entry `cbor:"counts"`
}

// LoadCounts reads what StoreCounts wrote at path: the month and its counters (empty without a file).
func LoadCounts(path string) (month int, counts map[string]int64, err error) {
	counts = map[string]int64{}
	if path == "" {
		return 0, counts, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, counts, nil
	}
	if err != nil {
		return 0, nil, err
	}
	var s snapshot
	if err := wire.Lenient(b, &s); err != nil {
		return 0, nil, err
	}
	for _, e := range s.Counts {
		counts[string(e.Key)] = e.Used
	}
	return s.Month, counts, nil
}

// StoreCounts atomically replaces path with month and counts.
func StoreCounts(path string, month int, counts map[string]int64) error {
	s := snapshot{Month: month, Counts: make([]entry, 0, len(counts))}
	for k, v := range counts {
		s.Counts = append(s.Counts, entry{[]byte(k), v})
	}
	b, err := wire.Enc.Marshal(s)
	if err != nil {
		return err
	}
	return durable.WriteFile(path, b)
}

// BillingUnavailable reports whether a refusal for device is only because the billing authority cannot be asked right
// now (not because the allowance is used up). Meters that cannot tell say false.
func BillingUnavailable(m Meter, device []byte) bool {
	if t, ok := m.(interface{ BillingUnavailable([]byte) bool }); ok {
		return t.BillingUnavailable(device)
	}
	return false
}

func (t *Traffic) BillingUnavailable(device []byte) bool {
	if u, ok := t.Devices.(interface{ BillingUnavailable([]byte) bool }); ok {
		return u.BillingUnavailable(device)
	}
	return false
}

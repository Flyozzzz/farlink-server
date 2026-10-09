package billing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/meter"
)

// Ledger counts server-forwarded bytes per bucket and UTC calendar month. With Path set the counts are saved
// (Save, every minute and at shutdown) and loaded back, so a restart doesn't forgive the month.
//
// The spec rule "the current file finishes, new ones go direct or wait" is split in two: Admit gates anything
// new (relay sessions, TURN allocations, spool uploads) on a bucket with room left; Charge keeps what was
// admitted running into an overdraft of up to one more limit, so a transfer is not cut mid-file, and only
// stops a session that runs past that.
//
// Account buckets (one per account, one per Teams network) are kept by the billing authority for the whole fleet. A
// server that is not the authority asks it for blocks of bytes (Grant) and spends them locally. A grant has an ID,
// and the authority remembers the answer to each ID in the same file as the counters, so asking again after a lost
// reply, a crash or a failed save gives the same answer and never a second grant. Nothing is ever given back or
// rolled back: bytes a server holds when it stops are simply spent (at most one block).
type Ledger struct {
	Buckets func(device []byte) []Bucket
	Now     func() time.Time
	Path    string // "" = memory only
	// MaxTracked bounds the device bucket counters (fresh keys each get a free one); past it the smallest of a few
	// is forgotten, which can only forgive a light user. Account counters and grant records are never forgotten:
	// when the table is full a grant is refused instead.
	MaxTracked int
	// Remote, when set, is the billing authority that keeps the counters of account buckets (nil: this server is
	// the authority, or the only server).
	Remote Remote
	// Block is how much is asked for at a time (default DefaultBlock).
	Block int64

	saveMu sync.Mutex
	mu     sync.Mutex
	month  int
	used   map[string]int64
	dirty  bool
	blocks map[string]*block // account bucket key -> bytes granted to this server and not spent yet
}

type block struct {
	left int64
	// month is the accounting period the bytes were granted for; a block from another month is not spendable.
	month int
}

// accountBucketPrefix names the one counter an account has per month, whatever it is entitled to: Free and Relay only
// differ in the limit it is held against, so upgrading in the middle of a month keeps what was already spent.
const accountBucketPrefix = "account:"

// teamsBucketPrefix: a Teams network's pooled counter, kept by the authority like an account's.
const teamsBucketPrefix = "teams:"

// MaxEntries bounds the counters and grant records of one month.
const MaxEntries = 4 << 20

// grantPrefix marks the record of an answered grant among the counters: the value is granted+1.
const grantPrefix = "g:"

func isAccountBucket(key string) bool {
	return strings.HasPrefix(key, accountBucketPrefix) || strings.HasPrefix(key, teamsBucketPrefix)
}

func (l *Ledger) remote(b Bucket) bool { return l.Remote != nil && isAccountBucket(b.Key) }

func NewLedger(buckets func([]byte) []Bucket) *Ledger {
	return &Ledger{Buckets: buckets, Now: time.Now, MaxTracked: meter.MaxTracked, used: map[string]int64{}}
}

// OpenLedger is NewLedger with the counts saved at path loaded back.
func OpenLedger(buckets func([]byte) []Bucket, path string) (*Ledger, error) {
	mo, used, err := meter.LoadCounts(path)
	if err != nil {
		return nil, err
	}
	l := NewLedger(buckets)
	l.Path, l.month, l.used = path, mo, used
	return l, nil
}

// Save writes the counts to Path if they changed since the last save.
func (l *Ledger) Save() error {
	l.saveMu.Lock()
	defer l.saveMu.Unlock()
	l.mu.Lock()
	if l.Path == "" || !l.dirty {
		l.mu.Unlock()
		return nil
	}
	used := make(map[string]int64, len(l.used))
	for k, v := range l.used {
		used[k] = v
	}
	mo := l.month
	l.dirty = false
	l.mu.Unlock()
	if err := meter.StoreCounts(l.Path, mo, used); err != nil {
		l.mu.Lock()
		l.dirty = true
		l.mu.Unlock()
		return err
	}
	return nil
}

func (l *Ledger) rollLocked() int {
	m := meter.Month(l.Now())
	if m != l.month {
		l.month, l.used, l.dirty = m, map[string]int64{}, true
		l.blocks = nil // they were granted against last month's counters
	}
	return m
}

func (l *Ledger) addLocked(key string, n int64) {
	meter.Bounded(l.used, key, l.MaxTracked, l.used[key]+n)
	l.dirty = true
}

// GrantRequest asks for Want bytes of the bucket Key, held against Limit (or twice it with Overdraft: the file that
// is already running finishes). With Exact the whole of Want or nothing. ID names the request: the same ID is
// answered with the first answer. Month is the accounting period the caller means.
type GrantRequest struct {
	ID        string `cbor:"id"`
	Month     int    `cbor:"month"`
	Key       string `cbor:"key"`
	Limit     int64  `cbor:"limit"`
	Want      int64  `cbor:"want"`
	Overdraft bool   `cbor:"overdraft,omitempty"`
	Exact     bool   `cbor:"exact,omitempty"`
}

// GrantResponse: Granted may be 0 (the allowance is used up, or the period is not the one asked for). Month is the
// authority's current period.
type GrantResponse struct {
	Granted int64 `cbor:"granted"`
	Month   int   `cbor:"month"`
}

var errLedgerFull = errors.New("billing: ledger full")

// GrantOnce is the authority's side (and a local bucket's): it answers a grant request at most once per ID, durably.
// It never undoes anything: if the save fails the grant stays applied in memory and asking again with the same ID
// returns it, so the caller can finish the same grant instead of making a second one.
func (l *Ledger) GrantOnce(req GrantRequest) (GrantResponse, error) {
	l.mu.Lock()
	month := l.rollLocked()
	if req.Month != month {
		l.mu.Unlock()
		return GrantResponse{Month: month}, nil
	}
	record := grantPrefix + req.ID
	if v, ok := l.used[record]; ok {
		l.mu.Unlock()
		// An earlier attempt may have failed to save, or a concurrent one may still be saving: Save waits for it and
		// retries a failed write, so a repeated answer is never given before it is on disk.
		if err := l.Save(); err != nil {
			return GrantResponse{}, err
		}
		return GrantResponse{Granted: v - 1, Month: month}, nil
	}
	if len(l.used) >= MaxEntries {
		l.mu.Unlock()
		return GrantResponse{}, errLedgerFull
	}
	ceiling := req.Limit
	if req.Overdraft {
		ceiling = 2 * req.Limit
	}
	head := max(0, ceiling-l.used[req.Key])
	granted := min(req.Want, head)
	if req.Exact && granted < req.Want {
		granted = 0
	}
	if granted > 0 {
		l.used[req.Key] += granted
	}
	l.used[record] = granted + 1
	l.dirty = true
	l.mu.Unlock()
	if err := l.Save(); err != nil { // the answer is a promise: it must survive a restart
		return GrantResponse{}, err
	}
	return GrantResponse{Granted: granted, Month: month}, nil
}

// grant asks the authority (or answers locally), repeating the same request once if the answer does not come.
func (l *Ledger) grant(b Bucket, req GrantRequest) (GrantResponse, bool) {
	for try := 0; try < 2; try++ {
		var resp GrantResponse
		var err error
		if l.remote(b) {
			resp, err = l.Remote.Grant(context.Background(), req)
		} else {
			resp, err = l.GrantOnce(req)
		}
		if err == nil {
			return resp, true
		}
	}
	return GrantResponse{}, false
}

func newID() string {
	raw := make([]byte, 16)
	rand.Read(raw)
	return hex.EncodeToString(raw)
}

// Admit reports whether device may start something new on our servers.
func (l *Ledger) Admit(device []byte) bool {
	bs := l.Buckets(device)
	for _, b := range bs {
		if l.remote(b) && l.remoteAdmit(b) {
			return true
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollLocked()
	for _, b := range bs {
		if !l.remote(b) && l.used[b.Key] < b.Limit {
			return true
		}
	}
	return false
}

// Charge bills n forwarded bytes to the first bucket with room; past every limit, to the first bucket still
// inside its overdraft. False means even that is used up: the caller stops forwarding.
func (l *Ledger) Charge(device []byte, n int64) bool {
	bs := l.Buckets(device)
	for _, overdraft := range []bool{false, true} {
		for _, b := range bs {
			if l.remote(b) {
				if l.remoteCharge(b, n, overdraft) {
					return true
				}
				continue
			}
			l.mu.Lock()
			l.rollLocked()
			ceiling := b.Limit
			if overdraft {
				ceiling = 2 * b.Limit
			}
			ok := l.used[b.Key]+n <= ceiling
			if ok {
				l.addLocked(b.Key, n)
			}
			l.mu.Unlock()
			if ok {
				return true
			}
		}
	}
	return false
}

// ChargeOnce bills n bytes to device's account for the logical send id, at most once however often it is asked: the
// same id answers yes without a second charge (a retry after a crash or a lost answer). The send is charged in full
// to the first bucket with room, the file that already runs going up to twice the limit.
func (l *Ledger) ChargeOnce(device []byte, id string, n int64) bool {
	if id == "" {
		return l.Charge(device, n)
	}
	bs := l.Buckets(device)
	l.mu.Lock()
	month := l.rollLocked()
	l.mu.Unlock()
	for _, overdraft := range []bool{false, true} {
		for _, b := range bs {
			req := GrantRequest{ID: id + "@" + b.Key, Month: month, Key: b.Key, Limit: b.Limit, Want: n, Overdraft: overdraft, Exact: true}
			if overdraft {
				req.ID += "!"
			}
			resp, answered := l.grant(b, req)
			if !answered {
				// The outcome is unknown (a lost reply, a failed save): that grant may exist. Trying another bucket or
				// the overdraft pass under another ID could charge the same send twice, so stop; the caller asks again
				// with the same id and gets the same answer.
				return false
			}
			if resp.Month == month && resp.Granted == n {
				return true
			}
		}
	}
	return false
}

func (l *Ledger) blockSize() int64 {
	if l.Block > 0 {
		return l.Block
	}
	return DefaultBlock
}

func (l *Ledger) blockLocked(key string, month int) *block {
	if l.blocks == nil {
		l.blocks = map[string]*block{}
	}
	bl := l.blocks[key]
	if bl == nil || bl.month != month {
		bl = &block{month: month}
		l.blocks[key] = bl
	}
	return bl
}

// remoteAdmit: an account bucket has room while a block has bytes left or the authority says the month is not used up.
// An unreachable authority admits nothing new.
func (l *Ledger) remoteAdmit(b Bucket) bool {
	l.mu.Lock()
	month := l.rollLocked()
	have := l.blockLocked(b.Key, month).left > 0
	l.mu.Unlock()
	if have {
		return true
	}
	used, usedMonth, err := l.Remote.Used(context.Background(), b.Key)
	return err == nil && usedMonth == month && used < b.Limit
}

// remoteCharge spends n from the bucket's block, asking the authority for another when it runs short. In the overdraft
// pass the grant may go up to twice the limit.
func (l *Ledger) remoteCharge(b Bucket, n int64, overdraft bool) bool {
	l.mu.Lock()
	month := l.rollLocked()
	bl := l.blockLocked(b.Key, month)
	if bl.left >= n {
		bl.left -= n
		l.mu.Unlock()
		return true
	}
	need := n - bl.left
	l.mu.Unlock()
	want := need
	if !overdraft {
		want = max(need, l.blockSize())
	}
	resp, answered := l.grant(b, GrantRequest{ID: newID(), Month: month, Key: b.Key, Limit: b.Limit, Want: want, Overdraft: overdraft})
	l.mu.Lock()
	defer l.mu.Unlock()
	if !answered || resp.Month != month || l.rollLocked() != month {
		return false // not answered, or the period turned: nothing to spend
	}
	bl = l.blockLocked(b.Key, month)
	bl.left += resp.Granted
	if bl.left >= n {
		bl.left -= n
		return true
	}
	return false // the rest of the allowance is granted by now; the next pass tries the overdraft
}

// UsedOf is what the bucket has been granted or has spent this month, and the period it is for.
func (l *Ledger) UsedOf(key string) (int64, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	month := l.rollLocked()
	return l.used[key], month
}

// Paid reports whether device draws on a purchased allowance (Relay or Teams), not only the free one.
func (l *Ledger) Paid(device []byte) bool {
	for _, b := range l.Buckets(device) {
		if b.Tier != "" {
			return true
		}
	}
	return false
}

// Exhausted is !Admit, for callers that phrase it as a refusal.
func (l *Ledger) Exhausted(device []byte) bool { return !l.Admit(device) }

// SpoolLimit is the spool storage device may hold: the best bucket it has.
func (l *Ledger) SpoolLimit(device []byte) int64 {
	var m int64
	for _, b := range l.Buckets(device) {
		m = max(m, b.Spool)
	}
	return m
}

// Balance is GET /v1/quota: the bucket device draws from now (the first with room, else the best one), what is
// used of it this month and when that resets.
type Balance struct {
	Unlimited   bool   `cbor:"unlimited"`
	Tier        string `cbor:"tier"` // "free", "relay", "teams"
	Limit       uint64 `cbor:"limit"`
	Used        uint64 `cbor:"used"`
	Exhausted   bool   `cbor:"exhausted"`
	PeriodStart uint64 `cbor:"period_start"`
	ResetsAt    uint64 `cbor:"resets_at"`
	SpoolLimit  uint64 `cbor:"spool_limit"`
	Seats       uint64 `cbor:"seats,omitempty"`     // Teams pack size
	TeamsPro    bool   `cbor:"teams_pro,omitempty"` // the network's Teams license gives this device Pro
	// Unavailable: the billing authority could not be asked, so how much is used is not known. It is not "used up":
	// new transfers wait and ask again, and a purchase would not help.
	Unavailable bool `cbor:"unavailable,omitempty"`
}

func (l *Ledger) Balance(device []byte) Balance {
	bs := l.Buckets(device)
	// Account buckets live on the authority: what it counts as used includes what this server holds unspent.
	remoteUsed := map[string]int64{}
	unknown := map[string]bool{} // buckets whose usage the authority could not tell us
	for _, b := range bs {
		if l.remote(b) {
			used, _, err := l.Remote.Used(context.Background(), b.Key)
			if err != nil {
				unknown[b.Key] = true // never make up room (admission still refuses), but do not claim it is used up
			}
			remoteUsed[b.Key] = used
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	month := l.rollLocked()
	usedOf := func(b Bucket) int64 {
		if u, ok := remoteUsed[b.Key]; ok {
			if bl := l.blocks[b.Key]; bl != nil && bl.month == month {
				u = max(0, u-bl.left)
			}
			return u
		}
		return l.used[b.Key]
	}
	pick := bs[0]
	exhausted := true
	unavailable := false
	for _, b := range bs {
		if unknown[b.Key] {
			pick, exhausted, unavailable = b, false, true
			break
		}
		if usedOf(b) < b.Limit {
			pick, exhausted = b, false
			break
		}
	}
	t := l.Now().UTC()
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	out := Balance{Tier: "free", Limit: uint64(pick.Limit), Used: uint64(min(usedOf(pick), pick.Limit)), Exhausted: exhausted,
		PeriodStart: uint64(start.UnixMilli()), ResetsAt: uint64(start.AddDate(0, 1, 0).UnixMilli())}
	if pick.Tier != "" {
		out.Tier = string(pick.Tier)
	}
	if unavailable {
		out.Unavailable, out.Used = true, 0
	}
	for _, b := range bs {
		out.SpoolLimit = max(out.SpoolLimit, uint64(b.Spool))
		if b.Tier == KindTeams {
			out.Seats, out.TeamsPro = uint64(b.Seats), true
		}
	}
	return out
}

// BillingUnavailable: the billing authority cannot be reached, so what is used is not known.
func (l *Ledger) BillingUnavailable(device []byte) bool { return l.Balance(device).Unavailable }

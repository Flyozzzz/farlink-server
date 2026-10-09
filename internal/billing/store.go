// Package billing turns verified App Store transactions into server resources (design §7.1–7.2, protocol v1
// §13): which quota bucket a device draws relay, TURN and spool bytes from. Entitlements never touch E2E
// authorization; a server started with quotas off (self-hosting) doesn't run this at all.
package billing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Flyozzzz/farlink-server/internal/durable"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/appstore"
)

type Kind string

const (
	KindPro   Kind = "pro" // device-side features only; no server resources
	KindRelay Kind = "relay"
	KindTeams Kind = "teams"
)

type Plan struct {
	Kind  Kind
	Seats int  // Teams: people the pack covers
	Max   bool // Relay: the large allowance (Relay Max) instead of the standard one
}

// Catalog maps App Store product IDs to plans (design §7.1). teams=false leaves Teams packs out.
func Catalog(prefix string, teams bool) map[string]Plan {
	c := map[string]Plan{
		prefix + ".pro":              {Kind: KindPro},
		prefix + ".trial14":          {Kind: KindPro},
		prefix + ".relay.monthly":    {Kind: KindRelay},
		prefix + ".relay.yearly":     {Kind: KindRelay},
		prefix + ".relaymax.monthly": {Kind: KindRelay, Max: true},
		prefix + ".relaymax.yearly":  {Kind: KindRelay, Max: true},
	}
	if teams {
		for _, n := range TeamsSizes {
			for _, period := range []string{"monthly", "yearly"} {
				c[fmt.Sprintf("%s.teams%d.%s", prefix, n, period)] = Plan{Kind: KindTeams, Seats: n}
			}
		}
	}
	return c
}

// TeamsSizes are the packs on sale; more than 50 people is invoiced outside the App Store.
var TeamsSizes = []int{3, 5, 10, 25, 50}

// Limits are per UTC calendar month. Relay traffic is counted in GiB (2^30 bytes): Free 10 GiB and Relay 200 GiB
// per account, however many devices it has; the queue sizes are still decimal (protocol v1 §13).
type Limits struct {
	FreeRelay, FreeSpool   int64 // per account (per device while a key is not bound to an account)
	RelayRelay, RelaySpool int64 // per subscription, shared by the devices that present it
	RelayMaxRelay          int64 // Relay Max: the large Relay allowance (2 TiB); 0 = not on sale
	TeamsPerPerson         int64 // pooled: seats × this for the whole network (Teams 3 = 600 GB … Teams 50 = 10 TB)
	TeamsSpool             int64 // per device of a Teams network
}

func DefaultLimits() Limits {
	return Limits{FreeRelay: 10 << 30, FreeSpool: 2e9, RelayRelay: 200 << 30, RelayMaxRelay: 2 << 40, RelaySpool: 20e9, TeamsPerPerson: 200e9, TeamsSpool: 20e9}
}

const (
	// A subscription's JWS can be copied; the pool is bounded anyway, and this bounds who draws from it.
	MaxDevicesPerSubscription = 32
	MaxDevices                = 1_000_000
	deviceIdle                = 90 * 24 * time.Hour
)

type Record struct {
	OriginalID string `json:"original_id"`
	ProductID  string `json:"product_id"`
	Kind       Kind   `json:"kind"`
	Seats      int    `json:"seats,omitempty"`
	Purchased  int64  `json:"purchased"`         // ms, of the transaction the record reflects
	Expires    int64  `json:"expires,omitempty"` // ms; 0 = no end
	Revoked    bool   `json:"revoked,omitempty"`
	// RevokedTx are the refunded or revoked transactions (id → revocation ms). A tombstone is never lifted: a
	// JWS of one of them, signed before the refund, can't bring the allowance back; only a later transaction
	// of the subscription (a real renewal or resubscription) does.
	RevokedTx map[string]int64 `json:"revoked_tx,omitempty"`
	Network   string           `json:"network,omitempty"` // Teams: hex billing tag the license is bound to
	Devices   map[string]int64 `json:"devices,omitempty"` // Relay: device (b64) → last presented, ms
	// Account (b64) owns a Relay subscription once an account-bound device presented it: every device of that account
	// then draws on it, and no other account can claim it.
	Account string `json:"account,omitempty"`
}

func (r *Record) active(now time.Time) bool {
	return !r.Revoked && (r.Expires == 0 || r.Expires > now.UnixMilli())
}

// revoke records a refund or revocation of tx (known to Apple's signature) for good. A refund of a period
// older than the one the record reflects only buries that transaction: the current period stays in force.
func (r *Record) revoke(tx *appstore.Transaction) {
	if r.RevokedTx == nil {
		r.RevokedTx = map[string]int64{}
	}
	if tx.TransactionID != "" {
		r.RevokedTx[tx.TransactionID] = tx.RevocationDate
	}
	if tx.PurchaseDate < r.Purchased {
		return
	}
	r.Revoked = true
}

// advance moves the record to tx if tx is not older. Only a strictly later, never revoked transaction lifts a
// revocation: presenting the same (or an older) signed transaction again changes nothing.
func (r *Record) advance(tx *appstore.Transaction, plan Plan) {
	if _, dead := r.RevokedTx[tx.TransactionID]; dead || tx.PurchaseDate < r.Purchased {
		return
	}
	if r.Revoked && tx.PurchaseDate == r.Purchased {
		return
	}
	r.ProductID, r.Kind, r.Seats, r.Purchased, r.Expires = tx.ProductID, plan.Kind, plan.Seats, tx.PurchaseDate, tx.ExpiresDate
	r.Revoked = false
}

type binding struct {
	Network string `json:"network,omitempty"` // hex billing tag
	Seen    int64  `json:"seen"`
}

// Store keeps verified entitlements, the membership head of each Teams network and which network each device
// said it is in; persisted to Path (JSON) so a restart doesn't take Teams away from members until their admin
// reconnects.
type Store struct {
	Verifier *appstore.Verifier
	Catalog  map[string]Plan
	Limits   Limits
	Now      func() time.Time
	Path     string
	// AccountOf names the Farlink account a transport key was proved to belong to (billing identity bindings).
	// Bound keys share one free allowance per account; a key that is not bound keeps its own.
	AccountOf func(transport []byte) ([]byte, bool)
	// RequireAccount: a key not bound to an account has no free allowance at all, so a fresh key cannot start a
	// new one. Off while self-hosting and until clients bind.
	RequireAccount bool

	mu      sync.Mutex
	records map[string]*Record      // original transaction id → record
	devices map[string]*binding     // device (b64) → network
	heads   map[string]*networkHead // network (hex tag) → newest verified membership head
	// Indexes over records, rebuilt on every change: Buckets runs for each forwarded frame.
	relayOf map[string][]string // device (b64) → subscriptions it presented
	// relayOfAccount: account (b64) → whether it owns an active Relay subscription, found at reindex time.
	relayOfAccount map[string][]string
	teamsOf        map[string]string // network (hex tag) → Teams subscription
}

func NewStore(v *appstore.Verifier, catalog map[string]Plan, limits Limits, path string) (*Store, error) {
	s := &Store{Verifier: v, Catalog: catalog, Limits: limits, Now: time.Now, Path: path,
		records: map[string]*Record{}, devices: map[string]*binding{}, heads: map[string]*networkHead{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("billing: %s: %w", path, err)
	}
	if st.Records != nil {
		s.records = st.Records
	}
	if st.Devices != nil {
		s.devices = st.Devices
	}
	for tag, h := range st.Heads {
		if h.load() == nil {
			s.heads[tag] = h
		}
	}
	s.reindexLocked()
	return s, nil
}

type state struct {
	Records map[string]*Record      `json:"records"`
	Devices map[string]*binding     `json:"devices"`
	Heads   map[string]*networkHead `json:"heads,omitempty"`
}

func (s *Store) reindexLocked() {
	s.relayOf, s.teamsOf, s.relayOfAccount = map[string][]string{}, map[string]string{}, map[string][]string{}
	for id, r := range s.records {
		switch r.Kind {
		case KindRelay:
			if r.Account != "" {
				s.relayOfAccount[r.Account] = append(s.relayOfAccount[r.Account], id)
				continue
			}
			for d := range r.Devices {
				s.relayOf[d] = append(s.relayOf[d], id)
			}
		case KindTeams:
			if old, ok := s.teamsOf[r.Network]; !ok || s.records[old].Expires < r.Expires {
				s.teamsOf[r.Network] = id
			}
		}
	}
}

// saveLocked reindexes and persists after a change.
func (s *Store) saveLocked() error {
	s.reindexLocked()
	if s.Path == "" {
		return nil
	}
	b, err := json.Marshal(state{s.records, s.devices, s.heads})
	if err != nil {
		return err
	}
	return durable.WriteFile(filepath.Clean(s.Path), b)
}

// BillingTokenFor is the appAccountToken a Teams purchase must carry for the network with this billing tag:
// the license binds to one network, and the server checks it without learning the group id.
func BillingTokenFor(tag []byte) string {
	h := sha256.Sum256(append([]byte("farlink/billing-token/v1"), tag...))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x80 // UUID version 8 (custom)
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	x := hex.EncodeToString(b)
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
}

// Result is what happened to one presented transaction.
type Result struct {
	ProductID string `cbor:"product_id,omitempty"`
	Kind      string `cbor:"kind,omitempty"`
	ExpiresAt uint64 `cbor:"expires_at,omitempty"`
	Code      string `cbor:"code,omitempty"` // empty = accepted
}

var b64 = base64.RawURLEncoding

// ChainResult is what the server made of a presented membership slice: Code empty = accepted (or nothing
// presented), Epoch the head it now knows for the network (0 with none), so the client sends from there.
type ChainResult struct {
	Code  string `cbor:"code,omitempty"`
	Epoch uint64 `cbor:"epoch"`
	Known bool   `cbor:"known"`
}

// Apply binds device to what the transactions grant. For Teams it takes the network's membership: chain (a
// contiguous slice of SignedMembership.encoded links) moves the server's head for the network forward, a Teams
// pack is bound to the network only when device is an admin of that head (the first head is accepted with it),
// and device draws from the pool only while the head lists it.
func (s *Store) Apply(device, network []byte, chain [][]byte, transactions []string) ([]Result, ChainResult, error) {
	now := s.Now()
	dev := b64.EncodeToString(device)
	tag := hex.EncodeToString(network)
	out := make([]Result, len(transactions))
	// Signatures of a long chain are checked outside the lock (Buckets takes it for every forwarded frame), and
	// again under it in the rare case another request moved the head meanwhile.
	var h *networkHead
	var err error
	s.mu.Lock()
	known := s.heads[tag]
	s.mu.Unlock()
	if len(network) == 32 && len(chain) > 0 {
		h, err = advance(network, known, chain, device)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.devices[dev]; !seen {
		s.gcLocked(now)
		if len(s.devices) >= MaxDevices {
			return nil, ChainResult{}, errors.New("billing: device table full")
		}
	}
	var cr ChainResult
	// pending: the presented head of a network the server doesn't know yet, accepted with its Teams pack.
	var pending *networkHead
	if len(network) == 32 && len(chain) > 0 {
		if s.heads[tag] != known {
			known = s.heads[tag]
			h, err = advance(network, known, chain, device)
		}
		switch {
		case err != nil:
			cr.Code = chainCode(err)
		case known == nil:
			pending = h
		default:
			s.heads[tag] = h
		}
	}
	for i, jws := range transactions {
		out[i] = s.applyLocked(dev, device, network, jws, now, &pending)
	}
	b := &binding{Seen: now.UnixMilli()}
	if h := s.heads[tag]; h != nil && h.isMember(device) {
		b.Network = tag
	}
	s.devices[dev] = b
	if h := s.heads[tag]; h != nil {
		cr.Epoch, cr.Known = h.Epoch, true
	}
	return out, cr, s.saveLocked()
}

func chainCode(err error) string {
	switch {
	case errors.Is(err, ErrChainGap):
		return "MEMBERSHIP_GAP"
	case errors.Is(err, ErrChainFork):
		return "MEMBERSHIP_FORK"
	case errors.Is(err, ErrOtherNet):
		return "NETWORK_MISMATCH"
	default:
		return "MEMBERSHIP_INVALID"
	}
}

func (s *Store) applyLocked(dev string, device, network []byte, jws string, now time.Time, pending **networkHead) Result {
	tx, err := s.Verifier.VerifyTransaction(jws)
	if tx == nil {
		return Result{Code: codeFor(err)}
	}
	res := Result{ProductID: tx.ProductID}
	plan, ok := s.Catalog[tx.ProductID]
	if !ok {
		res.Code = "UNKNOWN_PRODUCT"
		return res
	}
	res.Kind = string(plan.Kind)
	if e := tx.Expires(); !e.IsZero() {
		res.ExpiresAt = uint64(e.UnixMilli())
	}
	rec := s.records[tx.OriginalTransactionID]
	if errors.Is(err, appstore.ErrRevoked) {
		if rec == nil {
			rec = &Record{OriginalID: tx.OriginalTransactionID, ProductID: tx.ProductID, Kind: plan.Kind, Seats: plan.Seats, Purchased: tx.PurchaseDate}
			s.records[tx.OriginalTransactionID] = rec
		}
		rec.revoke(tx)
	}
	if err != nil {
		res.Code = codeFor(err)
		return res
	}
	if plan.Kind == KindPro {
		return res // nothing on the server; accepted so the client knows the JWS was fine
	}
	if tx.IsUpgraded {
		res.Code = "UPGRADED" // superseded by a later transaction of the same subscription
		return res
	}
	tag := hex.EncodeToString(network)
	if plan.Kind == KindTeams {
		if len(network) != 32 || !strings.EqualFold(tx.AppAccountToken, BillingTokenFor(network)) {
			res.Code = "NETWORK_MISMATCH"
			return res
		}
		// Knowing the tag (and even holding the pack's JWS, which sits in every member's chain) is not enough:
		// the pack goes to the network only from an admin of a verified head.
		h := s.heads[tag]
		if h == nil {
			h = *pending
		}
		if h == nil {
			res.Code = "MEMBERSHIP_REQUIRED"
			return res
		}
		if !h.isAdmin(device) {
			res.Code = "NOT_ADMIN"
			return res
		}
		if s.heads[tag] == nil {
			s.heads[tag], *pending = h, nil
		}
	}
	// Relay belongs to the account that presented it first; with accounts required, an unbound key presents nothing.
	var owner string
	if plan.Kind == KindRelay && s.AccountOf != nil {
		account, bound := s.AccountOf(device)
		switch {
		case !bound && s.RequireAccount:
			res.Code = "ACCOUNT_REQUIRED"
			return res
		case bound:
			owner = b64.EncodeToString(account)
			if rec != nil && rec.Account != "" && rec.Account != owner {
				res.Code = "OWNED_BY_ANOTHER_ACCOUNT"
				return res
			}
		}
	}
	if rec == nil {
		rec = &Record{OriginalID: tx.OriginalTransactionID}
		s.records[tx.OriginalTransactionID] = rec
	}
	if owner != "" && rec.Account == "" {
		rec.Account = owner
	}
	rec.advance(tx, plan)
	if _, dead := rec.RevokedTx[tx.TransactionID]; dead || (rec.Revoked && rec.Purchased >= tx.PurchaseDate) {
		res.Code = "REVOKED"
		return res
	}
	if plan.Kind == KindTeams {
		rec.Network = tag
	} else {
		if rec.Devices == nil {
			rec.Devices = map[string]int64{}
		}
		rec.Devices[dev] = now.UnixMilli()
		for len(rec.Devices) > MaxDevicesPerSubscription {
			oldest, at := "", int64(1<<62)
			for d, t := range rec.Devices {
				if t < at {
					oldest, at = d, t
				}
			}
			delete(rec.Devices, oldest)
		}
	}
	return res
}

func codeFor(err error) string {
	switch {
	case errors.Is(err, appstore.ErrRevoked):
		return "REVOKED"
	case errors.Is(err, appstore.ErrExpired):
		return "EXPIRED"
	case errors.Is(err, appstore.ErrBundle), errors.Is(err, appstore.ErrEnvironment):
		return "WRONG_APP"
	default:
		return "SIGNATURE_INVALID"
	}
}

// Notify applies a verified App Store Server Notification's transaction (refund, revoke, renewal, expiry). A
// refund of a subscription we don't know yet is kept as a tombstone, so its JWS presented later grants nothing;
// other unknown transactions are ignored (a device presenting them later is verified then).
func (s *Store) Notify(tx *appstore.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.records[tx.OriginalTransactionID]
	if rec == nil {
		if tx.RevocationDate == 0 {
			return nil
		}
		rec = &Record{OriginalID: tx.OriginalTransactionID, ProductID: tx.ProductID, Purchased: tx.PurchaseDate}
		if p, ok := s.Catalog[tx.ProductID]; ok {
			rec.Kind, rec.Seats = p.Kind, p.Seats
		}
		s.records[tx.OriginalTransactionID] = rec
	}
	if tx.RevocationDate != 0 {
		rec.revoke(tx)
		if tx.PurchaseDate > rec.Purchased {
			rec.Purchased = tx.PurchaseDate
		}
	} else if p, ok := s.Catalog[tx.ProductID]; ok && p.Kind == rec.Kind {
		rec.advance(tx, p)
	}
	return s.saveLocked()
}

// Bucket is one pool of monthly bytes a device may draw from.
type Bucket struct {
	Key   string
	Tier  Kind // "" for free
	Seats int  // Teams pack size
	Limit int64
	Spool int64 // spool storage the device may hold
}

// relayLimit is the monthly allowance of one Relay subscription record: Relay Max has the large one when it is on sale.
func (s *Store) relayLimit(r *Record) int64 {
	if p, ok := s.Catalog[r.ProductID]; ok && p.Max && s.Limits.RelayMaxRelay > 0 {
		return s.Limits.RelayMaxRelay
	}
	return s.Limits.RelayRelay
}

// Buckets lists what device may use, best first: its own Relay subscription, its network's Teams pool, and
// always the free allowance last.
func (s *Store) Buckets(device []byte) []Bucket {
	now := s.Now()
	dev := b64.EncodeToString(device)
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Bucket
	var account []byte
	bound := false
	if s.AccountOf != nil {
		account, bound = s.AccountOf(device)
	}
	paid := false
	if bound {
		// One pool per account, whatever number of subscriptions it holds: they do not stack.
		acct := b64.EncodeToString(account)
		limit := int64(0)
		for _, id := range s.relayOfAccount[acct] {
			if r := s.records[id]; r != nil && r.active(now) {
				// Subscriptions do not stack, but the larger one wins: Relay Max beats Relay.
				if l := s.relayLimit(r); l > limit {
					limit = l
				}
				paid = true
			}
		}
		if paid {
			out = append(out, Bucket{Key: accountBucketPrefix + acct, Tier: KindRelay, Limit: limit, Spool: s.Limits.RelaySpool})
		}
	} else {
		for _, id := range s.relayOf[dev] {
			if r := s.records[id]; r != nil && r.active(now) {
				out = append(out, Bucket{Key: "relay:" + id, Tier: KindRelay, Limit: s.relayLimit(r), Spool: s.Limits.RelaySpool})
			}
		}
	}
	// Only while the newest head the server verified lists the device: a revoke reaches the pool as soon as
	// any member or admin presents the head that made it.
	if b := s.devices[dev]; b != nil && b.Network != "" && s.heads[b.Network] != nil && s.heads[b.Network].isMember(device) {
		if r := s.records[s.teamsOf[b.Network]]; r != nil && r.active(now) {
			out = append(out, Bucket{Key: "teams:" + b.Network, Tier: KindTeams, Seats: r.Seats,
				Limit: int64(r.Seats) * s.Limits.TeamsPerPerson, Spool: s.Limits.TeamsSpool})
		}
	}
	if paid {
		return out // the paid allowance replaces the free one: 200 GiB in all, not 200 and 10 more
	}
	free, limit, spool := "free:"+dev, s.Limits.FreeRelay, s.Limits.FreeSpool
	if bound {
		free = accountBucketPrefix + b64.EncodeToString(account)
	} else if s.AccountOf != nil && s.RequireAccount {
		free, limit, spool = "unbound:"+dev, 0, 0
	}
	return append(out, Bucket{Key: free, Limit: limit, Spool: spool})
}

func (s *Store) gcLocked(now time.Time) {
	for d, b := range s.devices {
		if now.Sub(time.UnixMilli(b.Seen)) > deviceIdle {
			delete(s.devices, d)
		}
	}
}

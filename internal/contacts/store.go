// Package contacts is the authority side of Contacts (protocol v1 §17): per (recipient, sender) pair it keeps
// the state that decides whether a sender may deliver — pending, accepted, declined or removed — with a
// generation counter so that decisions made on different devices can't overwrite each other.
package contacts

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/federation"
)

const (
	MaxContacts    = 500
	MaxPending     = 50
	MaxRecords     = 2000 // live contacts plus the block-list tombstones that must outlive them
	MaxFirstBytes  = 100 << 20
	RetryAfter     = 24 * time.Hour
	MaxPendingLife = 7 * 24 * time.Hour
	MaxPageSize    = 200
	metaName       = "meta"
)

type State string

const (
	None     State = ""
	Pending  State = "pending"
	Accepted State = "accepted"
	Declined State = "declined"
	Removed  State = "removed"
)

type Action string

const (
	ActGet     Action = "get"
	ActAccept  Action = "accept"
	ActDecline Action = "decline"
	ActRemove  Action = "remove"
	ActForget  Action = "forget"
)

// Record is the whole state of one pair. Generation is drawn from a counter that only grows for the whole
// recipient, so a value is never reused, not even after the pair is forgotten and comes back.
type Record struct {
	Recipient       []byte `cbor:"recipient_account"`
	Sender          []byte `cbor:"sender_account"`
	Generation      uint64 `cbor:"generation"`
	State           State  `cbor:"state"`
	PendingDelivery []byte `cbor:"pending_delivery,omitempty"`
	PendingBytes    uint64 `cbor:"pending_bytes,omitempty"`
	PendingExpires  uint64 `cbor:"pending_expires,omitempty"`
	RetryAfter      uint64 `cbor:"retry_after,omitempty"`
	UpdatedAt       uint64 `cbor:"updated_at"`
}

// meta keeps the recipient's generation floor even after every pair is forgotten.
type meta struct {
	Clock uint64 `cbor:"clock"`
}

var (
	ErrStale    = &federation.Error{Status: 409, Code: "STALE_GENERATION"}
	ErrLimit    = &federation.Error{Status: 429, Code: "CONTACT_LIMIT"}
	errInternal = &federation.Error{Status: 503, Code: "INTERNAL", Retryable: true}
)

type Store struct {
	Now func() time.Time

	dir         string
	mu          sync.Mutex
	by          map[string]map[string]*Record // recipient -> sender -> record
	metas       map[string]*meta
	authorities map[string]*authorityState
}

// Open loads every record. An unreadable record stops the server: silently skipping it would let a sender the
// person removed deliver again, and "unknown" must never turn into "allowed".
func Open(dir string) (*Store, error) {
	return openStore(dir)
}

func (s *Store) now() uint64 {
	if s.Now != nil {
		return uint64(s.Now().UnixMilli())
	}
	return uint64(time.Now().UnixMilli())
}

func (s *Store) meta(recipient []byte) *meta {
	m := s.metas[string(recipient)]
	if m == nil {
		m = &meta{}
		s.metas[string(recipient)] = m
	}
	return m
}

func (s *Store) put(r *Record) {
	m := s.by[string(r.Recipient)]
	if m == nil {
		m = map[string]*Record{}
		s.by[string(r.Recipient)] = m
	}
	m[string(r.Sender)] = r
}

func (s *Store) get(recipient, sender []byte) *Record { return s.by[string(recipient)][string(sender)] }

// live says whether r takes up one of the recipient's contact places.
func live(r *Record, now uint64) bool {
	return r.State == Accepted || (r.State == Pending && now < r.PendingExpires)
}

// count is how many contacts recipient has, not counting except (the pair being decided).
func (s *Store) count(recipient, except []byte, now uint64) int {
	n := 0
	for k, r := range s.by[string(recipient)] {
		if k != string(except) && live(r, now) {
			n++
		}
	}
	return n
}

// room makes space for one more record of recipient, dropping only records that no longer mean anything:
// a decline whose wait is over and a pending batch that expired. Removed senders stay until the person
// forgets them, so the block list cannot be pushed out by an attacker filling it.
func (s *Store) room(recipient []byte, now uint64) error {
	m := s.by[string(recipient)]
	if len(m) < MaxRecords {
		return nil
	}
	for k, r := range m {
		if (r.State == Declined && now >= r.RetryAfter) || (r.State == Pending && now >= r.PendingExpires) {
			if s.remove(r) == nil {
				delete(m, k)
				if len(m) < MaxRecords {
					return nil
				}
			}
		}
	}
	if len(m) < MaxRecords {
		return nil
	}
	return ErrLimit
}

func (s *Store) path(recipient []byte, name string) string {
	return filepath.Join(s.dir, hex.EncodeToString(recipient), name)
}

func (s *Store) remove(r *Record) error {
	snapshot := s.snapshot(r.Recipient)
	for i, record := range snapshot.Records {
		if bytes.Equal(record.Sender, r.Sender) {
			snapshot.Records = append(snapshot.Records[:i], snapshot.Records[i+1:]...)
			break
		}
	}
	return s.persist(snapshot)
}

func (s *Store) write(recipient []byte, name string, v any) error {
	snapshot := s.snapshot(recipient)
	if name == metaName {
		snapshot.Clock = v.(*meta).Clock
	} else {
		next := *v.(*Record)
		found := false
		for i, record := range snapshot.Records {
			if bytes.Equal(record.Sender, next.Sender) {
				snapshot.Records[i] = next
				found = true
				break
			}
		}
		if !found {
			snapshot.Records = append(snapshot.Records, next)
		}
		snapshot.Clock = max(snapshot.Clock, next.Generation)
	}
	return s.persist(snapshot)
}

// commit makes next the record of its pair, under a fresh generation. Nothing changes if the write fails.
func (s *Store) commit(next *Record) error {
	m := s.meta(next.Recipient)
	if m.Clock == ^uint64(0) {
		return ErrLimit
	}
	next.Generation = m.Clock + 1
	if err := s.write(next.Recipient, hex.EncodeToString(next.Sender), next); err != nil {
		return errInternal
	}
	m.Clock = next.Generation
	s.put(next)
	return nil
}

// Admit decides whether sender may deliver a batch of the given size to recipient right now, recording a
// first contact as pending until the batch itself expires. The same delivery id is always answered the same
// way while it is the pending batch.
func (s *Store) Admit(recipient, sender, delivery []byte, size, expires uint64, authority ...accounts.HeadRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fenced(recipient, authority...) {
		return ErrMigration
	}
	now := s.now()
	cur := s.get(recipient, sender)
	next := Record{Recipient: recipient, Sender: sender}
	if cur != nil {
		next = *cur
	}
	next.UpdatedAt = now
	switch next.State {
	case Accepted:
		return nil
	case Removed:
		return &federation.Error{Status: 403, Code: "CONTACT_REMOVED"}
	case Declined:
		if now < next.RetryAfter {
			return &federation.Error{Status: 403, Code: "CONTACT_DECLINED"}
		}
		next.State = None
	case Pending:
		if now < next.PendingExpires {
			if !bytes.Equal(next.PendingDelivery, delivery) {
				return &federation.Error{Status: 409, Code: "CONTACT_PENDING"}
			}
			if size != next.PendingBytes {
				return &federation.Error{Status: 409, Code: "DELIVERY_CONFLICT"}
			}
			if size > MaxFirstBytes {
				return &federation.Error{Status: 413, Code: "CONTACT_TOO_LARGE"}
			}
			return nil
		}
		next.State = None // the unanswered batch has expired out of every queue; a new one may start
	}
	if size > MaxFirstBytes {
		return &federation.Error{Status: 413, Code: "CONTACT_TOO_LARGE"}
	}
	if s.count(recipient, sender, now) >= MaxContacts {
		return ErrLimit
	}
	pending := 0
	for _, record := range s.by[string(recipient)] {
		if record.State == Pending && now < record.PendingExpires {
			pending++
		}
	}
	if pending >= MaxPending {
		return &federation.Error{Status: 429, Code: "CONTACT_REQUEST_LIMIT"}
	}
	if cur == nil {
		if err := s.room(recipient, now); err != nil {
			return err
		}
	}
	next.State = Pending
	next.PendingDelivery = bytes.Clone(delivery)
	next.PendingBytes = size
	next.PendingExpires = min(now+uint64(MaxPendingLife.Milliseconds()), expires)
	next.RetryAfter = 0
	return s.commit(&next)
}

// AdmitControl lets conversation upkeep through for a sender the recipient accepted. It never records anything: a
// receipt or an update of devices must not take the one place a first request waits in.
func (s *Store) AdmitControl(recipient, sender []byte, authority ...accounts.HeadRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fenced(recipient, authority...) {
		return ErrMigration
	}
	cur := s.get(recipient, sender)
	switch {
	case cur != nil && cur.State == Accepted:
		return nil
	case cur != nil && cur.State == Removed:
		return &federation.Error{Status: 403, Code: "CONTACT_REMOVED"}
	default:
		return &federation.Error{Status: 403, Code: "CONTACT_NOT_ACCEPTED"}
	}
}

// Apply is a decision by the recipient's person. expected is the generation the caller saw (0: no record);
// a mismatch is STALE_GENERATION and changes nothing, so two devices can't both win.
func (s *Store) Apply(recipient, sender []byte, act Action, expected uint64, authority ...accounts.HeadRef) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fenced(recipient, authority...) {
		return Record{}, ErrMigration
	}
	cur := s.get(recipient, sender)
	var have uint64
	if cur != nil {
		have = cur.Generation
	}
	if act == ActGet {
		if cur == nil {
			return Record{Recipient: recipient, Sender: sender}, nil
		}
		return *cur, nil
	}
	if expected != have {
		return Record{}, ErrStale
	}
	now := s.now()
	next := Record{Recipient: recipient, Sender: sender}
	if cur != nil {
		next = *cur
	}
	next.UpdatedAt = now
	switch act {
	case ActAccept:
		if cur != nil && cur.State == Accepted {
			return *cur, nil
		}
		if s.count(recipient, sender, now) >= MaxContacts {
			return Record{}, ErrLimit
		}
		next.State = Accepted
		next.PendingDelivery, next.PendingBytes, next.PendingExpires, next.RetryAfter = nil, 0, 0, 0
	case ActDecline:
		if cur == nil || cur.State != Pending {
			return Record{}, &federation.Error{Status: 409, Code: "INVALID_STATE"}
		}
		next.State = Declined
		next.PendingDelivery, next.PendingBytes, next.PendingExpires = nil, 0, 0
		next.RetryAfter = now + uint64(RetryAfter.Milliseconds())
	case ActRemove:
		if cur != nil && cur.State == Removed {
			return *cur, nil
		}
		next.State = Removed
		next.PendingDelivery, next.PendingBytes, next.PendingExpires, next.RetryAfter = nil, 0, 0, 0
	case ActForget:
		if cur == nil || (cur.State != Declined && cur.State != Removed) {
			return Record{}, &federation.Error{Status: 409, Code: "INVALID_STATE"}
		}
		// The counter is saved before the record goes, so that a crash in between cannot let the pair come
		// back under a generation some device already holds.
		m := s.meta(recipient)
		if m.Clock == ^uint64(0) {
			return Record{}, ErrLimit
		}
		m.Clock++
		if err := s.write(recipient, metaName, m); err != nil {
			m.Clock--
			return Record{}, errInternal
		}
		if err := s.remove(cur); err != nil {
			return Record{}, errInternal
		}
		delete(s.by[string(recipient)], string(sender))
		return Record{Recipient: recipient, Sender: sender}, nil
	default:
		return Record{}, &federation.Error{Status: 400, Code: "INVALID_ENCODING"}
	}
	if cur == nil {
		if err := s.room(recipient, now); err != nil {
			return Record{}, err
		}
	}
	if err := s.commit(&next); err != nil {
		return Record{}, err
	}
	return next, nil
}

// Count is how many contacts (pending or accepted) recipient has.
func (s *Store) Count(recipient []byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count(recipient, nil, s.now())
}

// List returns up to limit records of recipient ordered by sender, starting after cursor, with the cursor for the
// next page (nil at the end).
func (s *Store) List(recipient, cursor []byte, limit int, authority ...accounts.HeadRef) (page []Record, next []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fenced(recipient, authority...) {
		return nil, nil, ErrMigration
	}
	if limit <= 0 || limit > MaxPageSize {
		limit = MaxPageSize
	}
	all := make([]*Record, 0, len(s.by[string(recipient)]))
	for _, r := range s.by[string(recipient)] {
		if bytes.Compare(r.Sender, cursor) > 0 {
			all = append(all, r)
		}
	}
	sort.Slice(all, func(i, j int) bool { return bytes.Compare(all[i].Sender, all[j].Sender) < 0 })
	if len(all) > limit {
		all, next = all[:limit], bytes.Clone(all[limit-1].Sender)
	}
	page = make([]Record, len(all))
	for i, r := range all {
		page[i] = *r
	}
	return page, next, nil
}

// PurgeAccount erases everything kept for an account that was deleted: its own relations and every record other people
// hold about it.
func (s *Store) PurgeAccount(account []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.RemoveAll(filepath.Join(s.dir, hex.EncodeToString(account))); err != nil {
		return err
	}
	if err := durable.SyncDir(s.dir); err != nil {
		return err
	}
	delete(s.by, string(account))
	delete(s.metas, string(account))
	delete(s.authorities, string(account))
	for _, m := range s.by {
		if r := m[string(account)]; r != nil {
			if err := s.remove(r); err != nil {
				return err
			}
			delete(m, string(account))
		}
	}
	return nil
}

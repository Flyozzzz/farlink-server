// Package mailbox is the durable hint queue of protocol v1 §17.4: small sealed envelopes ("a file is waiting
// for you at server X") kept up to their expiry (at most 7 days) for a device that is asleep or elsewhere.
// It never holds file bytes — those stay in the origin server's spool.
package mailbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	MaxEnvelope   = 32 << 10
	MaxLifetime   = 7 * 24 * time.Hour
	PerDevice     = 512     // live items for one device
	PerDeviceByte = 4 << 20 // bytes for one device
	PerSender     = 32      // live items from one sender device to one recipient device
	TotalBytes    = 1 << 30
	itemOverhead  = 256
)

var (
	ErrFull    = errors.New("QUOTA_EXCEEDED")
	ErrTooBig  = errors.New("LIMIT_EXCEEDED")
	ErrExpired = errors.New("EXPIRED")
	ErrInvalid = errors.New("INVALID_ENCODING")
	ErrGone    = errors.New("ACCOUNT_DELETED")
)

// Item is one envelope waiting for Dest. Sender is the authenticated device that dropped it on its origin.
type Item struct {
	DeliveryID []byte `cbor:"delivery_id"`
	Origin     string `cbor:"origin_server"`
	Sender     []byte `cbor:"sender_device"`
	Dest       []byte `cbor:"destination_device"`
	ExpiresAt  uint64 `cbor:"expires_at"`
	ReceivedAt uint64 `cbor:"received_at"`
	Kind       string `cbor:"kind"`
	SpoolID    []byte `cbor:"spool_id,omitempty"`
	Bytes      uint64 `cbor:"bytes,omitempty"`
	Envelope   []byte `cbor:"envelope"`
	Admission  []byte `cbor:"admission,omitempty"`
	Acked      bool   `cbor:"acked"`
}

// ID names an item for its recipient (the ack handle) and for duplicate detection.
func ID(sender, dest, deliveryID []byte) []byte {
	h := sha256.New()
	h.Write([]byte("farlink/mailbox/item/v1"))
	h.Write(sender)
	h.Write(dest)
	h.Write(deliveryID)
	return h.Sum(nil)
}

func (i *Item) id() []byte { return ID(i.Sender, i.Dest, i.DeliveryID) }

func (i *Item) cost() int64 { return int64(len(i.Envelope)+len(i.Admission)) + itemOverhead }

type Store struct {
	Now func() time.Time
	// OnPut runs (outside the lock) when a new item becomes visible to dest: wakes a connected device.
	OnPut func(dest []byte)

	// Deny says a device belongs to a deleted account: nothing is stored for it or from it.
	Deny func(device []byte) bool

	MaxPerDevice, MaxPerSender int
	MaxDeviceBytes, MaxBytes   int64

	dir   string
	mu    sync.Mutex
	items map[string]map[string]*Item // dest → item id → item
	bytes int64
}

func Open(dir string) (*Store, error) {
	s := &Store{Now: time.Now, MaxPerDevice: PerDevice, MaxPerSender: PerSender, MaxDeviceBytes: PerDeviceByte, MaxBytes: TotalBytes,
		dir: dir, items: map[string]map[string]*Item{}}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	devs, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		if !d.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, d.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			p := filepath.Join(dir, d.Name(), f.Name())
			data, err := os.ReadFile(p)
			var it Item
			if err != nil || wire.Lenient(data, &it) != nil || len(it.Dest) != 32 || hex.EncodeToString(it.Dest) != d.Name() ||
				hex.EncodeToString(it.id()) != f.Name() {
				os.Rename(p, p+".corrupt")
				continue
			}
			s.attach(&it)
		}
	}
	return s, nil
}

func (s *Store) attach(it *Item) {
	m := s.items[string(it.Dest)]
	if m == nil {
		m = map[string]*Item{}
		s.items[string(it.Dest)] = m
	}
	m[string(it.id())] = it
	s.bytes += it.cost()
}

func (s *Store) path(it *Item) string {
	return filepath.Join(s.dir, hex.EncodeToString(it.Dest), hex.EncodeToString(it.id()))
}

func (s *Store) write(it *Item) error {
	b, err := wire.Enc.Marshal(it)
	if err != nil {
		return err
	}
	p := s.path(it)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return durable.WriteFile(p, b)
}

func (s *Store) live(it *Item) bool { return uint64(s.Now().UnixMilli()) < it.ExpiresAt }

// Put stores it once: a repeat of the same (sender, destination, delivery_id) — a retry, or the copy that
// came through another server — is accepted and reported as not new. The bool is true when the item is new.
func (s *Store) Put(it Item) (bool, error) {
	now := uint64(s.Now().UnixMilli())
	if len(it.DeliveryID) != 16 || len(it.Sender) != 32 || len(it.Dest) != 32 || it.Origin == "" || len(it.Origin) > 300 ||
		len(it.Kind) == 0 || len(it.Kind) > 32 || (len(it.SpoolID) != 0 && len(it.SpoolID) != 16) || len(it.Envelope) == 0 {
		return false, ErrInvalid
	}
	if s.Deny != nil && (s.Deny(it.Dest) || s.Deny(it.Sender)) {
		return false, ErrGone
	}
	if len(it.Envelope) > MaxEnvelope {
		return false, ErrTooBig
	}
	if len(it.Admission) > 8<<10 {
		return false, ErrTooBig
	}
	if it.ExpiresAt <= now {
		return false, ErrExpired
	}
	if it.ExpiresAt > now+uint64(MaxLifetime.Milliseconds()) {
		it.ExpiresAt = now + uint64(MaxLifetime.Milliseconds())
	}
	it.ReceivedAt, it.Acked = now, false
	s.mu.Lock()
	s.gcLocked(it.Dest)
	if old := s.items[string(it.Dest)][string(it.id())]; old != nil {
		s.mu.Unlock()
		return false, nil // includes an acked one: its record stays until expiry exactly to catch late retries
	}
	c := it.cost()
	var devBytes int64
	perSender := 0
	live := 0
	for _, o := range s.items[string(it.Dest)] {
		if o.Acked {
			continue
		}
		live++
		devBytes += o.cost()
		if string(o.Sender) == string(it.Sender) {
			perSender++
		}
	}
	if live >= s.MaxPerDevice || perSender >= s.MaxPerSender || devBytes+c > s.MaxDeviceBytes || s.bytes+c > s.MaxBytes {
		s.mu.Unlock()
		return false, ErrFull
	}
	if err := s.write(&it); err != nil {
		s.mu.Unlock()
		return false, err
	}
	s.attach(&it)
	s.mu.Unlock()
	if s.OnPut != nil {
		s.OnPut(it.Dest)
	}
	return true, nil
}

// List returns dest's waiting items, oldest first.
func (s *Store) List(dest []byte) []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(dest)
	var out []Item
	for _, it := range s.items[string(dest)] {
		if !it.Acked {
			out = append(out, *it)
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].ReceivedAt != out[b].ReceivedAt {
			return out[a].ReceivedAt < out[b].ReceivedAt
		}
		return string(out[a].DeliveryID) < string(out[b].DeliveryID)
	})
	return out
}

// Get includes acknowledged tombstones, so retries still authorize the account.
func (s *Store) Get(dest, id []byte) (Item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.items[string(dest)][string(id)]
	if item == nil || !s.live(item) {
		return Item{}, false
	}
	return *item, true
}

// Ack forgets the envelope body but keeps the duplicate-detection record until expiry.
func (s *Store) Ack(dest, id []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	it := s.items[string(dest)][string(id)]
	if it == nil || !s.live(it) {
		return false
	}
	if it.Acked {
		return true
	}
	before := it.cost()
	prev := *it
	it.Envelope, it.Acked = nil, true
	if err := s.write(it); err != nil {
		*it = prev
		return false
	}
	s.bytes += it.cost() - before
	return true
}

// GC drops expired items of every device.
func (s *Store) GC() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for d := range s.items {
		s.gcLocked([]byte(d))
	}
}

func (s *Store) gcLocked(dest []byte) {
	m := s.items[string(dest)]
	for k, it := range m {
		if !s.live(it) {
			os.Remove(s.path(it))
			s.bytes -= it.cost()
			delete(m, k)
		}
	}
	if len(m) == 0 {
		delete(s.items, string(dest))
		os.Remove(filepath.Join(s.dir, hex.EncodeToString(dest)))
	}
}

// Held is the total bytes charged, for tests and metrics.
func (s *Store) Held() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// PurgeDevices erases everything addressed to or sent from the given devices (an account that was deleted).
func (s *Store) PurgeDevices(devs [][]byte) error {
	set := map[string]bool{}
	for _, d := range devs {
		set[string(d)] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for dest, m := range s.items {
		for k, it := range m {
			if !set[dest] && !set[string(it.Sender)] {
				continue
			}
			if err := os.Remove(s.path(it)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			s.bytes -= it.cost()
			delete(m, k)
		}
		if len(m) == 0 {
			delete(s.items, dest)
			os.Remove(filepath.Join(s.dir, hex.EncodeToString([]byte(dest))))
		}
	}
	return nil
}

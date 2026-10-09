// Package signal delivers sealed boxes between online devices (protocol v1 §10): presence, short-lived
// per-device mailboxes with server sequence numbers and acks. It is not a file queue — that is the spool.
package signal

import (
	"context"
	"errors"
	"hash/maphash"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/budget"
)

const (
	MailboxLimit = 512              // pending boxes per offline device
	MailboxTTL   = 10 * time.Minute // signalling is for the near-present, not for storage
	MaxBoxBytes  = 1 << 20

	// Byte budgets for queued boxes: anyone can make a key, so no single recipient, sender or the hub as a
	// whole may hold more than this. A box costs its length plus boxOverhead, so empty boxes are not free.
	MailboxBytes = 16 << 20
	SenderBytes  = 16 << 20
	TotalBytes   = 512 << 20
	// OfflineRecipients bounds how many distinct offline devices one sender can open mailboxes for per
	// MailboxTTL window: random device ids must not become an unbounded map.
	OfflineRecipients = 64
	boxOverhead       = 256
	// A remembered delivery_id outlives its box (it must, to catch late retries), so it costs the mailbox and
	// the hub this much until it expires: send→ack loops can't grow memory past the byte budgets.
	seenCost = 64

	// Open WebSockets, admitted before the upgrade. A device runs a few processes (app, extensions), each
	// with its own connection; an address may hide a whole office behind NAT.
	MaxConnsPerDevice = 16
	MaxConnsPerIP     = 1024
	MaxConns          = 100_000
	// RegisterTimeout is how long an admitted WebSocket may take to send its register frame.
	RegisterTimeout = 10 * time.Second
)

type Delivery struct {
	Sequence uint64
	Sender   []byte
	Box      []byte
	at       time.Time
}

// Forwarder hands a box to another server when the recipient is registered there (federation).
type Forwarder interface {
	Forward(ctx context.Context, sender, recipient, deliveryID, box []byte) error
}

type mailbox struct {
	next    uint64
	pending []Delivery
	bytes   int64 // pending boxes plus remembered delivery ids
	notify  chan struct{}
	hint    uint64 // bumped when a mailbox server has something for this device
	online  int
	// delivery_id dedup across servers and retries: keyed hashes (the key is per process, so senders can't
	// aim collisions), expired from the front of seenQ, which is in arrival order.
	seenIDs map[uint64]struct{}
	seenQ   []seenID
}

type seenID struct {
	key uint64
	at  time.Time
}

type sender struct {
	bytes      int64           // queued, unacked
	window     time.Time       // start of the current OfflineRecipients window
	recipients map[string]bool // offline recipients queued to in this window
}

type Hub struct {
	Now       func() time.Time
	Forwarder Forwarder
	// Remote reports whether some other server currently holds the device (set by federation).
	Remote func(deviceID []byte) bool

	MaxMailboxBytes, MaxSenderBytes, MaxTotalBytes int64
	MaxOfflineRecipients                           int
	// Conns admits WebSockets per device, per client address and in total.
	Conns           *budget.Gate
	RegisterTimeout time.Duration

	seed    maphash.Seed
	mu      sync.Mutex
	boxes   map[string]*mailbox
	senders map[string]*sender
	bytes   int64
	// Opaque presence tags (a hash only group members can compute) → online devices. Lets a device that
	// knows the group but not its members (recovery) find someone to sync from.
	tags map[string]map[string]int
}

func NewHub() *Hub {
	return &Hub{
		Now:             time.Now,
		MaxMailboxBytes: MailboxBytes, MaxSenderBytes: SenderBytes, MaxTotalBytes: TotalBytes,
		MaxOfflineRecipients: OfflineRecipients,
		Conns:                budget.NewGate(MaxConnsPerDevice, MaxConnsPerIP, MaxConns),
		RegisterTimeout:      RegisterTimeout,
		seed:                 maphash.MakeSeed(),
		boxes:                map[string]*mailbox{},
		senders:              map[string]*sender{},
		tags:                 map[string]map[string]int{},
	}
}

// Present registers device under tags while connected; the returned func removes it.
func (h *Hub) Present(device []byte, tags [][]byte) func() {
	h.mu.Lock()
	for _, t := range tags {
		if len(t) != 32 {
			continue
		}
		m := h.tags[string(t)]
		if m == nil {
			m = map[string]int{}
			h.tags[string(t)] = m
		}
		m[string(device)]++
	}
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, t := range tags {
			if m := h.tags[string(t)]; m != nil {
				if m[string(device)]--; m[string(device)] <= 0 {
					delete(m, string(device))
				}
				if len(m) == 0 {
					delete(h.tags, string(t))
				}
			}
		}
	}
}

// Peers returns up to 16 online devices under tag.
func (h *Hub) Peers(tag []byte) [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out [][]byte
	for d := range h.tags[string(tag)] {
		out = append(out, []byte(d))
		if len(out) == 16 {
			break
		}
	}
	return out
}

var ErrTooLarge = errors.New("RATE_LIMITED")
var ErrFull = errors.New("QUOTA_EXCEEDED")
var ErrFanout = errors.New("RATE_LIMITED")

// dedupKey keys a delivery by sender and delivery_id, so one sender can't suppress another's box by reusing its id.
func dedupKey(seed maphash.Seed, from, deliveryID []byte) uint64 {
	var mh maphash.Hash
	mh.SetSeed(seed)
	mh.Write(from)
	mh.Write(deliveryID)
	return mh.Sum64()
}

func cost(box []byte) int64 { return int64(len(box)) + boxOverhead }

func (h *Hub) box(id []byte) *mailbox {
	m := h.boxes[string(id)]
	if m == nil {
		m = &mailbox{next: 1, notify: make(chan struct{}), seenIDs: map[uint64]struct{}{}}
		h.boxes[string(id)] = m
	}
	return m
}

// Send queues a box for recipient. Same delivery_id twice (a retry, or the copy that came through the second
// server) is accepted once. Returns true if it was new.
func (h *Hub) Send(ctx context.Context, from, recipient, deliveryID, box []byte) (bool, error) {
	if len(box) > MaxBoxBytes {
		return false, ErrTooLarge
	}
	key := dedupKey(h.seed, from, deliveryID)
	h.mu.Lock()
	m := h.boxes[string(recipient)]
	if m != nil {
		h.expire(m)
		if _, dup := m.seenIDs[key]; dup {
			h.mu.Unlock()
			return false, nil
		}
	}
	local := m != nil && m.online > 0
	if !local && h.Forwarder != nil && h.Remote != nil && h.Remote(recipient) {
		h.mu.Unlock()
		return true, h.Forwarder.Forward(ctx, from, recipient, deliveryID, box)
	}
	defer h.mu.Unlock()
	now, c := h.Now(), cost(box)
	st := h.senders[string(from)]
	if st == nil {
		st = &sender{window: now, recipients: map[string]bool{}}
		h.senders[string(from)] = st
	}
	if now.Sub(st.window) >= MailboxTTL {
		st.window, st.recipients = now, map[string]bool{}
	}
	if !local && !st.recipients[string(recipient)] && len(st.recipients) >= h.MaxOfflineRecipients {
		return false, ErrFanout
	}
	if m != nil && (len(m.pending) >= MailboxLimit || m.bytes+c+seenCost > h.MaxMailboxBytes) {
		return false, ErrFull
	}
	if st.bytes+c > h.MaxSenderBytes || h.bytes+c+seenCost > h.MaxTotalBytes {
		return false, ErrFull
	}
	if !local {
		st.recipients[string(recipient)] = true
	}
	m = h.box(recipient)
	m.seenIDs[key] = struct{}{}
	m.seenQ = append(m.seenQ, seenID{key, now})
	m.pending = append(m.pending, Delivery{Sequence: m.next, Sender: from, Box: box, at: now})
	m.next++
	m.bytes += c + seenCost
	st.bytes += c
	h.bytes += c + seenCost
	// Broadcast: every connection waiting on this mailbox wakes, not just one of them.
	close(m.notify)
	m.notify = make(chan struct{})
	return true, nil
}

// drop releases the budgets of deliveries that left a mailbox.
func (h *Hub) drop(m *mailbox, gone []Delivery) {
	for _, d := range gone {
		c := cost(d.Box)
		m.bytes -= c
		h.bytes -= c
		if st := h.senders[string(d.Sender)]; st != nil {
			st.bytes -= c
		}
	}
	// The mailbox re-slices its backing array, so the boxes that left would stay reachable through it.
	clear(gone)
}

// Ack drops everything up to and including seq.
func (h *Hub) Ack(device []byte, seq uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.boxes[string(device)]
	if m == nil {
		return
	}
	i := 0
	for i < len(m.pending) && m.pending[i].Sequence <= seq {
		i++
	}
	h.drop(m, m.pending[:i])
	m.pending = m.pending[i:]
}

// Pending returns undelivered boxes after cursor and a channel that fires when more arrive.
func (h *Hub) Pending(device []byte, after uint64) ([]Delivery, <-chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.box(device)
	h.expire(m)
	var out []Delivery
	for _, d := range m.pending {
		if d.Sequence > after {
			out = append(out, d)
		}
	}
	return out, m.notify
}

// Online marks a connection; the returned func marks it gone.
func (h *Hub) Online(device []byte) func() {
	h.mu.Lock()
	h.box(device).online++
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		h.box(device).online--
		h.mu.Unlock()
	}
}

// GC expires every mailbox and forgets the ones nobody is connected to and nothing is queued in, and senders
// with nothing queued whose window is over.
func (h *Hub) GC() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, m := range h.boxes {
		h.expire(m)
		if m.online <= 0 && len(m.pending) == 0 && len(m.seenIDs) == 0 {
			delete(h.boxes, k)
		}
	}
	now := h.Now()
	for k, st := range h.senders {
		if st.bytes <= 0 && now.Sub(st.window) >= MailboxTTL {
			delete(h.senders, k)
		}
	}
}

func (h *Hub) IsOnline(device []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.boxes[string(device)]
	return m != nil && m.online > 0
}

func (h *Hub) expire(m *mailbox) {
	cut := h.Now().Add(-MailboxTTL)
	i := 0
	for i < len(m.pending) && m.pending[i].at.Before(cut) {
		i++
	}
	h.drop(m, m.pending[:i])
	m.pending = m.pending[i:]
	i = 0
	for i < len(m.seenQ) && m.seenQ[i].at.Before(cut) {
		delete(m.seenIDs, m.seenQ[i].key)
		i++
	}
	m.seenQ = m.seenQ[i:]
	m.bytes -= int64(i) * seenCost
	h.bytes -= int64(i) * seenCost
	if len(m.seenQ) == 0 {
		m.seenQ = nil // let the backing array go
	}
}

// Admit takes a connection slot for device at client address ip before the WebSocket upgrade.
func (h *Hub) Admit(device []byte, ip string) (release func(), ok bool) {
	return h.Conns.Take(string(device), ip, 1)
}

// Nudge tells a connected device that its mailbox server has something new. Nothing is stored: a device that
// is not connected polls the mailbox when it next connects.
func (h *Hub) Nudge(device []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := h.boxes[string(device)]
	if m == nil || m.online <= 0 {
		return
	}
	m.hint++
	close(m.notify)
	m.notify = make(chan struct{})
}

// Hint is the count of nudges so far; a connection compares it with the last one it reported.
func (h *Hub) Hint(device []byte) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m := h.boxes[string(device)]; m != nil {
		return m.hint
	}
	return 0
}

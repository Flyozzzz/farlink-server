package accounts

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// A catch-up answer holds at most this many links and bytes.
const (
	MaxSuffixLinks = 16
	MaxSuffixBytes = 256 << 10
)

// Registry holds every account chain this server has been given and the device → account index. A device key is in
// at most one account; a key that was ever revoked is dead for good, in every account.
type Registry struct {
	mu      sync.Mutex
	dir     string
	chains  map[string]*chain
	devices map[string]string // every observed device id → its permanent account owner
	deleted *tombstones       // accounts that were deleted (hashes only)
}

// Open loads (and re-verifies) the chains kept in dir.
func Open(dir string) (*Registry, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	r := &Registry{dir: dir, chains: map[string]*chain{}, devices: map[string]string{}}
	t, err := openTombstones(dir)
	if err != nil {
		return nil, err
	}
	r.deleted = t
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".chain" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var stored struct {
			Journal [][]byte `cbor:"journal"`
		}
		if wire.Lenient(data, &stored) != nil {
			return nil, errors.New("accounts: unreadable " + e.Name())
		}
		c, err := replay(stored.Journal)
		if err != nil || hex.EncodeToString(c.links[0].State.AccountID)+".chain" != e.Name() {
			return nil, errors.New("accounts: bad journal in " + e.Name())
		}
		for _, event := range c.journal {
			for _, device := range event.State.Devices {
				if owner, taken := r.devices[hex.EncodeToString(device.DeviceID)]; taken && owner != hex.EncodeToString(event.State.AccountID) {
					return nil, ErrDeviceTaken
				}
			}
		}
		r.index(c)
	}
	return r, nil
}

// index reserves ownership permanently, but AccountOf authorizes only the chosen
// non-forked head. Revocation on an RK-rejected branch cannot block its owner from
// choosing the other branch, nor can a foreign account's revocation erase ownership.
func (r *Registry) index(c *chain) {
	id := hex.EncodeToString(c.links[0].State.AccountID)
	r.chains[id] = c
	for _, event := range c.journal[c.indexed:] {
		for _, device := range event.State.Devices {
			r.devices[hex.EncodeToString(device.DeviceID)] = id
		}
	}
	c.indexed = len(c.journal)
}

func (r *Registry) save(c *chain) error {
	raws := make([][]byte, len(c.journal))
	for i, l := range c.journal {
		raws[i] = l.Raw
	}
	b, err := wire.Enc.Marshal(struct {
		Journal [][]byte `cbor:"journal"`
	}{raws})
	if err != nil {
		return err
	}
	return durable.WriteFile(filepath.Join(r.dir, hex.EncodeToString(c.links[0].State.AccountID)+".chain"), b)
}

// Submit persists every verified event, including a fork rejected for authorization.
// Only a valid RK successor can unfreeze the account; retries retain the exact journal.
func (r *Registry) Submit(raw []byte) (number uint64, headHash []byte, err error) {
	l, err := ParseLink(raw)
	if err != nil {
		return 0, nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.deleted.set[tombstoneOf(l.State.AccountID)] {
		return 0, nil, ErrDeleted
	}
	id := hex.EncodeToString(l.State.AccountID)
	if l.State.Number == 0 {
		if err := CheckGenesis(l); err != nil {
			return 0, nil, err
		}
		if c, ok := r.chains[id]; ok {
			if bytes.Equal(c.links[0].Raw, l.Raw) {
				return c.head().State.Number, c.head().Hash(), nil
			}
			return 0, nil, ErrExists
		}
		dev := hex.EncodeToString(l.State.Devices[0].DeviceID)
		if owner, taken := r.devices[dev]; taken && owner != id {
			return 0, nil, ErrDeviceTaken
		}
		c := newChain(l)
		if err := r.save(c); err != nil {
			return 0, nil, err
		}
		r.index(c)
		return 0, l.Hash(), nil
	}
	c, ok := r.chains[id]
	if !ok {
		return 0, nil, ErrUnknown
	}
	head := c.head()
	// Reserve keys across accounts even on a competing branch.
	for _, d := range l.State.Devices {
		if _, known := head.State.device(d.DeviceID); known {
			continue
		}
		dev := hex.EncodeToString(d.DeviceID)
		if owner, taken := r.devices[dev]; taken && owner != id {
			return 0, nil, ErrDeviceTaken
		}
	}
	before := len(c.journal)
	applyErr := c.apply(l)
	if len(c.journal) != before {
		c.dirty = true
		r.index(c)
	}
	if c.dirty {
		if err := r.save(c); err != nil {
			return 0, nil, err
		}
		c.dirty = false
	}
	if applyErr != nil {
		return 0, nil, applyErr
	}
	return c.head().State.Number, c.head().Hash(), nil
}

// Chain returns the raw links of an account, in order; the chain is public data.
func (r *Registry) Chain(accountID []byte) ([][]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.chains[hex.EncodeToString(accountID)]
	if !ok {
		return nil, false
	}
	out := make([][]byte, len(c.links))
	for i, l := range c.links {
		out[i] = l.Raw
	}
	return out, true
}

// AccountOf names the account an active device belongs to.
func (r *Registry) AccountOf(deviceID []byte) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.devices[hex.EncodeToString(deviceID)]
	if !ok || r.chains[a] == nil || r.chains[a].frozen() || r.chains[a].dirty {
		return nil, false
	}
	if raw, err := hex.DecodeString(a); err == nil && r.deleted.set[tombstoneOf(raw)] {
		return nil, false
	}
	if _, active := r.chains[a].head().State.device(deviceID); !active {
		return nil, false
	}
	id, _ := hex.DecodeString(a)
	return id, true
}

// Head is the newest state of an account, for callers that gate on it (auth, quotas).
func (r *Registry) Head(accountID []byte) (State, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.chains[hex.EncodeToString(accountID)]
	if !ok || c.frozen() || c.dirty || r.deleted.set[tombstoneOf(accountID)] {
		return State{}, false
	}
	return c.head().State, true
}

// HeadRef is the number and link hash of an account's newest state.
func (r *Registry) HeadRef(accountID []byte) (number uint64, hash []byte, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, found := r.chains[hex.EncodeToString(accountID)]
	if !found {
		return 0, nil, false
	}
	return c.head().State.Number, c.head().Hash(), true
}

// Suffix returns the links after number `after` (none when the caller is current): see Page.
func (r *Registry) Suffix(accountID []byte, after uint64) (links [][]byte, ok bool) {
	return r.Page(accountID, after+1)
}

// Page returns the links from number `from` on, capped at MaxSuffixLinks and MaxSuffixBytes so that catching up costs a
// bounded answer; the caller asks again from the last number it got.
func (r *Registry) Page(accountID []byte, from uint64) (links [][]byte, ok bool) {
	links = [][]byte{}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, found := r.chains[hex.EncodeToString(accountID)]
	if !found {
		return nil, false
	}
	size := 0
	for i := from; i < uint64(len(c.links)) && len(links) < MaxSuffixLinks; i++ {
		raw := c.links[i].Raw
		if size+len(raw) > MaxSuffixBytes && len(links) > 0 {
			break
		}
		size += len(raw)
		links = append(links, raw)
	}
	return links, true
}

// JournalPage exposes durable fork evidence and recovery decisions as bounded events.
func (r *Registry) JournalPage(accountID []byte, from uint64) ([][]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, found := r.chains[hex.EncodeToString(accountID)]
	if !found {
		return nil, false
	}
	page := [][]byte{}
	size := 0
	for i := from; i < uint64(len(c.journal)) && len(page) < MaxSuffixLinks; i++ {
		raw := c.journal[i].Raw
		if size+len(raw) > MaxSuffixBytes {
			break
		}
		page = append(page, raw)
		size += len(raw)
	}
	return page, true
}

// OwnerDeleted reports whether a device key was one of a deleted account's (proven by signing for it).
func (r *Registry) OwnerDeleted(deviceID []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleted.set[deviceTombstoneOf(deviceID)]
}

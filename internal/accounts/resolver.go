package accounts

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

var (
	ErrUnreachable      = errors.New("ACCOUNT_UNREACHABLE")
	ErrBehindCheckpoint = errors.New("ACCOUNT_BEHIND_CHECKPOINT")
)

// HeadRef names a particular state, not a reusable permission to act under it.
type HeadRef struct {
	Number uint64 `cbor:"number"`
	Hash   []byte `cbor:"hash"`
}

// Replica reads bounded pages of the verified event journal by ordinal.
// A nil page means unknown; an empty page ends the journal. Page honors cancellation.
type Replica struct {
	ID   string
	Page func(ctx context.Context, accountID []byte, from uint64) ([][]byte, error)
}

// VerifiedAccount is an immutable snapshot for one authorization operation only.
// Call Current again at the next boundary, even when the previous answer allowed it.
type VerifiedAccount struct{ links []Link }

func (v VerifiedAccount) Head() State { return v.links[len(v.links)-1].State }
func (v VerifiedAccount) HeadRef() HeadRef {
	l := v.links[len(v.links)-1]
	return HeadRef{Number: l.State.Number, Hash: l.Hash()}
}
func (v VerifiedAccount) ActiveDevice(id []byte) (Device, bool) { return v.Head().device(id) }
func (v VerifiedAccount) Contains(ref HeadRef) bool {
	return ref.Number < uint64(len(v.links)) && bytes.Equal(v.links[ref.Number].Hash(), ref.Hash)
}

// ContactRoutes names each signed authority transition. Disabling contacts does
// not erase the previous authority or its relation-state floor.
type ContactRoute struct {
	Server string  `cbor:"server"`
	Head   HeadRef `cbor:"head"`
}

func (v VerifiedAccount) ContactRoutes() []ContactRoute {
	var routes []ContactRoute
	for _, link := range v.links {
		mailboxes := link.State.ContactMailboxes
		if len(mailboxes) == 0 {
			continue
		}
		if len(routes) == 0 || routes[len(routes)-1].Server != mailboxes[0] {
			routes = append(routes, ContactRoute{Server: mailboxes[0], Head: HeadRef{Number: link.State.Number, Hash: link.Hash()}})
		}
	}
	return routes
}

func (v VerifiedAccount) ContactAuthority() string {
	if len(v.Head().ContactMailboxes) == 0 {
		return ""
	}
	return v.Head().ContactMailboxes[0]
}

type resolverCheckpoint struct {
	Journal [][]byte `cbor:"journal"`
}

type resolvedAccount struct {
	mu    sync.Mutex
	state *chain
	dirty bool
	users int // guarded by Resolver.cacheMu
}

// Resolver reads self + the current federation peers in parallel, without caching
// permissions. Peers=nil is an explicitly standalone server; an unavailable peer
// directory must return an error, never silently shrink to a quorum of one.
// Checkpoints retain verified conflicts and RK decisions, including rejected branches.
type Resolver struct {
	Registry *Registry
	Peers    func() ([]Replica, error)
	Timeout  time.Duration
	dir      string
	known    sync.Map // account bytes -> *resolvedAccount
	inflight chan struct{}
	initOnce sync.Once
	cacheMu  sync.Mutex
}

func OpenResolver(reg *Registry, dir string, peers func() ([]Replica, error)) (*Resolver, error) {
	if reg == nil {
		return nil, ErrUnreachable
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	r := &Resolver{Registry: reg, Peers: peers, Timeout: 3 * time.Second, dir: dir}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".checkpoint" {
			continue
		}
		id, err := hex.DecodeString(e.Name()[:len(e.Name())-len(".checkpoint")])
		if err != nil || len(id) != 32 || e.IsDir() {
			return nil, fmt.Errorf("accounts: invalid checkpoint %s", e.Name())
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var cp resolverCheckpoint
		if wire.Lenient(data, &cp) != nil {
			return nil, fmt.Errorf("accounts: unreadable checkpoint %s", e.Name())
		}
		state, err := replay(cp.Journal)
		if err != nil || !bytes.Equal(state.head().State.AccountID, id) {
			return nil, fmt.Errorf("accounts: bad checkpoint %s", e.Name())
		}
		r.known.Store(string(id), &resolvedAccount{state: state})
	}
	return r, nil
}

func (r *Resolver) save(id []byte, a *resolvedAccount) error {
	if !a.dirty {
		return nil
	}
	cp := resolverCheckpoint{Journal: make([][]byte, len(a.state.journal))}
	for i, l := range a.state.journal {
		cp.Journal[i] = l.Raw
	}
	data, err := wire.Enc.Marshal(cp)
	if err != nil {
		return err
	}
	if err := durable.WriteFile(filepath.Join(r.dir, hex.EncodeToString(id)+".checkpoint"), data); err != nil {
		return err
	}
	a.dirty = false
	return nil
}

func appendPage(id []byte, state *chain, page [][]byte) (*chain, error) {
	if len(page) > MaxSuffixLinks {
		return nil, ErrTooLong
	}
	for _, raw := range page {
		l, err := ParseLink(raw)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(l.State.AccountID, id) {
			return nil, ErrWrongAccount
		}
		if state == nil {
			if err := CheckGenesis(l); err != nil {
				return nil, err
			}
			state = newChain(l)
		} else {
			before := len(state.journal)
			if err := state.apply(l); err != nil && (err != ErrFork || before == len(state.journal)) {
				return nil, err
			}
		}
	}
	return state, nil
}

// The anchor is a journal event, not just the current winning head: a frozen
// registry must expose the signed fork evidence even when its head did not move.
func readReplica(ctx context.Context, replica Replica, id []byte, base *chain) (*chain, error) {
	var state *chain
	var from uint64
	if base != nil {
		from = uint64(len(base.journal) - 1)
		page, err := replica.Page(ctx, id, from)
		if err != nil || page == nil {
			return nil, err
		}
		if len(page) > MaxSuffixLinks {
			return nil, ErrTooLong
		}
		if len(page) > 0 && bytes.Equal(page[0], base.journal[len(base.journal)-1].Raw) {
			state, err = appendPage(id, base.clone(), page[1:])
			if err != nil {
				return nil, err
			}
			from += uint64(len(page))
		} else {
			from = 0
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := replica.Page(ctx, id, from)
		if err != nil || page == nil {
			return nil, err
		}
		if len(page) == 0 {
			return state, nil
		}
		if from+uint64(len(page)) > MaxJournalEvents {
			return nil, ErrTooLong
		}
		state, err = appendPage(id, state, page)
		if err != nil {
			return nil, err
		}
		from += uint64(len(page))
	}
}

func (r *Resolver) Current(ctx context.Context, id []byte) (VerifiedAccount, error) {
	if len(id) != 32 {
		return VerifiedAccount{}, ErrMalformed
	}
	if r.Registry.IsDeleted(id) {
		return VerifiedAccount{}, ErrDeleted
	}
	r.initOnce.Do(func() { r.inflight = make(chan struct{}, 32) })
	select {
	case r.inflight <- struct{}{}:
		defer func() { <-r.inflight }()
	default:
		return VerifiedAccount{}, ErrUnreachable
	}
	// Serialize cache lifetime changes with acquisition. References held by other
	// lookups prevent removal; durable checkpoints and fork evidence never expire.
	r.cacheMu.Lock()
	value, _ := r.known.LoadOrStore(string(id), &resolvedAccount{})
	a := value.(*resolvedAccount)
	a.users++
	r.cacheMu.Unlock()
	defer func() {
		r.cacheMu.Lock()
		defer r.cacheMu.Unlock()
		a.mu.Lock()
		defer a.mu.Unlock()
		a.users--
		if a.users == 0 && a.state == nil && !a.dirty {
			r.known.CompareAndDelete(string(id), a)
		}
	}()
	a.mu.Lock()
	base := a.state
	a.mu.Unlock()
	var replicas []Replica
	if r.Peers != nil {
		var err error
		replicas, err = r.Peers()
		if err != nil {
			return VerifiedAccount{}, err
		}
	}
	seen := map[string]bool{}
	for _, peer := range replicas {
		if peer.ID == "" || peer.Page == nil || seen[peer.ID] {
			return VerifiedAccount{}, ErrUnreachable
		}
		seen[peer.ID] = true
	}
	replicas = append(replicas, Replica{Page: func(ctx context.Context, id []byte, from uint64) ([][]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, found := r.Registry.JournalPage(id, from)
		if !found {
			return nil, nil
		}
		return page, nil
	}})
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type answer struct {
		state *chain
		err   error
	}
	answers := make(chan answer, len(replicas))
	for _, peer := range replicas {
		go func(peer Replica) {
			links, err := readReplica(readCtx, peer, id, base)
			answers <- answer{links, err}
		}(peer)
	}
	answered := 0
	var states []*chain
	remaining := len(replicas)
	for remaining > 0 {
		select {
		case got := <-answers:
			remaining--
			if got.err != nil {
				log.Printf("accounts: replica read failed: %v", got.err)
				continue
			}
			answered++
			if got.state != nil {
				states = append(states, got.state)
			}
		case <-readCtx.Done():
			remaining = 0
		}
	}
	sort.SliceStable(states, func(i, j int) bool { return len(states[i].links) < len(states[j].links) })
	// Reconcile against the latest checkpoint after network I/O. Every state is
	// independently verified; evidence survives both minority reads and restart.
	a.mu.Lock()
	defer a.mu.Unlock()
	var merged *chain
	if a.state != nil {
		merged = a.state.clone()
	}
	longest := 0
	for _, state := range states {
		if len(state.links) > longest {
			longest = len(state.links)
		}
		if merged == nil {
			merged = state.clone()
			continue
		}
		if err := merged.merge(state); err != nil {
			return VerifiedAccount{}, err
		}
	}
	if merged != nil {
		if a.state == nil || len(merged.journal) != len(a.state.journal) {
			a.dirty = true
		}
		a.state = merged
		if merged.frozen() {
			if err := r.save(id, a); err != nil {
				return VerifiedAccount{}, err
			}
			return VerifiedAccount{}, ErrFork
		}
	}
	if err := ctx.Err(); err != nil {
		return VerifiedAccount{}, err
	}
	if answered*2 <= len(replicas) {
		return VerifiedAccount{}, ErrUnreachable
	}
	if merged == nil {
		return VerifiedAccount{}, ErrUnknown
	}
	if longest < len(merged.links) {
		return VerifiedAccount{}, ErrBehindCheckpoint
	}
	if err := r.save(id, a); err != nil {
		return VerifiedAccount{}, err
	}
	return VerifiedAccount{links: merged.links}, nil
}

// Forget erases what the resolver kept about an account: its cached state and its checkpoint file.
func (r *Resolver) Forget(id []byte) error {
	r.cacheMu.Lock()
	r.known.Delete(string(id))
	r.cacheMu.Unlock()
	err := os.Remove(filepath.Join(r.dir, hex.EncodeToString(id)+".checkpoint"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return durable.SyncDir(r.dir)
}

package contacts

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

var ErrMigration = &federation.Error{Status: 409, Code: "AUTHORITY_MIGRATION_REQUIRED"}

// AuthoritySnapshot is immutable once the source fence is durable. The transition
// names a signed account link; mTLS authenticates the only permitted source.
type AuthoritySnapshot struct {
	Recipient  []byte           `cbor:"recipient_account"`
	Transition accounts.HeadRef `cbor:"transition"`
	From       string           `cbor:"from"`
	To         string           `cbor:"to"`
	Clock      uint64           `cbor:"clock"`
	Records    []Record         `cbor:"records"`
}

type authorityState struct {
	Route   accounts.HeadRef    `cbor:"route"`
	Fenced  bool                `cbor:"fenced"`
	Exports []AuthoritySnapshot `cbor:"exports"`
}

type storedRelations struct {
	Recipient []byte         `cbor:"recipient_account"`
	Clock     uint64         `cbor:"clock"`
	Records   []Record       `cbor:"records"`
	Authority authorityState `cbor:"authority"`
}

func validRecords(recipient []byte, clock uint64, records []Record) bool {
	if len(recipient) != 32 || len(records) > MaxRecords {
		return false
	}
	seen := map[string]bool{}
	for _, r := range records {
		if !bytes.Equal(r.Recipient, recipient) || len(r.Sender) != 32 || bytes.Equal(r.Sender, recipient) ||
			r.Generation == 0 || r.Generation > clock || seen[string(r.Sender)] {
			return false
		}
		switch r.State {
		case Pending, Accepted, Declined, Removed:
		default:
			return false
		}
		if r.State == Pending && (len(r.PendingDelivery) != 16 || r.PendingBytes > MaxFirstBytes) {
			return false
		}
		seen[string(r.Sender)] = true
	}
	return true
}

func openStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, by: map[string]map[string]*Record{}, metas: map[string]*meta{}, authorities: map[string]*authorityState{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			return nil, fmt.Errorf("contacts: unexpected file %s", entry.Name())
		}
		id, err := hex.DecodeString(entry.Name())
		if err != nil || len(id) != 32 {
			return nil, fmt.Errorf("contacts: invalid recipient %s", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name(), "state"))
		if os.IsNotExist(err) {
			// Before the first rename, only private regular .tmp-* files may
			// exist. Never infer an empty store from a corrupt committed state
			// or from unknown files, directories, or symlinks.
			recipientDir := filepath.Join(dir, entry.Name())
			files, readErr := os.ReadDir(recipientDir)
			if readErr != nil {
				return nil, readErr
			}
			for _, file := range files {
				if !file.Type().IsRegular() || !strings.HasPrefix(file.Name(), ".tmp-") || len(file.Name()) <= len(".tmp-") {
					return nil, fmt.Errorf("contacts: missing state with unexpected file %s", file.Name())
				}
			}
			for _, file := range files {
				if err := os.Remove(filepath.Join(recipientDir, file.Name())); err != nil {
					return nil, err
				}
			}
			if len(files) != 0 {
				if err := durable.SyncDir(recipientDir); err != nil {
					return nil, err
				}
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		var state storedRelations
		if wire.Unmarshal(data, &state) != nil || !bytes.Equal(id, state.Recipient) || !validRecords(id, state.Clock, state.Records) {
			return nil, fmt.Errorf("contacts: unreadable state for %s", entry.Name())
		}
		for _, exported := range state.Authority.Exports {
			if !bytes.Equal(exported.Recipient, id) || len(exported.Transition.Hash) != 32 ||
				!validRecords(id, exported.Clock, exported.Records) {
				return nil, fmt.Errorf("contacts: invalid migration journal")
			}
		}
		s.install(state)
	}
	return s, nil
}

// Caller holds the store lock. One atomic file contains relations, generation
// floor, source fences and imported epoch; there is no partially imported state.
func (s *Store) snapshot(recipient []byte) storedRelations {
	state := storedRelations{Recipient: recipient, Clock: s.meta(recipient).Clock, Records: []Record{}}
	for _, record := range s.by[string(recipient)] {
		state.Records = append(state.Records, *record)
	}
	sort.Slice(state.Records, func(i, j int) bool { return bytes.Compare(state.Records[i].Sender, state.Records[j].Sender) < 0 })
	if authority := s.authorities[string(recipient)]; authority != nil {
		state.Authority = *authority
	}
	return state
}

func (s *Store) persist(state storedRelations) error {
	path := s.path(state.Recipient, "state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := wire.Enc.Marshal(state)
	if err != nil {
		return err
	}
	if err := durable.WriteFile(path, data); err != nil {
		return err
	}
	return durable.SyncDir(s.dir)
}

func (s *Store) install(state storedRelations) {
	s.by[string(state.Recipient)] = map[string]*Record{}
	for _, record := range state.Records {
		r := record
		s.put(&r)
	}
	s.metas[string(state.Recipient)] = &meta{Clock: state.Clock}
	s.authorities[string(state.Recipient)] = &state.Authority
}

func (s *Store) fenced(recipient []byte, expected ...accounts.HeadRef) bool {
	a := s.authorities[string(recipient)]
	return a != nil && a.Fenced || len(expected) != 0 && (a == nil || len(expected) != 1 || !sameRef(a.Route, expected[0]))
}

func sameRef(a, b accounts.HeadRef) bool { return a.Number == b.Number && bytes.Equal(a.Hash, b.Hash) }
func routeIndex(routes []accounts.ContactRoute, ref accounts.HeadRef) int {
	for i, route := range routes {
		if sameRef(route.Head, ref) {
			return i
		}
	}
	return -1
}

// ready never permits a rollback of an imported epoch or a canceled source fence.
func (s *Store) ready(recipient []byte, routes []accounts.ContactRoute) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(routes) == 0 {
		return false, ErrMigration
	}
	a := authorityState{}
	if known := s.authorities[string(recipient)]; known != nil {
		a = *known
	}
	if len(a.Route.Hash) == 0 && len(routes) == 1 {
		state := s.snapshot(recipient)
		state.Authority.Route = routes[0].Head
		if err := s.persist(state); err != nil {
			return false, errInternal
		}
		s.install(state)
		return true, nil
	}
	if len(a.Route.Hash) != 0 && routeIndex(routes, a.Route) < 0 {
		return false, ErrMigration
	}
	// A recovery that removes an already executed handoff must not reopen the old
	// snapshot: the receiving authority may have accepted newer blocks/decisions.
	for _, exported := range a.Exports {
		if routeIndex(routes, exported.Transition) < 0 {
			return false, ErrMigration
		}
	}
	return sameRef(a.Route, routes[len(routes)-1].Head) && !a.Fenced, nil
}

func (s *Store) export(recipient []byte, previous, next accounts.ContactRoute) (AuthoritySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.snapshot(recipient)
	for _, exported := range state.Authority.Exports {
		if sameRef(exported.Transition, next.Head) {
			// Retry the write too: a previous fsync may have failed after rename.
			if err := s.persist(state); err != nil {
				return AuthoritySnapshot{}, errInternal
			}
			return exported, nil
		}
	}
	if !sameRef(state.Authority.Route, previous.Head) || state.Authority.Fenced {
		return AuthoritySnapshot{}, ErrMigration
	}
	exported := AuthoritySnapshot{Recipient: recipient, Transition: next.Head, From: previous.Server, To: next.Server,
		Clock: state.Clock, Records: state.Records}
	state.Authority.Exports = append(append([]AuthoritySnapshot(nil), state.Authority.Exports...), exported)
	state.Authority.Fenced = true
	// Even an ambiguous fsync failure must fence concurrent operations in memory.
	s.install(state)
	if err := s.persist(state); err != nil {
		return AuthoritySnapshot{}, errInternal
	}
	return exported, nil
}

func (s *Store) importSnapshot(snapshot AuthoritySnapshot, routes []accounts.ContactRoute) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validRecords(snapshot.Recipient, snapshot.Clock, snapshot.Records) {
		return ErrMigration
	}
	state := s.snapshot(snapshot.Recipient)
	index := routeIndex(routes, snapshot.Transition)
	if index < 1 || routes[index].Server != snapshot.To || routes[index-1].Server != snapshot.From {
		return ErrMigration
	}
	oldIndex := routeIndex(routes, state.Authority.Route)
	if len(state.Authority.Route.Hash) != 0 && oldIndex < 0 {
		return ErrMigration
	}
	for _, exported := range state.Authority.Exports {
		if routeIndex(routes, exported.Transition) < 0 {
			return ErrMigration
		}
	}
	if oldIndex >= index {
		return nil
	} // duplicate/older snapshot never overwrites later decisions
	if state.Clock > snapshot.Clock {
		return ErrMigration
	}
	state.Clock, state.Records = snapshot.Clock, snapshot.Records
	state.Authority.Route, state.Authority.Fenced = snapshot.Transition, false
	if err := s.persist(state); err != nil {
		return errInternal
	}
	s.install(state)
	return nil
}

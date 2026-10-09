package federation

import (
	"errors"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/registry"
)

func TestAnExpiredCatalogIsKeptForTheGraceThenDropped(t *testing.T) {
	pin := PinString(make([]byte, 32))
	reg := registry.Registry{ExpiresAt: 1_000_000, Servers: []registry.Server{{ServerID: "a", FederationIdentity: pin}}}
	dir, err := NewDirectory(reg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_000_000)
	failing := errors.New("expired")
	w := &Watch{Dir: dir, Grace: time.Hour, Now: func() time.Time { return now },
		Load: func() (registry.Registry, error) { return registry.Registry{}, failing }}
	w.Start(reg)

	now = now.Add(30 * time.Minute)
	if w.Tick() == nil {
		t.Fatal("no error reported")
	}
	if _, ok := dir.Peer("a"); !ok {
		t.Fatal("dropped inside the grace")
	}
	now = now.Add(31 * time.Minute)
	w.Tick()
	if _, ok := dir.Peer("a"); ok {
		t.Fatal("still trusted after the grace")
	}

	w.Load = func() (registry.Registry, error) {
		r := reg
		r.ExpiresAt = uint64(now.Add(time.Hour).UnixMilli())
		return r, nil
	}
	if err := w.Tick(); err != nil {
		t.Fatal(err)
	}
	if _, ok := dir.Peer("a"); !ok {
		t.Fatal("a fresh catalog did not bring the peer back")
	}
}

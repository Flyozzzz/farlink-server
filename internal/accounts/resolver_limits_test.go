package accounts

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestUnknownResolutionsDoNotAccumulateAndCheckpointsRemain(t *testing.T) {
	g, raw := genesis(t, newDev(), newDev())
	r := resolverWith(t, registryWith(t, raw), t.TempDir())
	if _, err := r.Current(context.Background(), g.AccountID); err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 300; i++ {
		id := make([]byte, 32)
		binary.BigEndian.PutUint64(id, i)
		if _, err := r.Current(context.Background(), id); !errors.Is(err, ErrUnknown) {
			t.Fatal(err)
		}
	}
	count := 0
	r.known.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("retained %d entries, want only verified checkpoint", count)
	}
	if _, ok := r.known.Load(string(g.AccountID)); !ok {
		t.Fatal("lost verified checkpoint")
	}
}

func TestConcurrentResolutionsAreBoundedBeforePeerIO(t *testing.T) {
	started := make(chan struct{}, 64)
	release := make(chan struct{})
	peer := Replica{ID: "peer", Page: func(ctx context.Context, _ []byte, _ uint64) ([][]byte, error) {
		started <- struct{}{}
		select {
		case <-release:
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	r := resolverWith(t, registryWith(t), t.TempDir(), peer)
	done := make(chan struct{}, 32)
	for i := range 32 {
		go func(i int) {
			id := make([]byte, 32)
			id[0] = byte(i)
			r.Current(context.Background(), id)
			done <- struct{}{}
		}(i)
	}
	for range 32 {
		<-started
	}
	if _, err := r.Current(context.Background(), make([]byte, 32)); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("overload: %v", err)
	}
	select {
	case <-started:
		t.Fatal("overloaded request reached peer")
	default:
	}
	close(release)
	for range 32 {
		<-done
	}
}

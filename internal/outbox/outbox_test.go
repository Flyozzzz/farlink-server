package outbox

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/federation"
)

type fake struct {
	mu    sync.Mutex
	errs  []error
	by    map[string]error // fixed answer per destination, checked first
	calls []string
}

func (f *fake) Send(_ context.Context, to string, _ federation.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, to)
	if e, ok := f.by[to]; ok {
		return e
	}
	if len(f.errs) == 0 {
		return nil
	}
	e := f.errs[0]
	f.errs = f.errs[1:]
	return e
}

func req(id byte, exp time.Time) federation.Request {
	did := bytes.Repeat([]byte{id}, 16)
	return federation.NewRequest("me", did, make([]byte, 32), make([]byte, 32), "spool-hint", uint64(exp.UnixMilli()), []byte("e"))
}

func open(t *testing.T, dir string, f *fake, clock *time.Time) *Outbox {
	o, err := Open(dir, "me", f, federation.SinkFunc(func(context.Context, federation.Peer, federation.Request) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	o.Now = func() time.Time { return *clock }
	return o
}

func TestRetriesWithBackoffAndSurvivesRestart(t *testing.T) {
	dir, now, f := t.TempDir(), time.Now(), &fake{errs: []error{errors.New("down"), errors.New("down")}}
	o := open(t, dir, f, &now)
	if err := o.Enqueue("b", req(1, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue("b", req(1, now.Add(time.Hour))); err != nil || o.Pending() != 1 {
		t.Fatal("same delivery must be one entry")
	}
	if o.Process(context.Background()) != 0 || o.Process(context.Background()) != 0 {
		t.Fatal("delivered while the peer was down or before backoff elapsed")
	}
	if len(f.calls) != 1 {
		t.Fatalf("backoff ignored: %d calls", len(f.calls))
	}
	o = open(t, dir, f, &now) // restart
	now = now.Add(6 * time.Second)
	o.Process(context.Background()) // second failure
	now = now.Add(11 * time.Second)
	if o.Process(context.Background()) != 1 || o.Pending() != 0 {
		t.Fatal("not delivered after the peer came back")
	}
}

func TestPermanentRefusalAndExpiryDropTheEntry(t *testing.T) {
	dir, now := t.TempDir(), time.Now()
	f := &fake{by: map[string]error{"b": &federation.Error{Status: 409, Code: "FEDERATION_LOOP"}, "c": errors.New("down")}}
	o := open(t, dir, f, &now)
	o.Enqueue("b", req(2, now.Add(time.Hour)))
	o.Enqueue("c", req(3, now.Add(10*time.Second)))
	o.Process(context.Background())
	if o.Pending() != 1 {
		t.Fatalf("pending %d: refused entry must go, unreachable one stays", o.Pending())
	}
	now = now.Add(time.Minute)
	o.Process(context.Background())
	if o.Pending() != 0 {
		t.Fatal("expired entry kept")
	}
}

func TestRetryableRefusalKeepsTheEntry(t *testing.T) {
	dir, now := t.TempDir(), time.Now()
	f := &fake{errs: []error{&federation.Error{Status: 429, Code: "QUOTA_EXCEEDED", Retryable: true}}}
	o := open(t, dir, f, &now)
	o.Enqueue("b", req(4, now.Add(time.Hour)))
	o.Process(context.Background())
	if o.Pending() != 1 {
		t.Fatal("a full mailbox must be retried, not dropped")
	}
}

func TestLocalDeliveryDoesNotUseTheNetwork(t *testing.T) {
	dir, now, f := t.TempDir(), time.Now(), &fake{}
	got := 0
	o, _ := Open(dir, "me", f, federation.SinkFunc(func(context.Context, federation.Peer, federation.Request) error { got++; return nil }))
	o.Now = func() time.Time { return now }
	o.Enqueue("me", req(5, now.Add(time.Hour)))
	if o.Process(context.Background()) != 1 || got != 1 || len(f.calls) != 0 {
		t.Fatalf("local=%d remote=%d", got, len(f.calls))
	}
}

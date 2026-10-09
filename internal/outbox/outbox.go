// Package outbox is the origin server's durable queue of envelopes headed for other servers' mailboxes: an
// entry survives a restart and is retried with backoff until it is delivered, refused for good, or expires.
package outbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	MaxPending = 20000
	minBackoff = 5 * time.Second
	maxBackoff = 10 * time.Minute
)

var ErrFull = errors.New("QUOTA_EXCEEDED")

type Sender interface {
	Send(ctx context.Context, to string, req federation.Request) error
}

type entry struct {
	To       string             `cbor:"to"`
	Req      federation.Request `cbor:"req"`
	Attempts uint64             `cbor:"attempts"`
	NextAt   uint64             `cbor:"next_at"`
	LastErr  string             `cbor:"last_error,omitempty"`
}

type Outbox struct {
	Self   string
	Remote Sender
	Local  federation.Sink // takes envelopes addressed to this very server
	Now    func() time.Time

	dir  string
	mu   sync.Mutex
	wake chan struct{}
	// InFlight guards a pass against a second concurrent pass delivering the same entry twice.
	run sync.Mutex
}

func Open(dir, self string, remote Sender, local federation.Sink) (*Outbox, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Outbox{Self: self, Remote: remote, Local: local, dir: dir, wake: make(chan struct{}, 1)}, nil
}

func (o *Outbox) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func name(to string, req federation.Request) string {
	h := sha256.New()
	h.Write([]byte("farlink/outbox/v1"))
	for _, p := range [][]byte{[]byte(to), req.Sender, req.Destination, req.DeliveryID} {
		h.Write([]byte{byte(len(p) >> 8), byte(len(p))})
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (o *Outbox) write(name string, e entry) error {
	data, err := wire.Enc.Marshal(e)
	if err != nil {
		return err
	}
	return durable.WriteFile(filepath.Join(o.dir, name), data)
}

// Enqueue makes the delivery durable before returning. The same delivery to the same server is one entry.
func (o *Outbox) Enqueue(to string, req federation.Request) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := name(to, req)
	if _, err := os.Stat(filepath.Join(o.dir, n)); err == nil {
		return nil
	}
	if o.count() >= MaxPending {
		return ErrFull
	}
	if err := o.write(n, entry{To: to, Req: req, NextAt: uint64(o.now().UnixMilli())}); err != nil {
		return err
	}
	select {
	case o.wake <- struct{}{}:
	default:
	}
	return nil
}

func (o *Outbox) count() int {
	list, _ := os.ReadDir(o.dir)
	n := 0
	for _, f := range list {
		if len(f.Name()) == 64 {
			n++
		}
	}
	return n
}

func (o *Outbox) Pending() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.count()
}

// Process makes one pass over the entries that are due and returns how many it delivered.
func (o *Outbox) Process(ctx context.Context) int {
	o.run.Lock()
	defer o.run.Unlock()
	list, _ := os.ReadDir(o.dir)
	delivered := 0
	for _, f := range list {
		if len(f.Name()) != 64 || ctx.Err() != nil {
			continue
		}
		path := filepath.Join(o.dir, f.Name())
		data, err := os.ReadFile(path)
		var e entry
		if err != nil || wire.Lenient(data, &e) != nil {
			os.Rename(path, path+".corrupt")
			continue
		}
		now := uint64(o.now().UnixMilli())
		if e.Req.ExpiresAt <= now {
			os.Remove(path)
			continue
		}
		if e.NextAt > now {
			continue
		}
		err = o.deliver(ctx, e)
		if err == nil {
			delivered++
			os.Remove(path)
			continue
		}
		if fe := new(federation.Error); errors.As(err, &fe) && !fe.Retryable && fe.Status < 500 && fe.Code != "QUOTA_EXCEEDED" {
			// The destination refused it for good (unknown server, expired, malformed, loop): retrying can't help.
			os.Remove(path)
			continue
		}
		e.Attempts++
		e.LastErr = err.Error()
		e.NextAt = now + uint64(backoff(e.Attempts).Milliseconds())
		o.mu.Lock()
		o.write(f.Name(), e)
		o.mu.Unlock()
	}
	return delivered
}

func (o *Outbox) deliver(ctx context.Context, e entry) error {
	if e.To == o.Self {
		return o.Local.Receive(ctx, federation.Peer{ServerID: o.Self}, e.Req)
	}
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return o.Remote.Send(c, e.To, e.Req)
}

func backoff(attempts uint64) time.Duration {
	d := minBackoff
	for i := uint64(1); i < attempts && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

// Run delivers until ctx ends, waking for new entries and otherwise every few seconds.
func (o *Outbox) Run(ctx context.Context) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		o.Process(ctx)
		select {
		case <-ctx.Done():
			return
		case <-o.wake:
		case <-t.C:
		}
	}
}

// PurgeDevices drops every queued delivery from or to the given devices (an account that was deleted).
func (o *Outbox) PurgeDevices(devs [][]byte) error {
	set := map[string]bool{}
	for _, d := range devs {
		set[string(d)] = true
	}
	o.run.Lock()
	defer o.run.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	list, err := os.ReadDir(o.dir)
	if err != nil {
		return err
	}
	for _, f := range list {
		if len(f.Name()) != 64 {
			continue
		}
		path := filepath.Join(o.dir, f.Name())
		data, err := os.ReadFile(path)
		var e entry
		if err != nil || wire.Lenient(data, &e) != nil {
			continue
		}
		if set[string(e.Req.Sender)] || set[string(e.Req.Destination)] {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return durable.SyncDir(o.dir)
}

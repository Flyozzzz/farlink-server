// Package relay forwards opaque binary frames between exactly two authenticated devices (protocol v1 §10):
// the WSS fallback when neither direct paths nor TURN work. It sees ciphertext only and counts bytes for quota.
package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/budget"
	"github.com/Flyozzzz/farlink-server/internal/meter"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	SessionTTL    = time.Hour
	JoinTimeout   = 2 * time.Minute // how long the first side waits for the second
	MaxFrame      = 20 << 20
	DefaultBudget = int64(1) << 40
	MaxPerOwner   = 32 // open relay sessions one device may hold
	// Fresh keys are free, so open sessions are also bounded per client address of the creator and in total.
	MaxPerIP = 256
	MaxTotal = 20_000
	// Frames being read or waiting to be written, across all sessions. A frame is held from its first byte until
	// the other side has taken it; when the budget is used up the session that asked for more is closed.
	MaxInflight = int64(512) << 20
	readStep    = 256 << 10
	// One frame arrives and leaves within this, or the session ends: a slow or stalled frame can't hold budget.
	FrameTimeout = 2 * time.Minute
)

// Inflight is a budget of bytes held in memory at once.
type Inflight struct {
	mu        sync.Mutex
	used, max int64
}

func NewInflight(max int64) *Inflight { return &Inflight{max: max} }

// TryAcquire takes n bytes if they fit; it never waits, so two sessions each holding part of a frame can't wait on
// each other.
func (i *Inflight) TryAcquire(n int64) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.used+n > i.max {
		return false
	}
	i.used += n
	return true
}

func (i *Inflight) Release(n int64) {
	i.mu.Lock()
	i.used -= n
	i.mu.Unlock()
}

type session struct {
	id        []byte
	owner     []byte
	ownerIP   string // bytes are billed to the owner and its address
	peer      []byte
	release   func() // gives back the owner's admission slot
	expires   time.Time
	joined    map[string]bool            // device id → slot taken (reserved before the upgrade)
	conns     map[string]*websocket.Conn // device id → conn
	ready     chan struct{}              // closed when both sides are connected
	readyOnce sync.Once
	endOnce   sync.Once
}

type Service struct {
	Auth *auth.Service
	// Meter admits new sessions and is charged every forwarded frame, to the device that opened the session and
	// its address. Sessions already open keep going on the ledger's overdraft, so the file in flight finishes.
	Meter meter.Meter
	// Blocked says a device belongs to a deleted account: a session ends at its next frame if either side does.
	Blocked     func(device []byte) bool
	Open        *budget.Gate // open sessions per owner device, owner address and in total
	Inflight    *Inflight    // frames held in memory, all sessions together
	Now         func() time.Time
	JoinTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*session
	lastGC   time.Time
}

func New(a *auth.Service) *Service {
	return &Service{Auth: a, Meter: meter.Off{}, Open: budget.NewGate(MaxPerOwner, MaxPerIP, MaxTotal), Now: time.Now, Inflight: NewInflight(MaxInflight),
		JoinTimeout: JoinTimeout, sessions: map[string]*session{}}
}

type CreateRequest struct {
	Peer []byte `cbor:"peer"`
}

type CreateResponse struct {
	RelayID   []byte `cbor:"relay_id"`
	ExpiresAt uint64 `cbor:"expires_at"`
}

// HandleCreate: POST /v1/relay/sessions. The peer consents by connecting to the session as itself. The session
// lives no longer than the creator's auth session.
func (s *Service) HandleCreate(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		var req CreateRequest
		if err := wire.ReadLimit(r, &req, wire.ControlBody); err != nil {
			wire.WriteReadError(w, err)
			return
		}
		if len(req.Peer) != 32 || string(req.Peer) == string(sess.DeviceID) {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		id := make([]byte, 16)
		rand.Read(id)
		exp := s.Now().Add(SessionTTL)
		if sess.ExpiresAt.Before(exp) {
			exp = sess.ExpiresAt
		}
		ip := wire.ClientIP(r)
		if !s.Meter.Admit(sess.DeviceID, ip) {
			wire.WriteError(w, 429, "QUOTA_EXCEEDED", false)
			return
		}
		s.mu.Lock()
		s.gc()
		s.mu.Unlock()
		release, ok := s.Open.Take(string(sess.DeviceID), ip, 1)
		if !ok {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		s.mu.Lock()
		s.sessions[string(id)] = &session{id: id, owner: sess.DeviceID, ownerIP: ip, peer: req.Peer, expires: exp, release: release,
			joined: map[string]bool{}, conns: map[string]*websocket.Conn{}, ready: make(chan struct{})}
		s.mu.Unlock()
		wire.Write(w, CreateResponse{RelayID: id, ExpiresAt: uint64(exp.UnixMilli())})
	})(w, r)
}

// HandleConnect: GET /v1/relay/{id} → WebSocket. Only the two named devices may join, once each; the slot is
// taken before the upgrade so a second connect as the same device fails, and any way out ends the session.
func (s *Service) HandleConnect(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		rid, err := decodeID(r.PathValue("id"))
		if err != nil {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		me := string(sess.DeviceID)
		s.mu.Lock()
		se := s.sessions[string(rid)]
		if se == nil || s.Now().After(se.expires) || (me != string(se.owner) && me != string(se.peer)) || se.joined[me] {
			s.mu.Unlock()
			wire.WriteError(w, 403, "AUTH_FAILED", false)
			return
		}
		se.joined[me] = true
		s.mu.Unlock()
		c, err := websocket.Accept(w, r, nil)
		if err != nil { // not a WebSocket after all: give the slot back
			s.mu.Lock()
			delete(se.joined, me)
			s.mu.Unlock()
			return
		}
		defer s.end(se)
		c.SetReadLimit(MaxFrame)
		// Each side is cut off by its own auth session, the relay's expiry, or the join timeout while alone.
		deadline := se.expires
		if sess.ExpiresAt.Before(deadline) {
			deadline = sess.ExpiresAt
		}
		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		s.mu.Lock()
		if se.conns == nil { // ended while upgrading
			s.mu.Unlock()
			c.CloseNow()
			return
		}
		se.conns[me] = c
		both := len(se.conns) == 2
		s.mu.Unlock()
		if both {
			se.readyOnce.Do(func() { close(se.ready) })
		}
		join := time.NewTimer(s.JoinTimeout)
		defer join.Stop()
		select {
		case <-se.ready:
		case <-join.C:
			c.Close(websocket.StatusGoingAway, "peer did not join")
			return
		case <-ctx.Done():
			c.Close(websocket.StatusGoingAway, "peer did not join")
			return
		}
		s.mu.Lock()
		var other *websocket.Conn
		for k, oc := range se.conns {
			if k != me {
				other = oc
			}
		}
		s.mu.Unlock()
		if other == nil {
			return
		}
		s.pump(ctx, se, c, other)
	})(w, r)
}

// end removes the session and closes both sides; called on every way out of a connect.
func (s *Service) end(se *session) {
	se.endOnce.Do(func() {
		s.mu.Lock()
		if s.sessions[string(se.id)] == se {
			delete(s.sessions, string(se.id))
			s.release(se)
		}
		conns := se.conns
		se.conns = nil
		s.mu.Unlock()
		for _, c := range conns {
			c.CloseNow()
		}
	})
}

func (s *Service) release(se *session) { se.release() }

// pump copies frames from c to other until either side stops; each side runs its own pump.
func (s *Service) pump(ctx context.Context, se *session, c, other *websocket.Conn) {
	for {
		typ, data, ok := s.readFrame(ctx, c)
		if !ok {
			return
		}
		held := int64(len(data))
		if s.Blocked != nil && (s.Blocked(se.owner) || s.Blocked(se.peer)) {
			s.Inflight.Release(held)
			return
		}
		if !s.Meter.Charge(se.owner, se.ownerIP, held) {
			s.Inflight.Release(held)
			return // closed without a handshake by end: the sender may not be reading
		}
		wctx, cancel := context.WithTimeout(ctx, FrameTimeout)
		err := other.Write(wctx, typ, data)
		cancel()
		s.Inflight.Release(held)
		if err != nil {
			return
		}
	}
}

// readFrame reads one message, taking its bytes from the shared budget as they arrive (the size isn't known
// before). On success the caller owns len(data) bytes of it. A frame that doesn't finish in time, or one that
// doesn't fit, ends the session.
func (s *Service) readFrame(ctx context.Context, c *websocket.Conn) (websocket.MessageType, []byte, bool) {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	typ, r, err := c.Reader(rctx)
	if err != nil {
		return 0, nil, false
	}
	timer := time.AfterFunc(FrameTimeout, cancel)
	defer timer.Stop()
	var buf bytes.Buffer
	var held int64
	for {
		if !s.Inflight.TryAcquire(readStep) {
			s.Inflight.Release(held)
			c.Close(websocket.StatusTryAgainLater, "busy")
			return 0, nil, false
		}
		held += readStep
		_, err := io.CopyN(&buf, r, readStep)
		if err == io.EOF {
			break
		}
		if err != nil {
			s.Inflight.Release(held)
			return 0, nil, false
		}
	}
	s.Inflight.Release(held - int64(buf.Len()))
	return typ, buf.Bytes(), true
}

// gc drops expired sessions nobody joined; joined ones end through their connect handlers.
func (s *Service) gc() {
	now := s.Now()
	if now.Sub(s.lastGC) < time.Minute && now.After(s.lastGC) {
		return
	}
	s.lastGC = now
	for k, se := range s.sessions {
		if now.After(se.expires) && len(se.joined) == 0 {
			delete(s.sessions, k)
			s.release(se)
		}
	}
}

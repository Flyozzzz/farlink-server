package signal

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// Frame is one WebSocket message in either direction; T is the frame type.
type Frame struct {
	T            string   `cbor:"t"`
	ResumeCursor uint64   `cbor:"resume_cursor,omitempty"`
	Tags         [][]byte `cbor:"tags,omitempty"`
	DeliveryID   []byte   `cbor:"delivery_id,omitempty"`
	Recipient    []byte   `cbor:"recipient,omitempty"`
	Sender       []byte   `cbor:"sender,omitempty"`
	Box          []byte   `cbor:"box,omitempty"`
	Sequence     uint64   `cbor:"server_sequence,omitempty"`
	Code         string   `cbor:"code,omitempty"`
	// Role in register: "" receives the device's mailbox; RoleSend only sends (an app extension sharing the
	// device's key). A send-only connection is not online for delivery, gets no deliveries and cannot ack, so
	// it never takes a box away from the process that handles it.
	Role string `cbor:"role,omitempty"`
}

const RoleSend = "send"

const (
	TRegister = "register"
	TSend     = "send"
	TSent     = "sent"
	TDeliver  = "deliver"
	TAck      = "ack"
	TPing     = "ping"
	TPong     = "pong"
	// TMailbox tells a connected device to fetch GET /v1/mailbox; it carries nothing else.
	TMailbox = "mailbox_available"
	TError   = "error"
)

// PeersHandler serves GET /v1/signal/peers/{tag}: online devices under a presence tag (authenticated callers).
func PeersHandler(h *Hub, a *auth.Service) http.HandlerFunc {
	return a.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		tag, err := decodeB64(r.PathValue("tag"))
		if err != nil || len(tag) != 32 {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		wire.Write(w, map[string][][]byte{"devices": h.Peers(tag)})
	})
}

// Handler serves GET /v1/signal for authenticated devices.
func Handler(h *Hub, a *auth.Service) http.HandlerFunc {
	return a.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		// Admission happens before the upgrade, so a refused client costs a small HTTP answer, not a socket.
		release, ok := h.Admit(sess.DeviceID, wire.ClientIP(r))
		if !ok {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		defer release()
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c.SetReadLimit(MaxBoxBytes + 4096)
		defer c.CloseNow()
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		// The session's own expiry ends the connection; the device re-authenticates and resumes.
		ctx, cancelTTL := context.WithDeadline(ctx, sess.ExpiresAt)
		defer cancelTTL()
		go func() { // an account deleted while this socket is open ends it too
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if a.IsBlocked(sess.DeviceID) {
						cancel()
						return
					}
				}
			}
		}()
		serve(ctx, c, h, sess.DeviceID)
	})
}

func write(ctx context.Context, c *websocket.Conn, f Frame) error {
	b, err := wire.Enc.Marshal(f)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Write(wctx, websocket.MessageBinary, b)
}

func serve(ctx context.Context, c *websocket.Conn, h *Hub, me []byte) {
	// The first frame must be register, carrying the cursor to resume after a reconnect; a socket that never
	// registers gives its slot back soon.
	rctx, cancel := context.WithTimeout(ctx, h.RegisterTimeout)
	_, data, err := c.Read(rctx)
	cancel()
	var reg Frame
	if err != nil || wire.Lenient(data, &reg) != nil || reg.T != TRegister {
		c.Close(websocket.StatusPolicyViolation, "register first")
		return
	}
	receiver := reg.Role != RoleSend
	if receiver {
		offline := h.Online(me)
		defer offline()
		if len(reg.Tags) > 8 {
			reg.Tags = reg.Tags[:8]
		}
		absent := h.Present(me, reg.Tags)
		defer absent()
	}

	errs := make(chan error, 2)
	go func() { // writer: pushes pending deliveries as they arrive (a send-only connection only gets pings)
		cursor := reg.ResumeCursor
		var hinted uint64
		if receiver {
			hinted = h.Hint(me) // a fresh connection polls on its own; only later news is pushed
		}
		for {
			var pending []Delivery
			var more <-chan struct{}
			if receiver {
				pending, more = h.Pending(me, cursor)
			}
			for _, d := range pending {
				if err := write(ctx, c, Frame{T: TDeliver, Sequence: d.Sequence, Sender: d.Sender, Box: d.Box}); err != nil {
					errs <- err
					return
				}
				cursor = d.Sequence
			}
			if receiver {
				if n := h.Hint(me); n != hinted {
					hinted = n
					if err := write(ctx, c, Frame{T: TMailbox}); err != nil {
						errs <- err
						return
					}
				}
			}
			select {
			case <-more:
			case <-time.After(25 * time.Second):
				if err := write(ctx, c, Frame{T: TPing}); err != nil {
					errs <- err
					return
				}
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			}
		}
	}()
	go func() { // reader
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				errs <- err
				return
			}
			var f Frame
			if wire.Lenient(data, &f) != nil {
				errs <- err
				return
			}
			switch f.T {
			case TSend:
				if len(f.Recipient) != 32 || len(f.DeliveryID) != 16 {
					write(ctx, c, Frame{T: TError, DeliveryID: f.DeliveryID, Code: "INVALID_ENCODING"})
					continue
				}
				if _, err := h.Send(ctx, me, f.Recipient, f.DeliveryID, f.Box); err != nil {
					write(ctx, c, Frame{T: TError, DeliveryID: f.DeliveryID, Code: err.Error()})
					continue
				}
				write(ctx, c, Frame{T: TSent, DeliveryID: f.DeliveryID})
			case TAck:
				if receiver {
					h.Ack(me, f.Sequence)
				}
			case TPing:
				write(ctx, c, Frame{T: TPong})
			}
		}
	}()
	<-errs
}

func decodeB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

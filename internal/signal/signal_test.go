package signal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

func id(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

func TestHubQueuesAcksAndDedups(t *testing.T) {
	h := NewHub()
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	ctx := context.Background()
	if ok, _ := h.Send(ctx, a, b, id(1), []byte("box1")); !ok {
		t.Fatal("first send not new")
	}
	if ok, _ := h.Send(ctx, a, b, id(1), []byte("box1")); ok {
		t.Fatal("duplicate delivery id accepted twice")
	}
	h.Send(ctx, a, b, id(2), []byte("box2"))
	p, _ := h.Pending(b, 0)
	if len(p) != 2 || p[0].Sequence != 1 || !bytes.Equal(p[1].Box, []byte("box2")) {
		t.Fatalf("pending = %+v", p)
	}
	h.Ack(b, 1)
	if p, _ = h.Pending(b, 0); len(p) != 1 || p[0].Sequence != 2 {
		t.Fatalf("after ack = %+v", p)
	}
}

func TestMailboxExpiresAndIsBounded(t *testing.T) {
	h := NewHub()
	now := time.Now()
	h.Now = func() time.Time { return now }
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	h.Send(context.Background(), a, b, id(1), []byte("x"))
	now = now.Add(MailboxTTL + time.Second)
	if p, _ := h.Pending(b, 0); len(p) != 0 {
		t.Fatal("stale box not expired")
	}
	for i := 0; i < MailboxLimit; i++ {
		d := make([]byte, 16)
		d[0], d[1] = byte(i), byte(i>>8)
		d[2] = 9
		if _, err := h.Send(context.Background(), a, b, d, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Send(context.Background(), a, b, id(0xEE), []byte("x")); err != ErrFull {
		t.Fatalf("want ErrFull, got %v", err)
	}
}

type dev struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   []byte
}

func newDev() dev {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := sha256.Sum256(pub)
	return dev{priv, pub, s[:]}
}

func login(t *testing.T, srv *httptest.Server, d dev) string {
	post := func(path string, v any, out any) {
		b, _ := wire.Enc.Marshal(v)
		resp, err := http.Post(srv.URL+path, "application/cbor", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		wire.Lenient(buf.Bytes(), out)
	}
	var ch auth.ChallengeResponse
	post("/v1/auth/challenges", auth.ChallengeRequest{DeviceID: d.id}, &ch)
	msg, _ := wire.Enc.Marshal(auth.SignedChallenge{ChallengeID: ch.ChallengeID, Nonce: ch.Nonce, Audience: ch.Audience, ExpiresAt: ch.ExpiresAt, DeviceID: d.id})
	var sr auth.SessionResponse
	post("/v1/auth/sessions", auth.SessionRequest{ChallengeID: ch.ChallengeID, SigningKey: d.pub, Signature: ed25519.Sign(d.priv, append([]byte("farlink/server-auth/v1"), msg...))}, &sr)
	return sr.Token
}

func dial(t *testing.T, ctx context.Context, srv *httptest.Server, token string, cursor uint64) *websocket.Conn {
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/signal"
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + token}}})
	if err != nil {
		t.Fatal(err)
	}
	send(t, ctx, c, Frame{T: TRegister, ResumeCursor: cursor})
	return c
}

func send(t *testing.T, ctx context.Context, c *websocket.Conn, f Frame) {
	b, _ := wire.Enc.Marshal(f)
	if err := c.Write(ctx, websocket.MessageBinary, b); err != nil {
		t.Fatal(err)
	}
}

func recv(t *testing.T, ctx context.Context, c *websocket.Conn) Frame {
	for {
		_, b, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var f Frame
		wire.Lenient(b, &f)
		if f.T != TPing {
			return f
		}
	}
}

func server() *httptest.Server {
	a := auth.New("test")
	h := NewHub()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("GET /v1/signal", Handler(h, a))
	return httptest.NewServer(mux)
}

func TestTwoDevicesExchangeBoxesOverWebSocket(t *testing.T) {
	srv := server()
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, air := newDev(), newDev()
	cm := dial(t, ctx, srv, login(t, srv, mac), 0)
	ca := dial(t, ctx, srv, login(t, srv, air), 0)

	send(t, ctx, cm, Frame{T: TSend, DeliveryID: id(7), Recipient: air.id, Box: []byte("sealed-box")})
	if f := recv(t, ctx, cm); f.T != TSent {
		t.Fatalf("sender got %+v", f)
	}
	f := recv(t, ctx, ca)
	if f.T != TDeliver || !bytes.Equal(f.Sender, mac.id) || string(f.Box) != "sealed-box" {
		t.Fatalf("recipient got %+v", f)
	}
	send(t, ctx, ca, Frame{T: TAck, Sequence: f.Sequence})
}

func TestUndeliveredBoxesAreResentAfterReconnect(t *testing.T) {
	srv := server()
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, air := newDev(), newDev()
	cm := dial(t, ctx, srv, login(t, srv, mac), 0)
	send(t, ctx, cm, Frame{T: TSend, DeliveryID: id(1), Recipient: air.id, Box: []byte("while-offline")})
	recv(t, ctx, cm)

	token := login(t, srv, air)
	ca := dial(t, ctx, srv, token, 0)
	f := recv(t, ctx, ca)
	if string(f.Box) != "while-offline" {
		t.Fatalf("got %+v", f)
	}
	ca.CloseNow() // dies before acking
	ca = dial(t, ctx, srv, token, 0)
	if f2 := recv(t, ctx, ca); f2.Sequence != f.Sequence {
		t.Fatalf("unacked box not redelivered: %+v", f2)
	}
}

func TestPresenceTags(t *testing.T) {
	h := NewHub()
	tag := bytes.Repeat([]byte{5}, 32)
	d := bytes.Repeat([]byte{1}, 32)
	gone := h.Present(d, [][]byte{tag})
	if p := h.Peers(tag); len(p) != 1 || !bytes.Equal(p[0], d) {
		t.Fatalf("peers = %v", p)
	}
	gone()
	if p := h.Peers(tag); len(p) != 0 {
		t.Fatal("device still present after disconnect")
	}
}

func TestUnauthenticatedSignalRejected(t *testing.T) {
	srv := server()
	defer srv.Close()
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/signal"
	if _, _, err := websocket.Dial(context.Background(), u, nil); err == nil {
		t.Fatal("dial without token succeeded")
	}
}

func dev32(i int) []byte {
	d := make([]byte, 32)
	d[0], d[1], d[2] = byte(i), byte(i>>8), 0xAB
	return d
}

func did(i int) []byte {
	d := make([]byte, 16)
	d[0], d[1], d[2] = byte(i), byte(i>>8), byte(i>>16)
	return d
}

func TestRandomMailboxesAreBoundedPerSenderAndCollected(t *testing.T) {
	h := NewHub()
	now := time.Now()
	h.Now = func() time.Time { return now }
	a := bytes.Repeat([]byte{1}, 32)
	ctx := context.Background()
	for i := 0; i < OfflineRecipients; i++ {
		if _, err := h.Send(ctx, a, dev32(i), did(i), []byte("x")); err != nil {
			t.Fatalf("recipient %d: %v", i, err)
		}
	}
	if _, err := h.Send(ctx, a, dev32(9999), did(9999), []byte("x")); err != ErrFanout {
		t.Fatalf("want ErrFanout, got %v", err)
	}
	// An already opened mailbox still takes more boxes.
	if _, err := h.Send(ctx, a, dev32(0), did(10000), []byte("x")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(MailboxTTL + time.Second)
	h.GC()
	if len(h.boxes) != 0 || len(h.senders) != 0 || h.bytes != 0 {
		t.Fatalf("abandoned state kept: %d boxes, %d senders, %d bytes", len(h.boxes), len(h.senders), h.bytes)
	}
	if _, err := h.Send(ctx, a, dev32(9999), did(9999), []byte("x")); err != nil {
		t.Fatalf("new window: %v", err)
	}
}

func TestSignalByteBudgets(t *testing.T) {
	h := NewHub()
	h.MaxSenderBytes, h.MaxTotalBytes = 3*(1000+boxOverhead), 5*(1000+boxOverhead)
	ctx := context.Background()
	box := make([]byte, 1000)
	a, b, c := dev32(1), dev32(2), dev32(3)
	for i := 0; i < 3; i++ {
		if _, err := h.Send(ctx, a, c, did(i), box); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Send(ctx, a, c, did(3), box); err != ErrFull {
		t.Fatalf("per-sender budget: %v", err)
	}
	h.Send(ctx, b, c, did(4), box)
	h.Send(ctx, b, c, did(5), box)
	if _, err := h.Send(ctx, b, c, did(6), box); err != ErrFull {
		t.Fatalf("global budget: %v", err)
	}
	h.Ack(c, 2)
	if _, err := h.Send(ctx, a, c, did(7), box); err != nil {
		t.Fatalf("acked bytes not released: %v", err)
	}
	// Empty boxes are not free.
	h2 := NewHub()
	h2.MaxMailboxBytes = 10 * boxOverhead
	for i := 0; i < 10; i++ {
		h2.Send(ctx, a, c, did(i), nil)
	}
	if _, err := h2.Send(ctx, a, c, did(10), nil); err != ErrFull {
		t.Fatalf("per-mailbox budget: %v", err)
	}
}

func TestOnlineMailboxIsNotCollected(t *testing.T) {
	h := NewHub()
	d := dev32(1)
	off := h.Online(d)
	h.GC()
	if !h.IsOnline(d) {
		t.Fatal("online mailbox collected")
	}
	off()
	h.GC()
	if len(h.boxes) != 0 {
		t.Fatal("empty offline mailbox kept")
	}
}

// An app extension shares the device's key: registered send-only, it can send, but it neither takes the
// device's deliveries nor acks them away from the app.
func TestSendOnlyConnectionNeitherReceivesNorAcks(t *testing.T) {
	srv := server()
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, air := newDev(), newDev()
	airToken := login(t, srv, air)
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/signal"
	ext, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {"Bearer " + airToken}}})
	if err != nil {
		t.Fatal(err)
	}
	send(t, ctx, ext, Frame{T: TRegister, Role: RoleSend})

	cm := dial(t, ctx, srv, login(t, srv, mac), 0)
	send(t, ctx, cm, Frame{T: TSend, DeliveryID: id(3), Recipient: air.id, Box: []byte("for-the-app")})
	recv(t, ctx, cm)
	// The extension acks blindly; nothing is dropped.
	send(t, ctx, ext, Frame{T: TAck, Sequence: 1})
	// It can still send.
	send(t, ctx, ext, Frame{T: TSend, DeliveryID: id(4), Recipient: mac.id, Box: []byte("open-relay")})
	if f := recv(t, ctx, ext); f.T != TSent {
		t.Fatalf("send-only connection got %+v", f)
	}
	if f := recv(t, ctx, cm); string(f.Box) != "open-relay" {
		t.Fatalf("mac got %+v", f)
	}
	app := dial(t, ctx, srv, airToken, 0)
	if f := recv(t, ctx, app); f.T != TDeliver || string(f.Box) != "for-the-app" {
		t.Fatalf("app got %+v", f)
	}
}

// Two receiving connections of one device both wake on a new box (the mailbox notification is a broadcast).
func TestEveryReceivingConnectionWakes(t *testing.T) {
	srv := server()
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, air := newDev(), newDev()
	token := login(t, srv, air)
	a1, a2 := dial(t, ctx, srv, token, 0), dial(t, ctx, srv, token, 0)
	time.Sleep(100 * time.Millisecond) // both writers are waiting
	cm := dial(t, ctx, srv, login(t, srv, mac), 0)
	send(t, ctx, cm, Frame{T: TSend, DeliveryID: id(5), Recipient: air.id, Box: []byte("both")})
	for _, c := range []*websocket.Conn{a1, a2} {
		if f := recv(t, ctx, c); string(f.Box) != "both" {
			t.Fatalf("got %+v", f)
		}
	}
}

// A mailbox server can only say "something is waiting"; the connected device then fetches it over HTTPS.
func TestNudgeWakesReceivingConnectionsOnlyAndIsNotStored(t *testing.T) {
	a := auth.New("test")
	h := NewHub()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("GET /v1/signal", Handler(h, a))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	air := newDev()
	token := login(t, srv, air)
	h.Nudge(air.id) // nobody connected: nothing is remembered
	c1, c2 := dial(t, ctx, srv, token, 0), dial(t, ctx, srv, token, 0)
	time.Sleep(100 * time.Millisecond)
	h.Nudge(air.id)
	for _, c := range []*websocket.Conn{c1, c2} {
		if f := recv(t, ctx, c); f.T != TMailbox {
			t.Fatalf("got %+v", f)
		}
	}
	h.Nudge(make([]byte, 32)) // another device: no effect on this one
	rctx, rcancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer rcancel()
	if _, _, err := c1.Read(rctx); err == nil {
		t.Fatal("a nudge for someone else woke this device")
	}
}

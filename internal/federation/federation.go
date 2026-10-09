// Package federation lets Farlink servers hand small sealed envelopes to each other (protocol v1 §10.2, §17.4):
// mutual TLS between servers listed in the signed registry, a hop limit, loop detection, and duplicate
// suppression by the receiving store. It never carries file bytes.
package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/registry"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	HopLimit     = 4
	MaxEnvelope  = 32 << 10
	MaxRequest   = 48 << 10
	MaxLifetime  = 7 * 24 * time.Hour
	forwardPath  = "/v1/federation/forward"
	clockSkew    = 5 * time.Minute
	requestLimit = 15 * time.Second
)

// Request is the federation envelope. The payload is opaque to the transport; Kind tells the receiving
// service what it is.
type Request struct {
	DeliveryID  []byte   `cbor:"delivery_id"`
	Origin      string   `cbor:"origin_server"`
	Sender      []byte   `cbor:"sender_device"`
	Destination []byte   `cbor:"destination_device"`
	ExpiresAt   uint64   `cbor:"expires_at"`
	HopLimit    uint64   `cbor:"hop_limit"`
	Visited     []string `cbor:"visited_servers"`
	Kind        string   `cbor:"kind"`
	SpoolID     []byte   `cbor:"spool_id,omitempty"`
	SpoolIDs    [][]byte `cbor:"spool_ids,omitempty"`
	Bytes       uint64   `cbor:"bytes,omitempty"`
	Admission   []byte   `cbor:"admission,omitempty"`
	Envelope    []byte   `cbor:"envelope"`
}

// Error is a refusal a Sink or a peer reports; Status and Code go on the wire.
type Error struct {
	Status    int
	Code      string
	Retryable bool
}

func (e *Error) Error() string { return e.Code }

func codeOf(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// Peer is a server the registry allows to speak federation.
type Peer struct {
	ServerID  string
	APIOrigin string
	// Pin is the SHA-256 of the SPKI of the peer's federation certificate (its federation_identity).
	Pin     []byte
	TLSPins [][]byte
}

// Directory answers who a certificate or a server id belongs to.
type Directory struct {
	mu    sync.RWMutex
	byID  map[string]Peer
	byPin map[string]Peer
}

// PinString is the registry's federation_identity spelling of a certificate pin.
func PinString(pin []byte) string { return base64.RawURLEncoding.EncodeToString(pin) }

// SPKIPin hashes a certificate's SubjectPublicKeyInfo.
func SPKIPin(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

// NewDirectory builds the peer set from a verified registry. Servers without a federation_identity cannot
// federate; a malformed one is an error so a typo isn't silently dropped from the mesh.
func NewDirectory(reg registry.Registry) (*Directory, error) {
	d := &Directory{}
	return d, d.Update(reg)
}

// Update swaps in the peers of a newer verified registry; a bad one changes nothing.
func (d *Directory) Update(reg registry.Registry) error {
	byID, byPin := map[string]Peer{}, map[string]Peer{}
	for _, s := range reg.Servers {
		if s.FederationIdentity == "" {
			continue
		}
		pin, err := base64.RawURLEncoding.DecodeString(s.FederationIdentity)
		if err != nil || len(pin) != 32 {
			return fmt.Errorf("server %s: federation_identity must be base64url SHA-256", s.ServerID)
		}
		p := Peer{ServerID: s.ServerID, APIOrigin: s.APIOrigin, Pin: pin, TLSPins: s.TLSSPKIPins}
		byID[p.ServerID] = p
		byPin[string(pin)] = p
	}
	d.mu.Lock()
	d.byID, d.byPin = byID, byPin
	d.mu.Unlock()
	return nil
}

// IDs lists every server of the directory.
func (d *Directory) IDs() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, 0, len(d.byID))
	for id := range d.byID {
		out = append(out, id)
	}
	return out
}

func (d *Directory) Peer(id string) (Peer, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.byID[id]
	return p, ok
}

func (d *Directory) ByPin(pin []byte) (Peer, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.byPin[string(pin)]
	return p, ok
}

// Sink is what a server does with an envelope addressed to it. Return an *Error to refuse with a code.
type Sink interface {
	Receive(ctx context.Context, from Peer, req Request) error
}

type SinkFunc func(ctx context.Context, from Peer, req Request) error

func (f SinkFunc) Receive(ctx context.Context, from Peer, req Request) error {
	return f(ctx, from, req)
}

// Server handles POST /v1/federation/forward.
type Server struct {
	Self string // this server's id
	Dir  *Directory
	Sink Sink
	// Next names the server that should get the envelope instead of this one ("" or Self: keep it here).
	Next   func(req Request) string
	Client *Client
	Now    func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Authenticate maps the TLS client certificate to a registry peer.
func (s *Server) Authenticate(r *http.Request) (Peer, bool) {
	return AuthenticatePeer(s.Dir, r)
}

// AuthenticatePeer maps a TLS client certificate to a registry peer.
func AuthenticatePeer(d *Directory, r *http.Request) (Peer, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return Peer{}, false
	}
	return d.ByPin(SPKIPin(r.TLS.PeerCertificates[0]))
}

// Validate checks everything a hop can check without trusting the sender's claims about the payload.
func (s *Server) Validate(from Peer, req *Request) error {
	bad := &Error{Status: 400, Code: "INVALID_ENCODING"}
	if len(req.DeliveryID) != 16 || len(req.Sender) != 32 || len(req.Destination) != 32 || req.Kind == "" || len(req.Kind) > 32 ||
		len(req.Envelope) == 0 || len(req.Envelope) > MaxEnvelope || req.Origin == "" || len(req.Visited) == 0 || len(req.Visited) > HopLimit {
		return bad
	}
	if req.HopLimit == 0 || req.HopLimit > HopLimit {
		return &Error{Status: 409, Code: "HOP_LIMIT"}
	}
	if req.Visited[0] != req.Origin || req.Visited[len(req.Visited)-1] != from.ServerID {
		return &Error{Status: 403, Code: "PEER_UNAUTHORIZED"}
	}
	seen := map[string]bool{}
	for _, v := range req.Visited {
		if v == "" || seen[v] {
			return bad
		}
		seen[v] = true
	}
	if seen[s.Self] {
		return &Error{Status: 409, Code: "FEDERATION_LOOP"}
	}
	now := uint64(s.now().UnixMilli())
	if req.ExpiresAt <= now {
		return &Error{Status: 410, Code: "EXPIRED"}
	}
	if req.ExpiresAt > now+uint64((MaxLifetime+clockSkew).Milliseconds()) {
		return bad
	}
	return nil
}

func (s *Server) HandleForward(w http.ResponseWriter, r *http.Request) {
	from, ok := s.Authenticate(r)
	if !ok {
		wire.WriteError(w, 401, "PEER_UNAUTHORIZED", false)
		return
	}
	var req Request
	if err := wire.ReadLimit(r, &req, MaxRequest); err != nil {
		wire.WriteReadError(w, err)
		return
	}
	if err := s.Validate(from, &req); err != nil {
		e, _ := codeOf(err)
		wire.WriteError(w, e.Status, e.Code, e.Retryable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestLimit)
	defer cancel()
	if s.Next != nil {
		if next := s.Next(req); next != "" && next != s.Self {
			if req.HopLimit <= 1 {
				wire.WriteError(w, 409, "HOP_LIMIT", false)
				return
			}
			onward := req
			onward.HopLimit--
			onward.Visited = append(slices.Clone(req.Visited), s.Self)
			if s.Client == nil {
				wire.WriteError(w, 503, "PEER_UNAVAILABLE", true)
				return
			}
			if err := s.Client.Send(ctx, next, onward); err != nil {
				if e, ok := codeOf(err); ok {
					wire.WriteError(w, e.Status, e.Code, e.Retryable)
					return
				}
				wire.WriteError(w, 503, "PEER_UNAVAILABLE", true)
				return
			}
			w.WriteHeader(204)
			return
		}
	}
	if err := s.Sink.Receive(ctx, from, req); err != nil {
		if e, ok := codeOf(err); ok {
			wire.WriteError(w, e.Status, e.Code, e.Retryable)
			return
		}
		wire.WriteError(w, 500, "INTERNAL", true)
		return
	}
	w.WriteHeader(204)
}

// Client sends envelopes to peers over mutual TLS.
type Client struct {
	Self string
	Dir  *Directory
	// Cert is this server's federation certificate; peers know it by its SPKI pin.
	Cert tls.Certificate
	// Roots verify peers that pin nothing (system PKI when nil).
	Roots *x509.CertPool
	HTTP  *http.Client // tests inject a transport; nil builds one per peer
	// pooled keeps one client per peer and pinned key set, so a quorum read does not pay a fresh
	// mutual-TLS handshake for every page. A changed pin set or address is a different key.
	pooled sync.Map
}

func (c *Client) httpFor(p Peer) *http.Client {
	if c.HTTP != nil {
		client := *c.HTTP
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &client
	}
	key := p.APIOrigin
	for _, pin := range p.TLSPins {
		key += "|" + hex.EncodeToString(pin)
	}
	if known, ok := c.pooled.Load(key); ok {
		return known.(*http.Client)
	}
	built := c.buildClient(p)
	known, _ := c.pooled.LoadOrStore(key, built)
	return known.(*http.Client)
}

func (c *Client) buildClient(p Peer) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.Cert}, RootCAs: c.Roots}
	if len(p.TLSPins) > 0 {
		// The registry pinned this peer's certificate, so the system PKI is not needed and not consulted.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			// Only the leaf proves possession of a key during the handshake; a pinned key elsewhere in the
			// presented chain would be public information anyone could attach to their own certificate.
			if len(raw) == 0 {
				return errors.New("federation: peer sent no certificate")
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return errors.New("federation: unreadable peer certificate")
			}
			pin := SPKIPin(cert)
			for _, want := range p.TLSPins {
				if bytes.Equal(pin, want) {
					return nil
				}
			}
			return errors.New("federation: peer certificate does not match its pinned key")
		}
	}
	return &http.Client{Timeout: requestLimit, Transport: &http.Transport{TLSClientConfig: cfg, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Send delivers req to the named peer. The caller has already set Origin, HopLimit and Visited (ending with
// this server). A refusal comes back as *Error; anything else is a transport failure worth retrying.
func (c *Client) Send(ctx context.Context, to string, req Request) error {
	return c.Post(ctx, to, forwardPath, req)
}

// Post sends any CBOR body to a federation path of a peer, with the same error mapping as Send.
func (c *Client) Post(ctx context.Context, to, path string, msg any) error {
	p, ok := c.Dir.Peer(to)
	if !ok {
		return &Error{Status: 404, Code: "UNKNOWN_SERVER"}
	}
	body, err := wire.Enc.Marshal(msg)
	if err != nil {
		return err
	}
	hr, err := http.NewRequestWithContext(ctx, "POST", p.APIOrigin+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/cbor")
	resp, err := c.httpFor(p).Do(hr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 || resp.StatusCode == 200 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	var we wire.Error
	if wire.Lenient(data, &we) == nil && we.Code != "" {
		return &Error{Status: resp.StatusCode, Code: we.Code, Retryable: we.Retryable}
	}
	return &Error{Status: resp.StatusCode, Code: "PEER_UNAVAILABLE", Retryable: resp.StatusCode >= 500}
}

// Call is Post with an answer: it decodes the peer's CBOR reply into out.
func (c *Client) Call(ctx context.Context, to, path string, msg, out any) error {
	p, ok := c.Dir.Peer(to)
	if !ok {
		return &Error{Status: 404, Code: "UNKNOWN_SERVER"}
	}
	body, err := wire.Enc.Marshal(msg)
	if err != nil {
		return err
	}
	hr, err := http.NewRequestWithContext(ctx, "POST", p.APIOrigin+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/cbor")
	resp, err := c.httpFor(p).Do(hr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == 204 || (resp.StatusCode == 200 && out == nil) {
		return nil
	}
	if resp.StatusCode == 200 {
		return wire.Lenient(data, out)
	}
	var we wire.Error
	if wire.Lenient(data, &we) == nil && we.Code != "" {
		return &Error{Status: resp.StatusCode, Code: we.Code, Retryable: we.Retryable}
	}
	return &Error{Status: resp.StatusCode, Code: "PEER_UNAVAILABLE", Retryable: resp.StatusCode >= 500}
}

// NewRequest starts an envelope from this server: it is the origin and the first visited hop.
func NewRequest(self string, deliveryID, sender, dest []byte, kind string, expiresAt uint64, envelope []byte) Request {
	return Request{DeliveryID: deliveryID, Origin: self, Sender: sender, Destination: dest, ExpiresAt: expiresAt,
		HopLimit: HopLimit, Visited: []string{self}, Kind: kind, Envelope: envelope}
}

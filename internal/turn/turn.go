// Package turn runs STUN/TURN (pion/turn) for WebRTC paths that can't go direct, with short-lived credentials
// minted per authenticated device (the usual TURN REST scheme: username "expiry:device", HMAC password).
package turn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pion/randutil"
	pionturn "github.com/pion/turn/v4"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/budget"
	"github.com/Flyozzzz/farlink-server/internal/meter"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	Realm         = "farlink"
	CredentialTTL = 6 * time.Hour
)

type Service struct {
	Auth   *auth.Service
	Secret []byte
	URLs   []string // advertised to clients, e.g. turn:host:3478, turns:host:5349
	Now    func() time.Time
	// Meter admits credentials and allocations and is charged every relayed datagram, to the device named in
	// the credentials and the client's address; a refused charge ends the allocation. nil = not counted.
	Meter meter.Meter
	// Allocations bounds allocations held at once; nil = the Max*Allocations defaults.
	Allocations *budget.Gate
	// PeerAllowed filters the addresses clients may relay to; nil = PublicPeer.
	PeerAllowed func(ip net.IP) bool
	// RelayPorts limits the UDP ports relayed traffic uses (min, max inclusive); zero = any free port.
	RelayPorts [2]uint16
	// UDPAddr is the address Listen actually bound.
	UDPAddr string
}

// LoadSecret reads or creates the HMAC secret in dir.
func LoadSecret(dir string) ([]byte, error) {
	p := dir + "/turn.secret"
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := make([]byte, 32)
	rand.Read(b)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return b, os.WriteFile(p, b, 0o600)
}

func (s *Service) password(username string) string {
	m := hmac.New(sha1.New, s.Secret)
	m.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

type Credentials struct {
	Username  string   `cbor:"username"`
	Password  string   `cbor:"password"`
	URLs      []string `cbor:"urls"`
	ExpiresAt uint64   `cbor:"expires_at"`
}

func (s *Service) Mint(device []byte) Credentials {
	exp := s.Now().Add(CredentialTTL)
	user := strconv.FormatInt(exp.Unix(), 10) + ":" + base64.RawURLEncoding.EncodeToString(device)
	return Credentials{Username: user, Password: s.password(user), URLs: s.URLs, ExpiresAt: uint64(exp.UnixMilli())}
}

// HandleCredentials: POST /v1/turn/credentials.
func (s *Service) HandleCredentials(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		if !s.meter().Admit(sess.DeviceID, wire.ClientIP(r)) {
			wire.WriteError(w, 429, "QUOTA_EXCEEDED", false)
			return
		}
		wire.Write(w, s.Mint(sess.DeviceID))
	})(w, r)
}

// AuthKey is the pion/turn auth handler: accepts only unexpired usernames with the right HMAC password.
func (s *Service) AuthKey(username, realm string, _ net.Addr) ([]byte, bool) {
	exp, _, ok := strings.Cut(username, ":")
	if !ok {
		return nil, false
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || s.Now().Unix() > t {
		return nil, false
	}
	return pionturn.GenerateAuthKey(username, realm, s.password(username)), true
}

// PublicPeer refuses relaying into loopback, private, link-local and other non-routable ranges, so TURN
// can't reach services on the server's own host or network.
func PublicPeer(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!cgnat.Contains(ip) && !ip.Equal(net.IPv4bcast)
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func (s *Service) permit(_ net.Addr, peer net.IP) bool {
	if s.PeerAllowed != nil {
		return s.PeerAllowed(peer)
	}
	return PublicPeer(peer)
}

// Listen starts TURN on UDP (and TLS if a config is given). publicIP is the address relayed candidates carry.
func (s *Service) Listen(udpAddr, tlsAddr string, tlsConfig *tls.Config, publicIP string) (*pionturn.Server, error) {
	ip := net.ParseIP(publicIP)
	if ip == nil {
		return nil, fmt.Errorf("turn: public IP %q is required", publicIP)
	}
	if s.Allocations == nil {
		s.Allocations = budget.NewGate(MaxAllocations, MaxIPAllocations, MaxTotalAllocations)
	}
	al := &allocations{svc: s, gate: s.Allocations, pending: map[string]*relayConn{}, clients: map[string]*relayConn{}}
	var inner pionturn.RelayAddressGenerator = &pionturn.RelayAddressGeneratorStatic{RelayAddress: ip, Address: "0.0.0.0"}
	if s.RelayPorts[1] != 0 {
		inner = &pionturn.RelayAddressGeneratorPortRange{RelayAddress: ip, Address: "0.0.0.0", MinPort: s.RelayPorts[0], MaxPort: s.RelayPorts[1],
			MaxRetries: 32, Rand: randutil.NewMathRandomGenerator()}
	}
	gen := &generator{RelayAddressGenerator: inner, al: al}
	cfg := pionturn.ServerConfig{Realm: Realm, AuthHandler: s.AuthKey, QuotaHandler: al.quota,
		EventHandler: pionturn.EventHandler{OnAllocationCreated: al.created}}
	pc, err := net.ListenPacket("udp4", udpAddr)
	if err != nil {
		return nil, err
	}
	s.UDPAddr = pc.LocalAddr().String()
	cfg.PacketConnConfigs = []pionturn.PacketConnConfig{{PacketConn: pc, RelayAddressGenerator: gen, PermissionHandler: al.permit}}
	if tlsAddr != "" && tlsConfig != nil {
		l, err := tls.Listen("tcp", tlsAddr, tlsConfig)
		if err != nil {
			pc.Close()
			return nil, err
		}
		cfg.ListenerConfigs = []pionturn.ListenerConfig{{Listener: l, RelayAddressGenerator: gen, PermissionHandler: al.permit}}
	}
	return pionturn.NewServer(cfg)
}

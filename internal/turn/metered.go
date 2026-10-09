package turn

import (
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"

	pionturn "github.com/pion/turn/v4"

	"github.com/Flyozzzz/farlink-server/internal/budget"
	"github.com/Flyozzzz/farlink-server/internal/meter"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	// Allocations held at once per device, per client address and in total; they stay on without quotas.
	MaxAllocations      = 16
	MaxIPAllocations    = 256
	MaxTotalAllocations = 20_000
	// MaxPeers bounds the peer addresses one allocation may be permitted to.
	MaxPeers = 64
)

var errQuota = errors.New("turn: allocation over quota")

// Every relayed datagram passes through a relayConn, in both directions: client → peer is a WriteTo, peer →
// client a ReadFrom. Each is charged to the allocation's device before it moves; a refused charge (or an
// error returned from ReadFrom) makes pion delete the allocation.

// allocations maps pion's allocation lifecycle onto our relay sockets. pion allocates the socket before it
// tells us whose allocation it is, so a fresh socket waits in pending (by relayed address) until
// OnAllocationCreated binds it to a device; until then it relays nothing.
type allocations struct {
	svc     *Service
	gate    *budget.Gate
	mu      sync.Mutex
	pending map[string]*relayConn // relayed address → socket not yet bound
	clients map[string]*relayConn // client transport address → its allocation's socket
}

func clientKey(a net.Addr) string { return a.Network() + "/" + a.String() }

// deviceOf is the device id in a minted username ("expiry:base64url(device)").
func deviceOf(username string) ([]byte, bool) {
	_, d, ok := strings.Cut(username, ":")
	if !ok {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(d)
	return b, err == nil && len(b) == 32
}

func addrBucket(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		return wire.IPBucket(v.IP)
	case *net.TCPAddr:
		return wire.IPBucket(v.IP)
	}
	host, _, _ := net.SplitHostPort(a.String())
	if ip := net.ParseIP(host); ip != nil {
		return wire.IPBucket(ip)
	}
	return host
}

// quota refuses an allocation up front (486) when the device or its address holds too many, or has no
// traffic left. Taking the slot happens in created, which also catches a race past this check.
func (al *allocations) quota(username, _ string, src net.Addr) bool {
	d, ok := deviceOf(username)
	if !ok {
		return false
	}
	ip := addrBucket(src)
	return al.gate.Fits(string(d), ip, 1) && al.svc.meter().Admit(d, ip)
}

func (al *allocations) created(src, _ net.Addr, _, username, _ string, relayAddr net.Addr, _ int) {
	al.mu.Lock()
	c := al.pending[relayAddr.String()]
	delete(al.pending, relayAddr.String())
	al.mu.Unlock()
	if c == nil {
		return
	}
	d, ok := deviceOf(username)
	if !ok {
		c.Close()
		return
	}
	ip := addrBucket(src)
	release, ok := al.gate.Take(string(d), ip, 1)
	if !ok {
		c.Close() // pion sees the read error and deletes the allocation
		return
	}
	key := clientKey(src)
	c.mu.Lock()
	if c.closed { // deleted meanwhile
		c.mu.Unlock()
		release()
		return
	}
	c.device, c.ip, c.client, c.release = d, ip, key, release
	c.mu.Unlock()
	al.mu.Lock()
	al.clients[key] = c
	al.mu.Unlock()
}

// permit records a peer an allocation may exchange datagrams with, after the address filter.
func (al *allocations) permit(client net.Addr, peer net.IP) bool {
	if !al.svc.permit(client, peer) {
		return false
	}
	al.mu.Lock()
	c := al.clients[clientKey(client)]
	al.mu.Unlock()
	if c == nil {
		return true // no allocation yet (pion checks permissions on its own); nothing to record
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peers[peer.String()] {
		return true
	}
	if len(c.peers) >= MaxPeers {
		return false
	}
	c.peers[peer.String()] = true
	return true
}

// generator wraps pion's address generator so every relay socket is metered.
type generator struct {
	pionturn.RelayAddressGenerator
	al *allocations
}

func (g *generator) AllocatePacketConn(network string, port int) (net.PacketConn, net.Addr, error) {
	pc, addr, err := g.RelayAddressGenerator.AllocatePacketConn(network, port)
	if err != nil {
		return nil, nil, err
	}
	c := &relayConn{PacketConn: pc, al: g.al, relayAddr: addr.String(), peers: map[string]bool{}}
	g.al.mu.Lock()
	g.al.pending[c.relayAddr] = c
	g.al.mu.Unlock()
	return c, addr, nil
}

type relayConn struct {
	net.PacketConn
	al        *allocations
	relayAddr string

	mu      sync.Mutex
	device  []byte // nil until bound
	ip      string
	client  string
	release func()
	peers   map[string]bool // permitted peer IPs: datagrams from anyone else are dropped by pion, uncharged
	closed  bool
}

func (c *relayConn) charge(n int) error {
	c.mu.Lock()
	d, ip := c.device, c.ip
	c.mu.Unlock()
	if d == nil || !c.al.svc.meter().Charge(d, ip, int64(n)) {
		return errQuota
	}
	return nil
}

func (c *relayConn) permitted(a net.Addr) bool {
	u, ok := a.(*net.UDPAddr)
	if !ok {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peers[u.IP.String()]
}

func (c *relayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if !c.permitted(addr) {
			continue // pion would drop it; not relayed, so not charged
		}
		if err := c.charge(n); err != nil {
			c.Close()
			return 0, addr, err
		}
		return n, addr, nil
	}
}

func (c *relayConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.charge(len(p)); err != nil {
		c.Close()
		return 0, err
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *relayConn) Close() error {
	c.mu.Lock()
	first := !c.closed
	c.closed = true
	release, client := c.release, c.client
	c.mu.Unlock()
	if !first {
		return nil // pion closes the socket again when it deletes an allocation we stopped
	}
	c.al.mu.Lock()
	delete(c.al.pending, c.relayAddr)
	if client != "" && c.al.clients[client] == c {
		delete(c.al.clients, client)
	}
	c.al.mu.Unlock()
	if release != nil {
		release()
	}
	return c.PacketConn.Close()
}

func (s *Service) meter() meter.Meter {
	if s.Meter == nil {
		return meter.Off{}
	}
	return s.Meter
}

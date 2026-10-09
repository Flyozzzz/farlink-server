package billing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// Teams resources go to the members of the network the pack was bought for, and the billing tag alone proves
// nothing: every former member knows it. So the server keeps, per network, the newest membership head it has
// verified (protocol v1 §4.1: each state names its predecessor by hash and is signed by an admin of it), and a
// device draws from the pool only while that head lists it. Heads only move forward along the chain the server
// already accepted; the first one is accepted together with a Teams purchase from an admin of it.

const (
	membershipDomain = "farlink/membership/v1"
	billingTagDomain = "farlink/billing/v1"
	// MaxLinks bounds one presented chain slice.
	MaxLinks = 4096
)

var (
	ErrChainInvalid = errors.New("billing: membership chain invalid")
	// ErrChainGap: the slice doesn't connect to the head the server knows; the client sends from that epoch.
	ErrChainGap = errors.New("billing: membership chain does not reach the known head")
	// ErrChainFork: a different history than the one the server accepted, not presented by one of its admins.
	ErrChainFork = errors.New("billing: membership chain diverges from the known head")
	ErrOtherNet  = errors.New("billing: membership chain of another network")
)

type chainMember struct {
	DeviceID   []byte `cbor:"device_id"`
	SigningKey []byte `cbor:"signing_key"`
	Admin      bool   `cbor:"admin"`
}

// membership is the part of a Membership state (FarlinkGroup/Membership.swift) the server checks; the
// signature covers the exact bytes, so fields it doesn't read don't matter.
type membership struct {
	Protocol  uint64        `cbor:"protocol"`
	GroupID   []byte        `cbor:"group_id"`
	Epoch     uint64        `cbor:"epoch"`
	PrevHash  []byte        `cbor:"prev_hash"`
	Admission string        `cbor:"admission"`
	Members   []chainMember `cbor:"members"`
	Revoked   [][]byte      `cbor:"revoked"`
	Author    []byte        `cbor:"author"`
}

type link struct {
	env  []byte // SignedMembership.encoded: [bytes, signature]
	hash [32]byte
	m    membership
	sig  []byte
	body []byte
}

func decodeLink(env []byte) (*link, error) {
	var parts [][]byte
	if wire.Lenient(env, &parts) != nil || len(parts) != 2 {
		return nil, ErrChainInvalid
	}
	l := &link{env: env, hash: sha256.Sum256(env), body: parts[0], sig: parts[1]}
	if wire.Lenient(l.body, &l.m) != nil || l.m.Protocol != 1 || len(l.m.GroupID) != 16 || len(l.m.PrevHash) != 32 ||
		(l.m.Admission != "any" && l.m.Admission != "admins") {
		return nil, ErrChainInvalid
	}
	for i, m := range l.m.Members {
		sum := sha256.Sum256(m.SigningKey)
		if len(m.SigningKey) != ed25519.PublicKeySize || !bytes.Equal(sum[:], m.DeviceID) ||
			(i > 0 && bytes.Compare(l.m.Members[i-1].DeviceID, m.DeviceID) >= 0) {
			return nil, ErrChainInvalid
		}
	}
	return l, nil
}

func (m *membership) member(id []byte) *chainMember {
	for i := range m.Members {
		if bytes.Equal(m.Members[i].DeviceID, id) {
			return &m.Members[i]
		}
	}
	return nil
}

func (m *membership) canAdminister(id []byte) bool {
	x := m.member(id)
	return x != nil && (m.Admission == "any" || x.Admin)
}

func (l *link) signedBy(key []byte) bool {
	return ed25519.Verify(key, append([]byte(membershipDomain), l.body...), l.sig)
}

func verifyGenesis(g *link) error {
	m := &g.m
	if m.Epoch != 0 || m.PrevHash == nil || !bytes.Equal(m.PrevHash, make([]byte, 32)) || len(m.Members) != 1 ||
		!m.Members[0].Admin || !bytes.Equal(m.Author, m.Members[0].DeviceID) || len(m.Revoked) != 0 ||
		!g.signedBy(m.Members[0].SigningKey) {
		return ErrChainInvalid
	}
	return nil
}

// verifyNext is MembershipChain.check without the seat count (devices enforce seats; the server only needs to
// know who is in): signed by an admin of prev, revocation permanent, a device id never changes its key.
func verifyNext(prev, next *link) error {
	p, n := &prev.m, &next.m
	if !bytes.Equal(n.GroupID, p.GroupID) || n.Epoch != p.Epoch+1 || !bytes.Equal(n.PrevHash, prev.hash[:]) {
		return ErrChainInvalid
	}
	author := p.member(n.Author)
	if author == nil || !p.canAdminister(n.Author) || !next.signedBy(author.SigningKey) {
		return ErrChainInvalid
	}
	revoked := map[string]bool{}
	for _, r := range n.Revoked {
		revoked[string(r)] = true
	}
	for _, r := range p.Revoked {
		if !revoked[string(r)] {
			return ErrChainInvalid
		}
	}
	admin := false
	for _, m := range n.Members {
		if revoked[string(m.DeviceID)] {
			return ErrChainInvalid
		}
		if old := p.member(m.DeviceID); old != nil && !bytes.Equal(old.SigningKey, m.SigningKey) {
			return ErrChainInvalid
		}
		admin = admin || m.Admin
	}
	if !admin {
		return ErrChainInvalid
	}
	return nil
}

// TagFor is the billing tag of a group (Billing.tag in the client).
func TagFor(group []byte) []byte {
	h := sha256.Sum256(append([]byte(billingTagDomain), group...))
	return h[:]
}

// networkHead is the newest verified membership state of a Teams network.
type networkHead struct {
	Genesis string `json:"genesis"` // hex hash of the genesis link
	Epoch   uint64 `json:"epoch"`
	Link    []byte `json:"link"` // the head's SignedMembership.encoded

	head    *link
	members map[string]bool // Buckets asks for every forwarded frame
}

func newHead(genesis string, l *link) *networkHead {
	h := &networkHead{Genesis: genesis, Epoch: l.m.Epoch, Link: l.env, head: l, members: map[string]bool{}}
	for _, m := range l.m.Members {
		h.members[string(m.DeviceID)] = true
	}
	return h
}

func (h *networkHead) load() error {
	l, err := decodeLink(h.Link)
	if err != nil || l.m.Epoch != h.Epoch {
		return ErrChainInvalid
	}
	*h = *newHead(h.Genesis, l)
	return nil
}

func (h *networkHead) isMember(dev []byte) bool { return h.members[string(dev)] }
func (h *networkHead) isAdmin(dev []byte) bool  { return h.head.m.canAdminister(dev) }

// advance verifies a contiguous slice of the chain of the network with this tag against what the server knows
// (known may be nil) and returns the head to keep: known moved forward, known unchanged (the slice is behind it
// or equal), or, for a network not known yet, the presented head (fromGenesis).
//
// A slice starts at genesis, at the known head itself or right after it. A full chain that parts from the known
// history replaces it only when presenter is an admin of the known head and of the new one: that is how an
// admin's fork resolution reaches the server, and a revoked device is no admin of the known head.
func advance(tag []byte, known *networkHead, envs [][]byte, presenter []byte) (next *networkHead, err error) {
	if len(envs) == 0 || len(envs) > MaxLinks {
		return nil, ErrChainInvalid
	}
	links := make([]*link, len(envs))
	for i, e := range envs {
		if links[i], err = decodeLink(e); err != nil {
			return nil, err
		}
	}
	first := links[0]
	prev := first
	// reached: the slice covers the known head's epoch; diverged: with another state there.
	reached, diverged := known == nil, false
	switch {
	case first.m.Epoch == 0:
		if err := verifyGenesis(first); err != nil {
			return nil, err
		}
		if !bytes.Equal(TagFor(first.m.GroupID), tag) || (known != nil && known.Genesis != hex.EncodeToString(first.hash[:])) {
			return nil, ErrOtherNet
		}
	case known == nil:
		return nil, ErrChainGap
	case first.m.Epoch == known.Epoch && first.hash == known.head.hash:
		reached = true
	case first.m.Epoch == known.Epoch+1:
		if err := verifyNext(known.head, first); err != nil {
			return nil, err
		}
		reached = true
	default:
		return nil, ErrChainGap
	}
	for i, l := range links {
		if i > 0 {
			if err := verifyNext(prev, l); err != nil {
				return nil, err
			}
			prev = l
		}
		if known != nil && first.m.Epoch == 0 && l.m.Epoch == known.Epoch {
			reached, diverged = true, l.hash != known.head.hash
		}
	}
	nh := newHead(hex.EncodeToString(first.hash[:]), prev)
	switch {
	case known == nil:
		return nh, nil
	case diverged:
		if known.isAdmin(presenter) && nh.isAdmin(presenter) {
			nh.Genesis = known.Genesis
			return nh, nil
		}
		return nil, ErrChainFork
	case reached && prev.m.Epoch > known.Epoch:
		nh.Genesis = known.Genesis
		return nh, nil
	default:
		return known, nil // behind or equal: nothing new, and nothing to check it against
	}
}

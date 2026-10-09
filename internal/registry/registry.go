// Package registry builds, signs and verifies servers.json (protocol v1 §12): a JSON wrapper around a
// deterministic-CBOR payload signed with the operator's Ed25519 key. Mirrors are not trusted; the signature is.
package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	Format = "farlink-servers-v1"
	domain = "farlink/servers/v1"
)

type Server struct {
	ServerID           string   `cbor:"server_id" json:"server_id"`
	Roles              []string `cbor:"roles" json:"roles"`
	APIOrigin          string   `cbor:"api_origin" json:"api_origin"`
	TURNURLs           []string `cbor:"turn_urls" json:"turn_urls"`
	Region             string   `cbor:"region" json:"region"`
	Priority           uint64   `cbor:"priority" json:"priority"`
	ProtocolMin        uint64   `cbor:"protocol_min" json:"protocol_min"`
	ProtocolMax        uint64   `cbor:"protocol_max" json:"protocol_max"`
	FederationIdentity string   `cbor:"federation_identity" json:"federation_identity"`
	TLSSPKIPins        [][]byte `cbor:"tls_spki_pins" json:"tls_spki_pins"`
}

type NextKey struct {
	KeyID            string `cbor:"key_id" json:"key_id"`
	PublicKey        []byte `cbor:"public_key" json:"public_key"`
	ActivateSequence uint64 `cbor:"activate_sequence" json:"activate_sequence"`
}

type Registry struct {
	Protocol   uint64    `cbor:"protocol" json:"protocol"`
	RegistryID string    `cbor:"registry_id" json:"registry_id"`
	Sequence   uint64    `cbor:"sequence" json:"sequence"`
	IssuedAt   uint64    `cbor:"issued_at" json:"issued_at"`
	ExpiresAt  uint64    `cbor:"expires_at" json:"expires_at"`
	Mirrors    []string  `cbor:"mirrors" json:"mirrors"`
	Servers    []Server  `cbor:"servers" json:"servers"`
	NextKeys   []NextKey `cbor:"next_keys" json:"next_keys"`
}

type Signature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type File struct {
	Format     string      `json:"format"`
	Payload    string      `json:"payload"`
	Signatures []Signature `json:"signatures"`
}

var (
	encMode, _ = cbor.CoreDetEncOptions().EncMode()
	decMode, _ = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecMode()
	b64 = base64.RawURLEncoding

	ErrSignature = errors.New("registry: no valid signature from a trusted key")
	ErrExpired   = errors.New("registry: expired")
	ErrRollback  = errors.New("registry: sequence rollback")
	ErrEncoding  = errors.New("registry: payload is not canonical CBOR")
)

// Validate checks the fields a client relies on before anything is signed.
func (r *Registry) Validate() error {
	if r.Protocol != 1 {
		return fmt.Errorf("protocol must be 1")
	}
	if r.ExpiresAt <= r.IssuedAt {
		return fmt.Errorf("expires_at must be after issued_at")
	}
	for _, m := range r.Mirrors {
		if err := httpsOrigin(m); err != nil {
			return fmt.Errorf("mirror %q: %w", m, err)
		}
	}
	seen := map[string]bool{}
	for _, s := range r.Servers {
		if s.ServerID == "" || seen[s.ServerID] {
			return fmt.Errorf("server id %q empty or duplicate", s.ServerID)
		}
		seen[s.ServerID] = true
		if err := httpsOrigin(s.APIOrigin); err != nil {
			return fmt.Errorf("server %s api_origin: %w", s.ServerID, err)
		}
		for _, t := range s.TURNURLs {
			u, err := url.Parse(t)
			if err != nil || (u.Scheme != "turn" && u.Scheme != "turns" && u.Scheme != "stun") {
				return fmt.Errorf("server %s: bad turn url %q", s.ServerID, t)
			}
		}
		for _, p := range s.TLSSPKIPins {
			if len(p) != 32 {
				return fmt.Errorf("server %s: spki pin must be 32 bytes", s.ServerID)
			}
		}
		if s.ProtocolMin == 0 || s.ProtocolMax < s.ProtocolMin {
			return fmt.Errorf("server %s: bad protocol range", s.ServerID)
		}
	}
	ids := map[string]bool{}
	for _, k := range r.NextKeys {
		if k.KeyID == "" || ids[k.KeyID] || len(k.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("next key %q: empty or duplicate id, or not an Ed25519 public key", k.KeyID)
		}
		ids[k.KeyID] = true
		// Clients trust the key for catalogs from activate_sequence on; one at or below this catalog's own
		// sequence would be a mistake nobody could use.
		if k.ActivateSequence <= r.Sequence {
			return fmt.Errorf("next key %s: activate_sequence must be above %d", k.KeyID, r.Sequence)
		}
	}
	return nil
}

func httpsOrigin(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("must be an https origin without credentials, path, query or fragment")
	}
	return nil
}

// Signer is one operator key a catalog is signed with.
type Signer struct {
	KeyID string
	Key   ed25519.PrivateKey
}

// Sign produces servers.json for r with the operator key.
func Sign(r *Registry, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	return SignWith(r, Signer{keyID, key})
}

// SignWith signs r with every signer: during a key rotation the old and the new key both sign, so clients that
// have not seen the announcement yet still verify.
func SignWith(r *Registry, signers ...Signer) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, errors.New("registry: no key")
	}
	sort.Slice(r.Servers, func(i, j int) bool { return r.Servers[i].ServerID < r.Servers[j].ServerID })
	payload, err := encMode.Marshal(r)
	if err != nil {
		return nil, err
	}
	f := File{Format: Format, Payload: b64.EncodeToString(payload)}
	for _, s := range signers {
		sig := ed25519.Sign(s.Key, append([]byte(domain), payload...))
		f.Signatures = append(f.Signatures, Signature{KeyID: s.KeyID, Signature: b64.EncodeToString(sig)})
	}
	return json.MarshalIndent(f, "", "  ")
}

// Verify checks format, canonical encoding, a signature by one of trusted (key_id → public key), expiry and
// that the sequence doesn't go back from minSequence.
func Verify(data []byte, trusted map[string]ed25519.PublicKey, now time.Time, minSequence uint64) (*Registry, error) {
	return VerifyWith(data, trusted, nil, now, minSequence)
}

// VerifyWith is Verify that also trusts keys earlier accepted catalogs announced (next_keys), each only for
// catalogs from its activate_sequence on; a pinned key id is never replaced by an announcement.
func VerifyWith(data []byte, trusted map[string]ed25519.PublicKey, announced []NextKey, now time.Time, minSequence uint64) (*Registry, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil || f.Format != Format {
		return nil, fmt.Errorf("registry: bad wrapper")
	}
	payload, err := b64.DecodeString(f.Payload)
	if err != nil {
		return nil, fmt.Errorf("registry: bad payload encoding")
	}
	var r Registry
	if err := decMode.Unmarshal(payload, &r); err != nil {
		return nil, ErrEncoding
	}
	if again, err := encMode.Marshal(&r); err != nil || !bytes.Equal(again, payload) {
		return nil, ErrEncoding
	}
	keys := map[string]ed25519.PublicKey{}
	for id, k := range trusted {
		keys[id] = k
	}
	for _, k := range announced {
		if _, pinned := keys[k.KeyID]; !pinned && k.ActivateSequence <= r.Sequence && len(k.PublicKey) == ed25519.PublicKeySize {
			keys[k.KeyID] = ed25519.PublicKey(k.PublicKey)
		}
	}
	ok := false
	for _, s := range f.Signatures {
		pub, known := keys[s.KeyID]
		sig, err := b64.DecodeString(s.Signature)
		if known && err == nil && ed25519.Verify(pub, append([]byte(domain), payload...), sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, ErrSignature
	}
	if uint64(now.UnixMilli()) >= r.ExpiresAt {
		return nil, ErrExpired
	}
	if r.Sequence < minSequence {
		return nil, ErrRollback
	}
	return &r, nil
}

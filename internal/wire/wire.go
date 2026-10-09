// Package wire holds the deterministic CBOR codec and the error body every endpoint uses (protocol v1 §2, §14).
package wire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/fxamacker/cbor/v2"
)

const (
	MaxBody     = 20 << 20 // protocol v1 frame limit
	ControlBody = 16 << 10 // auth, invites, relay/turn control requests
)

var (
	Enc, _ = cbor.CoreDetEncOptions().EncMode()
	Dec, _ = cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		IndefLength:     cbor.IndefLengthForbidden,
		TagsMd:          cbor.TagsForbidden,
		MaxNestedLevels: 32,
	}.DecMode()
	ErrNonCanonical = errors.New("non-canonical CBOR")
	ErrTooLarge     = errors.New("LIMIT_EXCEEDED")
)

// Unmarshal decodes and insists the input was already in canonical form (signatures cover exact bytes).
func Unmarshal(data []byte, v any) error {
	if err := Dec.Unmarshal(data, v); err != nil {
		return err
	}
	again, err := Enc.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, data) {
		return ErrNonCanonical
	}
	return nil
}

// Lenient decodes without the canonical check, for request bodies that are not signed.
func Lenient(data []byte, v any) error { return Dec.Unmarshal(data, v) }

type Error struct {
	Protocol     uint64            `cbor:"protocol"`
	Code         string            `cbor:"code"`
	Retryable    bool              `cbor:"retryable"`
	RetryAfterMs uint64            `cbor:"retry_after_ms,omitempty"`
	Details      map[string]string `cbor:"details"`
}

func WriteError(w http.ResponseWriter, status int, code string, retryable bool) {
	b, _ := Enc.Marshal(Error{Protocol: 1, Code: code, Retryable: retryable, Details: map[string]string{}})
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(status)
	w.Write(b)
}

func Write(w http.ResponseWriter, v any) {
	b, err := Enc.Marshal(v)
	if err != nil {
		WriteError(w, 500, "INTERNAL", true)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.Write(b)
}

func Read(r *http.Request, v any) error { return ReadLimit(r, v, MaxBody) }

// ReadLimit decodes a request body of at most limit bytes.
func ReadLimit(r *http.Request, v any, limit int64) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(b)) > limit {
		return ErrTooLarge
	}
	return Lenient(b, v)
}

// WriteReadError answers a failed Read: LIMIT_EXCEEDED for oversized bodies, INVALID_ENCODING otherwise.
func WriteReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrTooLarge) {
		WriteError(w, 413, "LIMIT_EXCEEDED", false)
		return
	}
	WriteError(w, 400, "INVALID_ENCODING", false)
}

// ClientIP is the bucket per-address limits count against: the peer IPv4 address, or the /64 of an IPv6 one
// (one host usually owns a whole /64).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	return IPBucket(ip)
}

// IPBucket is ClientIP for an address that didn't come with an HTTP request (TURN).
func IPBucket(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

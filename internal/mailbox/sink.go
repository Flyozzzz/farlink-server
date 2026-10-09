package mailbox

import (
	"context"
	"errors"

	"github.com/Flyozzzz/farlink-server/internal/federation"
)

// Sink stores envelopes that other servers forward here; it is the federation endpoint's destination.
func (s *Store) Sink() federation.Sink {
	return federation.SinkFunc(func(_ context.Context, _ federation.Peer, r federation.Request) error {
		_, err := s.Put(Item{DeliveryID: r.DeliveryID, Origin: r.Origin, Sender: r.Sender, Dest: r.Destination,
			ExpiresAt: r.ExpiresAt, Kind: r.Kind, SpoolID: r.SpoolID, Bytes: r.Bytes, Envelope: r.Envelope, Admission: r.Admission})
		switch {
		case err == nil:
			return nil
		case errors.Is(err, ErrFull):
			return &federation.Error{Status: 429, Code: "QUOTA_EXCEEDED", Retryable: true}
		case errors.Is(err, ErrTooBig):
			return &federation.Error{Status: 413, Code: "LIMIT_EXCEEDED"}
		case errors.Is(err, ErrExpired):
			return &federation.Error{Status: 410, Code: "EXPIRED"}
		case errors.Is(err, ErrGone):
			return &federation.Error{Status: 410, Code: "ACCOUNT_DELETED"}
		case errors.Is(err, ErrInvalid):
			return &federation.Error{Status: 400, Code: "INVALID_ENCODING"}
		}
		return err
	})
}

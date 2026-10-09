package relay

import (
	"encoding/base64"
	"errors"
)

func decodeID(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, errors.New("bad id")
	}
	return b, nil
}

// EncodeID is how ids appear in URLs.
func EncodeID(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

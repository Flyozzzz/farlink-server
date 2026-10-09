package wire

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestReadLimit(t *testing.T) {
	b, _ := Enc.Marshal(map[string][]byte{"x": make([]byte, 100)})
	var v map[string][]byte
	if err := ReadLimit(httptest.NewRequest("POST", "/", bytes.NewReader(b)), &v, int64(len(b))); err != nil {
		t.Fatal(err)
	}
	if err := ReadLimit(httptest.NewRequest("POST", "/", bytes.NewReader(b)), &v, int64(len(b)-1)); err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestClientIPBuckets(t *testing.T) {
	for addr, want := range map[string]string{
		"198.51.100.7:443":         "198.51.100.7",
		"[2001:db8:1:2:3::4]:443":  "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff::]:80": "2001:db8:1:2::/64",
		"[::ffff:192.0.2.1]:80":    "192.0.2.1",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = addr
		if got := ClientIP(r); got != want {
			t.Errorf("%s → %s, want %s", addr, got, want)
		}
	}
}

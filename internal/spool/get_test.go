package spool

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

// capMeter lets limit bytes through and records what it was asked for.
type capMeter struct {
	mu      sync.Mutex
	limit   int64
	charged int64
}

func (m *capMeter) Admit([]byte, string) bool                      { return true }
func (m *capMeter) ChargeAccount(_ []byte, _ string, n int64) bool { return m.Charge(nil, "", n) }
func (m *capMeter) ChargeTransit([]byte, string, int64) bool       { return true }
func (m *capMeter) Charge(_ []byte, _ string, n int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.charged+n > m.limit {
		return false
	}
	m.charged += n
	return true
}

func uploaded(t *testing.T, f *fixture) string {
	pu := f.url("parts", enc.EncodeToString(f.part.PartID))
	if testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil) != 204 || f.commit(t) != 204 {
		t.Fatal("upload failed")
	}
	return pu
}

// A recipient that never acks can't pull a committed object forever: a few whole copies, then 429.
func TestRepeatedGetsOfOneObjectAreCapped(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	pu := uploaded(t, f)
	for i := 0; i < MaxServedCopies; i++ {
		var got []byte
		if code := testutil.Do(t, "GET", pu, f.tPeer, nil, &got); code != 200 || len(got) != 1000 {
			t.Fatalf("download %d = %d, %d bytes", i, code, len(got))
		}
	}
	if code := testutil.Do(t, "GET", pu, f.tPeer, nil, nil); code != 429 {
		t.Fatalf("download past the cap = %d", code)
	}
	f.s.mu.Lock()
	o := f.s.objects[string(f.id)]
	f.s.mu.Unlock()
	if served := o.Served[enc.EncodeToString(f.peer.ID)]; served != MaxServedCopies*1000 {
		t.Fatalf("served = %d", served)
	}
}

// One logical send is billed once, in full, before the first byte goes out: a meter that cannot cover the whole
// object refuses the download up front (nothing is sent unbilled), and once billed, further downloads - the same
// recipient resuming, another device of the recipient - are not billed again.
func TestDownloadIsBilledOnceInFullBeforeAnyByteGoesOut(t *testing.T) {
	srv, s := setup(t, 1<<30)
	defer srv.Close()
	owner, peer := testutil.NewDevice(), testutil.NewDevice()
	tOwner, tPeer := testutil.Login(t, srv.URL, owner), testutil.Login(t, srv.URL, peer)
	data := make([]byte, 1<<20)
	rand.Read(data)
	sum := sha256.Sum256(data)
	pid := make([]byte, 16)
	rand.Read(pid)
	f := &fixture{srv: srv, s: s, owner: owner, peer: peer, tOwner: tOwner, tPeer: tPeer, data: data,
		part: Part{PartID: pid, Size: uint64(len(data)), CiphertextSHA256: sum[:]}}
	var cr CreateResponse
	if testutil.Do(t, "POST", srv.URL+"/v1/spools", tOwner, CreateRequest{Recipients: [][]byte{peer.ID}, Parts: []Part{f.part}}, &cr) != 200 {
		t.Fatal("create failed")
	}
	f.id = cr.SpoolID
	pu := uploaded(t, f)
	m := &capMeter{limit: 300 << 10} // cannot cover the object
	s.Meter = m
	var got []byte
	if code := testutil.Do(t, "GET", pu, tPeer, nil, nil); code != 429 || m.charged != 0 {
		t.Fatalf("a meter that cannot cover the object: %d, billed %d", code, m.charged)
	}
	m.limit = 2 << 20
	if code := testutil.Do(t, "GET", pu, tPeer, nil, &got); code != 200 || len(got) != len(data) || m.charged != int64(len(data)) {
		t.Fatalf("covered download: %d, sent %d bytes, billed %d", code, len(got), m.charged)
	}
	// A second pass and a resume cost nothing more, even on a meter that has nothing left.
	m.limit = m.charged
	if code := testutil.Do(t, "GET", pu, tPeer, nil, &got); code != 200 || m.charged != int64(len(data)) {
		t.Fatalf("second download: %d, billed %d", code, m.charged)
	}
}

func TestConcurrentGetsAreBoundedPerRecipient(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	pu := uploaded(t, f)
	f.s.Gets.PerDevice = 1
	hold, ok := f.s.Gets.Take(string(f.peer.ID), "127.0.0.1", 1) // one download of this recipient in progress
	if !ok {
		t.Fatal("take")
	}
	if code := testutil.Do(t, "GET", pu, f.tPeer, nil, nil); code != 429 {
		t.Fatalf("second concurrent download = %d", code)
	}
	hold()
	f.s.GetInflight.PerDevice = 999 // the part is 1000 bytes
	if code := testutil.Do(t, "GET", pu, f.tPeer, nil, nil); code != 429 {
		t.Fatalf("download over the in-flight bytes = %d", code)
	}
	f.s.GetInflight.PerDevice = MaxGetInflightBytes
	if code := testutil.Do(t, "GET", pu, f.tPeer, nil, nil); code != 200 {
		t.Fatalf("download once there is room = %d", code)
	}
	if _, _, total := f.s.GetInflight.Held("", ""); total != 0 {
		t.Fatalf("in-flight bytes left held: %d", total)
	}
}

// A reader that stops taking bytes doesn't keep the file, the request slot or the in-flight bytes forever.
func TestAStalledDownloadReleasesWhatItHolds(t *testing.T) {
	old := GetStall
	GetStall = 300 * time.Millisecond
	defer func() { GetStall = old }()
	f := newFixture(t)
	defer f.srv.Close()
	f.data = make([]byte, 5<<20) // the largest part; the reader below takes almost nothing
	rand.Read(f.data)
	sum := sha256.Sum256(f.data)
	pid := make([]byte, 16)
	rand.Read(pid)
	f.part = Part{PartID: pid, Size: uint64(len(f.data)), CiphertextSHA256: sum[:]}
	var cr CreateResponse
	if testutil.Do(t, "POST", f.srv.URL+"/v1/spools", f.tOwner, CreateRequest{Recipients: [][]byte{f.peer.ID}, Parts: []Part{f.part}}, &cr) != 200 {
		t.Fatal("create failed")
	}
	f.id = cr.SpoolID
	pu := uploaded(t, f)

	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2048) })
	}}
	conn, err := d.Dial("tcp", strings.TrimPrefix(f.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	u, _ := url.Parse(pu)
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n\r\n", u.Path, u.Host, f.tPeer)

	deadline := time.Now().Add(10 * time.Second)
	sawHeld := false
	for time.Now().Before(deadline) {
		_, _, held := f.s.GetInflight.Held("", "")
		if held > 0 {
			sawHeld = true
		} else if sawHeld {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("stalled download still holds its bytes (seen holding: %v)", sawHeld)
}

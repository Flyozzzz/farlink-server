package spool

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

type multi struct {
	*fixture
	peers  []testutil.Device
	tokens []string
}

// newMulti reserves an object with n recipients, uploads its part and commits it.
func newMulti(t *testing.T, n int) *multi {
	f := &fixture{owner: testutil.NewDevice()}
	f.srv, f.s = setup(t, 1<<30)
	f.tOwner = testutil.Login(t, f.srv.URL, f.owner)
	m := &multi{fixture: f}
	var ids [][]byte
	for i := 0; i < n; i++ {
		d := testutil.NewDevice()
		m.peers = append(m.peers, d)
		m.tokens = append(m.tokens, testutil.Login(t, f.srv.URL, d))
		ids = append(ids, d.ID)
	}
	f.data = make([]byte, 4096)
	rand.Read(f.data)
	sum := sha256.Sum256(f.data)
	pid := make([]byte, 16)
	rand.Read(pid)
	f.part = Part{PartID: pid, Size: uint64(len(f.data)), CiphertextSHA256: sum[:]}
	var cr CreateResponse
	if testutil.Do(t, "POST", f.srv.URL+"/v1/spools", f.tOwner, CreateRequest{Recipients: ids, Parts: []Part{f.part}}, &cr) != 200 {
		t.Fatal("create failed")
	}
	f.id = cr.SpoolID
	if code := testutil.Do(t, "PUT", f.url("parts", enc.EncodeToString(pid)), f.tOwner, f.data, nil); code != 204 {
		t.Fatalf("put = %d", code)
	}
	if code := m.commitAll(t); code != 204 {
		t.Fatalf("commit = %d", code)
	}
	return m
}

func (m *multi) commitAll(t *testing.T) int {
	return testutil.Do(t, "POST", m.url("commit"), m.tOwner, m.commitRequest(), nil)
}

func (m *multi) commitRequest() CommitRequest {
	m.s.mu.Lock()
	o := m.s.objects[string(m.id)]
	m.s.mu.Unlock()
	o.mu.Lock()
	d := o.Descriptor
	o.mu.Unlock()
	d.Boxes = nil
	for _, p := range m.peers {
		d.Boxes = append(d.Boxes, Box{Recipient: p.ID, Box: []byte("sealed")})
	}
	msg, _ := wire.Enc.Marshal(d)
	return CommitRequest{Boxes: d.Boxes, SigningKey: m.owner.Pub, Signature: ed25519.Sign(m.owner.Priv, append([]byte(domain), msg...))}
}

func (s *Service) usageEmpty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.objects) == 0 && len(s.owners) == 0 && len(s.ips) == 0 && s.total == usage{}
}

func TestConcurrentReadAckAndDelete(t *testing.T) {
	m := newMulti(t, 6)
	defer m.srv.Close()
	pu := m.url("parts", enc.EncodeToString(m.part.PartID))
	var wg sync.WaitGroup
	for i, tok := range m.tokens {
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func(tok string, j int) {
				defer wg.Done()
				switch j {
				case 0:
					testutil.Do(t, "GET", m.url(), tok, nil, nil)
				case 1:
					var b []byte
					if code := testutil.Do(t, "GET", pu, tok, nil, &b); code == 200 && string(b) != string(m.data) {
						t.Error("torn part read")
					}
				case 2:
					testutil.Do(t, "GET", m.srv.URL+"/v1/spools", tok, nil, nil)
				case 3:
					if code := testutil.Do(t, "POST", m.url("ack"), tok, nil, nil); code != 204 && code != 404 {
						t.Errorf("ack = %d", code)
					}
				}
			}(tok, j)
		}
		if i == 3 {
			wg.Add(1)
			go func() { defer wg.Done(); testutil.Do(t, "DELETE", m.url(), m.tOwner, nil, nil) }()
		}
	}
	wg.Wait()
	if !m.s.usageEmpty() {
		t.Fatal("state or quota left after every recipient acked and the owner deleted")
	}
	if _, err := os.Stat(m.s.path(string(m.id))); !os.IsNotExist(err) {
		t.Fatal("object directory left on disk")
	}
}

func TestAllAcksRemoveTheObjectExactlyOnce(t *testing.T) {
	m := newMulti(t, 8)
	defer m.srv.Close()
	var wg sync.WaitGroup
	for _, tok := range m.tokens {
		for k := 0; k < 3; k++ {
			wg.Add(1)
			go func(tok string) {
				defer wg.Done()
				testutil.Do(t, "POST", m.url("ack"), tok, nil, nil)
			}(tok)
		}
	}
	wg.Wait()
	if !m.s.usageEmpty() {
		t.Fatal("object kept or quota released twice after concurrent acks")
	}
}

func TestConcurrentPutsCommitAndDelete(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	pu := f.url("parts", enc.EncodeToString(f.part.PartID))
	var wg sync.WaitGroup
	var stored atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// One body per part at a time: the others are told to retry, never half-accepted.
			switch code := testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil); code {
			case 204:
				stored.Add(1)
			case 429:
			default:
				t.Errorf("concurrent identical put = %d", code)
			}
		}()
	}
	wg.Wait()
	if stored.Load() == 0 {
		t.Fatal("no concurrent put stored the part")
	}
	tmps, _ := filepath.Glob(filepath.Join(f.s.path(string(f.id)), "*", "*.tmp"))
	if len(tmps) != 0 {
		t.Fatalf("temporary files left: %v", tmps)
	}
	// Commits and a delete race; whatever wins, the end state is consistent and no PUT lands afterwards.
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); f.commit(t) }()
		go func() { defer wg.Done(); testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); testutil.Do(t, "DELETE", f.url(), f.tOwner, nil, nil) }()
	wg.Wait()
	if code := testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil); code != 404 {
		t.Fatalf("put after commit/delete = %d", code)
	}
	if !f.s.usageEmpty() {
		t.Fatal("deleted object still counted")
	}
}

func TestCommitIsTerminal(t *testing.T) {
	m := newMulti(t, 1)
	defer m.srv.Close()
	if code := m.commitAll(t); code != 204 {
		t.Fatalf("retried identical commit = %d", code)
	}
	m.peers = append(m.peers, m.peers[0])
	req := m.commitRequest()
	req.Boxes = req.Boxes[:1]
	req.Boxes[0].Box = []byte("other")
	d := m.s.objects[string(m.id)].Descriptor
	d.Boxes = req.Boxes
	msg, _ := wire.Enc.Marshal(d)
	req.Signature = ed25519.Sign(m.owner.Priv, append([]byte(domain), msg...))
	if code := testutil.Do(t, "POST", m.url("commit"), m.tOwner, req, nil); code != 409 {
		t.Fatalf("re-commit with other boxes = %d", code)
	}
	if code := testutil.Do(t, "PUT", m.url("parts", enc.EncodeToString(m.part.PartID)), m.tOwner, m.data, nil); code != 404 {
		t.Fatalf("put after commit = %d", code)
	}
}

func TestPersistenceErrorsAreNotSuccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f := newFixture(t)
	defer f.srv.Close()
	dir := f.s.path(string(f.id))
	pu := f.url("parts", enc.EncodeToString(f.part.PartID))
	os.Chmod(filepath.Join(dir, "parts"), 0o500)
	if code := testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil); code != 500 {
		t.Fatalf("put with unwritable parts dir = %d", code)
	}
	os.Chmod(filepath.Join(dir, "parts"), 0o700)
	os.Chmod(dir, 0o500) // part lands, meta.cbor can't be saved
	if code := testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil); code != 500 {
		t.Fatalf("put with unsaved meta = %d", code)
	}
	if f.s.objects[string(f.id)].Uploaded[enc.EncodeToString(f.part.PartID)] {
		t.Fatal("unsaved upload recorded")
	}
	os.Chmod(dir, 0o700)
	testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil)
	os.Chmod(dir, 0o500)
	if code := f.commit(t); code != 500 {
		t.Fatalf("commit with unsaved meta = %d", code)
	}
	if o := f.s.objects[string(f.id)]; o.State != Uploading || o.Signature != nil {
		t.Fatal("unsaved commit took effect")
	}
	os.Chmod(dir, 0o700)
	if code := f.commit(t); code != 204 {
		t.Fatalf("commit after recovery = %d", code)
	}
	os.Chmod(dir, 0o500)
	if code := testutil.Do(t, "POST", f.url("ack"), f.tPeer, nil, nil); code != 500 {
		t.Fatalf("ack with unremovable meta = %d", code)
	}
	os.Chmod(dir, 0o700)
	if code := testutil.Do(t, "POST", f.url("ack"), f.tPeer, nil, nil); code != 204 || !f.s.usageEmpty() {
		t.Fatalf("ack after recovery = %d", code)
	}
}

func TestZeroPartObjectsCountAgainstObjectQuota(t *testing.T) {
	srv, s := setup(t, 1<<30)
	defer srv.Close()
	s.MaxObjects = 3
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	peer := testutil.NewDevice().ID
	for i := 0; i < 3; i++ {
		if code := testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{peer}}, nil); code != 200 {
			t.Fatalf("empty object %d = %d", i, code)
		}
	}
	if code := testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{peer}}, nil); code != 507 {
		t.Fatalf("over object quota = %d", code)
	}
	if s.total.bytes < 3*objectOverhead {
		t.Fatalf("empty objects cost %d bytes", s.total.bytes)
	}
}

func TestFreshKeysCannotBypassAddressAndGlobalQuota(t *testing.T) {
	srv, s := setup(t, 1<<30)
	defer srv.Close()
	s.MaxIPObjects = 2
	peer := testutil.NewDevice().ID
	create := func() int {
		tok := testutil.Login(t, srv.URL, testutil.NewDevice())
		return testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{peer}}, nil)
	}
	create()
	create()
	if code := create(); code != 507 {
		t.Fatalf("third key from one address = %d", code)
	}
	s.MaxIPObjects, s.MaxIPBytes = MaxIPObjects, 3*objectOverhead
	if code := create(); code != 507 {
		t.Fatalf("over per-address bytes = %d", code)
	}
	s.MaxIPBytes, s.MaxTotalObjects = 0, 2
	if code := create(); code != 507 {
		t.Fatalf("over global objects = %d", code)
	}
	s.MaxTotalObjects, s.MaxTotalBytes = MaxTotalObjects, 2*objectOverhead
	if code := create(); code != 507 {
		t.Fatalf("over global bytes = %d", code)
	}
}

func TestExpiryReleasesQuotaAndBadRecipientsRejected(t *testing.T) {
	srv, s := setup(t, 1<<30)
	defer srv.Close()
	s.MaxObjects = 1
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	peer := testutil.NewDevice().ID
	if code := testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{peer, peer}}, nil); code != 400 {
		t.Fatalf("duplicate recipients = %d", code)
	}
	if code := testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{[]byte("short")}}, nil); code != 400 {
		t.Fatalf("malformed recipient = %d", code)
	}
	testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{peer}}, nil)
	s.Now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	if code := testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{peer}}, nil); code != 200 {
		t.Fatalf("expired object still holds quota: %d", code)
	}
}

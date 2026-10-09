package spool

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/meter"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

// slowPut starts a PUT whose body arrives only when the returned func is called; the status comes on done.
func slowPut(t *testing.T, url, token string, data []byte) (finish func(), done <-chan int) {
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("PUT", url, pr)
	req.Header.Set("Authorization", "Bearer "+token)
	req.ContentLength = int64(len(data))
	ch := make(chan int, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			ch <- -1
			return
		}
		resp.Body.Close()
		ch <- resp.StatusCode
	}()
	pw.Write(data[:1]) // the server is now inside the handler, reading the body
	return func() { pw.Write(data[1:]); pw.Close() }, ch
}

func waitInflight(t *testing.T, s *Service, want int64) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if _, _, total := s.Inflight.Held("", ""); total == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _, total := s.Inflight.Held("", "")
	t.Fatalf("in-flight bytes = %d, want %d", total, want)
}

func TestParallelPutOfOnePartIsRefusedBeforeItsBody(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	pu := f.url("parts", enc.EncodeToString(f.part.PartID))
	finish, done := slowPut(t, pu, f.tOwner, f.data)
	waitInflight(t, f.s, int64(f.part.Size))
	for i := 0; i < 8; i++ {
		if code := testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil); code != 429 {
			t.Fatalf("parallel put of a part being read = %d", code)
		}
	}
	if _, _, total := f.s.Inflight.Held("", ""); total != int64(f.part.Size) {
		t.Fatalf("refused puts reserved memory: %d", total)
	}
	finish()
	if code := <-done; code != 204 {
		t.Fatalf("first put = %d", code)
	}
	waitInflight(t, f.s, 0)
	if code := testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil); code != 204 {
		t.Fatalf("idempotent retry after the first finished = %d", code)
	}
}

func TestInflightPutBytesAreCappedPerOwner(t *testing.T) {
	srv, s := setup(t, 1<<30)
	defer srv.Close()
	s.Inflight.PerDevice = 1500
	owner, peer := testutil.NewDevice(), testutil.NewDevice()
	tok := testutil.Login(t, srv.URL, owner)
	var parts []Part
	var datas [][]byte
	for i := 0; i < 2; i++ {
		d := make([]byte, 1000)
		rand.Read(d)
		sum := sha256.Sum256(d)
		pid := make([]byte, 16)
		rand.Read(pid)
		parts, datas = append(parts, Part{PartID: pid, Size: 1000, CiphertextSHA256: sum[:]}), append(datas, d)
	}
	var cr CreateResponse
	if testutil.Do(t, "POST", srv.URL+"/v1/spools", tok, CreateRequest{Recipients: [][]byte{peer.ID}, Parts: parts}, &cr) != 200 {
		t.Fatal("create failed")
	}
	base := srv.URL + "/v1/spools/" + enc.EncodeToString(cr.SpoolID) + "/parts/"
	finish, done := slowPut(t, base+enc.EncodeToString(parts[0].PartID), tok, datas[0])
	waitInflight(t, s, 1000)
	if code := testutil.Do(t, "PUT", base+enc.EncodeToString(parts[1].PartID), tok, datas[1], nil); code != 429 {
		t.Fatalf("second body over the owner's in-flight budget = %d", code)
	}
	finish()
	if <-done != 204 {
		t.Fatal("first put failed")
	}
	waitInflight(t, s, 0)
	if code := testutil.Do(t, "PUT", base+enc.EncodeToString(parts[1].PartID), tok, datas[1], nil); code != 204 {
		t.Fatalf("second part once the first is in = %d", code)
	}
}

// Downloads are billed to the owner's address too, so fresh recipient keys don't make them free.
func TestSpoolDownloadsAreBilledToTheOwnersAddress(t *testing.T) {
	f := newFixture(t)
	defer f.srv.Close()
	m, _ := meter.Open("")
	f.s.Meter = m
	pu := f.url("parts", enc.EncodeToString(f.part.PartID))
	if testutil.Do(t, "PUT", pu, f.tOwner, f.data, nil) != 204 || f.commit(t) != 204 {
		t.Fatal("upload failed")
	}
	for i := 0; i < 2; i++ {
		var got []byte
		if code := testutil.Do(t, "GET", pu, f.tPeer, nil, &got); code != 200 || len(got) != 1000 {
			t.Fatalf("download = %d, %d bytes", code, len(got))
		}
	}
	if used := m.IPUsed("127.0.0.1"); used != 2000 {
		t.Fatalf("address billed %d, want 2000", used)
	}
	m.IPLimit = 2000
	req := CreateRequest{Recipients: [][]byte{f.peer.ID}, Parts: []Part{f.part}}
	if code := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", testutil.Login(t, f.srv.URL, testutil.NewDevice()), req, nil); code != 429 {
		t.Fatalf("fresh key reserved on a used-up address = %d", code)
	}
}

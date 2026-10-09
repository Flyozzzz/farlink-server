package report

import (
	"bytes"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

func start(t *testing.T) (*Service, *httptest.Server) {
	a := auth.New("test")
	s, err := New(a, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("POST /v1/reports", s.HandleReport)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return s, srv
}

func good() Request {
	return Request{Subject: "contact", Reported: bytes.Repeat([]byte{7}, 32), Reason: "spam", Text: "sends junk"}
}

func TestReportIsStoredWithItsSenderAndNoFileData(t *testing.T) {
	s, srv := start(t)
	d := testutil.NewDevice()
	tok := testutil.Login(t, srv.URL, d)
	if code := testutil.Do(t, "POST", srv.URL+"/v1/reports", tok, good(), nil); code != 202 {
		t.Fatal(code)
	}
	files, _ := filepath.Glob(filepath.Join(s.Dir, "*.cbor"))
	if len(files) != 1 {
		t.Fatalf("stored %v", files)
	}
	data, _ := os.ReadFile(files[0])
	var st Stored
	if err := wire.Lenient(data, &st); err != nil || !bytes.Equal(st.ReporterDevice, d.ID) || st.Reason != "spam" || st.ReceivedAt == 0 {
		t.Fatalf("stored %+v %v", st, err)
	}
}

func TestBadReportsAndFloodsAreRefused(t *testing.T) {
	s, srv := start(t)
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	url := srv.URL + "/v1/reports"
	cases := map[string]func(r *Request){
		"bad subject": func(r *Request) { r.Subject = "file" },
		"short id":    func(r *Request) { r.Reported = r.Reported[:3] },
		"bad reason":  func(r *Request) { r.Reason = "dislike" },
		"long text":   func(r *Request) { r.Text = string(make([]byte, MaxText+1)) },
	}
	for name, mut := range cases {
		r := good()
		mut(&r)
		if code := testutil.Do(t, "POST", url, tok, r, nil); code != 400 {
			t.Errorf("%s = %d", name, code)
		}
	}
	if code := testutil.Do(t, "POST", url, "", good(), nil); code != 401 {
		t.Errorf("no session = %d", code)
	}
	for i := 0; i < PerDay; i++ {
		testutil.Do(t, "POST", url, tok, good(), nil)
	}
	if code := testutil.Do(t, "POST", url, tok, good(), nil); code != 429 {
		t.Errorf("flood = %d", code)
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	files, _ := filepath.Glob(filepath.Join(s.Dir, "*.cbor"))
	os.Chtimes(files[0], old, old)
	if s.GC() != 1 {
		t.Fatal("old report kept past retention")
	}
}

func TestTextLimitCountsCharactersNotBytes(t *testing.T) {
	_, srv := start(t)
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	url := srv.URL + "/v1/reports"
	r := good()
	r.Text = strings.Repeat("я", MaxText)
	if code := testutil.Do(t, "POST", url, tok, r, nil); code != 202 {
		t.Errorf("2000 characters = %d", code)
	}
	r.Text = strings.Repeat("я", MaxText+1)
	if code := testutil.Do(t, "POST", url, tok, r, nil); code != 400 {
		t.Errorf("2001 characters = %d", code)
	}
	r.Text = "bad \xff bytes"
	if code := testutil.Do(t, "POST", url, tok, r, nil); code != 400 {
		t.Errorf("invalid UTF-8 = %d", code)
	}
}

func TestRestartKeepsTheDailyAllowanceAndTheQuota(t *testing.T) {
	a := auth.New("test")
	dir := t.TempDir()
	s, err := New(a, dir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux.HandleFunc("POST /v1/reports", s.HandleReport)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	d := testutil.NewDevice()
	tok := testutil.Login(t, srv.URL, d)
	for i := 0; i < PerDay; i++ {
		if code := testutil.Do(t, "POST", srv.URL+"/v1/reports", tok, good(), nil); code != 202 {
			t.Fatal(code)
		}
	}
	os.WriteFile(filepath.Join(dir, "half-written.tmp"), []byte("x"), 0o600)

	s2, err := New(a, dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.count != PerDay {
		t.Fatalf("quota after restart counts %d", s2.count)
	}
	if _, err := os.Stat(filepath.Join(dir, "half-written.tmp")); err == nil {
		t.Fatal("an unacknowledged half-written report survived")
	}
	mux2 := http.NewServeMux()
	mux2.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux2.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	mux2.HandleFunc("POST /v1/reports", s2.HandleReport)
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	tok2 := testutil.Login(t, srv2.URL, d)
	if code := testutil.Do(t, "POST", srv2.URL+"/v1/reports", tok2, good(), nil); code != 429 {
		t.Errorf("restart gave a fresh allowance: %d", code)
	}
}

func TestQuotaIsAHardCapUnderConcurrency(t *testing.T) {
	s, _ := start(t)
	devs := make([][]byte, 100)
	for i := range devs {
		devs[i] = []byte{byte(i)}
	}
	s.count = MaxPending - 10
	var wg sync.WaitGroup
	var granted atomic.Int32
	for _, d := range devs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, status, _ := s.reserve(d); status == 0 {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if granted.Load() != 10 || s.count != MaxPending {
		t.Fatalf("granted %d, count %d", granted.Load(), s.count)
	}
}

func store(t *testing.T, dir string, dev []byte, at time.Time, name string) {
	t.Helper()
	data, err := wire.Enc.Marshal(Stored{Request: good(), ReporterDevice: dev, ReceivedAt: uint64(at.UnixMilli())})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+suffix), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRestartRebuildsTheSameFixedWindowsAsTheLivePath(t *testing.T) {
	dir := t.TempDir()
	dev := bytes.Repeat([]byte{1}, 32)
	t0 := time.Now().Add(-24*time.Hour - 2*time.Minute)
	store(t, dir, dev, t0, "a-first")
	for i := 0; i < 19; i++ {
		store(t, dir, dev, t0.Add(23*time.Hour+time.Duration(i)*time.Second), "b-late-"+string(rune('a'+i)))
	}
	store(t, dir, dev, t0.Add(24*time.Hour+time.Minute), "c-new-window")
	s, err := New(auth.New("test"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, n := s.window(dev); n != 1 {
		t.Fatalf("the current window should hold 1 report, got %d", n)
	}
	if s.count != 21 {
		t.Fatalf("quota counts %d", s.count)
	}
	for i := 0; i < PerDay-1; i++ {
		if _, status, _ := s.reserve(dev); status != 0 {
			t.Fatalf("admission %d refused with %d", i, status)
		}
	}
	if _, status, _ := s.reserve(dev); status != 429 {
		t.Fatalf("the 21st in the window = %d", status)
	}
}

func TestAReportThatCannotBeReadStopsTheStart(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x"+suffix), []byte("not cbor"), 0o600)
	if _, err := New(auth.New("test"), dir); err == nil {
		t.Fatal("a damaged report was skipped, which would reopen its sender's allowance")
	}
}

func TestAFailedRefundGoesToTheWindowThatWasCharged(t *testing.T) {
	s, _ := start(t)
	clock := time.Now()
	s.Now = func() time.Time { return clock }
	dev := bytes.Repeat([]byte{2}, 32)
	old, status, _ := s.reserve(dev)
	if status != 0 {
		t.Fatal(status)
	}
	clock = clock.Add(window + time.Minute)
	if _, status, _ := s.reserve(dev); status != 0 {
		t.Fatal(status)
	}
	s.release(old)
	if _, n := s.window(dev); n != 1 {
		t.Fatalf("the new window was refunded: n=%d", n)
	}
	if s.count != 1 {
		t.Fatalf("count %d", s.count)
	}
}

func TestAReportThatWasInstalledKeepsItsCharge(t *testing.T) {
	s, srv := start(t)
	write = func(path string, data []byte) error {
		if err := durable.WriteFile(path, data); err != nil {
			return err
		}
		return errors.New("directory sync failed")
	}
	t.Cleanup(func() { write = durable.WriteFile })
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	if code := testutil.Do(t, "POST", srv.URL+"/v1/reports", tok, good(), nil); code != 503 {
		t.Fatal(code)
	}
	files, _ := filepath.Glob(filepath.Join(s.Dir, "*.cbor"))
	if len(files) != 1 || s.count != 1 {
		t.Fatalf("%d files on disk but the quota counts %d", len(files), s.count)
	}
}

func TestAReportThatWasNotInstalledGivesItsChargeBack(t *testing.T) {
	s, srv := start(t)
	write = func(string, []byte) error { return errors.New("disk full") }
	t.Cleanup(func() { write = durable.WriteFile })
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	if code := testutil.Do(t, "POST", srv.URL+"/v1/reports", tok, good(), nil); code != 503 {
		t.Fatal(code)
	}
	if s.count != 0 {
		t.Fatalf("count %d", s.count)
	}
}

func TestAFailedFirstReportDoesNotAnchorTheWindow(t *testing.T) {
	dir := t.TempDir()
	s, err := New(auth.New("test"), dir)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	s.Now = func() time.Time { return clock }
	dev := bytes.Repeat([]byte{3}, 32)
	first, _, _ := s.reserve(dev)
	clock = clock.Add(23 * time.Hour)
	var kept []reservation
	for i := 0; i < PerDay; i++ {
		res, status, _ := s.reserve(dev)
		if status != 0 {
			// the first, still in flight, holds one place; the last one has to wait for its refund
			s.release(first)
			res, status, _ = s.reserve(dev)
			if status != 0 {
				t.Fatalf("admission %d refused with %d", i, status)
			}
		}
		kept = append(kept, res)
	}
	for i, res := range kept {
		store(t, dir, dev, res.at, "k"+string(rune('a'+i)))
	}
	clock = clock.Add(time.Hour + time.Minute)
	if start, _ := s.window(dev); !start.Equal(kept[0].at) {
		t.Fatalf("the live window starts at %v, not at the first report kept", start)
	}
	_, liveStatus, _ := s.reserve(dev)
	restarted, err := New(auth.New("test"), dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Now = s.Now
	_, restartStatus, _ := restarted.reserve(dev)
	if liveStatus != restartStatus {
		t.Fatalf("live answers %d, a restart %d", liveStatus, restartStatus)
	}
}

func TestARefundedOnlyReportLeavesNoWindow(t *testing.T) {
	s, _ := start(t)
	dev := bytes.Repeat([]byte{4}, 32)
	res, _, _ := s.reserve(dev)
	s.release(res)
	if s.rates[string(dev)] != nil || s.count != 0 {
		t.Fatalf("window %v count %d", s.rates[string(dev)], s.count)
	}
	if _, n := s.window(dev); n != 0 {
		t.Fatalf("window n=%d", n)
	}
}

func TestAStoredReportWithoutItsAccountingFieldsStopsTheStart(t *testing.T) {
	for name, st := range map[string]Stored{
		"no time":         {Request: good(), ReporterDevice: bytes.Repeat([]byte{1}, 32)},
		"short device id": {Request: good(), ReporterDevice: []byte{1}, ReceivedAt: uint64(time.Now().UnixMilli())},
	} {
		dir := t.TempDir()
		data, _ := wire.Enc.Marshal(st)
		os.WriteFile(filepath.Join(dir, "x"+suffix), data, 0o600)
		if _, err := New(auth.New("test"), dir); err == nil {
			t.Fatalf("%s: a damaged report was accepted", name)
		}
	}
}

func TestAnUncertainCheckDoesNotRefundAnInstalledReport(t *testing.T) {
	s, srv := start(t)
	write = func(path string, data []byte) error {
		if err := durable.WriteFile(path, data); err != nil {
			return err
		}
		return errors.New("directory sync failed")
	}
	stat = func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	t.Cleanup(func() { write = durable.WriteFile; stat = os.Stat })
	tok := testutil.Login(t, srv.URL, testutil.NewDevice())
	if code := testutil.Do(t, "POST", srv.URL+"/v1/reports", tok, good(), nil); code != 503 {
		t.Fatal(code)
	}
	if s.count != 1 {
		t.Fatalf("count %d: an installed report was refunded", s.count)
	}
}

// Sequence from the review: A in flight at T, 19 reports at T+23h, B at T+24h, then A is refunded. A restart sees
// the 19 reports and B; the live path must see the same, and both must let exactly as many through.
func TestARefundAfterTheWindowMovedOnMatchesARestart(t *testing.T) {
	dir := t.TempDir()
	s, err := New(auth.New("test"), dir)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	s.Now = func() time.Time { return clock }
	dev := bytes.Repeat([]byte{5}, 32)
	a, _, _ := s.reserve(dev)
	clock = a.at.Add(23 * time.Hour)
	for i := 0; i < PerDay-1; i++ {
		res, status, _ := s.reserve(dev)
		if status != 0 {
			t.Fatalf("admission %d refused with %d", i, status)
		}
		store(t, dir, dev, res.at, "m"+string(rune('a'+i)))
	}
	clock = a.at.Add(24 * time.Hour)
	b, status, _ := s.reserve(dev)
	if status != 0 {
		t.Fatalf("B refused with %d", status)
	}
	store(t, dir, dev, b.at, "z-b")
	s.release(a)
	restarted, err := New(auth.New("test"), dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Now = s.Now
	live, liveStart := s.window(dev)
	got, gotStart := restarted.window(dev)
	if !live.Equal(got) || liveStart != gotStart {
		t.Fatalf("live window (%v, %d), restart (%v, %d)", live, liveStart, got, gotStart)
	}
	for i := 0; ; i++ {
		_, ls, _ := s.reserve(dev)
		_, rs, _ := restarted.reserve(dev)
		if ls != rs {
			t.Fatalf("admission %d: live %d, restart %d", i, ls, rs)
		}
		if ls != 0 {
			break
		}
		if i > PerDay {
			t.Fatal("never refused")
		}
	}
}

func TestTimesAreWholeMillisecondsAtTheWindowEdge(t *testing.T) {
	s, _ := start(t)
	base := time.Now().Truncate(time.Millisecond)
	clock := base.Add(500 * time.Microsecond)
	s.Now = func() time.Time { return clock }
	dev := bytes.Repeat([]byte{6}, 32)
	res, _, _ := s.reserve(dev)
	if !res.at.Equal(base) {
		t.Fatalf("admitted at %v, stored as %v", res.at, base)
	}
	// One millisecond short of a day the window is still open; at a day it is over.
	clock = base.Add(window - time.Millisecond)
	if _, n := s.window(dev); n != 1 {
		t.Fatalf("just before the edge n=%d", n)
	}
	clock = base.Add(window)
	if _, n := s.window(dev); n != 0 {
		t.Fatalf("at the edge n=%d", n)
	}
}

func TestReportsAtTheSameMillisecondAreAllKept(t *testing.T) {
	s, _ := start(t)
	clock := time.Now()
	s.Now = func() time.Time { return clock }
	dev := bytes.Repeat([]byte{8}, 32)
	a, _, _ := s.reserve(dev)
	b, _, _ := s.reserve(dev)
	if _, n := s.window(dev); n != 2 {
		t.Fatalf("n=%d", n)
	}
	s.release(a)
	if _, n := s.window(dev); n != 1 {
		t.Fatalf("after one refund n=%d", n)
	}
	s.release(b)
	if s.rates[string(dev)] != nil {
		t.Fatal("the device still has a window")
	}
}

func TestGCForgetsWhatItRemoved(t *testing.T) {
	dir := t.TempDir()
	dev := bytes.Repeat([]byte{9}, 32)
	long := time.Now().Add(-100 * 24 * time.Hour)
	store(t, dir, dev, long, "old")
	store(t, dir, dev, time.Now().Add(-60*24*time.Hour), "new")
	os.Chtimes(filepath.Join(dir, "old"+suffix), long, long)
	s, err := New(auth.New("test"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.GC(); n != 1 {
		t.Fatalf("GC removed %d", n)
	}
	if got := len(s.rates[string(dev)].list); got != 1 || s.count != 1 {
		t.Fatalf("times kept %d, count %d", got, s.count)
	}
	s.Keep = 30 * 24 * time.Hour
	os.Chtimes(filepath.Join(dir, "new"+suffix), long, long)
	if n := s.GC(); n != 1 || s.rates[string(dev)] != nil || s.count != 0 {
		t.Fatalf("removed %d, rates %v, count %d", n, s.rates[string(dev)], s.count)
	}
}

// The review's sequence: GC removes a file by its mtime, and the report's own time is recent. The live allowance
// must then be what a restart finds.
func TestGCAndARestartAgreeWhenTheFileAgeAndTheReportTimeDiffer(t *testing.T) {
	dir := t.TempDir()
	dev := bytes.Repeat([]byte{10}, 32)
	now := time.Now()
	for i := 0; i < PerDay; i++ {
		store(t, dir, dev, now.Add(-time.Duration(i)*time.Minute), "r"+string(rune('a'+i)))
	}
	old := now.Add(-200 * 24 * time.Hour)
	os.Chtimes(filepath.Join(dir, "ra"+suffix), old, old)
	s, err := New(auth.New("test"), dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return now }
	if n := s.GC(); n != 1 {
		t.Fatalf("GC removed %d", n)
	}
	restarted, err := New(auth.New("test"), dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Now = s.Now
	if s.count != restarted.count {
		t.Fatalf("count: live %d, restart %d", s.count, restarted.count)
	}
	_, ls, _ := s.reserve(dev)
	_, rs, _ := restarted.reserve(dev)
	if ls != rs || ls != 0 {
		t.Fatalf("live %d, restart %d", ls, rs)
	}
	_, ls, _ = s.reserve(dev)
	_, rs, _ = restarted.reserve(dev)
	if ls != 429 || rs != 429 {
		t.Fatalf("after the place was used: live %d, restart %d", ls, rs)
	}
}

func TestGCKeepsTheChargeOfAFileItCouldNotRemove(t *testing.T) {
	dir := t.TempDir()
	dev := bytes.Repeat([]byte{11}, 32)
	long := time.Now().Add(-100 * 24 * time.Hour)
	store(t, dir, dev, long, "stuck")
	store(t, dir, dev, long, "gone")
	os.Chtimes(filepath.Join(dir, "stuck"+suffix), long, long)
	os.Chtimes(filepath.Join(dir, "gone"+suffix), long, long)
	s, err := New(auth.New("test"), dir)
	if err != nil {
		t.Fatal(err)
	}
	// A directory cannot be removed as a file, so this one stays.
	os.Remove(filepath.Join(dir, "stuck"+suffix))
	os.Mkdir(filepath.Join(dir, "stuck"+suffix), 0o700)
	os.WriteFile(filepath.Join(dir, "stuck"+suffix, "x"), nil, 0o600)
	os.Chtimes(filepath.Join(dir, "stuck"+suffix), long, long)
	if n := s.GC(); n != 1 {
		t.Fatalf("GC removed %d", n)
	}
	if got := len(s.rates[string(dev)].list); got != 1 || s.count != 1 {
		t.Fatalf("times kept %d, count %d: the file that stayed lost its charge", got, s.count)
	}
}

// The whole path: reports arrive over HTTP, one file ages out, GC removes it. The live service and one started from
// the directory must then agree, and the removed report's place must be free again.
func TestReportsReceivedOverHTTPAreForgottenByGCLikeARestartWould(t *testing.T) {
	s, srv := start(t)
	d := testutil.NewDevice()
	tok := testutil.Login(t, srv.URL, d)
	for i := 0; i < PerDay; i++ {
		if code := testutil.Do(t, "POST", srv.URL+"/v1/reports", tok, good(), nil); code != 202 {
			t.Fatalf("report %d = %d", i, code)
		}
	}
	if code := testutil.Do(t, "POST", srv.URL+"/v1/reports", tok, good(), nil); code != 429 {
		t.Fatalf("flood = %d", code)
	}
	for f := range s.files {
		if _, err := os.Stat(filepath.Join(s.Dir, f)); err != nil {
			t.Fatalf("charged name %s is not a stored file: %v", f, err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(s.Dir, "*.cbor"))
	if len(files) != PerDay || len(s.files) != PerDay {
		t.Fatalf("files %d, charged %d", len(files), len(s.files))
	}
	old := time.Now().Add(-200 * 24 * time.Hour)
	os.Chtimes(files[0], old, old)
	if s.GC() != 1 {
		t.Fatal("GC removed nothing")
	}
	restarted, err := New(auth.New("test"), s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.count != restarted.count || len(s.files) != len(restarted.files) || s.count != PerDay-1 {
		t.Fatalf("live count %d files %d, restart count %d files %d", s.count, len(s.files), restarted.count, len(restarted.files))
	}
	if _, st, _ := s.reserve(d.ID); st != 0 {
		t.Fatalf("live admission after GC = %d", st)
	}
	if _, st, _ := restarted.reserve(d.ID); st != 0 {
		t.Fatalf("restart admission after GC = %d", st)
	}
}

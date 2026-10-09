// Package report receives complaints about a contact or a network member. A report carries public identities,
// time, a reason and the reporter's text — never file contents, which the server cannot read anyway.
package report

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	MaxText      = 2000 // characters, not bytes
	MaxPending   = 20000
	PerDay       = 20
	DefaultKeep  = 90 * 24 * time.Hour
	maxBodyBytes = 16 << 10 // MaxText characters of four bytes each, plus the fields
)

var reasons = map[string]bool{"spam": true, "abuse": true, "illegal": true, "impersonation": true, "other": true}

type Request struct {
	Subject    string `cbor:"subject"` // contact | member
	Reported   []byte `cbor:"reported_identity"`
	Reporter   []byte `cbor:"reporter_identity,omitempty"`
	Reason     string `cbor:"reason"`
	Text       string `cbor:"text,omitempty"`
	DeliveryID []byte `cbor:"delivery_id,omitempty"`
}

// Stored is what is kept: the request plus who sent it, from where and when.
type Stored struct {
	Request
	ReporterDevice []byte `cbor:"reporter_device"`
	ReceivedAt     uint64 `cbor:"received_at"`
}

type Service struct {
	Auth *auth.Service
	Dir  string
	Keep time.Duration
	Now  func() time.Time

	mu    sync.Mutex
	rates map[string]*rate
	files map[string]string // report file name -> the device it is charged to
	count int               // reports on disk plus the ones being written
}

// rate is what one device has been admitted for: its kept reports, oldest first, each with the time it was admitted
// and the file that holds it. Its current daily window is always computed from them, by the same rule at run time
// and at restart, so the two cannot drift apart.
type rate struct {
	list []entry
}

type entry struct {
	at   time.Time
	file string
}

// current is the window that holds the newest report, or n == 0 when that window has run out. A window opens at
// the first kept report and takes every report less than a day after it.
func (r *rate) current(now time.Time) (start time.Time, n int) {
	for i, e := range r.list {
		if i == 0 || e.at.Sub(start) >= window {
			start, n = e.at, 0
		}
		n++
	}
	if n == 0 || now.Sub(start) >= window {
		return time.Time{}, 0
	}
	return start, n
}

func (r *rate) add(e entry) {
	i := sort.Search(len(r.list), func(i int) bool { return r.list[i].at.After(e.at) })
	r.list = append(r.list, entry{})
	copy(r.list[i+1:], r.list[i:])
	r.list[i] = e
}

func (r *rate) remove(file string) {
	for i, e := range r.list {
		if e.file == file {
			r.list = append(r.list[:i], r.list[i+1:]...)
			return
		}
	}
}

// write and stat are the durable write and the check for its file; tests replace them to fail at chosen points.
var (
	write = durable.WriteFile
	stat  = os.Stat
)

const (
	suffix = ".cbor"
	window = 24 * time.Hour
)

// New opens the report directory and rebuilds the counters from it, so a restart gives an abuser neither a fresh
// allowance nor a fresh disk. A report that cannot be read stops the start: guessing whose allowance it belonged
// to would reopen it.
func New(a *auth.Service, dir string) (*Service, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Service{Auth: a, Dir: dir, Keep: DefaultKeep, rates: map[string]*rate{}, files: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if !strings.HasSuffix(e.Name(), suffix) {
			os.Remove(path) // an interrupted write that was never acknowledged
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("report %s: %w", e.Name(), err)
		}
		var st Stored
		if err := wire.Lenient(data, &st); err != nil || len(st.ReporterDevice) != 32 || st.ReceivedAt == 0 {
			return nil, fmt.Errorf("report %s is damaged", e.Name())
		}
		s.count++
		s.charge(string(st.ReporterDevice), entry{at: time.UnixMilli(int64(st.ReceivedAt)), file: e.Name()})
	}
	return s, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// charge puts a report on its device's list.
func (s *Service) charge(dev string, e entry) {
	d := s.rates[dev]
	if d == nil {
		d = &rate{}
		s.rates[dev] = d
	}
	d.add(e)
	s.files[e.file] = dev
}

// discharge takes a report off its device's list, and the device off the map when nothing is left.
func (s *Service) discharge(file string) {
	dev, ok := s.files[file]
	if !ok {
		return
	}
	delete(s.files, file)
	if d := s.rates[dev]; d != nil {
		d.remove(file)
		if len(d.list) == 0 {
			delete(s.rates, dev)
		}
	}
}

// reservation is one admitted report: when it was admitted and the file it will be stored in.
type reservation struct {
	at   time.Time
	file string
}

// reserve takes one place in the device's daily allowance and one in the quota, or says which one is full. Times
// are whole milliseconds, exactly as they are stored, so a restart sees what this saw.
func (s *Service) reserve(dev []byte) (res reservation, code int, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rates == nil {
		s.rates, s.files = map[string]*rate{}, map[string]string{}
	}
	now := s.now().Truncate(time.Millisecond)
	if d := s.rates[string(dev)]; d != nil {
		if _, n := d.current(now); n >= PerDay {
			return reservation{}, 429, "RATE_LIMITED"
		}
	}
	if s.count >= MaxPending {
		return reservation{}, 503, "QUOTA_EXCEEDED"
	}
	var salt [6]byte
	rand.Read(salt[:])
	res = reservation{at: now, file: now.UTC().Format("20060102T150405") + "-" + hex.EncodeToString(salt[:]) + suffix}
	s.charge(string(dev), entry{at: now, file: res.file})
	s.count++
	return res, 0, ""
}

// release gives back what reserve took when the report was not stored. The window is not patched: the report just
// leaves the device's list, and the window is what remains, as a restart would find it.
func (s *Service) release(res reservation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.files[res.file]; ok {
		s.count--
		s.discharge(res.file)
	}
}

// window is the device's current daily window; n == 0 when it has none.
func (s *Service) window(dev []byte) (start time.Time, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.rates[string(dev)]; d != nil {
		return d.current(s.now().Truncate(time.Millisecond))
	}
	return time.Time{}, 0
}

// HandleReport: POST /v1/reports.
func (s *Service) HandleReport(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		var req Request
		if err := wire.ReadLimit(r, &req, maxBodyBytes); err != nil {
			wire.WriteReadError(w, err)
			return
		}
		if (req.Subject != "contact" && req.Subject != "member") || len(req.Reported) != 32 || !reasons[req.Reason] ||
			!utf8.ValidString(req.Text) || utf8.RuneCountInString(req.Text) > MaxText || (len(req.Reporter) != 0 && len(req.Reporter) != 32) || (len(req.DeliveryID) != 0 && len(req.DeliveryID) != 16) {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		res, status, code := s.reserve(sess.DeviceID)
		if status != 0 {
			wire.WriteError(w, status, code, true)
			return
		}
		data, err := wire.Enc.Marshal(Stored{Request: req, ReporterDevice: sess.DeviceID, ReceivedAt: uint64(res.at.UnixMilli())})
		if err != nil {
			s.release(res)
			wire.WriteError(w, 503, "INTERNAL", true)
			return
		}
		path := filepath.Join(s.Dir, res.file)
		if err := write(path, data); err != nil {
			// The file may be in place even though making the rename durable failed; then it still counts, and so
			// does any answer but "no such file", which does not show the file is absent.
			if _, statErr := stat(path); errors.Is(statErr, fs.ErrNotExist) {
				s.release(res)
			}
			wire.WriteError(w, 503, "INTERNAL", true)
			return
		}
		w.WriteHeader(202)
	})(w, r)
}

// GC removes reports older than Keep. What it forgets in memory is exactly the reports whose files it removed, so
// the lists stay what a restart would rebuild from the files left.
func (s *Service) GC() int {
	entries, _ := os.ReadDir(s.Dir)
	cut := s.now().Add(-s.Keep)
	var gone []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cut) {
			if os.Remove(filepath.Join(s.Dir, e.Name())) == nil {
				gone = append(gone, e.Name())
			}
		}
	}
	if len(gone) > 0 {
		durable.SyncDir(s.Dir)
		s.mu.Lock()
		for _, f := range gone {
			if _, ok := s.files[f]; ok {
				s.count--
				s.discharge(f)
			}
		}
		s.mu.Unlock()
	}
	return len(gone)
}

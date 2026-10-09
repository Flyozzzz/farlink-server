// Package spool stores encrypted transfer parts for devices that are asleep or in the background (protocol v1
// §11). It never sees plaintext: parts are chunk ciphertexts, the per-recipient index is a sealed box. Objects
// live at most TTL from reservation; reading or retrying never extends that.
package spool

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/budget"
	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/meter"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const domain = "farlink/spool/v1"

type State string

const (
	Uploading State = "uploading"
	Available State = "available"
)

type Part struct {
	PartID           []byte `cbor:"part_id"`
	Size             uint64 `cbor:"size"`
	CiphertextSHA256 []byte `cbor:"ciphertext_sha256"`
}

// A box is one recipient's sealed index: the file key and where each chunk lives, so it grows with the number of
// parts. Bounded by the object's own parts, the descriptor - which is served again and again and is not metered
// like the parts - cannot carry payload.
const (
	boxBaseBytes    = 4 << 10
	boxBytesPerPart = 256
)

func maxBoxBytes(parts int) int { return boxBaseBytes + boxBytesPerPart*parts }

type Box struct {
	Recipient []byte `cbor:"recipient"`
	Box       []byte `cbor:"box"`
}

// Descriptor is what the owner signs at commit (without the signature field).
type Descriptor struct {
	Protocol      uint64          `cbor:"protocol"`
	SpoolID       []byte          `cbor:"spool_id"`
	OwnerDeviceID []byte          `cbor:"owner_device_id"`
	Recipients    [][]byte        `cbor:"recipients"`
	OriginServer  string          `cbor:"origin_server"`
	CreatedAt     uint64          `cbor:"created_at"`
	ExpiresAt     uint64          `cbor:"expires_at"`
	Parts         []Part          `cbor:"parts"`
	Boxes         []Box           `cbor:"boxes"`
	Contact       *ContactBinding `cbor:"contact,omitempty"`
}

type object struct {
	quota      string          // key of the queue the object counts against, cached; guarded by Service.mu
	Descriptor Descriptor      `cbor:"descriptor"`
	Signature  []byte          `cbor:"signature"`
	State      State           `cbor:"state"`
	Acked      map[string]bool `cbor:"acked"`
	Uploaded   map[string]bool `cbor:"uploaded"`
	Total      uint64          `cbor:"total"`
	Charged    int64           `cbor:"charged,omitempty"` // what quotas count: parts plus metadata
	IP         string          `cbor:"ip,omitempty"`      // client address bucket of the creator
	// Served is what each recipient (b64) has downloaded of the parts, so repeated GETs can't turn one small
	// object into unlimited traffic. Persisted with the next metadata save, in memory until then.
	Served map[string]int64 `cbor:"served,omitempty"`
	// Billed: the whole object has been charged to its sender's account (once, at the first byte served).
	Billed bool `cbor:"billed,omitempty"`

	// mu serialises every read and write of the fields above after publication, and the object's files.
	mu      sync.Mutex
	removed bool
	putting map[string]bool // parts whose body is being read right now
	// Immutable once published, so Service.mu holders may read them without mu.
	id, owner  string
	expires    uint64
	recipients [][]byte
	acct       int64 // bytes charged to the quotas; guarded by Service.mu
}

type usage struct {
	bytes   int64
	objects int
}

const (
	MaxObjects      = 1024 // per owner device, including empty ones
	MaxIPObjects    = 4096
	MaxTotalObjects = 100_000
	objectOverhead  = 4096 // metadata, directory and inode of an object, charged even without parts

	// Part bodies are read into memory before they are checked, so what is being read at once is bounded
	// per owner, per client address and in total, independently of the storage quotas.
	MaxInflightBytes      = 64 << 20
	MaxIPInflightBytes    = 256 << 20
	MaxTotalInflightBytes = 2 << 30
	// PartReadTimeout bounds how long one part body may take, so a trickling client can't sit on its
	// in-flight reservation.
	PartReadTimeout = 5 * time.Minute

	// Downloads: what a recipient may pull of one object is bounded to a few whole copies (resumes and one
	// retry after a failed check), and what is being served at once is bounded like part uploads, in bytes and
	// in requests (open files).
	MaxServedCopies                  = 3
	MaxGetInflightBytes              = 64 << 20
	MaxIPGetInflightBytes            = 256 << 20
	MaxTotalGetInflightBytes         = 2 << 30
	MaxGets, MaxIPGets, MaxTotalGets = 16, 64, 2048
	// chargeChunk is how far ahead of the bytes on the wire a download is billed.
	chargeChunk = 64 << 10
)

// A download whose reader stops taking bytes gives up its file, its request slot and its in-flight bytes: each
// write may block for GetStall, and the whole part must move at GetMinRate bytes a second (plus one GetStall).
var (
	GetStall   = 30 * time.Second
	GetMinRate = int64(32 << 10)
)

type Service struct {
	Auth     *auth.Service
	Accounts *accounts.Resolver
	Dir      string
	TTL      time.Duration
	MaxBytes int64 // per owner, reserved at create; 0 = unlimited
	// OwnerMaxBytes, if set, replaces MaxBytes per owner (the tier's spool allowance).
	OwnerMaxBytes func(owner []byte) int64
	// ownerKey names whose queue an owner device's objects count against: its account when it is bound to one, so
	// several keys of one account share the allowance (see SetOwnerKey). Nil: each device on its own.
	ownerKey func(owner []byte) string
	// Meter admits new reservations (traffic left for the owner and its address) and is billed what recipients
	// download, to the object's owner, before the bytes go out. A download stops when the meter refuses: the
	// file in flight rides on the ledger's overdraft, and the address and server caps stay hard.
	Meter meter.Meter
	// Fresh keys are free, so per-owner limits alone can't protect the disk: per client address and total too.
	MaxIPBytes, MaxTotalBytes                 int64
	MaxObjects, MaxIPObjects, MaxTotalObjects int
	Now                                       func() time.Time
	// Inflight bounds part bodies being read at once (bytes).
	Inflight *budget.Gate
	// GetInflight (bytes of the parts being served) and Gets (requests) bound downloads in progress, per
	// recipient, per address and in total.
	GetInflight, Gets *budget.Gate

	mu      sync.Mutex
	objects map[string]*object
	owners  map[string]usage
	ips     map[string]usage
	total   usage
	lastGC  time.Time
}

func New(a *auth.Service, dir string, ttl time.Duration, maxBytes int64) (*Service, error) {
	s := &Service{Auth: a, Dir: dir, TTL: ttl, MaxBytes: maxBytes, Now: time.Now,
		MaxObjects: MaxObjects, MaxIPObjects: MaxIPObjects, MaxTotalObjects: MaxTotalObjects,
		Inflight: budget.NewGate(MaxInflightBytes, MaxIPInflightBytes, MaxTotalInflightBytes), Meter: meter.Off{},
		GetInflight: budget.NewGate(MaxGetInflightBytes, MaxIPGetInflightBytes, MaxTotalGetInflightBytes),
		Gets:        budget.NewGate(MaxGets, MaxIPGets, MaxTotalGets),
		objects:     map[string]*object{}, owners: map[string]usage{}, ips: map[string]usage{}}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries { // reload after restart
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "meta.cbor"))
		if errors.Is(err, os.ErrNotExist) {
			os.RemoveAll(filepath.Join(dir, e.Name())) // a removal or create that did not finish
			continue
		}
		if err != nil {
			continue
		}
		var o object
		if wire.Lenient(b, &o) == nil {
			o.seal()
			if o.Charged == 0 {
				o.Charged = int64(o.Total)
			}
			o.acct = o.Charged
			s.objects[o.id] = &o
			s.addLocked(&o, o.acct, 1)
			tmps, _ := filepath.Glob(filepath.Join(dir, e.Name(), "*.tmp"))
			more, _ := filepath.Glob(filepath.Join(dir, e.Name(), "parts", "*.tmp"))
			for _, t := range append(tmps, more...) {
				os.Remove(t)
			}
		}
	}
	return s, nil
}

// seal copies the fields that never change into the lock-free immutable ones.
func (o *object) seal() {
	o.id, o.owner = string(o.Descriptor.SpoolID), string(o.Descriptor.OwnerDeviceID)
	o.expires, o.recipients = o.Descriptor.ExpiresAt, o.Descriptor.Recipients
}

var b64 = base64.RawURLEncoding

func (s *Service) path(id string, parts ...string) string {
	return filepath.Join(append([]string{s.Dir, b64.EncodeToString([]byte(id))}, parts...)...)
}

func over(v, max int64) bool { return max > 0 && v > max }

// quotaKey is the queue o counts against.
func (s *Service) quotaKey(o *object) string {
	if o.quota == "" {
		o.quota = "d:" + o.owner
		if s.ownerKey != nil {
			o.quota = s.ownerKey([]byte(o.owner))
		}
	}
	return o.quota
}

// SetOwnerKey makes objects count against the key f gives their owner (an account, say) and recounts the queues of
// what is already stored, so a restart and the first request agree.
func (s *Service) SetOwnerKey(f func(owner []byte) string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ownerKey = f
	s.owners = map[string]usage{}
	for _, o := range s.objects {
		o.quota = ""
		u := s.owners[s.quotaKey(o)]
		u.bytes, u.objects = u.bytes+o.acct, u.objects+1
		s.owners[o.quota] = u
	}
}

// reserveLocked charges n bytes and objs objects to the object's owner, address and the whole spool, or
// reports that one of them is full.
func (s *Service) reserveLocked(o *object, n int64, objs int) bool {
	ow, ip := s.owners[s.quotaKey(o)], s.ips[o.IP]
	limit := s.MaxBytes
	if s.OwnerMaxBytes != nil {
		limit = s.OwnerMaxBytes([]byte(o.owner))
	}
	if over(ow.bytes+n, limit) || over(s.total.bytes+n, s.MaxTotalBytes) ||
		ow.objects+objs > s.MaxObjects || s.total.objects+objs > s.MaxTotalObjects {
		return false
	}
	if o.IP != "" && (over(ip.bytes+n, s.MaxIPBytes) || ip.objects+objs > s.MaxIPObjects) {
		return false
	}
	s.addLocked(o, n, objs)
	return true
}

func (s *Service) addLocked(o *object, n int64, objs int) {
	add := func(m map[string]usage, k string) {
		u := m[k]
		u.bytes, u.objects = u.bytes+n, u.objects+objs
		if u.objects <= 0 && u.bytes <= 0 {
			delete(m, k)
		} else {
			m[k] = u
		}
	}
	add(s.owners, s.quotaKey(o))
	if o.IP != "" {
		add(s.ips, o.IP)
	}
	s.total.bytes, s.total.objects = s.total.bytes+n, s.total.objects+objs
}

// dropLocked forgets a published object and gives its charges back.
func (s *Service) dropLocked(o *object) {
	if s.objects[o.id] == o {
		delete(s.objects, o.id)
		s.addLocked(o, -o.acct, -1)
	}
}

// save persists o's metadata; the caller holds o.mu (or o is not published yet).
func (s *Service) save(o *object) error {
	b, err := wire.Enc.Marshal(o)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(s.path(o.id), "meta.cbor", b)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path(o.id, "meta.cbor")); err != nil {
		os.Remove(tmp)
		return err
	}
	return durable.SyncDir(s.path(o.id))
}

// writeTemp writes data durably to a new uniquely named file in dir, so concurrent writers never share one.
func writeTemp(dir, prefix string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, prefix+".*.tmp")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

type CreateRequest struct {
	Recipients [][]byte        `cbor:"recipients"`
	Parts      []Part          `cbor:"parts"`
	Contact    *ContactBinding `cbor:"contact,omitempty"`
}

type CreateResponse struct {
	SpoolID      []byte `cbor:"spool_id"`
	OriginServer string `cbor:"origin_server"`
	CreatedAt    uint64 `cbor:"created_at"`
	ExpiresAt    uint64 `cbor:"expires_at"`
}

func (s *Service) HandleCreate(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		var req CreateRequest
		if err := wire.Read(r, &req); err != nil {
			wire.WriteReadError(w, err)
			return
		}
		if len(req.Recipients) == 0 || len(req.Recipients) > 64 || len(req.Parts) > 262144 {
			wire.WriteError(w, 400, "INVALID_ENCODING", false)
			return
		}
		if !s.authorizeContact(w, r, Descriptor{OwnerDeviceID: sess.DeviceID, Recipients: req.Recipients, Contact: req.Contact}, sess, true) {
			return
		}
		if !s.Meter.Admit(sess.DeviceID, wire.ClientIP(r)) {
			s.refuseQuota(w, sess.DeviceID)
			return
		}
		seen := map[string]bool{}
		for _, rc := range req.Recipients {
			if len(rc) != 32 || seen[string(rc)] {
				wire.WriteError(w, 400, "INVALID_ENCODING", false)
				return
			}
			seen[string(rc)] = true
		}
		var total uint64
		seen = map[string]bool{}
		for _, p := range req.Parts {
			if len(p.PartID) != 16 || len(p.CiphertextSHA256) != 32 || p.Size == 0 || p.Size > 5<<20 || seen[string(p.PartID)] {
				wire.WriteError(w, 400, "INVALID_ENCODING", false)
				return
			}
			seen[string(p.PartID)] = true
			total += p.Size
		}
		cost := int64(total) + objectOverhead + 64*int64(len(req.Parts)) + 32*int64(len(req.Recipients))
		now := s.Now()
		id := make([]byte, 16)
		rand.Read(id)
		o := &object{
			Descriptor: Descriptor{Protocol: 1, SpoolID: id, OwnerDeviceID: sess.DeviceID, Recipients: req.Recipients,
				Contact:      req.Contact,
				OriginServer: s.Auth.Audience, CreatedAt: uint64(now.UnixMilli()), ExpiresAt: uint64(now.Add(s.TTL).UnixMilli()), Parts: req.Parts},
			State: Uploading, Acked: map[string]bool{}, Uploaded: map[string]bool{}, Total: total,
			Charged: cost, IP: wire.ClientIP(r), acct: cost,
		}
		o.seal()
		s.GC()
		s.mu.Lock()
		ok := s.reserveLocked(o, cost, 1)
		s.mu.Unlock()
		if !ok {
			s.forceGC()
			s.mu.Lock()
			ok = s.reserveLocked(o, cost, 1)
			s.mu.Unlock()
		}
		if !ok {
			wire.WriteError(w, 507, "QUOTA_EXCEEDED", false)
			return
		}
		if err := os.MkdirAll(s.path(o.id, "parts"), 0o700); err != nil || s.save(o) != nil {
			os.RemoveAll(s.path(o.id))
			s.mu.Lock()
			s.addLocked(o, -cost, -1)
			s.mu.Unlock()
			wire.WriteError(w, 500, "INTERNAL", true)
			return
		}
		s.mu.Lock()
		s.objects[o.id] = o
		s.mu.Unlock()
		wire.Write(w, CreateResponse{SpoolID: id, OriginServer: s.Auth.Audience, CreatedAt: o.Descriptor.CreatedAt, ExpiresAt: o.Descriptor.ExpiresAt})
	})(w, r)
}

// lookup finds the object named in the path; callers lock it and check live before touching it.
func (s *Service) lookup(r *http.Request) *object {
	id, err := b64.DecodeString(r.PathValue("id"))
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.objects[string(id)]
}

// live: not removed and not expired; o.mu held.
func (s *Service) live(o *object) bool {
	return o != nil && !o.removed && uint64(s.Now().UnixMilli()) < o.expires
}

func (o *object) part(id []byte) (Part, bool) {
	for _, p := range o.Descriptor.Parts {
		if bytes.Equal(p.PartID, id) {
			return p, true
		}
	}
	return Part{}, false
}

func (o *object) isRecipient(dev []byte) bool {
	for _, r := range o.recipients {
		if bytes.Equal(r, dev) {
			return true
		}
	}
	return false
}

func (o *object) allAcked() bool {
	for _, r := range o.recipients {
		if !o.Acked[b64.EncodeToString(r)] {
			return false
		}
	}
	return true
}

// HandlePutPart: PUT /v1/spools/{id}/parts/{part_id}. Idempotent for identical bytes, PART_CONFLICT otherwise.
// One body per part is read at a time: a parallel PUT of the same part gets RATE_LIMITED before its body is
// touched, and every body being read holds its size against the in-flight budgets.
func (s *Service) HandlePutPart(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		o := s.lookup(r)
		pid, err := b64.DecodeString(r.PathValue("part"))
		if o == nil || err != nil || o.owner != string(sess.DeviceID) {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if !s.authorizeObject(w, r, o, sess, false) {
			return
		}
		name := b64.EncodeToString(pid)
		o.mu.Lock()
		ok := s.live(o) && o.State == Uploading
		p, known := o.part(pid)
		busy := o.putting[name]
		if ok && known && !busy {
			if o.putting == nil {
				o.putting = map[string]bool{}
			}
			o.putting[name] = true
		}
		o.mu.Unlock()
		if !ok {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if !known {
			wire.WriteError(w, 404, "INVALID_ENCODING", false)
			return
		}
		if busy {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		defer func() {
			o.mu.Lock()
			delete(o.putting, name)
			o.mu.Unlock()
		}()
		release, ok := s.Inflight.Take(o.owner, wire.ClientIP(r), int64(p.Size))
		if !ok {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		defer release()
		http.NewResponseController(w).SetReadDeadline(s.Now().Add(PartReadTimeout))
		data, err := io.ReadAll(io.LimitReader(r.Body, int64(p.Size)+1))
		sum := sha256.Sum256(data)
		if err != nil || uint64(len(data)) != p.Size || !bytes.Equal(sum[:], p.CiphertextSHA256) {
			wire.WriteError(w, 409, "PART_CONFLICT", false)
			return
		}
		tmp, err := writeTemp(s.path(o.id, "parts"), name, data)
		if err != nil {
			wire.WriteError(w, 500, "INTERNAL", true)
			return
		}
		defer os.Remove(tmp) // no-op once renamed
		o.mu.Lock()
		defer o.mu.Unlock()
		if !s.live(o) || o.State != Uploading { // committed, deleted or expired while the body was arriving
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if os.Rename(tmp, s.path(o.id, "parts", name)) != nil {
			wire.WriteError(w, 500, "INTERNAL", true)
			return
		}
		had := o.Uploaded[name]
		o.Uploaded[name] = true
		if s.save(o) != nil {
			if !had {
				delete(o.Uploaded, name)
			}
			wire.WriteError(w, 500, "INTERNAL", true)
			return
		}
		w.WriteHeader(204)
	})(w, r)
}

type CommitRequest struct {
	Boxes      []Box  `cbor:"boxes"`
	SigningKey []byte `cbor:"signing_key"`
	Signature  []byte `cbor:"signature"`
}

// HandleCommit: POST /v1/spools/{id}/commit. All parts present, owner signature over the full descriptor. A
// retry of the same commit succeeds again; a different one after commit is refused.
func (s *Service) HandleCommit(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		o := s.lookup(r)
		var req CommitRequest
		if o == nil || wire.Read(r, &req) != nil || o.owner != string(sess.DeviceID) {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		sum := sha256.Sum256(req.SigningKey)
		if len(req.SigningKey) != ed25519.PublicKeySize || !bytes.Equal(sum[:], sess.DeviceID) {
			wire.WriteError(w, 401, "AUTH_FAILED", false)
			return
		}
		if !s.authorizeObject(w, r, o, sess, true) {
			return
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if !s.live(o) {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if o.State != Uploading {
			if bytes.Equal(o.Signature, req.Signature) {
				w.WriteHeader(204)
			} else {
				wire.WriteError(w, 409, "IDEMPOTENCY_CONFLICT", false)
			}
			return
		}
		for _, p := range o.Descriptor.Parts {
			if !o.Uploaded[b64.EncodeToString(p.PartID)] {
				wire.WriteError(w, 409, "INTEGRITY_FAILED", true)
				return
			}
		}
		var extra int64
		boxed := map[string]bool{}
		for _, b := range req.Boxes {
			if !o.isRecipient(b.Recipient) || boxed[string(b.Recipient)] || len(b.Box) > maxBoxBytes(len(o.Descriptor.Parts)) {
				wire.WriteError(w, 400, "INVALID_ENCODING", false)
				return
			}
			boxed[string(b.Recipient)] = true
			extra += int64(len(b.Box)) + 32
		}
		d := o.Descriptor
		d.Boxes = req.Boxes
		msg, _ := wire.Enc.Marshal(d)
		if !ed25519.Verify(req.SigningKey, append([]byte(domain), msg...), req.Signature) {
			wire.WriteError(w, 400, "SIGNATURE_INVALID", false)
			return
		}
		s.mu.Lock()
		published := s.objects[o.id] == o
		ok := published && s.reserveLocked(o, extra, 0)
		if ok {
			o.acct += extra
		}
		s.mu.Unlock()
		if !published {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if !ok {
			wire.WriteError(w, 507, "QUOTA_EXCEEDED", false)
			return
		}
		prevD, prevSig, prevCharged := o.Descriptor, o.Signature, o.Charged
		o.Descriptor, o.Signature, o.State, o.Charged = d, req.Signature, Available, o.Charged+extra
		if s.save(o) != nil {
			o.Descriptor, o.Signature, o.State, o.Charged = prevD, prevSig, Uploading, prevCharged
			s.mu.Lock()
			if s.objects[o.id] == o {
				s.addLocked(o, -extra, 0)
				o.acct -= extra
			}
			s.mu.Unlock()
			wire.WriteError(w, 500, "INTERNAL", true)
			return
		}
		w.WriteHeader(204)
	})(w, r)
}

type ListItem struct {
	SpoolID   []byte `cbor:"spool_id"`
	Owner     []byte `cbor:"owner_device_id"`
	Size      uint64 `cbor:"size"`
	ExpiresAt uint64 `cbor:"expires_at"`
}

// HandleList: GET /v1/spools — committed, unacked objects for the calling recipient only.
func (s *Service) HandleList(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		s.GC()
		var mine []*object
		s.mu.Lock()
		for _, o := range s.objects {
			if o.isRecipient(sess.DeviceID) {
				mine = append(mine, o)
			}
		}
		s.mu.Unlock()
		out := []ListItem{}
		for _, o := range mine {
			o.mu.Lock()
			readable := s.readable(o, sess)
			o.mu.Unlock()
			if !readable || !s.authorizeObject(nil, r, o, sess, false) {
				continue
			}
			o.mu.Lock()
			if s.readable(o, sess) {
				out = append(out, ListItem{[]byte(o.id), []byte(o.owner), o.Total, o.expires})
			}
			o.mu.Unlock()
		}
		wire.Write(w, out)
	})(w, r)
}

type GetResponse struct {
	Descriptor Descriptor `cbor:"descriptor"` // boxes trimmed to the caller's own
	Signature  []byte     `cbor:"descriptor_signature"`
	Box        []byte     `cbor:"box"`
}

// readable: committed, and the caller is a recipient that has not acked; o.mu held.
func (s *Service) readable(o *object, sess auth.Session) bool {
	return s.live(o) && o.State == Available && o.isRecipient(sess.DeviceID) && !o.Acked[b64.EncodeToString(sess.DeviceID)]
}

func (s *Service) HandleGet(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		o := s.lookup(r)
		if o == nil {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if !s.authorizeObject(w, r, o, sess, false) {
			return
		}
		o.mu.Lock()
		ok := s.readable(o, sess)
		// A committed descriptor is replaced, never mutated, so the copy stays valid after unlock.
		resp := GetResponse{Descriptor: o.Descriptor, Signature: o.Signature}
		o.mu.Unlock()
		if !ok {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		for _, b := range resp.Descriptor.Boxes {
			if bytes.Equal(b.Recipient, sess.DeviceID) {
				resp.Box = b.Box
			}
		}
		// The recipient checks the signature over the full descriptor, so it gets every box's recipient but only
		// its own box contents would be enough — boxes are sealed per recipient, sending all is harmless.
		wire.Write(w, resp)
	})(w, r)
}

// HandleGetPart supports HTTP Range so background downloads can resume mid-part. Every byte is billed to the
// owner (and the address it reserved from) before it is sent, and counted against what this recipient may pull
// of the object (MaxServedCopies); the download stops at the first refusal.
func (s *Service) HandleGetPart(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		o := s.lookup(r)
		pid, err := b64.DecodeString(r.PathValue("part"))
		if o == nil || err != nil {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if !s.authorizeObject(w, r, o, sess, false) {
			return
		}
		dev, ip := string(sess.DeviceID), wire.ClientIP(r)
		o.mu.Lock()
		if !s.readable(o, sess) {
			o.mu.Unlock()
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		p, ok := o.part(pid)
		if !ok {
			o.mu.Unlock()
			wire.WriteError(w, 404, "INVALID_ENCODING", false)
			return
		}
		o.mu.Unlock()
		releaseReq, ok := s.Gets.Take(dev, ip, 1)
		if !ok {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		defer releaseReq()
		releaseBytes, ok := s.GetInflight.Take(dev, ip, int64(p.Size))
		if !ok {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		defer releaseBytes()
		o.mu.Lock()
		if !s.readable(o, sess) {
			o.mu.Unlock()
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		// Opened under the lock: an open file stays readable even if the object is removed meanwhile.
		f, err := os.Open(s.path(o.id, "parts", b64.EncodeToString(pid)))
		o.mu.Unlock()
		if err != nil {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		defer f.Close()
		rc := http.NewResponseController(w)
		defer rc.SetWriteDeadline(time.Time{}) // the connection is reused: a stale deadline would cut the next response
		span, multi := rangeSpan(r.Header.Get("Range"), int64(p.Size))
		if multi {
			w.Header().Set("Content-Range", "bytes */"+strconv.FormatUint(p.Size, 10))
			wire.WriteError(w, 416, "RANGE_NOT_SUPPORTED", false)
			return
		}
		// Preconditions are not offered: a mismatched If-Range would answer 200 with the whole part (unbilled), and a
		// matching If-None-Match or failing If-Match would answer 304/412 after the credit was already taken.
		for _, h := range []string{"If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
			r.Header.Del(h)
		}
		if r.Method == http.MethodHead {
			span = 0 // headers only
		}
		cw := &chargingWriter{ResponseWriter: w, left: span, take: func(n int64) bool { return s.takeServed(o, sess.DeviceID, n) },
			rc: rc, stall: GetStall, by: time.Now().Add(GetStall + time.Duration(int64(p.Size)*int64(time.Second)/max(GetMinRate, 1)))}
		// The first chunk is taken before any header goes out, so a used-up recipient or owner gets a clean
		// refusal rather than a truncated part.
		if span > 0 && !cw.reserve(min(cw.left, chargeChunk)) {
			s.refuseQuota(w, sess.DeviceID)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(cw, r, "", time.Time{}, f)
		s.saveServed(o)
	})(w, r)
}

// takeServed counts n more bytes of o sent to recipient against its share and bills them to the owner; false
// means stop sending.
func (s *Service) takeServed(o *object, recipient []byte, n int64) bool {
	key := b64.EncodeToString(recipient)
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.removed || o.Served[key]+n > MaxServedCopies*int64(o.Total) {
		return false
	}
	// One logical send is one charge to the sender's account: the whole object at the first byte served, whatever
	// the number of recipient devices, retries or resumes. The charge is asked once per object ID and the ledger
	// answers a repeat with the first answer, so asking before the address and server caps (which can refuse) costs
	// the account nothing when they do, and a crash between the two repeats nothing. The mark is saved before the
	// first byte goes out; the ledger holds its own record, so the mark only saves the round trip.
	if !o.Billed {
		if !s.Meter.ChargeAccount([]byte(o.owner), b64.EncodeToString([]byte(o.id)), int64(o.Total)) {
			return false
		}
		o.Billed = true
		if err := s.save(o); err != nil {
			log.Printf("spool: could not save the billing mark of %x: %v", o.id, err)
		}
	}
	if !s.Meter.ChargeTransit([]byte(o.owner), o.IP, n) {
		return false
	}
	if o.Served == nil {
		o.Served = map[string]int64{}
	}
	o.Served[key] += n
	return true
}

// saveServed persists the download counts best effort: losing them to a crash can only forgive a little.
func (s *Service) saveServed(o *object) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.removed {
		s.save(o)
	}
}

// HandleAck: the recipient has everything it needs (not a plaintext verdict). Deleted once all recipients ack.
func (s *Service) HandleAck(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		o := s.lookup(r)
		if o == nil {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if !s.authorizeCleanup(w, r, o, sess) {
			return
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if !s.readable(o, sess) {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if s.dropGrant(o, sess.DeviceID) != nil {
			wire.WriteError(w, 500, "INTERNAL", true)
			return
		}
		w.WriteHeader(204)
	})(w, r)
}

// HandleDelete: owner cancels the object; a recipient only drops its own grant.
func (s *Service) HandleDelete(w http.ResponseWriter, r *http.Request) {
	s.Auth.Require(func(w http.ResponseWriter, r *http.Request, sess auth.Session) {
		o := s.lookup(r)
		if o == nil {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		if !s.authorizeCleanup(w, r, o, sess) {
			return
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if !s.live(o) {
			wire.WriteError(w, 404, "SPOOL_EXPIRED", false)
			return
		}
		var err error
		switch {
		case o.owner == string(sess.DeviceID):
			err = s.remove(o)
		case o.isRecipient(sess.DeviceID):
			err = s.dropGrant(o, sess.DeviceID)
		default:
			wire.WriteError(w, 403, "AUTH_FAILED", false)
			return
		}
		if err != nil {
			wire.WriteError(w, 500, "INTERNAL", true)
			return
		}
		w.WriteHeader(204)
	})(w, r)
}

// dropGrant records that recipient is done and removes the object after the last one; o.mu held.
func (s *Service) dropGrant(o *object, recipient []byte) error {
	key := b64.EncodeToString(recipient)
	if o.Acked[key] {
		return nil
	}
	o.Acked[key] = true
	var err error
	if o.allAcked() {
		err = s.remove(o)
	} else {
		err = s.save(o)
	}
	if err != nil {
		delete(o.Acked, key)
	}
	return err
}

// remove deletes o for good; o.mu held. Once meta.cbor is gone a restart can't bring it back, so the rest of
// the directory is best effort.
func (s *Service) remove(o *object) error {
	if err := os.Remove(s.path(o.id, "meta.cbor")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	o.removed = true
	s.mu.Lock()
	s.dropLocked(o)
	s.mu.Unlock()
	os.RemoveAll(s.path(o.id))
	return nil
}

// GC removes expired objects; also runs (at most once a minute) on create and list.
func (s *Service) GC() {
	s.mu.Lock()
	now := s.Now()
	if now.Sub(s.lastGC) < time.Minute && now.After(s.lastGC) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.forceGC()
}

func (s *Service) forceGC() {
	now := uint64(s.Now().UnixMilli())
	var expired []*object
	s.mu.Lock()
	s.lastGC = s.Now()
	for _, o := range s.objects {
		if now >= o.expires {
			expired = append(expired, o)
			s.dropLocked(o)
		}
	}
	s.mu.Unlock()
	for _, o := range expired {
		o.mu.Lock()
		o.removed = true
		os.RemoveAll(s.path(o.id))
		o.mu.Unlock()
	}
}

// rangeLength is how many ciphertext bytes ServeContent sends for this Range header on a part of the given size. It
// follows the parsing of net/http exactly, so a refused (416) or empty range is billed nothing and a clipped one only
// what leaves. multi is set for more than one range: those are refused, since the multipart framing around many tiny
// ranges would be relay traffic that nothing bills.
func rangeLength(header string, size int64) int64 {
	n, _ := rangeSpan(header, size)
	return n
}

func rangeSpan(header string, size int64) (n int64, multi bool) {
	const prefix = "bytes="
	if header == "" {
		return size, false
	}
	if !strings.HasPrefix(header, prefix) {
		return 0, false
	}
	count, noOverlap := 0, false
	for _, spec := range strings.Split(header[len(prefix):], ",") {
		spec = strings.Trim(spec, " \t")
		if spec == "" {
			continue
		}
		from, to, ok := strings.Cut(spec, "-")
		if !ok {
			return 0, false
		}
		from, to = strings.Trim(from, " \t"), strings.Trim(to, " \t")
		var length int64
		if from == "" {
			if to == "" || to[0] == '-' {
				return 0, false
			}
			i, err := strconv.ParseInt(to, 10, 64)
			if err != nil || i < 0 {
				return 0, false
			}
			length = min(i, size)
		} else {
			i, err := strconv.ParseInt(from, 10, 64)
			if err != nil || i < 0 {
				return 0, false
			}
			if i >= size {
				noOverlap = true
				continue
			}
			if to == "" {
				length = size - i
			} else {
				j, err := strconv.ParseInt(to, 10, 64)
				if err != nil || i > j {
					return 0, false
				}
				length = min(j, size-1) - i + 1
			}
		}
		count++
		n = length
	}
	switch {
	case count > 1:
		return 0, true
	case count == 1:
		return n, false
	case noOverlap:
		return 0, false
	}
	return size, false // a Range with no specs at all is ignored
}

var errStopped = errors.New("spool: download stopped by quota")

// chargingWriter takes credit in chargeChunk steps before the bytes it covers are written, so nothing leaves
// unbilled. One response is at most the part, so credit never goes past it (left); what a download that ends
// early overpays is the unused rest of its last step.
type chargingWriter struct {
	http.ResponseWriter
	take   func(n int64) bool
	credit int64
	left   int64 // credit this response may still take
	rc     *http.ResponseController
	stall  time.Duration // longest one write may block
	by     time.Time     // the whole response is over by then
}

func (c *chargingWriter) reserve(n int64) bool {
	n = min(n, c.left)
	if n <= 0 || !c.take(n) {
		return false
	}
	c.credit, c.left = c.credit+n, c.left-n
	return true
}

func (c *chargingWriter) Write(p []byte) (int, error) {
	if need := int64(len(p)) - c.credit; need > 0 && (!c.reserve(max(need, chargeChunk)) || c.credit < int64(len(p))) {
		return 0, errStopped
	}
	if c.rc != nil {
		d := time.Now().Add(c.stall)
		if d.After(c.by) {
			d = c.by
		}
		c.rc.SetWriteDeadline(d)
	}
	n, err := c.ResponseWriter.Write(p)
	c.credit -= int64(n)
	return n, err
}

// Info is what the origin server may tell its notification path about a committed object: the facts a hint
// must not take from the client.
type Info struct {
	Bytes      uint64
	ExpiresAt  uint64
	Recipients [][]byte
	Contact    *ContactBinding
}

// Info returns a committed, live object that owner created, or false.
func (s *Service) Info(id, owner []byte) (Info, bool) {
	s.mu.Lock()
	o := s.objects[string(id)]
	s.mu.Unlock()
	if o == nil || o.owner != string(owner) {
		return Info{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !s.live(o) || o.State != Available {
		return Info{}, false
	}
	return Info{Bytes: o.Total, ExpiresAt: o.expires, Recipients: o.recipients, Contact: o.Descriptor.Contact}, true
}

// refuseQuota answers a refused charge: used up (429) or only unable to ask the billing authority (503, retry).
func (s *Service) refuseQuota(w http.ResponseWriter, device []byte) {
	if meter.BillingUnavailable(s.Meter, device) {
		wire.WriteError(w, 503, "BILLING_UNAVAILABLE", true)
		return
	}
	wire.WriteError(w, 429, "QUOTA_EXCEEDED", false)
}

// PurgeDevices erases what the given devices (an account that was deleted) own, and drops them from the objects
// meant for them; an object nobody else is waiting for goes with them.
func (s *Service) PurgeDevices(devs [][]byte) error {
	set := map[string]bool{}
	for _, d := range devs {
		set[string(d)] = true
	}
	s.mu.Lock()
	objs := make([]*object, 0, len(s.objects))
	for _, o := range s.objects {
		objs = append(objs, o)
	}
	s.mu.Unlock()
	var first error
	for _, o := range objs {
		o.mu.Lock()
		var err error
		switch {
		case o.removed:
		case set[o.owner]:
			err = s.remove(o)
		default:
			for _, rc := range o.recipients {
				if set[string(rc)] {
					if err = s.dropGrant(o, rc); err != nil || o.removed {
						break
					}
				}
			}
		}
		o.mu.Unlock()
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

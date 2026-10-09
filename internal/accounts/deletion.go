package accounts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/durable"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// Account deletion. The person asks for it with one signed request from a device that is active now; the server that
// takes it refuses everything for the account at once (a tombstone that is only a hash, kept for good so the same
// account cannot be made again from old keys), erases the account's data here, tells every other server and repeats
// until each has acknowledged. Only then does it drop the chain it kept for them to check. Nothing here is undone.

const (
	// DeleteDomain separates the signature from every other signature an account device makes.
	DeleteDomain = "farlink/account-delete/v1"
	// DeleteLifetime is how long a signed deletion request stays acceptable after it was made.
	DeleteLifetime = 10 * time.Minute

	deleteBody = 4 << 10
	// purgeRecheck is how long after the first erasing pass the second one runs.
	purgeRecheck = 2 * time.Minute
	// MaxDeletionRetry bounds how long a server keeps telling the others (the retention limit for what it keeps meanwhile).
	MaxDeletionRetry = 90 * 24 * time.Hour
	peerDeleteMax    = 8 << 20
)

// ErrDeleted: the account was deleted. Permanent, not a failure to retry.
var ErrDeleted = errors.New("ACCOUNT_DELETED")

// DeleteBody is what the account device signs.
type DeleteBody struct {
	Protocol  uint64 `cbor:"protocol"`
	AccountID []byte `cbor:"account_id"`
	Device    []byte `cbor:"device"`    // the signing device's id
	HeadHash  []byte `cbor:"head_hash"` // the newest link the signer saw
	ExpiresAt uint64 `cbor:"expires_at"`
}

// DeleteRequest is POST /v1/accounts/{id}/delete.
type DeleteRequest struct {
	DeleteBody
	Signature []byte `cbor:"signature"`
}

func (b DeleteBody) valid() bool {
	return b.Protocol == 1 && len(b.AccountID) == 32 && len(b.Device) == 32 && len(b.HeadHash) == 32
}

// SignDelete is what a client (and the tests) run.
func SignDelete(key ed25519.PrivateKey, body DeleteBody) DeleteRequest {
	raw, _ := wire.Enc.Marshal(body)
	return DeleteRequest{DeleteBody: body, Signature: ed25519.Sign(key, append([]byte(DeleteDomain), raw...))}
}

func (r DeleteRequest) signatureOK(key []byte) bool {
	raw, err := wire.Enc.Marshal(r.DeleteBody)
	return err == nil && len(r.Signature) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(key), append([]byte(DeleteDomain), raw...), r.Signature)
}

// VerifyDelete checks a request against the account as it is now: the signer is an active device, saw the newest link,
// signed this request, and it has not expired. An account that is forked or unreachable cannot be deleted until it is not.
func VerifyDelete(ctx context.Context, resolver *Resolver, req DeleteRequest, now time.Time) error {
	if !req.DeleteBody.valid() {
		return ErrMalformed
	}
	if req.ExpiresAt <= uint64(now.UnixMilli()) || req.ExpiresAt > uint64(now.Add(DeleteLifetime).UnixMilli()) {
		return ErrMalformed
	}
	account, err := resolver.Current(ctx, req.AccountID)
	if err != nil {
		return err
	}
	device, active := account.ActiveDevice(req.Device)
	if !active {
		return ErrNotAuthorized
	}
	if !bytes.Equal(account.HeadRef().Hash, req.HeadHash) {
		return ErrSync
	}
	if !req.signatureOK(device.SigningKey) {
		return ErrBadSignature
	}
	return nil
}

// --- tombstones --------------------------------------------------------------------------------------------------

// A tombstone is the SHA-256 of the account id under a domain: it says "this account was deleted" and nothing else.
func tombstoneOf(id []byte) [32]byte {
	return sha256.Sum256(append([]byte("farlink/account-deleted/v1"), id...))
}

// A device key of a deleted account is kept the same way, so that its sign-in stays refused after the chain is gone.
func deviceTombstoneOf(id []byte) [32]byte {
	return sha256.Sum256(append([]byte("farlink/account-deleted-device/v1"), id...))
}

const tombstoneMagic = "FLDEL1\n\x00"

type tombstones struct {
	path string
	f    *os.File
	set  map[[32]byte]bool
}

func openTombstones(dir string) (*tombstones, error) {
	t := &tombstones{path: filepath.Join(dir, "deleted.log"), set: map[[32]byte]bool{}}
	raw, err := os.ReadFile(t.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	good := len(tombstoneMagic)
	switch {
	case raw == nil:
	case len(raw) < len(tombstoneMagic) || string(raw[:len(tombstoneMagic)]) != tombstoneMagic:
		return nil, errors.New("accounts: unreadable deleted.log")
	default:
		for off := len(tombstoneMagic); off+32 <= len(raw); off += 32 {
			var h [32]byte
			copy(h[:], raw[off:off+32])
			t.set[h] = true
			good = off + 32
		}
	}
	f, err := os.OpenFile(t.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		if _, err := f.Write([]byte(tombstoneMagic)); err != nil {
			f.Close()
			return nil, err
		}
	} else if good != len(raw) {
		if err := f.Truncate(int64(good)); err != nil {
			f.Close()
			return nil, err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 2); err != nil {
		f.Close()
		return nil, err
	}
	if err := durable.SyncDir(dir); err != nil {
		f.Close()
		return nil, err
	}
	t.f = f
	return t, nil
}

// add records the tombstone durably; repeating it writes nothing.
func (t *tombstones) add(id []byte) error { return t.addHash(tombstoneOf(id)) }

func (t *tombstones) addHash(h [32]byte) error {
	if t.set[h] {
		return nil
	}
	if _, err := t.f.Write(h[:]); err != nil {
		t.cut()
		return err
	}
	if err := t.f.Sync(); err != nil {
		t.cut()
		return err
	}
	t.set[h] = true
	return nil
}

func (t *tombstones) cut() {
	end := int64(len(tombstoneMagic) + len(t.set)*32)
	_ = t.f.Truncate(end)
	_, _ = t.f.Seek(end, 0)
}

// IsDeleted reports whether the account was deleted.
func (r *Registry) IsDeleted(id []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleted != nil && r.deleted.set[tombstoneOf(id)]
}

// TombstoneDevices refuses these device keys from now on, durably.
func (r *Registry) TombstoneDevices(ids [][]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		if err := r.deleted.addHash(deviceTombstoneOf(id)); err != nil {
			return err
		}
	}
	return nil
}

// Tombstone refuses the account from now on, durably. The chain stays until DropChain so that other servers can be
// shown what was deleted.
func (r *Registry) Tombstone(id []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleted.add(id)
}

// DropChain erases the account's chain and its device index entries.
func (r *Registry) DropChain(id []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := hex.EncodeToString(id)
	if err := os.Remove(filepath.Join(r.dir, key+".chain")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := durable.SyncDir(r.dir); err != nil {
		return err
	}
	delete(r.chains, key)
	for dev, owner := range r.devices {
		if owner == key {
			delete(r.devices, dev)
		}
	}
	return nil
}

// --- the deleter -------------------------------------------------------------------------------------------------

// PeerDelete is what one server tells the others: the signed request and the chain it was checked against. The other
// server replays the chain itself (every link proves itself), so it does not have to ask anyone.
type PeerDelete struct {
	Request DeleteRequest `cbor:"request"`
	Chain   [][]byte      `cbor:"chain"`
}

// Purger erases an account's data kept by one store. It must be safe to repeat.
type Purger func(account []byte, devices [][]byte) error

type pendingDeletion struct {
	Request DeleteRequest `cbor:"request"`
	Chain   [][]byte      `cbor:"chain"`
	Devices [][]byte      `cbor:"devices"`
	Acked   []string      `cbor:"acked"`
	Local   bool          `cbor:"local"` // told by another server: nothing to push
	Purged  bool          `cbor:"purged"`
	// PurgedAt is when the first pass over the stores finished; Purged is set by the second.
	PurgedAt uint64 `cbor:"purged_at,omitempty"`
	At       uint64 `cbor:"at"`
}

// Deleter runs deletions from the request until every server has erased the account.
type Deleter struct {
	Reg      *Registry
	Resolver *Resolver
	Dir      string
	// Peers lists the other servers' ids; Push tells one of them.
	Peers func() []string
	Push  func(ctx context.Context, peer string, p PeerDelete) error
	// Expand adds what only the server knows to the account's device ids (the transport keys bound to it).
	Expand func(account []byte, devices [][]byte) [][]byte
	// Purge erases the account's data in each store.
	Purge []Purger
	// Finish runs once everything is done, to drop what only the deletion needed (the chain, bindings, checkpoints).
	Finish []func(account []byte) error
	// IsPeer says whether the request came from another server of the fleet (they may read a deleted account's chain).
	IsPeer func(*http.Request) bool
	Now    func() time.Time

	mu   sync.Mutex
	kick chan struct{}
}

func (d *Deleter) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Deleter) file(id []byte) string {
	return filepath.Join(d.Dir, hex.EncodeToString(id)+".deleting")
}

func (d *Deleter) save(p pendingDeletion) error {
	b, err := wire.Enc.Marshal(p)
	if err != nil {
		return err
	}
	return durable.WriteFile(d.file(p.Request.AccountID), b)
}

func (d *Deleter) load(path string) (pendingDeletion, error) {
	var p pendingDeletion
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	return p, wire.Lenient(raw, &p)
}

func (d *Deleter) wake() {
	select {
	case d.kick <- struct{}{}:
	default:
	}
}

// Open prepares the pending directory and the wake channel.
func (d *Deleter) Open() error {
	d.kick = make(chan struct{}, 1)
	return os.MkdirAll(d.Dir, 0o700)
}

// Start takes a deletion asked for by the person. It returns once the account is refused everywhere here and the work
// to finish it is saved; the rest goes on in the background (Run) and survives a restart.
func (d *Deleter) Start(ctx context.Context, req DeleteRequest) error {
	if d.Reg.IsDeleted(req.AccountID) {
		return nil // asked again: the same answer
	}
	if err := VerifyDelete(ctx, d.Resolver, req, d.now()); err != nil {
		return err
	}
	// Checked again, saved and refused in one step against the chain this server holds, so a revocation or a fork that
	// lands in between cannot be overtaken, and what is sent on is exactly the chain the request was checked against.
	return d.Reg.CommitDelete(req, func(chain, devices [][]byte) error {
		return d.merge(pendingDeletion{Request: req, Chain: chain, Devices: devices, At: uint64(d.now().UnixMilli())})
	})
}

// merge saves work for an account, keeping what an earlier save of the same deletion already holds: nothing it knows
// (the chain to send on, the devices, who has acknowledged) is lost by a repeated or concurrent request.
func (d *Deleter) merge(p pendingDeletion) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if old, err := d.load(d.file(p.Request.AccountID)); err == nil {
		if len(old.Chain) > 0 && len(p.Chain) == 0 {
			p.Chain = old.Chain
		}
		p.Local = p.Local && old.Local
		if len(p.Chain) > 0 {
			p.Local = false
		}
		seen := map[string]bool{}
		for _, dev := range p.Devices {
			seen[string(dev)] = true
		}
		for _, dev := range old.Devices {
			if !seen[string(dev)] {
				p.Devices = append(p.Devices, dev)
			}
		}
		p.Acked, p.Purged, p.PurgedAt = old.Acked, old.Purged, old.PurgedAt
		if old.At != 0 && (p.At == 0 || old.At < p.At) {
			p.At = old.At
		}
	}
	if err := d.save(p); err != nil {
		return err
	}
	d.wake()
	return nil
}

// ApplyPeer takes a deletion another server has checked. It checks what it can itself: the chain replays, the signer is
// an active device of its newest link, the request names that link and carries a good signature, and this server's own
// copy (if any) is the same history, not another branch of it.
func (d *Deleter) ApplyPeer(p PeerDelete) error {
	req := p.Request
	if !req.DeleteBody.valid() || len(p.Chain) == 0 || len(p.Chain) > MaxLinks {
		return ErrMalformed
	}
	if d.Reg.IsDeleted(req.AccountID) {
		return nil
	}
	c, err := replay(p.Chain)
	if err != nil || c.frozen() || !bytes.Equal(c.links[0].State.AccountID, req.AccountID) {
		return ErrMalformed
	}
	head := c.head()
	if !bytes.Equal(head.Hash(), req.HeadHash) {
		return ErrSync
	}
	device, active := head.State.device(req.Device)
	if !active || !req.signatureOK(device.SigningKey) {
		return ErrNotAuthorized
	}
	return d.Reg.CommitPeerDelete(req, c, func(devices [][]byte) error {
		return d.merge(pendingDeletion{Request: req, Devices: devices, Local: true, At: uint64(d.now().UnixMilli())})
	})
}

// process works on one deletion as far as it can now.
func (d *Deleter) process(ctx context.Context, path string) {
	d.mu.Lock()
	p, err := d.load(path)
	d.mu.Unlock()
	if err != nil {
		return
	}
	id := p.Request.AccountID
	devices := p.Devices
	if d.Expand != nil {
		devices = d.Expand(id, devices) // the transport keys bound to the account too
	}
	if err := d.Reg.Tombstone(id); err != nil || d.Reg.TombstoneDevices(devices) != nil {
		return
	}
	changed := false
	now := uint64(d.now().UnixMilli())
	purgeAll := func() bool {
		ok := true
		for _, purge := range d.Purge {
			if err := purge(id, devices); err != nil {
				ok = false
			}
		}
		return ok
	}
	// Twice, a couple of minutes apart: a request that was already running when the account was refused may still write
	// after the first pass.
	switch {
	case p.PurgedAt == 0:
		if purgeAll() {
			p.PurgedAt, changed = now, true
		}
	case !p.Purged && now >= p.PurgedAt+uint64(purgeRecheck.Milliseconds()):
		if purgeAll() {
			p.Purged, changed = true, true
		}
	}
	waiting := false
	if !p.Local && d.Peers != nil && d.Push != nil && now < p.At+uint64(MaxDeletionRetry.Milliseconds()) {
		acked := map[string]bool{}
		for _, a := range p.Acked {
			acked[a] = true
		}
		for _, peer := range d.Peers() {
			if acked[peer] {
				continue
			}
			if err := d.Push(ctx, peer, PeerDelete{Request: p.Request, Chain: p.Chain}); err != nil {
				waiting = true
				continue
			}
			p.Acked, changed = append(p.Acked, peer), true
		}
	}
	if changed {
		d.mu.Lock()
		err := d.save(p)
		d.mu.Unlock()
		if err != nil {
			return
		}
	}
	if p.Purged && !waiting {
		// Everyone has been told and the data is gone: nothing about the account but its tombstone is kept.
		if d.Reg.DropChain(id) != nil {
			return
		}
		for _, finish := range d.Finish {
			if finish(id) != nil {
				return
			}
		}
		d.mu.Lock()
		_ = os.Remove(path)
		_ = durable.SyncDir(d.Dir)
		d.mu.Unlock()
	}
}

// Pending lists the accounts whose deletion is not finished (for status and tests).
func (d *Deleter) Pending() [][]byte {
	entries, _ := os.ReadDir(d.Dir)
	var out [][]byte
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".deleting" {
			continue
		}
		if id, err := hex.DecodeString(e.Name()[:len(e.Name())-len(".deleting")]); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// Step runs every unfinished deletion once.
func (d *Deleter) Step(ctx context.Context) {
	entries, _ := os.ReadDir(d.Dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".deleting" {
			d.process(ctx, filepath.Join(d.Dir, e.Name()))
		}
	}
}

// Run repeats Step until ctx ends: soon after a new deletion, and every half minute for the ones waiting on a server.
func (d *Deleter) Run(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	d.Step(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.kick:
			d.Step(ctx)
		case <-tick.C:
			d.Step(ctx)
		}
	}
}

// --- HTTP --------------------------------------------------------------------------------------------------------

// HandleDelete: POST /v1/accounts/{id}/delete. The request proves itself; no bearer token.
func (d *Deleter) HandleDelete(a *API) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.allow(r) {
			wire.WriteError(w, 429, "RATE_LIMITED", true)
			return
		}
		var req DeleteRequest
		if err := wire.ReadLimit(r, &req, deleteBody); err != nil {
			wire.WriteReadError(w, err)
			return
		}
		if err := d.Start(r.Context(), req); err != nil {
			if errors.Is(err, ErrUnreachable) {
				wire.WriteError(w, 503, "ACCOUNT_UNAVAILABLE", true)
				return
			}
			st, code := status(err)
			wire.WriteError(w, st, code, st == 500)
			return
		}
		wire.Write(w, DeleteStatus{Accepted: true})
	}
}

// HandlePeer: POST /v1/federation/accounts/delete, from another server of the fleet.
func (d *Deleter) HandlePeer(w http.ResponseWriter, r *http.Request) {
	if d.IsPeer == nil || !d.IsPeer(r) {
		wire.WriteError(w, 401, "PEER_UNAUTHORIZED", false)
		return
	}
	var p PeerDelete
	if err := wire.ReadLimit(r, &p, peerDeleteMax); err != nil {
		wire.WriteReadError(w, err)
		return
	}
	if err := d.ApplyPeer(p); err != nil {
		st, code := status(err)
		wire.WriteError(w, st, code, st == 500)
		return
	}
	wire.Write(w, DeleteStatus{Accepted: true})
}

// DeleteStatus answers both routes.
type DeleteStatus struct {
	Accepted bool `cbor:"accepted"`
}

// provenDevices lists the device keys that have shown they hold their private key by signing a link of the chain (and the
// device that signs the deletion). A key that is only listed in someone's chain proves nothing: anyone can write another
// person's public key into their own account, so such a key is never tombstoned or erased with the account.
func provenDevices(requestSigner []byte, chains ...*chain) [][]byte {
	seen := map[string]bool{}
	var out [][]byte
	add := func(id []byte) {
		if len(id) == 32 && !seen[string(id)] {
			seen[string(id)] = true
			out = append(out, id)
		}
	}
	add(requestSigner)
	for _, c := range chains {
		if c == nil {
			continue
		}
		recovery := c.links[0].State.recoveryID()
		for _, event := range c.journal {
			if !bytes.Equal(event.State.Signer, recovery) {
				add(event.State.Signer)
			}
		}
	}
	return out
}

// CommitDelete checks the request against the chain held here and, in the same step, saves the work (save) and refuses the
// account. It is refused if the newest link is not the one the request names, the chain is forked, or the signer is not
// active in it.
func (r *Registry) CommitDelete(req DeleteRequest, save func(chain, devices [][]byte) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.deleted.set[tombstoneOf(req.AccountID)] {
		return nil
	}
	key := hex.EncodeToString(req.AccountID)
	c, ok := r.chains[key]
	if !ok {
		return ErrSync // this server has not caught up with the account yet; the others take it, this one is told next
	}
	if c.frozen() {
		return ErrFork
	}
	head := c.head()
	if !bytes.Equal(head.Hash(), req.HeadHash) {
		return ErrSync
	}
	device, active := head.State.device(req.Device)
	if !active || !req.signatureOK(device.SigningKey) {
		return ErrNotAuthorized
	}
	chain := make([][]byte, len(c.links))
	for i, l := range c.links {
		chain[i] = l.Raw
	}
	devices := provenDevices(req.Device, c)
	if err := save(chain, devices); err != nil {
		return err
	}
	return r.refuseLocked(req.AccountID, devices)
}

// CommitPeerDelete is CommitDelete for a deletion another server has checked and sent with its chain. This server's own
// copy of the account, if it has one, must be the same history (one the start of the other) and not forked.
func (r *Registry) CommitPeerDelete(req DeleteRequest, pushed *chain, save func(devices [][]byte) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.deleted.set[tombstoneOf(req.AccountID)] {
		return nil
	}
	key := hex.EncodeToString(req.AccountID)
	if own, ok := r.chains[key]; ok {
		if own.frozen() {
			return ErrFork
		}
		for i := 0; i < len(own.links) && i < len(pushed.links); i++ {
			if !bytes.Equal(own.links[i].Raw, pushed.links[i].Raw) {
				return ErrFork
			}
		}
		if len(own.links) > len(pushed.links) {
			if _, still := own.head().State.device(req.Device); !still {
				return ErrNotAuthorized // this server saw the signer revoked after the link it signed against
			}
		}
	}
	devices := provenDevices(req.Device, r.chains[key], pushed) // the longer history of this server counts too
	if err := save(devices); err != nil {
		return err
	}
	return r.refuseLocked(req.AccountID, devices)
}

func (r *Registry) refuseLocked(account []byte, devices [][]byte) error {
	if err := r.deleted.add(account); err != nil {
		return err
	}
	for _, id := range devices {
		if err := r.deleted.addHash(deviceTombstoneOf(id)); err != nil {
			return err
		}
	}
	return nil
}

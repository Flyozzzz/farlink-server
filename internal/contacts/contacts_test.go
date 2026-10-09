package contacts

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func id(b byte) []byte  { return bytes.Repeat([]byte{b}, 32) }
func did(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

func soon() uint64 { return uint64(time.Now().Add(72 * time.Hour).UnixMilli()) }

func code(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func open(t *testing.T, dir string) (*Store, *time.Time) {
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.Now = func() time.Time { return now }
	return s, &now
}

func TestStateSurvivesARestartWithItsGeneration(t *testing.T) {
	dir := t.TempDir()
	s, _ := open(t, dir)
	if err := s.Admit(id(1), id(2), did(1), 100, soon()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(id(1), id(2), ActAccept, 1); err != nil {
		t.Fatal(err)
	}
	s2, _ := open(t, dir)
	rec, _ := s2.Apply(id(1), id(2), ActGet, 0)
	if rec.State != Accepted || rec.Generation != 2 {
		t.Fatalf("after restart %+v", rec)
	}
	if _, err := s2.Apply(id(1), id(2), ActRemove, 1); code(err) != "STALE_GENERATION" {
		t.Fatalf("stale after restart = %v", err)
	}
}

func TestACorruptRecordStopsTheServerInsteadOfBecomingAnOpenDoor(t *testing.T) {
	dir := t.TempDir()
	s, _ := open(t, dir)
	s.Admit(id(1), id(2), did(1), 100, soon())
	files, _ := filepath.Glob(filepath.Join(dir, "*", "*"))
	var rec string
	for _, f := range files {
		if filepath.Base(f) != "meta" {
			rec = f
		}
	}
	if rec == "" {
		t.Fatal(files)
	}
	os.WriteFile(rec, []byte("garbage"), 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("a block-list that cannot be read must stop startup, not vanish")
	}
}

func TestGenerationOnlyGrowsAndNoRecordMeansZero(t *testing.T) {
	s, _ := open(t, t.TempDir())
	if _, err := s.Apply(id(1), id(2), ActAccept, 5); code(err) != "STALE_GENERATION" {
		t.Fatalf("accept with a made-up generation = %v", err)
	}
	rec, err := s.Apply(id(1), id(2), ActAccept, 0) // the person adds a contact by code before any file came
	if err != nil || rec.Generation != 1 || rec.State != Accepted {
		t.Fatalf("%+v %v", rec, err)
	}
	rec, err = s.Apply(id(1), id(2), ActAccept, 1) // idempotent: already accepted keeps the generation
	if err != nil || rec.Generation != 1 {
		t.Fatalf("repeat accept %+v %v", rec, err)
	}
}

func TestDeclineNeedsAPendingBatch(t *testing.T) {
	s, _ := open(t, t.TempDir())
	s.Apply(id(1), id(2), ActAccept, 0)
	if _, err := s.Apply(id(1), id(2), ActDecline, 1); code(err) != "INVALID_STATE" {
		t.Fatalf("declining an accepted contact = %v", err)
	}
	if _, err := s.Apply(id(1), id(2), Action("explode"), 1); err == nil {
		t.Fatal("unknown action accepted")
	}
}

func TestAnUnansweredBatchExpiresAndAllowsANewOne(t *testing.T) {
	s, now := open(t, t.TempDir())
	s.Admit(id(1), id(2), did(1), 100, soon())
	if code(s.Admit(id(1), id(2), did(2), 100, soon())) != "CONTACT_PENDING" {
		t.Fatal("second batch must wait")
	}
	*now = now.Add(MaxPendingLife + time.Minute)
	if err := s.Admit(id(1), id(2), did(2), 100, soon()); err != nil {
		t.Fatalf("after the first batch expired: %v", err)
	}
}

func TestLimitDoesNotCountTheSenderBeingDecided(t *testing.T) {
	s, _ := open(t, t.TempDir())
	for i := range MaxContacts {
		sender := bytes.Repeat([]byte{byte(i), byte(i >> 8), 7}, 11)[:32]
		if i == 0 {
			if err := s.Admit(id(1), sender, did(1), 1, soon()); err != nil {
				t.Fatal(err)
			}
		} else if _, err := s.Apply(id(1), sender, ActAccept, 0); err != nil {
			t.Fatal(err)
		}
	}
	first := bytes.Repeat([]byte{0, 0, 7}, 11)[:32]
	acc, err := s.Apply(id(1), first, ActAccept, 1)
	if err != nil {
		t.Fatalf("accepting a pending contact at the limit: %v", err)
	}
	if _, err := s.Apply(id(1), id(9), ActAccept, 0); code(err) != "CONTACT_LIMIT" {
		t.Fatalf("adding a 501st = %v", err)
	}
	if _, err := s.Apply(id(1), first, ActRemove, acc.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(id(1), id(9), ActAccept, 0); err != nil {
		t.Fatalf("removing frees a place: %v", err)
	}
}

func TestForgetNeverTakesAGenerationBack(t *testing.T) {
	dir := t.TempDir()
	s, _ := open(t, dir)
	s.Admit(id(1), id(2), did(1), 10, soon())
	rec, _ := s.Apply(id(1), id(2), ActDecline, 1)
	if _, err := s.Apply(id(1), id(2), ActForget, rec.Generation); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Apply(id(1), id(2), ActGet, 0); got.State != None || got.Generation != 0 {
		t.Fatalf("after forget %+v", got)
	}
	s2, _ := open(t, dir) // the counter also survives a restart
	if err := s2.Admit(id(1), id(2), did(2), 10, soon()); err != nil {
		t.Fatal(err)
	}
	again, _ := s2.Apply(id(1), id(2), ActGet, 0)
	if again.Generation <= rec.Generation {
		t.Fatalf("generation %d came back after %d: a device holding the old one would win", again.Generation, rec.Generation)
	}
	if _, err := s2.Apply(id(1), id(2), ActDecline, rec.Generation); code(err) != "STALE_GENERATION" {
		t.Fatalf("decision on an old generation = %v", err)
	}
}

func TestForgetOnlyLiftsABlock(t *testing.T) {
	s, _ := open(t, t.TempDir())
	s.Admit(id(1), id(2), did(1), 10, soon())
	rec, _ := s.Apply(id(1), id(2), ActGet, 0)
	if _, err := s.Apply(id(1), id(2), ActForget, rec.Generation); code(err) != "INVALID_STATE" {
		t.Fatalf("forgetting a pending contact = %v", err)
	}
	acc, _ := s.Apply(id(1), id(2), ActAccept, rec.Generation)
	if _, err := s.Apply(id(1), id(2), ActForget, acc.Generation); code(err) != "INVALID_STATE" {
		t.Fatalf("forgetting an accepted contact = %v", err)
	}
	rm, _ := s.Apply(id(1), id(2), ActRemove, acc.Generation)
	if _, err := s.Apply(id(1), id(2), ActForget, rm.Generation); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit(id(1), id(2), did(3), 10, soon()); err != nil {
		t.Fatalf("a forgotten sender starts over: %v", err)
	}
}

func TestBlocksCannotBePushedOutByFillingTheList(t *testing.T) {
	if testing.Short() {
		t.Skip("writes MaxRecords durable records")
	}
	s, now := open(t, t.TempDir())
	victim := id(200)
	s.Admit(id(1), victim, did(1), 10, soon())
	rec, _ := s.Apply(id(1), victim, ActGet, 0)
	s.Apply(id(1), victim, ActRemove, rec.Generation)
	for i := 0; ; i++ {
		sender := bytes.Repeat([]byte{byte(i), byte(i >> 8), 9}, 11)[:32]
		if err := s.Admit(id(1), sender, did(1), 1, soon()); err != nil {
			if code(err) != "CONTACT_LIMIT" {
				t.Fatalf("filling the list stopped with %v", err)
			}
			break
		}
		if r, _ := s.Apply(id(1), sender, ActGet, 0); r.State == Pending {
			s.Apply(id(1), sender, ActDecline, r.Generation)
		}
		if i > MaxRecords+10 {
			t.Fatal("the list never filled")
		}
	}
	if err := s.Admit(id(1), victim, did(9), 10, soon()); code(err) != "CONTACT_REMOVED" {
		t.Fatalf("the removed sender must stay blocked, got %v", err)
	}
	*now = now.Add(RetryAfter + time.Minute) // the declines are over and make room; the removal is not
	if err := s.Admit(id(1), id(77), did(1), 1, soon()); err != nil {
		t.Fatalf("old declines make room: %v", err)
	}
	if err := s.Admit(id(1), victim, did(10), 10, soon()); code(err) != "CONTACT_REMOVED" {
		t.Fatalf("removal must outlive the pressure: %v", err)
	}
}

func TestSameDeliveryWithAnotherSizeIsAConflict(t *testing.T) {
	s, _ := open(t, t.TempDir())
	s.Admit(id(1), id(2), did(1), 10, soon())
	if err := s.Admit(id(1), id(2), did(1), 11, soon()); code(err) != "DELIVERY_CONFLICT" {
		t.Fatalf("resized retry = %v", err)
	}
	if err := s.Admit(id(1), id(2), did(1), 10, soon()); err != nil {
		t.Fatalf("plain retry = %v", err)
	}
	if err := s.Admit(id(1), id(3), did(1), MaxFirstBytes+1, soon()); code(err) != "CONTACT_TOO_LARGE" {
		t.Fatalf("oversize first batch = %v", err)
	}
}

func TestPendingNeverOutlivesItsDelivery(t *testing.T) {
	s, now := open(t, t.TempDir())
	exp := uint64(now.Add(time.Hour).UnixMilli())
	s.Admit(id(1), id(2), did(1), 10, exp)
	rec, _ := s.Apply(id(1), id(2), ActGet, 0)
	if rec.PendingExpires != exp {
		t.Fatalf("pending expires %d, delivery %d", rec.PendingExpires, exp)
	}
	*now = now.Add(2 * time.Hour)
	if s.Count(id(1)) != 0 {
		t.Fatal("an expired pending batch must not take a place")
	}
}

func TestListPagesThroughManyContacts(t *testing.T) {
	s, _ := open(t, t.TempDir())
	for i := range 450 {
		if _, err := s.Apply(id(1), bytes.Repeat([]byte{byte(i >> 8), byte(i), 5}, 11)[:32], ActAccept, 0); err != nil {
			t.Fatal(err)
		}
	}
	var seen, cursor = 0, []byte(nil)
	var last []byte
	pages := 0
	for {
		page, next, err := s.List(id(1), cursor, 200)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range page {
			if last != nil && bytes.Compare(last, r.Sender) >= 0 {
				t.Fatal("pages must be ordered and never repeat")
			}
			last = r.Sender
		}
		seen += len(page)
		pages++
		if next == nil {
			break
		}
		cursor = next
	}
	if seen != 450 || pages != 3 {
		t.Fatalf("saw %d in %d pages", seen, pages)
	}
}

func TestPendingRequestsAreBoundedIndependentlyOfContacts(t *testing.T) {
	s, now := open(t, t.TempDir())
	for i := range MaxPending {
		if err := s.Admit(id(1), id(byte(i+2)), did(1), 1, soon()); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Admit(id(1), id(99), did(1), 1, soon()); code(err) != "CONTACT_REQUEST_LIMIT" {
		t.Fatalf("51st pending request: %v", err)
	}
	if err := s.Admit(id(1), id(2), did(1), 1, soon()); err != nil {
		t.Fatalf("retry at pending limit: %v", err)
	}
	record, _ := s.Apply(id(1), id(2), ActGet, 0)
	if _, err := s.Apply(id(1), id(2), ActAccept, record.Generation); err != nil {
		t.Fatal(err)
	}
	if err := s.Admit(id(1), id(99), did(1), 1, soon()); err != nil {
		t.Fatalf("accept should release pending slot: %v", err)
	}
	*now = now.Add(MaxPendingLife + time.Minute)
	if err := s.Admit(id(1), id(100), did(2), 1, uint64(now.Add(time.Hour).UnixMilli())); err != nil {
		t.Fatalf("expired pending requests should release slots: %v", err)
	}
}

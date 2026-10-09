package billing

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// directRemote is the authority reached without a network: its own ledger, or an outage.
type directRemote struct {
	authority *Ledger
	down      bool
	// loseReplies: the authority applies the request and the answer never arrives.
	loseReplies int
	asked       int
}

func (d *directRemote) Grant(_ context.Context, req GrantRequest) (GrantResponse, error) {
	if d.down {
		return GrantResponse{}, errors.New("unreachable")
	}
	d.asked++
	resp, err := d.authority.GrantOnce(req)
	if err != nil {
		return GrantResponse{}, err
	}
	if d.loseReplies > 0 {
		d.loseReplies--
		return GrantResponse{}, errors.New("reply lost")
	}
	return resp, nil
}

func (d *directRemote) Used(_ context.Context, key string) (int64, int, error) {
	if d.down {
		return 0, 0, errors.New("unreachable")
	}
	used, month := d.authority.UsedOf(key)
	return used, month, nil
}

var account = accountBucketPrefix + b64.EncodeToString(bytes.Repeat([]byte{7}, 32))

func buckets(limit int64) func([]byte) []Bucket {
	return func([]byte) []Bucket { return []Bucket{{Key: account, Limit: limit}} }
}

// three servers: one is the authority, two ask it for blocks.
func threeServers(limit, block int64) (authority, one, two *Ledger, remote *directRemote) {
	authority = NewLedger(buckets(limit))
	remote = &directRemote{authority: authority}
	one, two = NewLedger(buckets(limit)), NewLedger(buckets(limit))
	one.Remote, one.Block = remote, block
	two.Remote, two.Block = remote, block
	return
}

func used(l *Ledger) int64 { u, _ := l.UsedOf(account); return u }

func TestServersShareOneAllowanceFromTheAuthority(t *testing.T) {
	authority, one, two, _ := threeServers(100, 30)
	dev := []byte("d")
	if !one.Charge(dev, 40) || !two.Charge(dev, 40) {
		t.Fatal("charges inside the allowance refused")
	}
	// 80 of 100 are spent: 20 are left in the whole fleet, not 20 per server. The file that is running finishes
	// (up to twice the limit), after that nothing new starts anywhere.
	if !one.Charge(dev, 40) {
		t.Fatal("the running file was cut")
	}
	if one.Admit(dev) || two.Admit(dev) || authority.Admit(dev) {
		t.Fatal("a server still admits new work on a used-up account")
	}
	if two.Charge(dev, 200) {
		t.Fatal("charge past the overdraft accepted")
	}
	if got := used(authority); got > 200 {
		t.Fatalf("the authority counts %d, more than twice the limit", got)
	}
}

func TestALostReplyIsAskedAgainWithTheSameIDAndNotGrantedTwice(t *testing.T) {
	authority, one, _, remote := threeServers(100, 30)
	remote.loseReplies = 1
	if !one.Charge([]byte("d"), 5) {
		t.Fatal("the charge failed after one lost reply")
	}
	if got := used(authority); got != 30 {
		t.Fatalf("a lost reply was granted twice: the authority counts %d", got)
	}
	// The block was granted once and is spent from: the next 20 bytes need no second request.
	asked := remote.asked
	if !one.Charge([]byte("d"), 20) || remote.asked != asked {
		t.Fatalf("a held block was not spent (asked %d times)", remote.asked-asked)
	}
}

func TestWithoutTheAuthorityAServerSpendsWhatItHoldsAndThenRefuses(t *testing.T) {
	_, one, _, remote := threeServers(100, 30)
	dev := []byte("d")
	if !one.Charge(dev, 10) {
		t.Fatal("charge")
	}
	remote.down = true
	// 20 are still held: they can be spent, a new block cannot be had, and nothing new is admitted without them.
	if !one.Admit(dev) || !one.Charge(dev, 20) {
		t.Fatal("what was already granted was not spendable")
	}
	if one.Admit(dev) || one.Charge(dev, 1) {
		t.Fatal("a server invented an allowance while the authority was out of reach")
	}
	if got := one.Balance(dev); got.Exhausted || !got.Unavailable {
		t.Fatalf("balance with no authority = %+v", got)
	}
}

func TestANewMonthStartsWithoutStaleBlocks(t *testing.T) {
	authority, one, _, _ := threeServers(100, 30)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	one.Now = func() time.Time { return now }
	authority.Now = one.Now
	if !one.Charge([]byte("d"), 10) {
		t.Fatal("charge")
	}
	now = time.Date(2026, 11, 1, 0, 1, 0, 0, time.UTC)
	if used(authority) != 0 {
		t.Fatal("the authority did not roll over")
	}
	if !one.Charge([]byte("d"), 25) || used(authority) != 30 {
		t.Fatalf("the new month counted last month's block: used %d", used(authority))
	}
}

func TestAGrantForAnotherMonthGrantsNothing(t *testing.T) {
	authority, _, _, _ := threeServers(100, 30)
	_, month := authority.UsedOf(account)
	resp, err := authority.GrantOnce(GrantRequest{ID: "old", Month: month - 1, Key: account, Limit: 100, Want: 10})
	if err != nil || resp.Granted != 0 || resp.Month != month {
		t.Fatalf("grant for last month = %+v, %v", resp, err)
	}
	if got := used(authority); got != 0 {
		t.Fatalf("a stale request changed the counter: %d", got)
	}
}

func TestAGrantAnswerSurvivesARestartAndAFailedSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.cbor")
	authority, err := OpenLedger(buckets(100), path)
	if err != nil {
		t.Fatal(err)
	}
	_, month := authority.UsedOf(account)
	req := GrantRequest{ID: "g1", Month: month, Key: account, Limit: 100, Want: 30}
	if resp, err := authority.GrantOnce(req); err != nil || resp.Granted != 30 {
		t.Fatalf("grant = %+v, %v", resp, err)
	}
	// After a restart the same request is answered the same, and nothing more is taken.
	again, err := OpenLedger(buckets(100), path)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := again.GrantOnce(req); err != nil || resp.Granted != 30 || used(again) != 30 {
		t.Fatalf("after restart: %+v, %v, used %d", resp, err, used(again))
	}
	// A save that fails does not undo the grant: asking again with the same ID returns it, once.
	broken, _ := OpenLedger(buckets(100), filepath.Join(t.TempDir(), "gone", "ledger.cbor"))
	bad := GrantRequest{ID: "g2", Month: month, Key: account, Limit: 100, Want: 30}
	if _, err := broken.GrantOnce(bad); err == nil {
		t.Fatal("a save into a missing directory succeeded")
	}
	broken.Path = filepath.Join(t.TempDir(), "ledger.cbor")
	if resp, err := broken.GrantOnce(bad); err != nil || resp.Granted != 30 || used(broken) != 30 {
		t.Fatalf("retry after the failed save: %+v, %v, used %d", resp, err, used(broken))
	}
}

func TestALogicalSendIsChargedOnceWhoeverAsksAndHoweverOften(t *testing.T) {
	authority, one, two, remote := threeServers(100, 30)
	dev := []byte("d")
	if !one.ChargeOnce(dev, "send-1", 40) {
		t.Fatal("first charge refused")
	}
	// A retry (the answer was lost), and the same send billed from another server, change nothing.
	if !one.ChargeOnce(dev, "send-1", 40) || !two.ChargeOnce(dev, "send-1", 40) {
		t.Fatal("a repeat was refused")
	}
	if got := used(authority); got != 40 {
		t.Fatalf("the send was charged %d times", got/40)
	}
	// Past the limit the running file may finish (twice the limit), nothing beyond.
	if !two.ChargeOnce(dev, "send-2", 50) || used(authority) != 90 {
		t.Fatalf("second send: %d", used(authority))
	}
	if !one.ChargeOnce(dev, "send-3", 100) || used(authority) != 190 {
		t.Fatalf("third send: %d", used(authority))
	}
	if two.ChargeOnce(dev, "send-4", 20) {
		t.Fatal("a send past twice the limit was accepted")
	}
	// A lost reply is repeated with the same ID: one charge, not two.
	remote.loseReplies = 1
	if !one.ChargeOnce(dev, "send-1", 40) { // already charged: an answer from the record
		t.Fatal("repeat after a lost reply")
	}
	// The authority being out of reach refuses; it is not guessed.
	remote.down = true
	if one.ChargeOnce(dev, "send-5", 1) {
		t.Fatal("charged without the authority")
	}
	// An empty id is the ordinary, non-idempotent charge.
	remote.down = false
	if !authority.ChargeOnce(dev, "", 1) {
		t.Fatal("empty id")
	}
}

func TestARepeatedGrantIsNotAnsweredBeforeItIsOnDisk(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "ledger.cbor")
	broken, err := OpenLedger(buckets(100), filepath.Join(dir, "gone", "ledger.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	_, month := broken.UsedOf(account)
	req := GrantRequest{ID: "g3", Month: month, Key: account, Limit: 100, Want: 30}
	for i := 0; i < 3; i++ { // every repeat while the disk is broken is refused, none is answered from memory
		if _, err := broken.GrantOnce(req); err == nil {
			t.Fatalf("attempt %d answered a grant that is not on disk", i)
		}
	}
	broken.Path = good
	if resp, err := broken.GrantOnce(req); err != nil || resp.Granted != 30 {
		t.Fatalf("after repair: %+v, %v", resp, err)
	}
	again, err := OpenLedger(buckets(100), good)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := again.GrantOnce(req); err != nil || resp.Granted != 30 || used(again) != 30 {
		t.Fatalf("after reopen: %+v, %v, used %d", resp, err, used(again))
	}
}

func TestASendWhoseGrantOutcomeIsUnknownIsNotChargedTwice(t *testing.T) {
	dir := t.TempDir()
	ledger, err := OpenLedger(buckets(100), filepath.Join(dir, "gone", "ledger.cbor")) // saves fail
	if err != nil {
		t.Fatal(err)
	}
	dev := []byte("d")
	if ledger.ChargeOnce(dev, "send-9", 30) {
		t.Fatal("charged although the grant could not be saved")
	}
	ledger.Path = filepath.Join(dir, "ledger.cbor") // the disk comes back
	if !ledger.ChargeOnce(dev, "send-9", 30) {
		t.Fatal("the same send was not charged after the disk came back")
	}
	if got := used(ledger); got != 30 {
		t.Fatalf("one send of 30 was charged %d", got)
	}
}

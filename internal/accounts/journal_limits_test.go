package accounts

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestRejectedBranchJournalBudgetsPreserveRecovery(t *testing.T) {
	first, rk := newDev(), newDev()
	g, raw := genesis(t, first, rk)
	a, b := next(g, raw, first), next(g, raw, first)
	a.Nickname, b.Nickname = "rejected", "chosen"
	ar, br := sign(t, a, first), sign(t, b, first)
	dir := t.TempDir()
	reg, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range [][]byte{raw, ar, br} {
		if _, _, err := reg.Submit(event); err != nil && !errors.Is(err, ErrFork) {
			t.Fatal(err)
		}
	}
	resolution := next(b, br, rk)
	rr := sign(t, resolution, rk)
	if _, _, err := reg.Submit(rr); err != nil {
		t.Fatal(err)
	}
	var child State
	var childRaw []byte
	// 16 events at a height: one selected slot and at most 15 alternatives.
	for i := range 4200 {
		s := next(a, ar, first)
		s.Nickname = fmt.Sprintf("sibling-%d", i)
		sr := sign(t, s, first)
		_, _, err := reg.Submit(sr)
		if i < 15 {
			if err != nil {
				t.Fatal(err)
			}
			child, childRaw = s, sr
		} else if !errors.Is(err, ErrTooLong) {
			t.Fatalf("sibling %d admitted: %v", i, err)
		}
	}
	// Across heights the off-branch budget is 256, including the rejected A1.
	for i := 16; i < 256; i++ {
		child = next(child, childRaw, first)
		childRaw = sign(t, child, first)
		if _, _, err := reg.Submit(childRaw); err != nil {
			t.Fatal(err)
		}
	}
	overflow := sign(t, next(child, childRaw, first), first)
	if _, _, err := reg.Submit(overflow); !errors.Is(err, ErrTooLong) {
		t.Fatalf("journal overflow: %v", err)
	}
	// Reserved selected slots remain usable after the attack.
	nextState := next(resolution, rr, rk)
	nextRaw := sign(t, nextState, rk)
	if _, _, err := reg.Submit(nextRaw); err != nil {
		t.Fatal(err)
	}
	reg, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, replayed := range [][]byte{ar, childRaw} {
		if _, _, err := reg.Submit(replayed); err != nil {
			t.Fatal(err)
		}
	}
	h, ok := reg.Head(g.AccountID)
	if !ok || h.Number != nextState.Number {
		t.Fatal("replay froze recovered account")
	}
	var journal [][]byte
	for {
		page, _ := reg.JournalPage(g.AccountID, uint64(len(journal)))
		if len(page) == 0 {
			break
		}
		journal = append(journal, page...)
	}
	if len(journal) != 260 {
		t.Fatalf("unbounded journal: %d", len(journal))
	}
	replayed, err := replay(journal)
	if err != nil || replayed.frozen() || !bytes.Equal(replayed.head().Raw, nextRaw) {
		t.Fatalf("genesis replay: %v", err)
	}
}

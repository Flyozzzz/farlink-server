package accounts

import "bytes"

// chain retains verified events in arrival order. Replaying only the winning
// branch loses rejected forks and lets their replay freeze a recovered account.
type chain struct {
	links     []Link
	conflicts []Link
	rejected  map[string]Link
	journal   []Link
	heights   map[uint64]int // all admitted events at each height
	dirty     bool
	indexed   int // registry ownership events already indexed; not part of verified state
}

func newChain(first Link) *chain {
	return &chain{links: []Link{first}, journal: []Link{first}, rejected: map[string]Link{}, heights: map[uint64]int{0: 1}}
}

func (c *chain) head() Link   { return c.links[len(c.links)-1] }
func (c *chain) frozen() bool { return len(c.conflicts) != 0 }

func (c *chain) clone() *chain {
	next := &chain{
		links: append([]Link(nil), c.links...), conflicts: append([]Link(nil), c.conflicts...),
		journal: append([]Link(nil), c.journal...), rejected: make(map[string]Link, len(c.rejected)),
		heights: make(map[uint64]int, len(c.heights)),
	}
	for hash, link := range c.rejected {
		next.rejected[hash] = link
	}
	for number, count := range c.heights {
		next.heights[number] = count
	}
	return next
}

func (c *chain) merge(other *chain) error {
	if !bytes.Equal(c.links[0].Raw, other.links[0].Raw) {
		return ErrFork
	}
	for _, event := range other.journal[1:] {
		if err := c.apply(event); err != nil && !c.frozen() {
			return err
		}
	}
	return nil
}

func (c *chain) admitAlternative(number uint64) error {
	selected := 0
	if number < uint64(len(c.links)) {
		selected = 1
	}
	if len(c.journal)-len(c.links) >= MaxForkEvents || c.heights[number]-selected >= MaxSiblings-1 {
		return ErrTooLong
	}
	return nil
}

func (c *chain) record(l Link) {
	c.journal = append(c.journal, l)
	c.heights[l.State.Number]++
}

func (c *chain) apply(l Link) error {
	n, h := l.State, c.head()
	if !bytes.Equal(n.AccountID, h.State.AccountID) {
		return ErrWrongAccount
	}
	hash := string(l.Hash())
	if _, rejected := c.rejected[hash]; rejected {
		return nil
	}
	if parent, rejected := c.rejected[string(n.PrevHash)]; rejected {
		if n.Number >= MaxLinks {
			return ErrTooLong
		}
		if err := Check(l, parent.State, parent.Hash()); err != nil {
			return err
		}
		if err := c.admitAlternative(n.Number); err != nil {
			return err
		}
		c.rejected[hash] = l
		c.record(l)
		return nil
	}
	if n.Number <= h.State.Number {
		if bytes.Equal(c.links[n.Number].Raw, l.Raw) {
			return nil
		}
		if n.Number == 0 {
			return ErrBadSignature
		}
		prev := c.links[n.Number-1]
		if Check(l, prev.State, prev.Hash()) != nil {
			return ErrBadSignature
		}
		for _, conflict := range c.conflicts {
			if bytes.Equal(conflict.Raw, l.Raw) {
				return ErrFork
			}
		}
		if err := c.admitAlternative(n.Number); err != nil {
			return err
		}
		c.conflicts = append(c.conflicts, l)
		c.record(l)
		return ErrFork
	}
	if len(c.links) >= MaxLinks {
		return ErrTooLong
	}
	if c.frozen() {
		if !bytes.Equal(n.Signer, h.State.recoveryID()) {
			return ErrFork
		}
		chosen := h
		if !bytes.Equal(n.PrevHash, h.Hash()) {
			found := false
			for _, alternative := range c.conflicts {
				if alternative.State.Number == h.State.Number && bytes.Equal(alternative.Hash(), n.PrevHash) {
					chosen, found = alternative, true
					break
				}
			}
			if !found {
				return ErrFork
			}
		}
		if err := Check(l, chosen.State, chosen.Hash()); err != nil {
			return err
		}
		if !bytes.Equal(chosen.Hash(), h.Hash()) {
			c.rejected[string(h.Hash())] = h
			c.links[len(c.links)-1] = chosen
		}
		for _, conflict := range c.conflicts {
			if !bytes.Equal(conflict.Hash(), chosen.Hash()) {
				c.rejected[string(conflict.Hash())] = conflict
			}
		}
		c.conflicts = nil
	} else if err := Check(l, h.State, h.Hash()); err != nil {
		return err
	}
	c.links = append(c.links, l)
	c.record(l)
	return nil
}

func replay(raws [][]byte) (*chain, error) {
	if len(raws) == 0 {
		return nil, ErrMalformed
	}
	first, err := ParseLink(raws[0])
	if err != nil {
		return nil, err
	}
	if err := CheckGenesis(first); err != nil {
		return nil, err
	}
	c := newChain(first)
	for _, raw := range raws[1:] {
		l, err := ParseLink(raw)
		if err != nil {
			return nil, err
		}
		before := len(c.journal)
		if err := c.apply(l); err != nil && (err != ErrFork || len(c.journal) == before) {
			return nil, err
		}
	}
	return c, nil
}

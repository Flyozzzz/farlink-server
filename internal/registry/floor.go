package registry

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/Flyozzzz/farlink-server/internal/durable"
)

// Floor remembers the highest catalog sequence this process ever accepted, so a restart cannot be talked back
// into an older signed catalog that still lists a server the operator removed.
type Floor struct{ Path string }

// Read returns the stored sequence; a missing file is 0, an unreadable one is an error rather than a fresh start.
func (f Floor) Read() (uint64, error) {
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

var raiseMu sync.Mutex

// Raise stores seq if it is above the current floor. Read, compare and write happen under one lock, so a lower
// sequence can never overwrite a higher one that was accepted meanwhile.
func (f Floor) Raise(seq uint64) error {
	raiseMu.Lock()
	defer raiseMu.Unlock()
	cur, err := f.Read()
	if err != nil {
		return err
	}
	if seq <= cur {
		return nil
	}
	return durable.WriteFile(f.Path, []byte(strconv.FormatUint(seq, 10)))
}

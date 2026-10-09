package federation

import (
	"time"

	"github.com/Flyozzzz/farlink-server/internal/registry"
)

// Watch keeps a Directory in step with the signed catalog. A catalog that cannot be refreshed stays in force
// until it has been expired for Grace; after that the directory is emptied, because trusting a list nobody has
// vouched for in weeks is how a removed server keeps its place. Local delivery does not depend on it.
type Watch struct {
	Dir   *Directory
	Load  func() (registry.Registry, error)
	Grace time.Duration
	Now   func() time.Time

	expires time.Time
}

func (w *Watch) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Tick loads the catalog and applies it; the error says why the previous list was kept or dropped.
func (w *Watch) Tick() error {
	r, err := w.Load()
	if err == nil {
		err = w.Dir.Update(r)
	}
	if err == nil {
		w.expires = time.UnixMilli(int64(r.ExpiresAt))
		return nil
	}
	if !w.expires.IsZero() && w.now().After(w.expires.Add(w.Grace)) {
		w.Dir.Update(registry.Registry{})
		w.expires = time.Time{}
	}
	return err
}

// Start records the catalog the directory was built from.
func (w *Watch) Start(r registry.Registry) { w.expires = time.UnixMilli(int64(r.ExpiresAt)) }

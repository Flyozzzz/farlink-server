// Package durable writes small files so that a crash leaves either the old content or the new, and so that the
// new name itself survives: the directory is synced after the rename.
package durable

import (
	"errors"
	"os"
	"path/filepath"
)

// WriteFile replaces path with data atomically and durably. The directory must exist.
// The file is private (0600).
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return SyncDir(dir)
}

// SyncDir makes renames and removals inside dir durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

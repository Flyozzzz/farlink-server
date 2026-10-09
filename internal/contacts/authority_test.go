package contacts

import (
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
)

func migrationRoutes() []accounts.ContactRoute {
	return []accounts.ContactRoute{{Server: "a", Head: accounts.HeadRef{Number: 0, Hash: id(10)}},
		{Server: "b", Head: accounts.HeadRef{Number: 2, Hash: id(11)}},
		{Server: "a", Head: accounts.HeadRef{Number: 4, Hash: id(12)}}}
}

func TestAuthorityMigrationFenceSnapshotRestartAndReturn(t *testing.T) {
	routes := migrationRoutes()
	adir, bdir := t.TempDir(), t.TempDir()
	a, err := Open(adir)
	if err != nil {
		t.Fatal(err)
	}
	if ready, err := a.ready(id(1), routes[:1]); err != nil || !ready {
		t.Fatal(err)
	}
	blocked, err := a.Apply(id(1), id(2), ActRemove, 0)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := a.Apply(id(1), id(3), ActAccept, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Admit(id(1), id(4), did(4), 100, soon()); err != nil {
		t.Fatal(err)
	}
	exported, err := a.export(id(1), routes[0], routes[1])
	if err != nil {
		t.Fatal(err)
	}
	a, err = Open(adir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(id(1), id(2), ActForget, blocked.Generation, routes[0].Head); !errors.Is(err, ErrMigration) {
		t.Fatal("unfenced mutation", err)
	}
	if _, _, err := a.List(id(1), nil, 20); !errors.Is(err, ErrMigration) {
		t.Fatal("unfenced read", err)
	}
	b, err := Open(bdir)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.importSnapshot(exported, routes[:2]); err != nil {
		t.Fatal(err)
	}
	b, err = Open(bdir)
	if err != nil {
		t.Fatal(err)
	}
	if ready, err := b.ready(id(1), routes[:2]); err != nil || !ready {
		t.Fatal(err)
	}
	if err := b.Admit(id(1), id(2), did(9), 1, soon(), routes[1].Head); err == nil {
		t.Fatal("lost block")
	}
	if err := b.AdmitControl(id(1), id(3), routes[1].Head); err != nil {
		t.Fatal("lost accepted relation", err)
	}
	if err := b.Admit(id(1), id(4), did(4), 100, soon(), routes[1].Head); err != nil {
		t.Fatal("lost pending idempotency", err)
	}
	changed, err := b.Apply(id(1), id(3), ActRemove, accepted.Generation, routes[1].Head)
	if err != nil || changed.Generation <= exported.Clock {
		t.Fatal("lost generation floor", err)
	}
	if err := b.importSnapshot(exported, routes[:2]); err != nil {
		t.Fatal(err)
	}
	got, err := b.Apply(id(1), id(3), ActGet, 0, routes[1].Head)
	if err != nil || got.State != Removed || got.Generation != changed.Generation {
		t.Fatal("snapshot replay overwrote decision", err)
	}
	back, err := b.export(id(1), routes[1], routes[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := a.importSnapshot(back, routes); err != nil {
		t.Fatal(err)
	}
	a, err = Open(adir)
	if err != nil {
		t.Fatal(err)
	}
	if ready, err := a.ready(id(1), routes); err != nil || !ready {
		t.Fatal(err)
	}
	if _, err := a.Apply(id(1), id(3), ActAccept, changed.Generation, routes[0].Head); !errors.Is(err, ErrMigration) {
		t.Fatal("old in-flight authorization crossed round trip", err)
	}
	if err := a.AdmitControl(id(1), id(3), routes[2].Head); err == nil {
		t.Fatal("return lost latest removal")
	}
	// RK selecting a branch without the executed transfer cannot discard decisions.
	if ready, err := a.ready(id(1), routes[:1]); ready || !errors.Is(err, ErrMigration) {
		t.Fatal("RK route rollback reopened stale state", err)
	}
}

func TestAuthorityMigrationFailedFenceRemainsClosedAndRetryPersists(t *testing.T) {
	routes := migrationRoutes()
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ready(id(1), routes[:1]); err != nil {
		t.Fatal(err)
	}
	path := store.path(id(1), "state")
	saved := path + ".saved"
	if err := os.Rename(path, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.export(id(1), routes[0], routes[1]); err == nil {
		t.Fatal("fence write unexpectedly succeeded")
	}
	if err := store.Admit(id(1), id(2), did(1), 1, soon()); !errors.Is(err, ErrMigration) {
		t.Fatal("failed fence authorized", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.export(id(1), routes[0], routes[1]); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(filepath.Clean(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.AdmitControl(id(1), id(2)); !errors.Is(err, ErrMigration) {
		t.Fatal("retry lost durable fence", err)
	}
}

func TestAuthorityMigrationGenerationOverflowCannotReuseCAS(t *testing.T) {
	routes := migrationRoutes()
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := AuthoritySnapshot{Recipient: id(1), From: "a", To: "b", Transition: routes[1].Head, Clock: ^uint64(0), Records: []Record{}}
	if err := store.importSnapshot(snapshot, routes[:2]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(id(1), id(2), ActAccept, 0, routes[1].Head); !errors.Is(err, ErrLimit) {
		t.Fatal("wrapped generation", err)
	}
}

func TestAuthorityFirstWriteCrashBeforeRename(t *testing.T) {
	if dir := os.Getenv("FARLINK_CRASH_FIRST_AUTHORITY_WRITE"); dir != "" {
		// The durable writer's pre-rename sequence, with no deferred cleanup.
		tmp, err := os.CreateTemp(dir, ".tmp-")
		if err != nil {
			panic(err)
		}
		if _, err := tmp.Write([]byte("incomplete uncommitted CBOR")); err != nil {
			panic(err)
		}
		if err := tmp.Sync(); err != nil {
			panic(err)
		}
		os.Exit(77)
	}
	root := t.TempDir()
	dir := filepath.Join(root, hex.EncodeToString(id(1)))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuthorityFirstWriteCrashBeforeRename$")
	cmd.Env = append(os.Environ(), "FARLINK_CRASH_FIRST_AUTHORITY_WRITE="+dir)
	var exit *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() != 77 {
		t.Fatalf("crash helper: %v", err)
	}
	store, err := Open(root)
	if err != nil {
		t.Fatalf("restart after initial write crash: %v", err)
	}
	if ready, err := store.ready(id(1), migrationRoutes()[:1]); err != nil || !ready {
		t.Fatalf("retry: %v", err)
	}
	removed, err := store.Apply(id(1), id(2), ActRemove, 0)
	if err != nil {
		t.Fatal(err)
	}
	store, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Apply(id(1), id(2), ActGet, 0)
	if err != nil || record.State != Removed || record.Generation != removed.Generation {
		t.Fatal("lost committed state", err)
	}
}

func TestAuthorityTempDoesNotHideCommittedCorruption(t *testing.T) {
	for _, existing := range []string{"state", "unexpected", ".tmp-directory", ".tmp-symlink"} {
		t.Run(existing, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, hex.EncodeToString(id(1)))
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ".tmp-orphan"), []byte("uncommitted"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, existing)
			var err error
			switch existing {
			case ".tmp-directory":
				err = os.Mkdir(path, 0o700)
			case ".tmp-symlink":
				err = os.Symlink("missing", path)
			default:
				err = os.WriteFile(path, []byte("corrupt"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Open(root); err == nil {
				t.Fatal("corrupt committed/unknown state treated as empty")
			}
		})
	}
}

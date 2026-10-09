package content

// snapshot.go provides the on-disk snapshot boundary shared by every reader
// and writer of an OCI layout: serve population, the layout itself,
// inventory/metadata writes, concurrent updates, deletion (GC/Flush),
// validation, and crash recovery.
//
// A snapshot is one committed index.json generation together with the
// immutable blob files it references. index.json's atomic temp-file rename is
// the single publication point; blob files are content-addressed and never
// modified in place. Two advisory locks under <root>/.hauler/ coordinate
// processes (flock works between separate open file descriptions, so it
// orders goroutines in this process just as well as other hauler processes):
//
//   - snapshot.lock: shared by Views (logical reads) and by in-flight Tx
//     staging, EXCLUSIVE for blob deletion (GC/Flush) and the recovery sweep.
//     An exclusive holder therefore proves no reader can still open a blob
//     and no writer is still staging one: old requests finish before unlinks,
//     new requests see only the post-delete snapshot.
//   - commit.lock: exclusive for the short index.json
//     reload-merge-validate-save critical section, so concurrent processes
//     can't lose each other's index entries. It never blocks readers.
//
// Lock ordering is fixed to avoid upgrade deadlocks: a Tx holds snapshot.lock
// shared for the whole (possibly long) staging phase, then takes commit.lock
// for its short commit. GC/Flush takes snapshot.lock exclusive alone -- while
// it is held no Tx can be active, so it performs its own index commit without
// commit.lock.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"

	"hauler.dev/go/hauler/v2/pkg/consts"
)

var (
	// ErrSnapshotLockBusy is returned when an exclusive boundary or a view
	// lease cannot be acquired before its timeout. Commands should surface it
	// verbatim so the caller can retry rather than reporting a corrupted store.
	ErrSnapshotLockBusy = errors.New("content: snapshot lock busy")

	// ErrSnapshotValidation is returned when a transaction's commit would
	// publish descriptors whose referenced blobs are missing or short. The
	// commit is rejected and index.json is left untouched.
	ErrSnapshotValidation = errors.New("content: snapshot validation failed")
)

const (
	snapshotLockRetryInterval = 50 * time.Millisecond
	viewLockTimeout           = 30 * time.Second
	commitLockTimeout         = 30 * time.Second
	exclusiveLockTimeout      = 60 * time.Second
	sweepLockTimeout          = 2 * time.Second
)

// leaseRelease undoes one lock acquisition. It is safe for the zero value
// (a degraded lock that could not actually be taken).
type leaseRelease func()

func noopLease() {}

func lockDirFor(root string) string {
	return filepath.Join(root, consts.SnapshotLockDir)
}

func snapshotLockPathFor(root string) string {
	return filepath.Join(lockDirFor(root), consts.SnapshotLockFile)
}

func commitLockPathFor(root string) string {
	return filepath.Join(lockDirFor(root), consts.SnapshotCommitLockFile)
}

// ensureLockDir creates the lock directory. It lives inside the store root so
// a lock always protects exactly one layout.
func ensureLockDir(root string) error {
	return os.MkdirAll(lockDirFor(root), 0o700)
}

// lockKind selects shared vs exclusive flock acquisition.
type lockKind int

const (
	lockShared lockKind = iota
	lockExclusive
)

// acquireFlock opens a fresh flock handle and takes the requested lock with a
// bounded wait. A fresh handle per lease is deliberate: flock associates the
// lock with the open file description, so shared leases held by concurrent
// views/txs must not share one handle (one Unlock would release everyone).
//
// On timeout the wrapped sentinel is ErrSnapshotLockBusy. On an operational
// error creating the lock file the returned lease is a no-op and degraded is
// true: the in-process OCI mutex still keeps a single process correct, and
// existing hauler file locks degrade best-effort rather than turning an
// uncooperative filesystem into a hard failure.
func acquireFlock(path string, kind lockKind, timeout time.Duration) (release leaseRelease, degraded bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fl := flock.New(path)
	var locked bool
	switch kind {
	case lockShared:
		locked, err = fl.TryRLockContext(ctx, snapshotLockRetryInterval)
	default:
		locked, err = fl.TryLockContext(ctx, snapshotLockRetryInterval)
	}
	if err != nil {
		_ = fl.Close()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return noopLease, false, fmt.Errorf("%w: timed out waiting for %s", ErrSnapshotLockBusy, filepath.Base(path))
		}
		// Filesystem that does not support flock: degrade.
		return noopLease, true, err
	}
	if !locked {
		_ = fl.Close()
		return noopLease, false, fmt.Errorf("%w: could not lock %s", ErrSnapshotLockBusy, filepath.Base(path))
	}
	return func() {
		_ = fl.Unlock()
		_ = fl.Close()
	}, false, nil
}

// acquireView takes snapshot.lock shared for one logical read or one update's
// staging phase. The returned release MUST be called when the read's blob
// accesses are done. degraded reports that the filesystem refused the lock and
// the lease is in-process only.
func acquireView(root string) (release leaseRelease, degraded bool, err error) {
	if err := ensureLockDir(root); err != nil {
		return noopLease, true, err
	}
	return acquireFlock(snapshotLockPathFor(root), lockShared, viewLockTimeout)
}

// acquireCommit takes commit.lock exclusive for one index.json RMW commit.
func acquireCommit(root string) (release leaseRelease, degraded bool, err error) {
	if err := ensureLockDir(root); err != nil {
		return noopLease, true, err
	}
	return acquireFlock(commitLockPathFor(root), lockExclusive, commitLockTimeout)
}

// acquireExclusive takes snapshot.lock exclusive for GC/Flush: the barrier
// under which index.json and referenced blobs transition together.
func acquireExclusive(root string) (release leaseRelease, degraded bool, err error) {
	if err := ensureLockDir(root); err != nil {
		return noopLease, true, err
	}
	return acquireFlock(snapshotLockPathFor(root), lockExclusive, exclusiveLockTimeout)
}

// tryAcquireExclusive is acquireExclusive with the short sweep timeout; when
// the lock is busy it returns acquired==false with no error so open-time
// recovery can skip sweeping while another process is alive.
func tryAcquireExclusive(root string) (release leaseRelease, degraded bool, acquired bool, err error) {
	if err := ensureLockDir(root); err != nil {
		return noopLease, true, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), sweepLockTimeout)
	defer cancel()
	fl := flock.New(snapshotLockPathFor(root))
	locked, lerr := fl.TryLockContext(ctx, snapshotLockRetryInterval)
	if lerr != nil {
		_ = fl.Close()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return noopLease, false, false, nil
		}
		return noopLease, true, false, lerr
	}
	if !locked {
		_ = fl.Close()
		return noopLease, false, false, nil
	}
	return func() {
		_ = fl.Unlock()
		_ = fl.Close()
	}, false, true, nil
}

// TempMatch reports whether an entry name (basename) is recognizable
// crash residue by the snapshot boundary's naming rules.
type TempMatch func(name string) bool

// IndexTempMatch matches abandoned index.json rewrites: "index-*.json.tmp".
func IndexTempMatch(name string) bool {
	return strings.HasPrefix(name, consts.SnapshotIndexTempPrefix) &&
		strings.HasSuffix(name, consts.SnapshotIndexTempSuffix)
}

// MetaTempMatch matches abandoned store metadata rewrites: "store-*.json.tmp".
func MetaTempMatch(name string) bool {
	return strings.HasPrefix(name, consts.SnapshotMetaTempPrefix) &&
		strings.HasSuffix(name, consts.SnapshotIndexTempSuffix)
}

// InventoryTempMatch matches abandoned stores.json rewrites.
func InventoryTempMatch(name string) bool {
	return strings.HasPrefix(name, consts.SnapshotInventoryTempPrefix) &&
		strings.HasSuffix(name, consts.SnapshotIndexTempSuffix)
}

// BlobTempMatch matches abandoned blob ingest temps: "<hex>.tmp-*".
func BlobTempMatch(name string) bool {
	return strings.Contains(name, consts.SnapshotBlobTempSegment)
}

// StagingTempMatch matches abandoned hauler staging directories.
func StagingTempMatch(name string) bool {
	return strings.HasPrefix(name, consts.SnapshotStagingPrefix)
}

// ExtractTempMatch matches abandoned directory-extraction staging dirs:
// ".<base>.hauler-extract-*".
func ExtractTempMatch(name string) bool {
	return strings.Contains(name, consts.SnapshotExtractTempSegment)
}

// SweepResult is the observable outcome of one recovery sweep.
type SweepResult struct {
	// Removed counts deleted files/directories.
	Removed int
	// Skipped is true when the store was locked by a live process; no residue
	// was touched and a later open performs the sweep.
	Skipped bool
	// Degraded is true when the filesystem refused advisory locking; residue
	// was still swept on a best-effort basis.
	Degraded bool
}

// SweepTemp removes recognizable crash residue from an OCI layout root. It is
// only safe with no live lease holders, which the short exclusive try-lock
// proves: every temp it matches here (index rewrites and staging dirs) is
// created while its transaction holds that same shared lease, so finding none
// held means they can only belong to a dead process. It removes:
//   - <root>/index-*.json.tmp
//   - <root>/.hauler-staging-* directories
//   - <root>/blobs/<alg>/<hex>.tmp-* blob ingest temps
//
// Store metadata temps (store-*.json.tmp) are deliberately NOT swept here:
// store.json creation holds a different, snapshot-lock-free critical section,
// so that flock alone sweeps its own residue (see loadOrCreateStoreID).
// Nothing by these names is committed content, so removal never changes a
// readable snapshot.
func SweepTemp(root string) SweepResult {
	release, degraded, acquired, err := tryAcquireExclusive(root)
	if err != nil || degraded {
		// Locking is unavailable on this filesystem -- sweep best-effort
		// anyway: an operator re-opening a store after a crash still expects
		// the residue gone, and temp names can never be live content.
		degraded = true
	} else if !acquired {
		return SweepResult{Skipped: true}
	}
	if release != nil {
		defer release()
	}

	var res SweepResult
	res.Degraded = degraded

	rootMatches := []TempMatch{IndexTempMatch, StagingTempMatch}
	res.Removed += sweepDir(root, rootMatches...)

	blobsRoot := filepath.Join(root, "blobs")
	if algEntries, err := os.ReadDir(blobsRoot); err == nil {
		for _, alg := range algEntries {
			if !alg.IsDir() {
				continue
			}
			res.Removed += sweepDir(filepath.Join(blobsRoot, alg.Name()), BlobTempMatch)
		}
	}
	return res
}

// SweepMatching removes entries in dir matching any of matchers. It is the
// shared primitive for roots outside an OCI layout (inventory directory,
// fileserver/git backend directories), where callers already hold their own
// coordination lock or know no concurrent worker exists.
func SweepMatching(dir string, matchers ...TempMatch) int {
	return sweepDir(dir, matchers...)
}

func sweepDir(dir string, matchers ...TempMatch) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		matched := false
		for _, m := range matchers {
			if m(name) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, name)); err == nil {
			removed++
		}
	}
	return removed
}

// SweepMatchingRecursive walks dir and removes entries matching matchers at
// ANY depth (without descending into matched directories themselves). It is
// used by serve backends whose extraction staging is a sibling of its target
// at arbitrary depth. Callers must own the tree (serve startup does) or hold
// the coordination lock for it: unlike SweepTemp this takes no locks.
func SweepMatchingRecursive(dir string, matchers ...TempMatch) int {
	removed := 0
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == dir {
			return nil
		}
		for _, m := range matchers {
			if !m(d.Name()) {
				continue
			}
			if rmErr := os.RemoveAll(path); rmErr == nil {
				removed++
			}
			// Matched entries are staging residue: never descend into them.
			return filepath.SkipDir
		}
		return nil
	})
	return removed
}

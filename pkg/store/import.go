package store

// Staged, verified, atomic import of one local OCI layout into another.
//
// store load historically streamed the extracted haul straight into the live
// destination store: each root manifest updated dest's index.json as soon as
// its own graph had been copied, so a failure or kill midway left the existing
// store's index referencing artifacts that never fully arrived -- a store
// that looked updated but was missing content, with the next load silently
// merging more state on top of it.
//
// ImportLayout inverts the visibility order:
//
//  1. The complete descriptor graph of the source layout is enumerated and
//     every manifest in it is parsed. A missing blob or malformed manifest
//     fails the import before the destination is touched at all.
//  2. Every blob is staged into dest's content-addressed blob directory with
//     content.OCI.WriteBlob -- temp file, inline digest verification, fsync,
//     rename. Blobs are inert without index entries, so staging never changes
//     what the existing store serves; an interrupted stage leaves only
//     unreferenced blobs (harmless, reclaimed by store cleanup).
//  3. Only after the whole graph is staged does the merged index get published
//     exactly once (content.OCI.MergeIndex: load-modify-save under a cross-
//     process flock, temp-file + rename). Dest therefore keeps its previous
//     index.json up to the single atomic switch.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gofrs/flock"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"

	"hauler.dev/go/hauler/v2/pkg/content"
)

// importLockName is the cross-process lock guarding a destination store's
// index merge during load. It lives in the store root and is excluded from
// hauls by save's enumeration; the OS releases it automatically if the
// importing process dies, so it never needs manual recovery.
const importLockName = ".hauler-import.lock"

// importLockTimeout bounds the wait for another hauler process finishing an
// import. Imports of large stores legitimately hold the lock for minutes;
// flock is released by the kernel on process death, so this only guards
// against a wedged NFS lock.
const importLockTimeout = 30 * time.Minute

// ImportLayout stages and verifies the entire source layout l into the local
// OCI store at destRoot, then publishes the merged index once. destRoot is
// created if absent. Importing a layout into itself is rejected.
func (l *Layout) ImportLayout(ctx context.Context, destRoot string) error {
	absDest, err := filepath.Abs(destRoot)
	if err != nil {
		return err
	}
	if absDest == l.Root {
		return fmt.Errorf("cannot import a layout into itself [%s]", absDest)
	}
	if err := os.MkdirAll(absDest, 0o755); err != nil {
		return fmt.Errorf("creating destination store [%s]: %w", absDest, err)
	}

	// 1. Enumerate the source index roots.
	var roots []ocispec.Descriptor
	if err := l.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		roots = append(roots, desc)
		return nil
	}); err != nil {
		return fmt.Errorf("reading haul index: %w", err)
	}
	// An empty index is a legitimate haul (e.g. an empty store saved only to
	// carry its audit.log): there is nothing to stage or merge, and callers
	// still merge sidecar files such as audit.log afterwards.

	// 2. Collect the full blob set up front, parsing every manifest so a
	// truncated or malformed graph fails before dest is touched.
	blobs, err := l.collectImportBlobs(ctx, roots)
	if err != nil {
		return err
	}

	dest, err := content.NewOCI(absDest)
	if err != nil {
		return fmt.Errorf("opening destination store [%s]: %w", absDest, err)
	}
	if err := dest.LoadIndex(); err != nil {
		return fmt.Errorf("reading destination index: %w", err)
	}

	// 3. Stage all blobs, digest-verified, without touching dest's index.
	//    Bounded concurrency matches the rest of the codebase; ctx cancel
	//    aborts in-flight staging via WriteBlob's ctx-aware copy.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))
	for _, d := range blobs {
		d := d
		g.Go(func() error {
			return dest.WriteBlob(gctx, d.Digest, d.Size, func() (io.ReadCloser, error) {
				return l.OCI.Fetch(gctx, d)
			})
		})
	}
	if err := g.Wait(); err != nil {
		return fmt.Errorf("staging haul content into [%s] (destination index unchanged): %w", absDest, err)
	}

	// 4. Publish the merged index once, under a cross-process lock so a
	//    concurrent load can't lost-update the other's entries.
	fl := flock.New(filepath.Join(absDest, importLockName))
	lockCtx, cancel := context.WithTimeout(ctx, importLockTimeout)
	locked, err := fl.TryLockContext(lockCtx, 250*time.Millisecond)
	cancel()
	if err != nil {
		return fmt.Errorf("acquiring import lock for [%s]: %w", absDest, err)
	}
	if !locked {
		return fmt.Errorf("timed out waiting for another hauler process importing into [%s]", absDest)
	}
	defer fl.Unlock()

	if _, err := dest.MergeIndex(roots); err != nil {
		return fmt.Errorf("publishing merged index into [%s]: %w", absDest, err)
	}
	return nil
}

// collectImportBlobs walks every root's manifest graph and returns the
// deduplicated set of descriptors (manifests, indexes, configs, layers) whose
// bytes must be staged. Fetching and JSON-decoding each manifest here is the
// structural verification gate: an index that names a manifest the haul
// lacks, or an unparseable manifest, errors before anything is written to
// dest.
func (l *Layout) collectImportBlobs(ctx context.Context, roots []ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	seen := make(map[string]bool)
	var blobs []ocispec.Descriptor

	add := func(d ocispec.Descriptor) error {
		if d.Digest.Validate() != nil {
			return nil
		}
		key := d.Digest.String()
		if seen[key] {
			return nil
		}
		seen[key] = true
		blobs = append(blobs, d)
		return nil
	}

	var walk func(desc ocispec.Descriptor) error
	walk = func(desc ocispec.Descriptor) error {
		if desc.Digest.Validate() != nil {
			return nil
		}
		if err := add(desc); err != nil {
			return err
		}

		rc, err := l.OCI.Fetch(ctx, desc)
		if err != nil {
			return fmt.Errorf("fetching %s from haul: %w", desc.Digest, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("reading %s from haul: %w", desc.Digest, err)
		}

		var m manifestLike
		if err := json.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("haul manifest %s is malformed: %w", desc.Digest, err)
		}
		if m.Config.Digest.Validate() == nil {
			if err := add(m.Config); err != nil {
				return err
			}
		}
		for _, lyr := range m.Layers {
			if lyr.Digest.Validate() == nil {
				if err := add(lyr); err != nil {
					return err
				}
			}
		}
		for _, child := range m.Manifests {
			if child.Digest.Validate() != nil {
				continue
			}
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}

	for _, r := range roots {
		if err := walk(r); err != nil {
			return nil, err
		}
	}
	return blobs, nil
}

// IsImportLock reports whether name is the import lock file -- used by save's
// store enumeration to keep the lock out of hauls.
func IsImportLock(name string) bool { return name == importLockName }

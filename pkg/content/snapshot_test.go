package content

// snapshot_test.go covers the snapshot boundary primitives: transaction
// atomicity and commit-time validation, generation accounting, the
// shared-view vs exclusive-deletion lock order (exercised through separate
// OCI handles exactly as separate processes would hit flock), and crash
// recovery sweeping.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func blobDescriptor(t *testing.T, o *OCI, data []byte, ref string) ocispec.Descriptor {
	t.Helper()
	d := digest.FromBytes(data)
	path := o.path(ocispec.ImageBlobsDir, d.Algorithm().String(), d.Hex())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	return ocispec.Descriptor{
		MediaType: testBlobMediaType,
		Digest:    d,
		Size:      int64(len(data)),
		Annotations: map[string]string{
			ocispec.AnnotationRefName: ref,
		},
	}
}

// TestSnapshotTx_CommitValidationRejectsMissingBlob: a descriptor referencing
// an absent blob can never be committed; index.json stays untouched and the
// generation does not advance.
func TestSnapshotTx_CommitValidationRejectsMissingBlob(t *testing.T) {
	dir := t.TempDir()
	o := newTestOCI(t, dir)

	missing := ocispec.Descriptor{
		MediaType: testBlobMediaType,
		Digest:    digest.FromBytes([]byte("nobody ever wrote these bytes to disk")),
		Size:      32,
		Annotations: map[string]string{
			ocispec.AnnotationRefName: "example.com/broken:latest",
		},
	}

	tx, err := o.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.AddIndex(missing); err != nil {
		t.Fatalf("AddIndex: %v", err)
	}
	if _, err := tx.Commit(); !errors.Is(err, ErrSnapshotValidation) {
		t.Fatalf("Commit error = %v, want ErrSnapshotValidation", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ocispec.ImageIndexFile)); !os.IsNotExist(err) {
		t.Fatalf("index.json must not be created by a rejected commit, stat err = %v", err)
	}
	if gen := o.SnapshotGeneration(); gen != 0 {
		t.Errorf("generation = %d after rejected commit, want 0", gen)
	}

	// A subsequent valid commit works and starts at generation 1.
	tx2, err := o.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx(2): %v", err)
	}
	good := blobDescriptor(t, o, []byte("complete snapshot bytes"), "example.com/good:latest")
	if err := tx2.AddIndex(good); err != nil {
		t.Fatalf("AddIndex(good): %v", err)
	}
	gen, err := tx2.Commit()
	if err != nil {
		t.Fatalf("Commit(2): %v", err)
	}
	if gen != 1 {
		t.Errorf("generation after valid commit = %d, want 1", gen)
	}
}

// TestSnapshotTx_RollbackLeavesNoTrace: staged descriptors are discarded and
// a later committed snapshot knows nothing of them.
func TestSnapshotTx_RollbackLeavesNoTrace(t *testing.T) {
	dir := t.TempDir()
	o := newTestOCI(t, dir)

	tx, err := o.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	d := blobDescriptor(t, o, []byte("rolled back"), "example.com/rollback:latest")
	if err := tx.AddIndex(d); err != nil {
		t.Fatalf("AddIndex: %v", err)
	}
	tx.Rollback()

	if _, err := os.Stat(filepath.Join(dir, ocispec.ImageIndexFile)); !os.IsNotExist(err) {
		t.Fatalf("index.json created despite rollback, stat err = %v", err)
	}

	// The rolled-back blob is unreferenced content -- invisible to the
	// catalog. GC must reclaim it.
	tx2, err := o.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx(2): %v", err)
	}
	other := blobDescriptor(t, o, []byte("kept bytes here"), "example.com/kept:latest")
	if err := tx2.AddIndex(other); err != nil {
		t.Fatalf("AddIndex(other): %v", err)
	}
	if _, err := tx2.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// The rolled-back entry is invisible; its orphaned blob is reclaimed by
	// store-level GC (covered by pkg/store's delete-boundary tests).
	count := 0
	if err := o.Walk(func(_ string, _ ocispec.Descriptor) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if count != 1 {
		t.Errorf("catalog entries = %d after rollback + commit, want 1 (the rolled-back entry must not appear)", count)
	}
}

// TestSnapshotGeneration_MonotonicAcrossReopen: every content-changing commit
// bumps the generation exactly once, and the generation survives a fresh
// reader opening the same directory.
func TestSnapshotGeneration_MonotonicAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	o := newTestOCI(t, dir)

	for i := 0; i < 3; i++ {
		tx, err := o.BeginTx(context.Background())
		if err != nil {
			t.Fatalf("BeginTx(%d): %v", i, err)
		}
		d := blobDescriptor(t, o, []byte{byte(i + 1), byte(i + 2), byte(i + 3)}, "example.com/repo:v"+string(rune('0'+i+1)))
		if err := tx.AddIndex(d); err != nil {
			t.Fatalf("AddIndex(%d): %v", i, err)
		}
		gen, err := tx.Commit()
		if err != nil {
			t.Fatalf("Commit(%d): %v", i, err)
		}
		if gen != uint64(i+1) {
			t.Errorf("generation = %d after commit %d, want %d", gen, i, i+1)
		}
	}

	fresh := newTestOCI(t, dir)
	if gen := fresh.SnapshotGeneration(); gen != 3 {
		t.Errorf("generation after reopen = %d, want 3", gen)
	}
	count := 0
	if err := fresh.Walk(func(_ string, _ ocispec.Descriptor) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if count != 3 {
		t.Errorf("fresh OCI sees %d entries, want 3", count)
	}
}

// TestSnapshot_ConcurrentTransactionsSeparateHandlesMerge exercises the
// cross-process commit path: two independent OCI handles (each with its own
// loaded nameMap, like two hauler processes) commit concurrently, and every
// descriptor survives to disk -- commit.lock + disk-baseline merge prevents
// last-writer-wins.
func TestSnapshot_ConcurrentTransactionsSeparateHandlesMerge(t *testing.T) {
	dir := t.TempDir()
	const n = 20
	handles := []*OCI{newTestOCI(t, dir), newTestOCI(t, dir)}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o := handles[i%2]
			tx, err := o.BeginTx(context.Background())
			if err != nil {
				errs <- err
				return
			}
			d := blobDescriptor(t, o, []byte("merge-"+string(rune('A'+i%26))+string(rune('a'+i))), "example.com/m"+string(rune('a'+i))+":latest")
			if err := tx.AddIndex(d); err != nil {
				tx.Rollback()
				errs <- err
				return
			}
			if _, err := tx.Commit(); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent tx: %v", err)
	}

	fresh := newTestOCI(t, dir)
	count := 0
	if err := fresh.Walk(func(_ string, _ ocispec.Descriptor) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if count != n {
		t.Errorf("committed entries = %d, want %d (lost cross-handle updates)", count, n)
	}
}

// TestSnapshot_ViewBlocksExclusiveDeletion is the delete-race guarantee: while
// a read lease is held (Walk snapshot plus subsequent blob reads), an
// exclusive GC/Flush boundary on a separate handle cannot enter -- it waits,
// so the in-flight request finishes on its snapshot. Once the view releases,
// the exclusive boundary proceeds.
func TestSnapshot_ViewBlocksExclusiveDeletion(t *testing.T) {
	dir := t.TempDir()
	a := newTestOCI(t, dir)
	d := blobDescriptor(t, a, []byte("pinned while readers exist"), "example.com/pin:latest")
	tx, err := a.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.AddIndex(d); err != nil {
		t.Fatalf("AddIndex: %v", err)
	}
	if _, err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	b := newTestOCI(t, dir)

	view, err := a.View(context.Background())
	if err != nil {
		t.Fatalf("View: %v", err)
	}

	entered := make(chan struct{})
	go func() {
		_ = b.Exclusive(context.Background(), func() error {
			close(entered)
			return nil
		})
	}()

	select {
	case <-entered:
		t.Fatal("exclusive boundary entered while a read lease was held -- a delete could unlink in-use blobs")
	case <-time.After(300 * time.Millisecond):
	}

	view.Release()

	select {
	case <-entered:
	case <-time.After(exclusiveLockTimeout + 5*time.Second):
		t.Fatal("exclusive boundary did not proceed after the read lease released")
	}
}

// TestSweepTemp_RemovesRecognizedResidue verifies recovery sweeps exactly the
// recognized temp patterns and never committed content.
func TestSweepTemp_RemovesRecognizedResidue(t *testing.T) {
	dir := t.TempDir()

	// committed content
	if err := os.MkdirAll(filepath.Join(dir, ocispec.ImageBlobsDir, "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	committedBlob := filepath.Join(dir, ocispec.ImageBlobsDir, "sha256", "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")
	if err := os.WriteFile(committedBlob, []byte("committed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ocispec.ImageIndexFile), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// residue of crashed updates, by every snapshot-lock-protected pattern
	residue := []string{
		filepath.Join(dir, "index-1730000000.json.tmp"),
		filepath.Join(dir, ocispec.ImageBlobsDir, "sha256", "cccc.tmp-987654"),
	}
	for _, p := range residue {
		if err := os.WriteFile(p, []byte("partial"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, ".hauler-staging-123"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hauler-staging-123", "partial.blob"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Metadata temps belong to a different lock domain and are swept there;
	// SweepTemp must leave them alone.
	metaTemp := filepath.Join(dir, "store-keep.json.tmp")
	if err := os.WriteFile(metaTemp, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := SweepTemp(dir)
	if res.Skipped {
		t.Fatal("sweep skipped with no lease holders")
	}
	if res.Removed != 3 {
		t.Errorf("Removed = %d, want 3 (index temp, staging dir, blob temp)", res.Removed)
	}

	for _, p := range residue {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("residue %s still present", p)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".hauler-staging-123")); !os.IsNotExist(err) {
		t.Error("staging dir still present")
	}
	if _, err := os.Stat(metaTemp); err != nil {
		t.Error("store metadata temp was swept outside its own lock domain")
	}
	if _, err := os.Stat(committedBlob); err != nil {
		t.Errorf("committed blob removed by sweep: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ocispec.ImageIndexFile)); err != nil {
		t.Errorf("committed index removed by sweep: %v", err)
	}
}

// TestSweepTemp_SkippedWhileViewHeld: with a live lease (another process in
// the middle of a request/update), recovery removes nothing -- it cannot tell
// a temp owned by that process from crash residue -- and the temp is swept on
// the next unopposed open.
func TestSweepTemp_SkippedWhileViewHeld(t *testing.T) {
	dir := t.TempDir()
	o := newTestOCI(t, dir)
	view, err := o.View(context.Background())
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	defer view.Release()

	tmp := filepath.Join(dir, "index-active.json.tmp")
	if err := os.WriteFile(tmp, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := SweepTemp(dir)
	if !res.Skipped {
		t.Errorf("Skipped = false with a view held, result = %+v", res)
	}
	if res.Removed != 0 {
		t.Errorf("Removed = %d while a view was held, want 0", res.Removed)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Errorf("temp was removed while a process held a lease: %v", err)
	}
}

// TestSweepMatchingRecursive covers serve-backend extraction residue nested at
// arbitrary depth.
func TestSweepMatchingRecursive(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "repo-a")
	if err := os.MkdirAll(keep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keep, "HEAD"), []byte("ref"), 0o644); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(keep, ".repo-a.hauler-extract-42")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "partial"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if n := SweepMatchingRecursive(dir, ExtractTempMatch); n != 1 {
		t.Errorf("removed %d, want 1", n)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Error("staging dir remains")
	}
	if _, err := os.Stat(filepath.Join(keep, "HEAD")); err != nil {
		t.Errorf("committed content removed: %v", err)
	}
}

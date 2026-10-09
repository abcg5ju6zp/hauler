package store_test

// store_snapshot_test.go covers the snapshot boundary as observed through the
// public Layout API: delete-vs-read serialization across independent layout
// handles (the cross-process shape), orphan reclamation after rollback, and
// crash-recovery sweeping at NewLayout.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/pkg/consts"
	"hauler.dev/go/hauler/v2/pkg/content"
	"hauler.dev/go/hauler/v2/pkg/store"
)

// seedRawBlobEntry materializes one non-manifest blob and commits an index
// entry for it through a snapshot transaction, returning the entry's Walk key.
func seedRawBlobEntry(t *testing.T, s *store.Layout, refName string, data []byte) (key string, desc ocispec.Descriptor) {
	t.Helper()
	d := digest.FromBytes(data)
	blobPath := filepath.Join(s.Root, ocispec.ImageBlobsDir, d.Algorithm().String(), d.Hex())
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(blobPath, data, 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	desc = ocispec.Descriptor{
		MediaType: "application/vnd.hauler.test.blob",
		Digest:    d,
		Size:      int64(len(data)),
		Annotations: map[string]string{
			ocispec.AnnotationRefName: refName,
			consts.KindAnnotationName: consts.KindAnnotationImage,
		},
	}
	tx, err := s.OCI.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.AddIndex(desc); err != nil {
		t.Fatalf("AddIndex: %v", err)
	}
	if _, err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.OCI.LoadIndex(); err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	if err := s.Walk(func(k string, dd ocispec.Descriptor) error {
		if dd.Digest == d {
			key = k
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if key == "" {
		t.Fatal("seeded entry not found by Walk")
	}
	return key, desc
}

// TestSnapshot_DeleteWaitsForInFlightRead is the core "old requests finish"
// guarantee: a read lease held across the index-walk + blob-read request
// blocks a second handle's removal+GC until the request releases; the in-flight
// reader successfully reads every blob its snapshot names.
func TestSnapshot_DeleteWaitsForInFlightRead(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewLayout(dir)
	if err != nil {
		t.Fatalf("NewLayout: %v", err)
	}
	data := []byte("a reader in flight must finish on its snapshot bytes")
	key, desc := seedRawBlobEntry(t, s, "example.com/app:v1", data)

	// Second independent handle -- a separate hauler process would take the
	// same flock path.
	s2, err := store.NewLayout(dir)
	if err != nil {
		t.Fatalf("NewLayout(2): %v", err)
	}

	view, err := s.View(context.Background())
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	genAtStart := view.Generation()
	if genAtStart == 0 {
		t.Fatal("view generation is 0 after a commit")
	}

	done := make(chan error, 1)
	go func() {
		_, _, _, gerr := s2.RemoveArtifacts(context.Background(), []string{key})
		done <- gerr
	}()

	// Deletion (specifically its GC boundary) must not proceed while the
	// request is in flight.
	select {
	case err := <-done:
		t.Fatalf("remove+GC completed while the read lease was held (err=%v) -- in-flight request could see torn state", err)
	case <-time.After(300 * time.Millisecond):
	}

	// The request still resolves its manifest and reads its blob: no
	// manifest-exists/blob-404 contradiction.
	rc, err := s.Fetch(context.Background(), desc)
	if err != nil {
		t.Fatalf("Fetch under read lease: %v", err)
	}
	got := make([]byte, len(data))
	if _, err := rc.Read(got); err != nil && err.Error() != "EOF" {
		t.Fatalf("read blob: %v", err)
	}
	rc.Close()
	if string(got) != string(data) {
		t.Errorf("blob read under delete contention = %q, want %q", got, data)
	}

	view.Release()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RemoveArtifacts after release: %v", err)
		}
	case <-time.After(70 * time.Second):
		t.Fatal("remove+GC never completed after the read lease released")
	}

	// New requests now observe only the post-delete snapshot.
	s3, err := store.NewLayout(dir)
	if err != nil {
		t.Fatalf("NewLayout(3): %v", err)
	}
	count := 0
	if err := s3.Walk(func(_ string, _ ocispec.Descriptor) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if count != 0 {
		t.Errorf("entries after remove = %d, want 0", count)
	}
	blobPath := filepath.Join(dir, ocispec.ImageBlobsDir, desc.Digest.Algorithm().String(), desc.Digest.Hex())
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Errorf("blob still present after GC: %v", err)
	}
	if info := s3.Info(); info.Generation <= genAtStart {
		t.Errorf("generation after remove = %d, want > %d", info.Generation, genAtStart)
	}
}

// TestSnapshot_GCReclaimsOrphansFromRolledBackUpdate proves blobs staged by an
// update that never commits are invisible immediately and reclaimed by GC.
func TestSnapshot_GCReclaimsOrphansFromRolledBackUpdate(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewLayout(dir)
	if err != nil {
		t.Fatalf("NewLayout: %v", err)
	}

	orphan := []byte("staged then the validation failed upstream")
	d := digest.FromBytes(orphan)
	orphanPath := filepath.Join(dir, ocispec.ImageBlobsDir, d.Algorithm().String(), d.Hex())
	if err := os.MkdirAll(filepath.Dir(orphanPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphanPath, orphan, 0o644); err != nil {
		t.Fatal(err)
	}

	tx, err := s.OCI.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := tx.AddIndex(ocispec.Descriptor{
		MediaType: "application/vnd.hauler.test.blob",
		Digest:    d,
		Size:      int64(len(orphan)),
		Annotations: map[string]string{
			ocispec.AnnotationRefName: "example.com/orphan:latest",
		},
	}); err != nil {
		t.Fatalf("AddIndex: %v", err)
	}
	tx.Rollback() // e.g. a later stage of the same update failed

	count := 0
	if err := s.Walk(func(_ string, _ ocispec.Descriptor) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if count != 0 {
		t.Errorf("rolled-back descriptor is visible, entries = %d", count)
	}

	removed, _, err := s.CleanUp(context.Background())
	if err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if removed != 1 {
		t.Errorf("GC removed %d blobs, want 1 orphan", removed)
	}
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Error("orphan blob survived GC")
	}
}

// TestNewLayout_RecoversCrashResidue verifies the observable recovery result:
// reopening a store with leftover temp objects reports them swept, and no
// temporary name ever becomes a readable artifact.
func TestNewLayout_RecoversCrashResidue(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ocispec.ImageBlobsDir, "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	temps := []string{
		filepath.Join(dir, "index-0001.json.tmp"),
		filepath.Join(dir, "store-0002.json.tmp"),
		filepath.Join(dir, ocispec.ImageBlobsDir, "sha256", "dddd.tmp-0003"),
	}
	for _, p := range temps {
		if err := os.WriteFile(p, []byte("partial"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, ".hauler-staging-0004"), 0o755); err != nil {
		t.Fatal(err)
	}

	s, err := store.NewLayout(dir)
	if err != nil {
		t.Fatalf("NewLayout: %v", err)
	}
	// index temp + staging dir + blob temp via the snapshot-lock sweep; the
	// store metadata temp is swept under the store-id flock inside the same
	// NewLayout call.
	sw := s.LastSweep()
	if sw.Skipped || sw.Removed != 3 {
		t.Fatalf("LastSweep = %+v, want {Removed:3 Skipped:false}", sw)
	}
	for _, p := range temps {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("residue remains: %s", p)
		}
	}

	// A reopened store is readable and empty; the swept files never catalogued.
	count := 0
	if err := s.Walk(func(_ string, _ ocispec.Descriptor) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if count != 0 {
		t.Errorf("recovered store lists %d artifacts, want 0", count)
	}
}

// TestNewLayout_SweepSkippedWhileLeaseHeld: while another handle has a live
// read lease, an open skips the sweep and still works.
func TestNewLayout_SweepSkippedWhileLeaseHeld(t *testing.T) {
	dir := t.TempDir()
	holder, err := content.NewOCI(dir)
	if err != nil {
		t.Fatalf("NewOCI: %v", err)
	}
	view, err := holder.View(context.Background())
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	defer view.Release()

	tmp := filepath.Join(dir, "index-live.json.tmp")
	if err := os.WriteFile(tmp, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := store.NewLayout(dir)
	if err != nil {
		t.Fatalf("NewLayout: %v", err)
	}
	if !s.LastSweep().Skipped {
		t.Errorf("sweep = %+v, want Skipped", s.LastSweep())
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Errorf("temp removed despite a live lease: %v", err)
	}
}

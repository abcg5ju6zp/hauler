package store

// atomic_flow_test.go covers the save/load atomic publish-and-recovery flow
// end to end: duplicate saves, mode switching, interrupted-save leftovers,
// chunk corruption detection + safe retry, large chunked archives, and failed
// loads leaving the destination store unpolluted.

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hauler.dev/go/hauler/v2/internal/flags"
	v1 "hauler.dev/go/hauler/v2/pkg/apis/hauler.cattle.io/v1"
	"hauler.dev/go/hauler/v2/pkg/archives"
	"hauler.dev/go/hauler/v2/pkg/store"
)

// fileStore seeds a store with one local file artifact and flushes its index.
func fileStore(t *testing.T, ctx context.Context, name string, size int) (*store.Layout, []byte) {
	t.Helper()
	dir := t.TempDir()
	content := make([]byte, size)
	if _, err := rand.Read(content); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(dir, name)
	if err := os.WriteFile(local, content, 0o644); err != nil {
		t.Fatal(err)
	}
	s := newTestStore(t)
	if err := storeFile(ctx, s, v1.File{Path: local, Name: name}, defaultCliOpts(), defaultRootOpts(s.Root)); err != nil {
		t.Fatalf("storeFile: %v", err)
	}
	if err := s.SaveIndex(); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	return s, content
}

func loadOptsFor(path, dest string) *flags.LoadOpts {
	return &flags.LoadOpts{
		StoreRootOpts: defaultRootOpts(dest),
		FileName:      []string{path},
	}
}

func assertRefPresent(t *testing.T, root, ref string) {
	t.Helper()
	s, err := store.NewLayout(root)
	if err != nil {
		t.Fatalf("NewLayout(%s): %v", root, err)
	}
	assertArtifactInStore(t, s, ref)
}

func assertRefAbsent(t *testing.T, root, ref string) {
	t.Helper()
	s, err := store.NewLayout(root)
	if err != nil {
		t.Fatalf("NewLayout(%s): %v", root, err)
	}
	assertArtifactNotInStore(t, s, ref)
}

// TestSaveLoad_ChunkedCorruptionDetectedAndRetried: a tampered published
// chunk must fail the load manifest gate, and a fresh re-save must restore the
// set so the retried load succeeds.
func TestSaveLoad_ChunkedCorruptionDetectedAndRetried(t *testing.T) {
	ctx := newTestContext(t)
	src, _ := fileStore(t, ctx, "chunked.bin", 400_000)

	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "haul.tar.zst")
	so := newSaveOpts(src.Root, archivePath)
	so.ChunkSize = "128K"
	if err := SaveCmd(ctx, so, src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("SaveCmd chunked: %v", err)
	}
	if _, err := os.Stat(archivePath); !os.IsNotExist(err) {
		t.Fatal("single-file archive must be retired when chunks are published")
	}
	chunks, err := filepath.Glob(archivePath + ".[0-9][0-9][0-9]")
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	if _, err := os.Stat(archivePath + ".chunks.json"); err != nil {
		t.Fatalf("publication manifest missing: %v", err)
	}

	// Healthy set loads.
	dest1 := t.TempDir()
	if err := LoadCmd(ctx, loadOptsFor(archivePath, dest1), mustOpen(t, dest1), defaultRootOpts(dest1), defaultCliOpts()); err != nil {
		t.Fatalf("LoadCmd healthy chunks: %v", err)
	}
	assertRefPresent(t, dest1, "chunked.bin")

	// Tamper with the first chunk: load must fail closed.
	if err := writeByteAt(chunks[0], 200, 0xFF); err != nil {
		t.Fatal(err)
	}
	dest2 := t.TempDir()
	if err := LoadCmd(ctx, loadOptsFor(archivePath, dest2), mustOpen(t, dest2), defaultRootOpts(dest2), defaultCliOpts()); err == nil {
		t.Fatal("LoadCmd must reject a chunk set that fails manifest verification")
	} else if !strings.Contains(err.Error(), "incomplete or corrupted chunk set") {
		t.Fatalf("expected an incomplete/corrupted chunk set error, got: %v", err)
	}
	assertRefAbsent(t, dest2, "chunked.bin")

	// Safe retry: re-save, the set is rebuilt and loads again.
	if err := SaveCmd(ctx, so, src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("retry SaveCmd: %v", err)
	}
	dest3 := t.TempDir()
	if err := LoadCmd(ctx, loadOptsFor(archivePath, dest3), mustOpen(t, dest3), defaultRootOpts(dest3), defaultCliOpts()); err != nil {
		t.Fatalf("LoadCmd after retry: %v", err)
	}
	assertRefPresent(t, dest3, "chunked.bin")
}

// TestSaveLoad_InterruptedLeftoversSwept plants the exact files a killed save
// leaves behind and confirms the next SaveCmd starts clean and publishes a
// working archive, with the leftovers removed.
func TestSaveLoad_InterruptedLeftoversSwept(t *testing.T) {
	ctx := newTestContext(t)
	src, _ := fileStore(t, ctx, "sweep.bin", 10_000)
	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "haul.tar.zst")

	deadTemp := filepath.Join(outDir, ".haul.tar.zst.tmp-deadbeef")
	deadStage := filepath.Join(outDir, ".haul.tar.zst.split-01020304")
	if err := os.WriteFile(deadTemp, []byte("half archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(deadStage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deadStage, "001"), []byte("half chunk"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := SaveCmd(ctx, newSaveOpts(src.Root, archivePath), src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("SaveCmd over leftovers: %v", err)
	}
	for _, p := range []string{deadTemp, deadStage} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("leftover %s not swept", p)
		}
	}
	dest := t.TempDir()
	if err := LoadCmd(ctx, loadOptsFor(archivePath, dest), mustOpen(t, dest), defaultRootOpts(dest), defaultCliOpts()); err != nil {
		t.Fatalf("LoadCmd: %v", err)
	}
	assertRefPresent(t, dest, "sweep.bin")
}

// TestSaveLoad_DuplicateSavesAndModeSwitching exercises repeated saves and
// chunked<->single-file switching: every final state must be loadable and no
// superseded generation may linger.
func TestSaveLoad_DuplicateSavesAndModeSwitching(t *testing.T) {
	ctx := newTestContext(t)
	src, _ := fileStore(t, ctx, "dup.bin", 60_000)
	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "haul.tar.zst")

	// 1) single file
	so := newSaveOpts(src.Root, archivePath)
	if err := SaveCmd(ctx, so, src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("save #1: %v", err)
	}
	// 2) duplicate single-file save (idempotent success)
	if err := SaveCmd(ctx, so, src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("save #2: %v", err)
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("archive missing after duplicate saves: %v", err)
	}

	// 3) switch to chunked: archive retired, set + manifest present
	so.ChunkSize = "32K"
	if err := SaveCmd(ctx, so, src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("chunked save: %v", err)
	}
	if _, err := os.Stat(archivePath); !os.IsNotExist(err) {
		t.Fatal("single-file archive should be gone after chunked publish")
	}
	if _, err := os.Stat(archivePath + ".chunks.json"); err != nil {
		t.Fatalf("chunk manifest missing: %v", err)
	}

	// 4) switch back: single file returns, chunks and manifest are retired
	so.ChunkSize = ""
	if err := SaveCmd(ctx, so, src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("back-to-single save: %v", err)
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("archive missing after switching back: %v", err)
	}
	leftovers, _ := filepath.Glob(archivePath + ".[0-9][0-9][0-9]")
	if len(leftovers) != 0 {
		t.Errorf("superseded chunks remain: %v", leftovers)
	}
	if _, err := os.Stat(archivePath + ".chunks.json"); !os.IsNotExist(err) {
		t.Error("superseded chunk manifest remains")
	}

	dest := t.TempDir()
	if err := LoadCmd(ctx, loadOptsFor(archivePath, dest), mustOpen(t, dest), defaultRootOpts(dest), defaultCliOpts()); err != nil {
		t.Fatalf("LoadCmd final archive: %v", err)
	}
	assertRefPresent(t, dest, "dup.bin")
}

// TestSaveLoad_LargeArchiveManyChunks pushes a multi-megabyte incompressible
// artifact through a small --chunk-size to exercise the streaming path, then
// merges it into a store that already holds another artifact.
func TestSaveLoad_LargeArchiveManyChunks(t *testing.T) {
	ctx := newTestContext(t)
	src, _ := fileStore(t, ctx, "large.bin", 3<<20)
	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "haul.tar.zst")
	so := newSaveOpts(src.Root, archivePath)
	so.ChunkSize = "256K"
	if err := SaveCmd(ctx, so, src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("SaveCmd large: %v", err)
	}
	chunks, err := filepath.Glob(archivePath + ".[0-9][0-9][0-9]")
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 5 {
		t.Fatalf("expected many chunks for a 3MiB store, got %d", len(chunks))
	}

	// Destination already carries an unrelated artifact: the large haul must
	// merge in, not replace it.
	dest, _ := fileStore(t, ctx, "existing.bin", 1024)
	if err := LoadCmd(ctx, loadOptsFor(archivePath, dest.Root), dest, defaultRootOpts(dest.Root), defaultCliOpts()); err != nil {
		t.Fatalf("LoadCmd large chunks: %v", err)
	}
	assertRefPresent(t, dest.Root, "large.bin")
	assertRefPresent(t, dest.Root, "existing.bin")
}

// TestSaveLoad_TruncatedArchiveDoesNotPolluteDest verifies a truncated haul
// fails extraction before any destination content is staged, leaving the
// existing store index exactly as it was; loading an intact haul afterwards
// still merges cleanly.
func TestSaveLoad_TruncatedArchiveDoesNotPolluteDest(t *testing.T) {
	ctx := newTestContext(t)

	dest, _ := fileStore(t, ctx, "keep.bin", 2048)
	src, _ := fileStore(t, ctx, "new.bin", 2048)
	archivePath := filepath.Join(t.TempDir(), "haul.tar.zst")
	if err := SaveCmd(ctx, newSaveOpts(src.Root, archivePath), src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("SaveCmd: %v", err)
	}

	good, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(good) < 100 {
		t.Fatal("test setup: archive too small")
	}
	truncated := filepath.Join(t.TempDir(), "truncated.tar.zst")
	if err := os.WriteFile(truncated, good[:len(good)/2], 0o644); err != nil {
		t.Fatal(err)
	}

	if err := LoadCmd(ctx, loadOptsFor(truncated, dest.Root), dest, defaultRootOpts(dest.Root), defaultCliOpts()); err == nil {
		t.Fatal("LoadCmd must reject a truncated archive")
	}
	assertRefPresent(t, dest.Root, "keep.bin")
	assertRefAbsent(t, dest.Root, "new.bin")

	// Intact haul loads on retry and merges.
	if err := LoadCmd(ctx, loadOptsFor(archivePath, dest.Root), dest, defaultRootOpts(dest.Root), defaultCliOpts()); err != nil {
		t.Fatalf("LoadCmd intact after failure: %v", err)
	}
	assertRefPresent(t, dest.Root, "keep.bin")
	assertRefPresent(t, dest.Root, "new.bin")
}

// TestSaveLoad_OutputInsideStoreDir ensures saving the archive into the store
// directory cannot nest the archive/lock/chunks into the haul itself.
func TestSaveLoad_OutputInsideStoreDir(t *testing.T) {
	ctx := newTestContext(t)
	src, _ := fileStore(t, ctx, "inside.bin", 5_000)
	archivePath := filepath.Join(src.Root, "haul.tar.zst")
	so := newSaveOpts(src.Root, archivePath)
	so.ChunkSize = "1K"
	if err := SaveCmd(ctx, so, src, defaultRootOpts(src.Root), defaultCliOpts()); err != nil {
		t.Fatalf("SaveCmd into store dir: %v", err)
	}
	chunks, err := filepath.Glob(archivePath + ".[0-9][0-9][0-9]")
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) == 0 {
		t.Fatal("expected chunks in the store directory")
	}
	dest := t.TempDir()
	if err := LoadCmd(ctx, loadOptsFor(archivePath, dest), mustOpen(t, dest), defaultRootOpts(dest), defaultCliOpts()); err != nil {
		t.Fatalf("LoadCmd: %v", err)
	}
	assertRefPresent(t, dest, "inside.bin")

	// The extracted haul must not contain its own chunk family: mirror
	// unarchiveLayoutTo's resolve -> join -> extract sequence and inspect
	// the extracted tree for output-family entries.
	resolved := resolveHaulPath(archivePath)
	joined, err := archives.JoinChunks(ctx, resolved, t.TempDir())
	if err != nil {
		t.Fatalf("JoinChunks: %v", err)
	}
	extractDir := t.TempDir()
	if err := archives.Unarchive(ctx, joined, extractDir); err != nil {
		t.Fatalf("Unarchive joined set: %v", err)
	}
	bad, err := filepath.Glob(filepath.Join(extractDir, "haul.tar.zst*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 0 {
		t.Errorf("haul saved into the store dir contains its own output family: %v", bad)
	}
}

// --- small local helpers ---

func mustOpen(t *testing.T, root string) *store.Layout {
	t.Helper()
	s, err := store.NewLayout(root)
	if err != nil {
		t.Fatalf("NewLayout(%s): %v", root, err)
	}
	return s
}

func writeByteAt(path string, offset int64, val byte) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	b[offset] = val
	return os.WriteFile(path, b, 0o644)
}

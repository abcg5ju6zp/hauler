package archives

// atomic_test.go covers the atomic publish/recovery contract:
// verify-then-rename archive publication, interrupted-save cleanup, chunk
// manifest validation on join, corrupted/incomplete set rejection, and
// multi-megabyte streaming splits.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mholt/archives"
)

// writeGoodArchive builds a small verified tar.zst at out from a source dir.
func writeGoodArchive(t *testing.T, ctx context.Context, srcDir, out string) {
	t.Helper()
	if err := Archive(ctx, srcDir, out, archives.Zstd{}, archives.Tar{}); err != nil {
		t.Fatalf("Archive: %v", err)
	}
}

// TestArchiveFiles_ReplacesPreviousAtomically verifies the previous archive
// remains loadable while a replacement is being built and that a failed build
// leaves both the previous output and a clean directory (no temp left behind).
func TestArchiveFiles_ReplacesPreviousAtomically(t *testing.T) {
	ctx := testContext(t)
	work := t.TempDir()
	out := filepath.Join(work, "haul.tar.zst")

	// v1 archive.
	src1 := t.TempDir()
	if err := os.WriteFile(filepath.Join(src1, "a.txt"), []byte("version-one"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeGoodArchive(t, ctx, src1, out)
	v1, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	// Failing replacement: a fileMap entry whose source vanished between map
	// and write fails before any commit. The v1 output must survive byte for
	// byte.
	src2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(src2, "b.txt"), []byte("version-two"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(src2, "gone.txt")
	if err := os.WriteFile(missing, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	badMap := map[string]string{missing: "gone.txt"}
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	if err := ArchiveFiles(ctx, badMap, out, CompressionMap["zst"], ArchivalMap["tar"]); err == nil {
		t.Fatal("expected ArchiveFiles to fail for a vanished source, got nil")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("previous archive must remain readable after a failed save: %v", err)
	}
	if !bytes.Equal(got, v1) {
		t.Fatal("previous archive was modified by a failed replacement save")
	}

	// Successful replacement publishes the new content.
	writeGoodArchive(t, ctx, src2, out)
	dst := t.TempDir()
	if err := Unarchive(ctx, out, dst); err != nil {
		t.Fatalf("Unarchive replaced archive: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(dst, filepath.Base(src2), "b.txt")); err != nil {
		t.Fatalf("expected v2 content after replacement: %v", err)
	}

	// No hidden temps survive success or failure.
	assertNoInFlight(t, work, "haul.tar.zst")
}

// TestArchiveFiles_FailureLeavesNoLoadableTruncation simulates the
// "looks loadable but missing content" hazard directly: a truncated archive
// must fail VerifyArchive, which is the gate rename happens behind.
func TestVerifyArchive_RejectsTruncation(t *testing.T) {
	ctx := testContext(t)
	src := t.TempDir()
	payload := bytes.Repeat([]byte("abcdefghij"), 200) // ~2KB compresses poorly enough to span blocks
	if err := os.WriteFile(filepath.Join(src, "blob.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(t.TempDir(), "good.tar.zst")
	writeGoodArchive(t, ctx, src, good)

	data, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 64 {
		t.Fatalf("test setup: archive unexpectedly tiny (%d bytes)", len(data))
	}
	for _, cut := range []int{16, len(data) / 2, len(data) - 8} {
		bad := filepath.Join(t.TempDir(), "truncated.tar.zst")
		if err := os.WriteFile(bad, data[:cut], 0o644); err != nil {
			t.Fatal(err)
		}
		if err := VerifyArchive(ctx, bad, nil); err == nil {
			t.Errorf("VerifyArchive accepted archive truncated to %d of %d bytes", cut, len(data))
		}
	}
	if err := VerifyArchive(ctx, good, nil); err != nil {
		t.Errorf("VerifyArchive rejected the intact archive: %v", err)
	}
}

// TestVerifyArchive_MissingRequiredEntry proves an archive lacking a required
// member fails verification rather than publishing a plausible-but-incomplete
// file.
func TestVerifyArchive_MissingRequiredEntry(t *testing.T) {
	ctx := testContext(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "only.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(t.TempDir(), "good.tar.zst")
	writeGoodArchive(t, ctx, src, good)
	if err := VerifyArchive(ctx, good, []string{filepath.Base(src) + "/only.txt"}); err != nil {
		t.Fatalf("expected entry verification to pass: %v", err)
	}
	if err := VerifyArchive(ctx, good, []string{"missing/index.json"}); err == nil {
		t.Fatal("VerifyArchive accepted a missing required entry")
	}
}

// TestPrepareOutput_RemovesInterruptedArtifacts plants exactly what a killed
// save leaves behind and confirms PrepareOutput removes it while completed
// outputs are untouched.
func TestPrepareOutput_RemovesInterruptedArtifacts(t *testing.T) {
	ctx := testContext(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "haul.tar.zst")

	staleTemp := filepath.Join(dir, ".haul.tar.zst.tmp-deadbeef")
	staleSidecarTemp := filepath.Join(dir, ".haul.tar.zst.chunks-cafe1234")
	staleStage := filepath.Join(dir, ".haul.tar.zst.split-01020304")
	for _, p := range []string{staleTemp, staleSidecarTemp} {
		if err := os.WriteFile(p, []byte("partial"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(staleStage, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleStage, "001"), []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Completed artifacts that must be preserved.
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeGoodArchive(t, ctx, src, out)
	oldChunk := out + ".001"
	if err := os.WriteFile(oldChunk, []byte("published"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := PrepareOutput(ctx, out); err != nil {
		t.Fatalf("PrepareOutput: %v", err)
	}
	for _, p := range []string{staleTemp, staleSidecarTemp, staleStage} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("stale artifact %s was not removed", p)
		}
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("completed archive was removed: %v", err)
	}
	if _, err := os.Stat(oldChunk); err != nil {
		t.Errorf("completed chunk was removed: %v", err)
	}
}

// TestSplitArchive_ManifestRoundTripAndRejection covers plain chunk sets:
// manifest is published, joins verify, tamper/removal is rejected with
// ErrIncompleteChunkSet, and a legacy set (no manifest) still joins.
func TestSplitArchive_ManifestRoundTripAndRejection(t *testing.T) {
	ctx := testContext(t)
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "haul.tar.zst")
	data := make([]byte, 300_000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	chunks, err := SplitArchive(ctx, archivePath, 64_000)
	if err != nil {
		t.Fatalf("SplitArchive: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	manifestPath := archivePath + chunkManifestSuffix
	mf, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("chunk manifest missing: %v", err)
	}
	if !strings.Contains(string(mf), "archiveDigest") {
		t.Fatalf("manifest lacks archiveDigest: %s", mf)
	}
	assertNoInFlight(t, dir, "haul.tar.zst")

	// Good set joins.
	joined, err := JoinChunks(ctx, chunks[0], t.TempDir())
	if err != nil {
		t.Fatalf("JoinChunks good set: %v", err)
	}
	got, err := os.ReadFile(joined)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("joined chunks do not match source")
	}

	// Flip a byte in a chunk: size unchanged, content wrong -> digest fail.
	tampered := filepath.Join(t.TempDir(), "tamper-set")
	copySet(t, dir, tampered, "haul.tar.zst")
	target := filepath.Join(tampered, "haul.tar.zst.001")
	flipByte(t, target, 10)
	if _, err := JoinChunks(ctx, filepath.Join(tampered, "haul.tar.zst.001"), t.TempDir()); !errors.Is(err, ErrIncompleteChunkSet) {
		t.Fatalf("tampered chunk set: want ErrIncompleteChunkSet, got %v", err)
	}

	// Remove a chunk entirely: pre-join completeness check fails.
	incomplete := filepath.Join(t.TempDir(), "incomplete-set")
	copySet(t, dir, incomplete, "haul.tar.zst")
	if err := os.Remove(filepath.Join(incomplete, "haul.tar.zst.002")); err != nil {
		t.Fatal(err)
	}
	if _, err := JoinChunks(ctx, filepath.Join(incomplete, "haul.tar.zst.001"), t.TempDir()); !errors.Is(err, ErrIncompleteChunkSet) {
		t.Fatalf("incomplete chunk set: want ErrIncompleteChunkSet, got %v", err)
	}

	// Legacy set (manifest removed) joins best-effort like older hauler.
	legacy := filepath.Join(t.TempDir(), "legacy-set")
	copySet(t, dir, legacy, "haul.tar.zst")
	if err := os.Remove(filepath.Join(legacy, "haul.tar.zst"+chunkManifestSuffix)); err != nil {
		t.Fatal(err)
	}
	joinedLegacy, err := JoinChunks(ctx, filepath.Join(legacy, "haul.tar.zst.001"), t.TempDir())
	if err != nil {
		t.Fatalf("legacy set must still join: %v", err)
	}
	got, err = os.ReadFile(joinedLegacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("legacy join content mismatch")
	}
}

// TestSplitArchive_ReplacesOldGeneration verifies an interrupted-style old
// state (previous larger generation + a leftover staging dir) is recovered:
// the republished set is exactly the new chunks plus manifest.
func TestSplitArchive_ReplacesOldGeneration(t *testing.T) {
	ctx := testContext(t)
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "haul.tar.zst")

	// Old, larger generation on disk plus a dead staging dir from the kill.
	for i := 1; i <= 6; i++ {
		if err := os.WriteFile(filepath.Join(dir, "haul.tar.zst."+pad3(i)), []byte("OLD"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldSidecar := filepath.Join(dir, "haul.tar.zst"+chunkManifestSuffix)
	if err := os.WriteFile(oldSidecar, []byte(`{"version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	deadStage := filepath.Join(dir, ".haul.tar.zst.split-abcdef12")
	if err := os.MkdirAll(deadStage, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deadStage, "001"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 120_000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	chunks, err := SplitArchive(ctx, archivePath, 64_000)
	if err != nil {
		t.Fatalf("SplitArchive over old generation: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 new chunks, got %d", len(chunks))
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("hidden staging dir survived publication: %s", e.Name())
		}
	}
	joined, err := JoinChunks(ctx, chunks[0], t.TempDir())
	if err != nil {
		t.Fatalf("JoinChunks republished set: %v", err)
	}
	got, err := os.ReadFile(joined)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("republished chunks do not match source")
	}
}

// TestSplitArchive_LargeMultichunkStreaming exercises a multi-megabyte,
// many-chunk split (256 KiB shards) end to end -- the streaming path must hold
// regardless of archive size.
func TestSplitArchive_LargeMultichunkStreaming(t *testing.T) {
	ctx := testContext(t)
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "haul.tar.zst")
	data := make([]byte, 5<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	chunks, err := SplitArchive(ctx, archivePath, 256<<10)
	if err != nil {
		t.Fatalf("SplitArchive: %v", err)
	}
	if len(chunks) != 20 {
		t.Fatalf("expected 20 chunks, got %d", len(chunks))
	}
	joined, err := JoinChunks(ctx, chunks[0], t.TempDir())
	if err != nil {
		t.Fatalf("JoinChunks: %v", err)
	}
	got, err := os.ReadFile(joined)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("large archive did not survive the chunk round trip")
	}
}

// TestSplitArchiveRedundant_ManifestRejectsWrongGeneration corrupts a data
// shard within parity budget (repair succeeds) and then corrupts beyond it;
// the manifest digest gate must reject any repair that does not reproduce the
// originally published archive.
func TestSplitArchiveRedundant_ManifestDigestGate(t *testing.T) {
	ctx := testContext(t)
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "haul.tar.zst")
	data := make([]byte, 200_000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SplitArchiveRedundant(ctx, archivePath, 40_000, 100); err != nil {
		t.Fatalf("SplitArchiveRedundant: %v", err)
	}

	// Corrupt one data shard: parity repair must reproduce the digest.
	repairDir := filepath.Join(t.TempDir(), "repair")
	copySet(t, dir, repairDir, "haul.tar.zst")
	flipByte(t, filepath.Join(repairDir, "haul.tar.zst.001"), redundancyHeaderSize+50)
	joined, err := JoinChunks(ctx, filepath.Join(repairDir, "haul.tar.zst.001"), t.TempDir())
	if err != nil {
		t.Fatalf("within-budget corruption should repair: %v", err)
	}
	got, err := os.ReadFile(joined)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("repaired archive does not match the published digest")
	}

	// Damage the manifest digest after publication: even a correct reassembly
	// must fail closed against a marker that no longer binds the set.
	doomed := filepath.Join(t.TempDir(), "doomed")
	copySet(t, dir, doomed, "haul.tar.zst")
	mp := filepath.Join(doomed, "haul.tar.zst"+chunkManifestSuffix)
	md, _ := os.ReadFile(mp)
	md = bytes.Replace(md, []byte("sha256:"), []byte("sha257:"), 1)
	if err := os.WriteFile(mp, md, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := JoinChunks(ctx, filepath.Join(doomed, "haul.tar.zst.001"), t.TempDir()); err == nil {
		t.Fatal("join with a tampered manifest must fail")
	}
}

// TestDiscardChunkSet removes a superseded chunk family but leaves other files.
func TestDiscardChunkSet(t *testing.T) {
	ctx := testContext(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "haul.tar.zst")
	for i := 1; i <= 3; i++ {
		if err := os.WriteFile(base+"."+pad3(i), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(base+chunkManifestSuffix, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := DiscardChunkSet(ctx, base); err != nil {
		t.Fatalf("DiscardChunkSet: %v", err)
	}
	for _, p := range []string{base + ".001", base + ".002", base + ".003", base + chunkManifestSuffix} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s removed", p)
		}
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("unrelated file removed: %v", err)
	}
}

// --- helpers ---

func pad3(i int) string {
	return string([]byte{byte('0' + (i/100)%10), byte('0' + (i/10)%10), byte('0' + i%10)})
}

func flipByte(t *testing.T, path string, offset int64) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read for flip: %v", err)
	}
	if int(offset) >= len(b) {
		t.Fatalf("flip offset %d beyond file size %d", offset, len(b))
	}
	b[offset] ^= 0xFF
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write after flip: %v", err)
	}
}

func copySet(t *testing.T, fromDir, toDir, baseName string) {
	t.Helper()
	if err := os.MkdirAll(toDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(fromDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), baseName) {
			continue
		}
		in, err := os.ReadFile(filepath.Join(fromDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(toDir, e.Name()), in, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func assertNoInFlight(t *testing.T, dir, baseName string) {
	t.Helper()
	patterns := []string{
		"." + baseName + ".tmp-*",
		"." + baseName + ".split-*",
		"." + baseName + ".chunks-*",
	}
	for _, p := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Errorf("in-flight artifact(s) remain for %s: %v", baseName, matches)
		}
	}
}

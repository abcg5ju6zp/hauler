package archives

// Atomic publish primitives for hauler archives.
//
// Publication contract enforced by this file:
//
//   - A new archive is written to a uniquely-named hidden temp file in the
//     output file's own directory, fully verified while still under that temp
//     name, and only then renamed over the final path. A reader therefore
//     only ever observes the previous complete archive or the new complete
//     archive -- never a truncated one.
//   - Chunk sets are built inside a private staging directory, verified end
//     to end, and published over the previous generation. A chunk manifest
//     sidecar (<base>.chunks.json) carrying the joined archive's size and
//     digest is the commit marker: it is renamed into place last. Loads that
//     find it verify the set strictly and fail loudly on anything an
//     interrupted save could leave behind. Sets without a sidecar (written
//     by older hauler versions) keep the legacy best-effort behavior.
//   - Every failure path removes only its own temp/staging artifacts; final
//     names are touched exclusively by verified renames. PrepareOutput sweeps
//     leftovers a killed process could not remove, so a retry starts clean.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/mholt/archives"

	"hauler.dev/go/hauler/v2/pkg/log"
)

const (
	// chunkManifestSuffix is appended to a chunk set's base path (e.g.
	// haul.tar.zst.chunks.json) for the commit marker that records every
	// chunk name/size plus the joined archive's size and digest. It never
	// matches chunkInfo's <base>.NNN pattern, so glob-based chunk discovery
	// can never mistake it for a shard.
	chunkManifestSuffix = ".chunks.json"

	// chunkManifestVersion is the sidecar schema version.
	chunkManifestVersion = 1

	// temp name templates: the archive temp is .<base>.tmp-<rand>, split
	// staging dirs are .<base>.split-<rand>/, and the sidecar temp is
	// .<base>.chunks-<rand>.
	tempArchivePattern = ".%s.tmp-*"
	tempSplitPattern   = ".%s.split-*"
	tempSidecarPattern = ".%s.chunks-*"
)

// ErrIncompleteChunkSet marks a chunk set whose manifest cannot validate it,
// i.e. an interrupted or corrupted publication. Callers may retry the save
// that produces the set; no partial content has been merged anywhere yet.
var ErrIncompleteChunkSet = errors.New("incomplete or corrupted chunk set")

// syncDir fsyncs a directory so a rename into it survives power loss; the
// file's own fsync does not persist the directory entry that points at it.
// No-op on Windows; EINVAL/ENOTSUP are tolerated for NFS/SMB mounts that do
// not support directory fsync (mirrors content.syncDir's policy).
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			return nil
		}
		return err
	}
	return d.Close()
}

// fsyncFile flushes f's writes to stable storage. Writes that overflow the
// disk frequently surface here (or at Close), which is why the archive
// pipeline cannot rely on mholt/archives' deferred compressor close -- that
// error is discarded by the library.
func fsyncFile(f *os.File) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return f.Sync()
}

// tempArtifacts returns glob patterns for every kind of in-flight artifact
// associated with outfile (half-written archive temp, split staging dirs,
// sidecar temps).
func tempArtifacts(outfile string) []string {
	dir := filepath.Dir(outfile)
	base := filepath.Base(outfile)
	return []string{
		filepath.Join(dir, fmt.Sprintf(tempArchivePattern, base)),
		filepath.Join(dir, fmt.Sprintf(tempSplitPattern, base)),
		filepath.Join(dir, fmt.Sprintf(tempSidecarPattern, base)),
	}
}

// PrepareOutput removes temp files and staging directories left by an earlier
// save to outfile that exited before publishing (kill -9, power loss, panic).
// A completed archive or chunk set at outfile is never touched: only the
// hidden, uniquely-named in-flight patterns are removed. Safe to call when no
// leftovers exist.
func PrepareOutput(ctx context.Context, outfile string) error {
	l := log.FromContext(ctx)
	removed := 0
	for _, pattern := range tempArtifacts(outfile) {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("inspecting in-flight artifacts for [%s]: %w", outfile, err)
		}
		for _, m := range matches {
			if err := os.RemoveAll(m); err != nil {
				return fmt.Errorf("removing in-flight artifact [%s] from an interrupted save: %w", m, err)
			}
			removed++
		}
	}
	if removed > 0 {
		l.Warnf("removed [%d] in-flight artifact(s) left by an interrupted save of [%s]", removed, outfile)
	}
	return nil
}

// commitFile closes (when non-nil), fsyncs, and atomically renames tmpPath
// over finalPath, then fsyncs the directory. Both paths must be on the same
// filesystem -- callers create temps next to the final path for this reason
// (and so ENOSPC is raised on the target volume, not a scratch one).
func commitFile(tmpPath, finalPath string) error {
	dir := filepath.Dir(finalPath)
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("syncing directory before commit of [%s]: %w", finalPath, err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("committing [%s]: %w", finalPath, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("syncing directory after commit of [%s]: %w", finalPath, err)
	}
	return nil
}

// VerifyArchive streams the whole archive through its full decompression and
// archival extraction pipeline, discarding payloads, proving the file is
// structurally complete. A truncation caused by ENOSPC or a killed writer
// fails here: the compressed stream's trailing checksum/footer and the tar
// trailer cannot validate. When required is non-empty, every named entry
// must also be present in the archive.
func VerifyArchive(ctx context.Context, archivePath string, required []string) error {
	l := log.FromContext(ctx)

	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening archive for verification [%s]: %w", archivePath, err)
	}
	defer archiveFile.Close()

	format, input, err := archives.Identify(ctx, archivePath, archiveFile)
	if err != nil {
		return fmt.Errorf("identifying archive for verification [%s]: %w", archivePath, err)
	}
	extractor, ok := format.(archives.Extractor)
	if !ok {
		return fmt.Errorf("archive [%s] is not extractable for verification", archivePath)
	}

	want := make(map[string]bool, len(required))
	for _, name := range required {
		want[name] = true
	}
	seen := make(map[string]bool, len(required))
	fileEntries := 0

	handler := func(_ context.Context, f archives.FileInfo) error {
		if f.IsDir() || f.LinkTarget != "" {
			return nil
		}
		fileEntries++
		if want[f.NameInArchive] {
			seen[f.NameInArchive] = true
		}
		rc, openErr := f.Open()
		if openErr != nil {
			return fmt.Errorf("opening entry [%s] during verification: %w", f.NameInArchive, openErr)
		}
		defer rc.Close()
		if _, copyErr := io.Copy(io.Discard, rc); copyErr != nil {
			return fmt.Errorf("reading entry [%s] during verification: %w", f.NameInArchive, copyErr)
		}
		return nil
	}

	if err := extractor.Extract(ctx, input, handler); err != nil {
		return fmt.Errorf("archive [%s] failed verification: %w", archivePath, err)
	}

	if len(want) > 0 {
		var missing []string
		for name := range want {
			if !seen[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return fmt.Errorf("archive [%s] is missing [%d] expected entr(ies) after verification: %s", archivePath, len(missing), strings.Join(missing, ", "))
		}
	}
	if fileEntries == 0 {
		return fmt.Errorf("archive [%s] contains no files after verification", archivePath)
	}
	l.Debugf("verified archive [%s] (%d file entr(ies))", archivePath, fileEntries)
	return nil
}

// newTempFile creates a hidden, uniquely-named temp file in dir using
// pattern (a os.CreateTemp pattern containing "*").
func newTempFile(dir, pattern string) (*os.File, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	// CreateTemp defaults to 0600; published archives are 0644 like every
	// other hauler output file. Chmod before content is written so the mode
	// is correct even if the process is killed mid-write.
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}

// randomToken returns 8 hex characters of CSPRNG data for unique temp names.
func randomToken() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not a situation to continue publishing
		// archives in; a fixed fallback would defeat unique temp names.
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------------------
// chunk manifest (publication commit marker)
// ---------------------------------------------------------------------------

// chunkManifestFile describes one published chunk.
type chunkManifestFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// chunkManifest is the JSON sidecar committed last when a chunk set is
// published. It binds the set's chunks to the joined archive's exact size and
// digest, so a load can distinguish a complete set from a mix of generations
// or a half-written shard without trusting file names alone.
type chunkManifest struct {
	Version        int                 `json:"version"`
	SetID          string              `json:"setId"`
	ArchiveSize    int64               `json:"archiveSize"`
	ArchiveDigest  string              `json:"archiveDigest"`
	Redundant      bool                `json:"redundant,omitempty"`
	Chunks         []chunkManifestFile `json:"chunks"`
}

func chunkManifestPath(base string) string {
	return base + chunkManifestSuffix
}

// loadChunkManifest reads the sidecar for the chunk set rooted at base.
// present is false (without error) when no sidecar exists -- a set written by
// an older hauler version, which the caller must treat as legacy.
func loadChunkManifest(base string) (m *chunkManifest, present bool, err error) {
	p := chunkManifestPath(base)
	data, rerr := os.ReadFile(p)
	if rerr != nil {
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("reading chunk manifest [%s]: %w", p, rerr)
	}
	var got chunkManifest
	if uerr := json.Unmarshal(data, &got); uerr != nil {
		return nil, false, fmt.Errorf("parsing chunk manifest [%s]: %w ... the chunk set is from an interrupted or corrupted save", p, uerr)
	}
	if got.Version != chunkManifestVersion || len(got.Chunks) == 0 || got.ArchiveDigest == "" {
		return nil, false, fmt.Errorf("chunk manifest [%s] is invalid (version=%d, chunks=%d, digest=%q)", p, got.Version, len(got.Chunks), got.ArchiveDigest)
	}
	return &got, true, nil
}

// writeChunkManifest publishes the sidecar via temp-file + fsync + rename so
// the marker itself can never be observed half-written.
func writeChunkManifest(base string, m *chunkManifest) error {
	dir := filepath.Dir(base)
	tmp, err := newTempFile(dir, fmt.Sprintf(tempSidecarPattern, filepath.Base(base)))
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing chunk manifest for [%s]: %w", base, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing chunk manifest for [%s]: %w", base, err)
	}
	if err := commitFile(tmpPath, chunkManifestPath(base)); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// verifyJoinedDigest streams path through sha256 and checks size+digest
// against the manifest's record of the archive bytes the chunks must
// reassemble into.
func verifyJoinedDigest(path string, m *chunkManifest) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fmt.Errorf("reading reassembled archive for verification: %w", err)
	}
	if n != m.ArchiveSize {
		return fmt.Errorf("%w: reassembled size %d does not match manifest size %d", ErrIncompleteChunkSet, n, m.ArchiveSize)
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != m.ArchiveDigest {
		return fmt.Errorf("%w: reassembled digest %s does not match manifest digest %s", ErrIncompleteChunkSet, got, m.ArchiveDigest)
	}
	return nil
}

// assertChunkSetComplete is the strict pre-join check for plain (non
// redundant) sets with a manifest: every listed chunk file must exist at
// exactly its recorded size, and no chunk from a previous, larger generation
// may be mixed in. Redundant sets do not use this check because parity is
// allowed to replace missing or corrupt shards.
func assertChunkSetComplete(base string, m *chunkManifest) error {
	dir := filepath.Dir(base)
	listed := make(map[string]int64, len(m.Chunks))
	for _, c := range m.Chunks {
		listed[c.Name] = c.Size
	}

	problems := make([]string, 0)
	for name, size := range listed {
		info, err := os.Stat(filepath.Join(dir, name))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			problems = append(problems, fmt.Sprintf("missing chunk [%s]", name))
		case err != nil:
			problems = append(problems, fmt.Sprintf("unreadable chunk [%s]: %v", name, err))
		case info.IsDir():
			problems = append(problems, fmt.Sprintf("chunk path [%s] is a directory", name))
		case info.Size() != size:
			problems = append(problems, fmt.Sprintf("chunk [%s] is %d bytes, manifest records %d", name, info.Size(), size))
		}
	}

	// Catch an old-generation leftover that the glob would otherwise join
	// silently: any chunk-shaped sibling of base not in the manifest is a mix
	// of two saves.
	all, err := filepath.Glob(base + ".*")
	if err != nil {
		return fmt.Errorf("inspecting chunk set directory: %w", err)
	}
	for _, p := range all {
		if b, idx, ok := chunkInfo(p); ok && filepath.Clean(b) == filepath.Clean(base) {
			if _, known := listed[filepath.Base(p)]; !known {
				problems = append(problems, fmt.Sprintf("unexpected chunk [%s] not part of this save (index %d)", filepath.Base(p), idx))
			}
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%w: %s", ErrIncompleteChunkSet, strings.Join(problems, "; "))
	}
	return nil
}

// DiscardChunkSet removes the published chunk set and sidecar for base --
// used when a non-chunked save supersedes a previous chunked save to the same
// base name, so the retired chunks cannot be mistaken for the new archive's
// contents. Called only after the new single-file archive has itself been
// verified and committed.
func DiscardChunkSet(ctx context.Context, base string) error {
	l := log.FromContext(ctx)
	matches, err := filepath.Glob(base + ".*")
	if err != nil {
		return err
	}
	removed := 0
	for _, p := range matches {
		if b, _, ok := chunkInfo(p); ok && filepath.Clean(b) == filepath.Clean(base) {
			if err := os.Remove(p); err != nil {
				return fmt.Errorf("removing superseded chunk [%s]: %w", p, err)
			}
			removed++
		}
	}
	if err := os.Remove(chunkManifestPath(base)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing superseded chunk manifest: %w", err)
	}
	if removed > 0 {
		l.Infof("removed [%d] chunk(s) superseded by the single-file archive [%s]", removed, base)
	}
	return nil
}

package archives

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/mholt/archives"
	"hauler.dev/go/hauler/v2/pkg/log"
)

// maps to handle compression types
var CompressionMap = map[string]archives.Compression{
	"gz":  archives.Gz{},
	"bz2": archives.Bz2{},
	"xz":  archives.Xz{},
	"zst": archives.Zstd{},
	"lz4": archives.Lz4{},
	"br":  archives.Brotli{},
}

// maps to handle archival types
var ArchivalMap = map[string]archives.Archival{
	"tar": archives.Tar{},
	"zip": archives.Zip{},
}

// check if a path exists
func isExist(path string) bool {
	_, statErr := os.Stat(path)
	return !os.IsNotExist(statErr)
}

// archives the files in a directory
// dir: the directory to Archive
// outfile: the output file
// compression: the compression to use (gzip, bzip2, etc.)
// archival: the archival to use (tar, zip, etc.)
func Archive(ctx context.Context, dir, outfile string, compression archives.Compression, archival archives.Archival) error {
	l := log.FromContext(ctx)
	l.Debugf("starting the archival process for [%s]", dir)

	if !isExist(dir) {
		errMsg := fmt.Errorf("directory [%s] does not exist, cannot proceed with archival", dir)
		l.Debugf("%s", errMsg.Error())
		return errMsg
	}

	// FilesFromDisk maps a directory key to the directory's *contents*
	// nested one level under the map value: {dir: "blobs"} yields an archive
	// tree rooted at "blobs/<dir's children>", not "blobs/<dir's basename>/...".
	// So the source dir's basename must be supplied explicitly as the map
	// value to reproduce Archive's historical top-level-named layout.
	archiveDirName := filepath.Base(filepath.Clean(dir))
	if dir == "." {
		archiveDirName = ""
	}
	return ArchiveFiles(ctx, map[string]string{dir: archiveDirName}, outfile, compression, archival)
}

// ArchiveFiles archives an explicit disk-path -> archive-path map rather than a
// whole directory, so save can substitute generated files (filtered index.json,
// manifest.json) without ever mutating the source store directory (#744).
//
// Publication is atomic: the archive is built in a hidden temp file next to
// outfile, fully verified (every entry streamed back through decompression),
// and only then renamed over outfile. A pre-existing outfile therefore stays a
// complete, loadable archive until the replacement has been verified, and an
// ENOSPC/kill mid-build leaves nothing at the final path but a removable temp.
// See atomic.go for the full publication contract.
func ArchiveFiles(ctx context.Context, fileMap map[string]string, outfile string, compression archives.Compression, archival archives.Archival) error {
	l := log.FromContext(ctx)

	// Defensive in case the caller did not run PrepareOutput itself: sweep
	// temps from a previously interrupted attempt at THIS outfile before
	// minting a new one. Never touches a completed outfile or chunk set.
	if err := PrepareOutput(ctx, outfile); err != nil {
		return err
	}

	// map files on disk to their paths in the archive
	l.Debugf("mapping files for archive [%s]", outfile)
	// mholt/archives.FilesFromDisk ranges over fileMap directly, and Go
	// randomizes map iteration order per range -- even two ranges over the same
	// map in one process can differ. Left alone, that made two saves of an
	// identical store produce byte-different .tar.zst files and shifted
	// --chunk-size boundaries. Each root is walked independently (no shared
	// state across roots in FilesFromDisk), so calling it once per sorted key
	// and concatenating gives the same []FileInfo the library would produce,
	// just in a fixed order.
	keys := make([]string, 0, len(fileMap))
	for k := range fileMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var files []archives.FileInfo
	for _, rootOnDisk := range keys {
		rootFiles, err := archives.FilesFromDisk(ctx, nil, map[string]string{rootOnDisk: fileMap[rootOnDisk]})
		if err != nil {
			errMsg := fmt.Errorf("error mapping files: %w", err)
			l.Debugf("%s", errMsg.Error())
			return errMsg
		}
		files = append(files, rootFiles...)
	}
	l.Debugf("successfully mapped files for archive [%s]", outfile)

	// Names every non-directory, non-link entry must have in the finished
	// archive; verification fails if any are missing after the round trip.
	required := make([]string, 0, len(files))
	for _, f := range files {
		if !f.IsDir() && f.LinkTarget == "" {
			required = append(required, f.NameInArchive)
		}
	}

	// create the hidden temp output file in outfile's own directory so the
	// final rename is atomic and a full target volume reports ENOSPC here
	// rather than in some scratch directory.
	dir := filepath.Dir(outfile)
	base := filepath.Base(outfile)
	l.Debugf("creating temporary output for [%s]", outfile)
	outf, err := newTempFile(dir, fmt.Sprintf(tempArchivePattern, base))
	if err != nil {
		errMsg := fmt.Errorf("error creating temporary output for [%s]: %w", outfile, err)
		l.Debugf("%s", errMsg.Error())
		return errMsg
	}
	tmpPath := outf.Name()
	committed := false
	defer func() {
		// Unconditional cleanup: harmless ENOENT after commit, essential
		// after any error in the verify/rename window below.
		if !committed {
			l.Debugf("removing unverified temporary output [%s]", tmpPath)
			os.Remove(tmpPath)
		}
	}()

	// define the archive format
	l.Debugf("defining the archive format: [%T]/[%T]", archival, compression)
	format := archives.CompressedArchive{
		Compression: compression,
		Archival:    archival,
	}

	// create the archive. format.Archive closes the compression writer via a
	// deferred Close whose error is DISCARDED by the library, so its nil
	// return cannot be trusted to mean the trailer/footer flush succeeded.
	// The fsync below and the VerifyArchive round trip after close are what
	// catch a truncated stream (ENOSPC at flush, killed process, etc.).
	l.Debugf("starting archive for [%s]", tmpPath)
	if err := format.Archive(ctx, outf, files); err != nil {
		outf.Close()
		errMsg := fmt.Errorf("error during archive creation for output file [%s]: %w", outfile, err)
		l.Debugf("%s", errMsg.Error())
		return errMsg
	}
	if err := fsyncFile(outf); err != nil {
		outf.Close()
		return fmt.Errorf("flushing archive [%s] to disk (disk full?): %w", tmpPath, err)
	}
	// Close can surface the final buffered write failing -- do not ignore it.
	if err := outf.Close(); err != nil {
		return fmt.Errorf("closing archive [%s] (disk full?): %w", tmpPath, err)
	}

	// verify before publish: the temp result only becomes visible once the
	// whole archive has been proven complete.
	l.Debugf("verifying temporary archive [%s]", tmpPath)
	if err := VerifyArchive(ctx, tmpPath, required); err != nil {
		return fmt.Errorf("newly created archive failed verification; leaving existing [%s] untouched: %w", outfile, err)
	}

	// atomic publish over any previous complete archive.
	l.Debugf("committing verified archive [%s] -> [%s]", tmpPath, outfile)
	if err := commitFile(tmpPath, outfile); err != nil {
		return err
	}
	committed = true
	l.Debugf("archive created and verified successfully [%s]", outfile)
	return nil
}

// stagedChunk is one chunk produced inside the split staging directory.
type stagedChunk struct {
	// stagePath is the hidden, not-yet-published path.
	stagePath string
	// finalName is the published basename, e.g. haul.tar.zst.001.
	finalName string
	size      int64
}

// splitIntoStaging reads src in maxBytes ranges into hidden staged chunks,
// hashing the full source stream as it goes so the publisher can bind the
// finished set to an end-to-end digest. Nothing at a final chunk name is
// touched. Streaming throughout: memory use is one 32 KiB buffer regardless
// of archive size.
func splitIntoStaging(src io.Reader, archivePath, stageDir string, maxBytes int64) ([]stagedChunk, string, int64, error) {
	base := filepath.Base(archivePath)
	sum := sha256.New()
	reader := io.TeeReader(src, sum)

	var staged []stagedChunk
	buf := make([]byte, 32*1024)
	var totalSize int64
	var written int64
	var outf *os.File
	var outStage *stagedChunk

	closeCurrent := func() {
		if outf != nil {
			outf.Close()
			outf = nil
		}
	}

	for {
		remaining := maxBytes - written
		readSize := int64(len(buf))
		if readSize > remaining {
			readSize = remaining
		}

		n, readErr := reader.Read(buf[:readSize])
		if n > 0 {
			// chunks are only created once there's real data, so an archive
			// size that's an exact multiple of maxBytes never leaves a
			// trailing empty chunk behind.
			if outf == nil {
				idx := len(staged) + 1
				finalName := fmt.Sprintf("%s.%03d", base, idx)
				stagePath := filepath.Join(stageDir, fmt.Sprintf("%03d", idx))
				f, err := os.OpenFile(stagePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
				if err != nil {
					closeCurrent()
					return nil, "", 0, fmt.Errorf("failed to create chunk %d: %w", idx, err)
				}
				outf = f
				sc := stagedChunk{stagePath: stagePath, finalName: finalName}
				staged = append(staged, sc)
				outStage = &staged[len(staged)-1]
			}
			if _, err := outf.Write(buf[:n]); err != nil {
				closeCurrent()
				return nil, "", 0, fmt.Errorf("failed to write to chunk: %w", err)
			}
			written += int64(n)
			totalSize += int64(n)
			outStage.size += int64(n)
		}

		if readErr == io.EOF {
			closeCurrent()
			break
		}
		if readErr != nil {
			closeCurrent()
			return nil, "", 0, fmt.Errorf("failed to read archive: %w", readErr)
		}

		if written >= maxBytes {
			closeCurrent()
			written = 0
		}
	}

	if len(staged) == 0 {
		return nil, "", 0, fmt.Errorf("archive [%s] is empty; refusing to publish an empty chunk set", archivePath)
	}
	return staged, "sha256:" + hex.EncodeToString(sum.Sum(nil)), totalSize, nil
}

// verifyStagedChunks re-reads the staged chunks in order and checks they
// concatenate back to exactly the source's size and digest -- catching a
// short disk write or a swapped chunk before anything is published.
func verifyStagedChunks(staged []stagedChunk, wantDigest string, wantSize int64) error {
	sum := sha256.New()
	var n int64
	for _, sc := range staged {
		f, err := os.Open(sc.stagePath)
		if err != nil {
			return fmt.Errorf("opening staged chunk [%s] for verification: %w", sc.finalName, err)
		}
		nn, copyErr := io.Copy(sum, f)
		f.Close()
		if copyErr != nil {
			return fmt.Errorf("reading staged chunk [%s] for verification: %w", sc.finalName, copyErr)
		}
		n += nn
	}
	if n != wantSize {
		return fmt.Errorf("staged chunks total %d bytes, source archive is %d bytes", n, wantSize)
	}
	if got := "sha256:" + hex.EncodeToString(sum.Sum(nil)); got != wantDigest {
		return fmt.Errorf("staged chunks digest %s does not match source archive digest %s", got, wantDigest)
	}
	return nil
}

// publishStagedChunks is the chunk-set commit: staged files are renamed over
// the previous generation (verified content first, final names only at this
// point), the source archive is retired, old-generation leftovers removed, and
// the chunk manifest sidecar -- the marker loads validate against -- is
// committed last. The staging dir is removed on success. A failure anywhere
// leaves the staging dir for cleanup/inspection and never deletes the source
// archive unless the whole new set is visibly in place.
func publishStagedChunks(ctx context.Context, archivePath, stageDir string, staged []stagedChunk, setID, archiveDigest string, archiveSize int64, redundant bool) ([]string, error) {
	l := log.FromContext(ctx)
	dir := filepath.Dir(archivePath)

	// fsync staged contents before the renames so published names never point
	// at unflushed data.
	for _, sc := range staged {
		if err := syncFile(sc.stagePath); err != nil {
			return nil, fmt.Errorf("syncing staged chunk [%s]: %w", sc.finalName, err)
		}
	}

	finalChunks := make([]string, 0, len(staged))
	manifest := chunkManifest{
		Version:       chunkManifestVersion,
		SetID:         setID,
		ArchiveSize:   archiveSize,
		ArchiveDigest: archiveDigest,
		Redundant:     redundant,
	}
	for _, sc := range staged {
		finalPath := filepath.Join(dir, sc.finalName)
		if err := os.Rename(sc.stagePath, finalPath); err != nil {
			return nil, fmt.Errorf("publishing chunk [%s]: %w", sc.finalName, err)
		}
		finalChunks = append(finalChunks, finalPath)
		manifest.Chunks = append(manifest.Chunks, chunkManifestFile{Name: sc.finalName, Size: sc.size})
	}
	if err := syncDir(dir); err != nil {
		return nil, fmt.Errorf("syncing directory after publishing chunks: %w", err)
	}

	// New verified set is in place; only now is the superseded single-file
	// archive retired.
	if err := os.Remove(archivePath); err != nil {
		return nil, fmt.Errorf("removing source archive after chunk publication: %w", err)
	}
	if err := removeLeftoverChunks(ctx, archivePath, len(staged)); err != nil {
		return nil, err
	}

	// Commit marker last: its presence is what makes the set strictly
	// verifiable on load.
	if err := writeChunkManifest(archivePath, &manifest); err != nil {
		return nil, err
	}
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	if err := os.Remove(stageDir); err != nil {
		// Non-fatal: all final names are in place and verified; the empty
		// staging dir is swept by PrepareOutput on the next save.
		l.Debugf("failed to remove staging dir [%s] after publication: %v", stageDir, err)
	}
	return finalChunks, nil
}

// syncFile opens path and fsyncs it (post-rename durability for staged data).
func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if runtime.GOOS == "windows" {
		return nil
	}
	return f.Sync()
}

// SplitArchive splits an existing, verified archive into chunks of at most
// maxBytes each. Chunks are built in a private staging directory, verified to
// rejoin to the source archive's exact bytes, then atomically published as
// <archivePath>.001, .002, ... with a <archivePath>.chunks.json manifest
// binding the set to the joined archive's size and digest. The original
// archive is removed only after the whole new set is in place. An interrupted
// split leaves no final-name half chunks -- just a removable staging dir.
func SplitArchive(ctx context.Context, archivePath string, maxBytes int64) ([]string, error) {
	l := log.FromContext(ctx)

	if maxBytes <= 0 {
		return nil, fmt.Errorf("maxBytes must be greater than zero, received %d", maxBytes)
	}

	// Defensive standalone use (SaveCmd already swept): clear staging dirs a
	// previously killed split left behind before creating a new one.
	if err := PrepareOutput(ctx, archivePath); err != nil {
		return nil, err
	}

	info, err := os.Stat(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat archive for splitting: %w", err)
	}

	src, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive for splitting: %w", err)
	}

	stageDir, err := os.MkdirTemp(filepath.Dir(archivePath), fmt.Sprintf(tempSplitPattern, filepath.Base(archivePath)))
	if err != nil {
		src.Close()
		return nil, fmt.Errorf("failed to create staging directory for chunk split: %w", err)
	}
	published := false
	defer func() {
		if !published {
			// Aborted/failed split: final names were never (fully) touched
			// and the source archive is intact; drop our staging work.
			os.RemoveAll(stageDir)
		}
	}()

	staged, digest, size, err := splitIntoStaging(src, archivePath, stageDir, maxBytes)
	src.Close()
	if err != nil {
		return nil, err
	}
	if info.Size() != size {
		return nil, fmt.Errorf("split read %d bytes but archive is %d bytes", size, info.Size())
	}
	if err := verifyStagedChunks(staged, digest, size); err != nil {
		return nil, fmt.Errorf("verifying staged chunks before publication: %w", err)
	}

	chunks, err := publishStagedChunks(ctx, archivePath, stageDir, staged, randomToken(), digest, size, false)
	if err != nil {
		return nil, err
	}
	published = true
	l.Infof("split archive [%s] into %d verified chunk(s)", filepath.Base(archivePath), len(chunks))
	return chunks, nil
}

// removeLeftoverChunks deletes chunks numbered above keep that an earlier, larger save left behind, since load treats every matching chunk as part of the set.
func removeLeftoverChunks(ctx context.Context, archivePath string, keep int) error {
	all, err := filepath.Glob(archivePath + ".*")
	if err != nil {
		return err
	}
	removed := 0
	for _, m := range all {
		if base, idx, ok := chunkInfo(m); ok && base == filepath.Clean(archivePath) && idx > keep {
			if err := os.Remove(m); err != nil {
				return fmt.Errorf("failed to remove leftover chunk [%s]: %w", m, err)
			}
			removed++
		}
	}
	if removed > 0 {
		log.FromContext(ctx).Infof("removed [%d] leftover chunk(s) from a previous save", removed)
	}
	return nil
}

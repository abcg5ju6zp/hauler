package store

// Startup recovery: sweep the unmistakable remnants of interrupted writes.
//
// Every durable write in a store either lands via temp-file + fsync + rename
// (index.json, store.json, blobs) or is staged under a hidden name. A process
// killed (SIGKILL, power loss) between temp creation and rename cannot leave
// a corrupt final file, but it CAN leave the temp file behind, and enough
// accumulated temps waste space and confuse operators browsing the store.
//
// The patterns below match ONLY the internal temp naming conventions -- never
// user content (blobs are 64-hex digest names without a ".tmp-" segment).
// Unreferenced but complete blobs from an interrupted load are deliberately
// NOT removed here: they are valid content-addressed data, indistinguishable
// from a pre-staged cache, and `store cleanup` reclaims them explicitly.

import (
	"os"
	"path/filepath"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	zlog "github.com/rs/zerolog/log"

	"hauler.dev/go/hauler/v2/pkg/consts"
)

// staleTempGrace bounds how fresh an in-flight temp may be before startup
// cleanup treats it as abandoned. A live writer -- especially a large layer
// pull whose blob temp legitimately exists for minutes -- must never have its
// temp deleted out from under another open of the same store. Killed-process
// leftovers are swept on any later startup that runs after this grace window;
// same-path save retries reclaim immediately via archives.PrepareOutput, which
// runs under the save publication lock.
const staleTempGrace = 10 * time.Minute

// cleanupInterruptedArtifacts removes temp files a crashed hauler process
// could not clean up in root, provided they predate staleTempGrace. Best
// effort: it never blocks opening a store; failures are logged and ignored.
// Returns the count removed.
func cleanupInterruptedArtifacts(root string) int {
	removed := 0
	cutoff := time.Now().Add(-staleTempGrace)

	removeIfStale := func(p string) {
		info, err := os.Stat(p)
		if err != nil {
			return // vanished concurrently, nothing to do
		}
		if info.ModTime().After(cutoff) {
			// Could belong to a hauler process writing right now; leave it.
			return
		}
		if removeTemp(p) {
			removed++
		}
	}

	// saveIndexLocked writes "index-*.json" temps directly in the store root.
	indexTemps, err := filepath.Glob(filepath.Join(root, "index-*.json"))
	if err != nil {
		zlog.Debug().Err(err).Str("path", root).Msg("startup cleanup: failed to glob index temps")
	}
	for _, p := range indexTemps {
		removeIfStale(p)
	}

	// loadOrCreateStoreID leaves store.json.tmp behind if killed mid-create.
	removeIfStale(filepath.Join(root, consts.DefaultStoreMetadataName+".tmp"))

	// content.OCI.WriteBlob / ociBlobWriter stage "<hex>.tmp-*" under
	// blobs/<algorithm>/.
	blobTemps, err := filepath.Glob(filepath.Join(root, ocispec.ImageBlobsDir, "*", "*.tmp-*"))
	if err != nil {
		zlog.Debug().Err(err).Str("path", root).Msg("startup cleanup: failed to glob blob temps")
	}
	for _, p := range blobTemps {
		removeIfStale(p)
	}

	if removed > 0 {
		zlog.Info().Int("count", removed).Str("path", root).Msg("startup cleanup: removed in-flight files left by an interrupted hauler process")
	}
	return removed
}

// removeTemp deletes path, treating ENOENT as success.
func removeTemp(path string) bool {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		zlog.Debug().Err(err).Str("path", path).Msg("startup cleanup: failed to remove temp file")
		return false
	}
	return true
}

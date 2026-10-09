package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	zlog "github.com/rs/zerolog/log"

	"hauler.dev/go/hauler/v2/pkg/consts"
	"hauler.dev/go/hauler/v2/pkg/content"
)

// inventoryLockTimeout bounds how long updateStoreInventory waits for the inventory lock, since it's a best-effort bookkeeping step that must never hang a store command over a stuck lock.
const inventoryLockTimeout = 5 * time.Second

// inventoryEntry is a store's last-known location, keyed by StoreID
type inventoryEntry struct {
	Path    string `json:"path"`
	Updated string `json:"updated"`
}

type storeInventory map[string]inventoryEntry

func inventoryPath(haulerDir string) string {
	return filepath.Join(haulerDir, consts.DefaultStoreInventoryName)
}

// ensureDir creates dir, tolerating a concurrent creator: os.MkdirAll can still surface the raw "file exists" error from its own EEXIST self-heal check under a fast concurrent creator on some filesystems, so re-stat before treating the failure as real
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		if fi, statErr := os.Stat(dir); statErr == nil && fi.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

func loadInventory(haulerDir string) storeInventory {
	inv := storeInventory{}
	p := inventoryPath(haulerDir)
	data, err := os.ReadFile(p)
	if err != nil {
		return inv
	}
	if err := json.Unmarshal(data, &inv); err != nil {
		zlog.Warn().Err(err).Str("path", p).Msg("failed to parse store inventory... ignoring")
		return storeInventory{}
	}
	return inv
}

func saveInventory(haulerDir string, inv storeInventory) error {
	if err := ensureDir(haulerDir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	// Unique temp name (stores-*.json.tmp) in the same directory, then rename:
	// recognizable to snapshot recovery and safe against concurrent writers.
	tmp, err := os.CreateTemp(haulerDir, "stores-*"+consts.SnapshotIndexTempSuffix)
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, inventoryPath(haulerDir))
}

// updateStoreInventory records storeID's path in <haulerDir>/stores.json, pruning stale entries, under a lock so concurrent hauler processes can't drop each other's update.
func updateStoreInventory(haulerDir, storeID, path string) {
	if err := ensureDir(haulerDir); err != nil {
		zlog.Warn().Err(err).Msg("failed to create hauler directory for store inventory... store id lookup may not find this store later")
		return
	}

	fl := flock.New(inventoryPath(haulerDir) + ".lock")
	ctx, cancel := context.WithTimeout(context.Background(), inventoryLockTimeout)
	defer cancel()
	locked, err := fl.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil || !locked {
		zlog.Warn().Err(err).Msg("failed to lock store inventory... store id lookup may not find this store later")
		return
	}
	defer fl.Unlock()

	// Holding the inventory lock proves no other inventory writer is live, so
	// any stores-*.json.tmp here is residue of a crashed update: sweep it.
	content.SweepMatching(haulerDir, content.InventoryTempMatch)

	inv := loadInventory(haulerDir)

	for id, entry := range inv {
		if id == storeID {
			continue
		}
		if !MatchesStoreID(entry.Path, id) {
			delete(inv, id)
		}
	}

	inv[storeID] = inventoryEntry{
		Path:    path,
		Updated: time.Now().UTC().Format(time.RFC3339),
	}

	if err := saveInventory(haulerDir, inv); err != nil {
		zlog.Warn().Err(err).Msg("failed to update store inventory... store id lookup may not find this store later")
	}
}

// MatchesStoreID reports whether path's store.json identifies it as storeID
func MatchesStoreID(path, storeID string) bool {
	data, err := os.ReadFile(filepath.Join(path, consts.DefaultStoreMetadataName))
	if err != nil {
		return false
	}
	var m storeMetadata
	if json.Unmarshal(data, &m) != nil {
		return false
	}
	return m.StoreID == storeID
}

// ResolveStoreID looks up idOrPrefix (a StoreID or an unambiguous prefix of
// one) in <haulerDir>/stores.json and returns the matched store's full id and
// last-known path. Callers should verify the path with MatchesStoreID before
// trusting it
func ResolveStoreID(haulerDir, idOrPrefix string) (id string, path string, err error) {
	inv := loadInventory(haulerDir)

	if entry, ok := inv[idOrPrefix]; ok {
		return idOrPrefix, entry.Path, nil
	}

	var matchID, matchPath string
	count := 0
	for invID, entry := range inv {
		if strings.HasPrefix(invID, idOrPrefix) {
			matchID, matchPath = invID, entry.Path
			count++
		}
	}

	switch count {
	case 0:
		return "", "", fmt.Errorf("no store found matching id %q", idOrPrefix)
	case 1:
		return matchID, matchPath, nil
	default:
		return "", "", fmt.Errorf("store id %q is ambiguous and matches multiple stores", idOrPrefix)
	}
}

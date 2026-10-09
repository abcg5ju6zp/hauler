package store_test

// import_test.go covers the staged/verified/atomic import path used by
// `hauler store load`: merges into a populated store, failure isolation (the
// destination index must never be half-polluted), idempotent re-import,
// concurrent imports, and startup sweeping of interrupted-write leftovers.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/pkg/consts"
	"hauler.dev/go/hauler/v2/pkg/store"
)

// indexedRefs returns the sorted ref annotations in s's index.
func indexedRefs(t *testing.T, s *store.Layout) []string {
	t.Helper()
	var refs []string
	if err := s.OCI.Walk(func(_ string, d ocispec.Descriptor) error {
		refs = append(refs, d.Annotations[ocispec.AnnotationRefName])
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(refs)
	return refs
}

// artifactStore builds a fresh layout with one random image artifact at ref.
func artifactStore(t *testing.T, ref string) *store.Layout {
	t.Helper()
	s, err := store.NewLayout(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayout: %v", err)
	}
	if _, err := s.AddArtifact(context.Background(), genArtifact(t, ref), ref); err != nil {
		t.Fatalf("AddArtifact %s: %v", ref, err)
	}
	return s
}

func reopen(t *testing.T, root string) *store.Layout {
	t.Helper()
	s, err := store.NewLayout(root)
	if err != nil {
		t.Fatalf("reopen %s: %v", root, err)
	}
	return s
}

// TestImportLayout_MergesIntoExistingStore proves loading into a populated
// store unions both sets and that re-importing the same haul is idempotent.
func TestImportLayout_MergesIntoExistingStore(t *testing.T) {
	ctx := context.Background()
	dest := artifactStore(t, "example.com/dest:v1")
	src := artifactStore(t, "example.com/incoming:v1")

	before := indexedRefs(t, dest)
	if err := src.ImportLayout(ctx, dest.Root); err != nil {
		t.Fatalf("ImportLayout: %v", err)
	}

	got := indexedRefs(t, reopen(t, dest.Root))
	want := append(append([]string{}, before...), "example.com/incoming:v1")
	sort.Strings(want)
	if strings2(got, want) != "" {
		t.Errorf("merged index mismatch: %s", strings2(got, want))
	}

	// Every blob referenced by the incoming index must be present.
	checker := reopen(t, dest.Root).NewChecker()
	reopened := reopen(t, dest.Root)
	if err := reopened.OCI.Walk(func(_ string, d ocispec.Descriptor) error {
		r := checker.Check(ctx, d)
		if !r.OK {
			t.Errorf("blob graph for %s failed check after import: %+v", d.Annotations[ocispec.AnnotationRefName], r.Problems)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Idempotent re-import: same refs, no error.
	if err := reopen(t, src.Root).ImportLayout(ctx, dest.Root); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	again := indexedRefs(t, reopen(t, dest.Root))
	if strings2(again, want) != "" {
		t.Errorf("index changed on re-import: %s", strings2(again, want))
	}
}

// TestImportLayout_FailureLeavesDestUntouched is the core "no silent
// pollution" guarantee: a haul whose graph is missing a blob must fail, and
// the destination's index.json must be byte-identical to before the load.
func TestImportLayout_FailureLeavesDestUntouched(t *testing.T) {
	ctx := context.Background()
	dest := artifactStore(t, "example.com/keep:v1")
	src := artifactStore(t, "example.com/must-not-merge:v1")

	// Delete one layer blob out from under the source index.
	idxBytes, err := os.ReadFile(filepath.Join(src.Root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(idxBytes, &idx); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(src.Root, "blobs", "sha256", idx.Manifests[0].Digest.Hex()))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Layers) == 0 {
		t.Fatal("test artifact has no layers to delete")
	}
	victim := filepath.Join(src.Root, "blobs", "sha256", manifest.Layers[0].Digest[len("sha256:"):])
	if err := os.Remove(victim); err != nil {
		t.Fatal(err)
	}

	destIndexBefore, err := os.ReadFile(filepath.Join(dest.Root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := src.ImportLayout(ctx, dest.Root); err == nil {
		t.Fatal("ImportLayout must fail when a referenced blob is missing")
	}

	destIndexAfter, err := os.ReadFile(filepath.Join(dest.Root, "index.json"))
	if err != nil {
		t.Fatalf("dest index unreadable after failed import: %v", err)
	}
	if string(destIndexBefore) != string(destIndexAfter) {
		t.Fatal("destination index.json was modified by a failed import")
	}
	refs := indexedRefs(t, reopen(t, dest.Root))
	if len(refs) != 1 || refs[0] != "example.com/keep:v1" {
		t.Fatalf("destination index polluted by failed import: %v", refs)
	}
}

// TestImportLayout_Concurrent merges two different hauls into one store from
// two processes-simulating goroutines: both sets must land without lost
// updates, thanks to the cross-process index lock.
func TestImportLayout_Concurrent(t *testing.T) {
	ctx := context.Background()
	destRoot := t.TempDir()
	if _, err := store.NewLayout(destRoot); err != nil {
		t.Fatal(err)
	}
	srcA := artifactStore(t, "example.com/concurrent-a:v1")
	srcB := artifactStore(t, "example.com/concurrent-b:v1")

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, src := range []*store.Layout{srcA, srcB} {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			// src is the receiver (the layout being imported FROM); the
			// cross-process lock is taken inside on the destination.
			errs <- src.ImportLayout(ctx, destRoot)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent import: %v", err)
		}
	}

	got := indexedRefs(t, reopen(t, destRoot))
	if len(got) != 2 {
		t.Fatalf("expected both imports merged, got %v", got)
	}
}

// TestNewLayout_StartupCleanup verifies that opening a store sweeps exactly
// the remnants an interrupted process can leave (index temp, blob temp,
// store.json temp) while leaving real content alone.
func TestNewLayout_StartupCleanup(t *testing.T) {
	root := t.TempDir()
	blobDir := filepath.Join(root, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}

	indexTemp := filepath.Join(root, "index-123456789.json")
	storeIDTemp := filepath.Join(root, consts.DefaultStoreMetadataName+".tmp")
	blobTemp := filepath.Join(blobDir, "deadbeef.tmp-0001")
	// A fresh temp looks like a live writer's in-flight file and must be
	// preserved; only temps older than the grace window are swept.
	freshBlobTemp := filepath.Join(blobDir, "cafef00d.tmp-0002")
	legitBlob := filepath.Join(blobDir, "a1b2c3")
	stale := time.Now().Add(-time.Hour)
	for _, p := range []string{indexTemp, storeIDTemp, blobTemp, freshBlobTemp} {
		if err := os.WriteFile(p, []byte("partial"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{indexTemp, storeIDTemp, blobTemp} {
		if err := os.Chtimes(p, stale, stale); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(legitBlob, []byte("real content-addressed bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := store.NewLayout(root); err != nil {
		t.Fatalf("NewLayout: %v", err)
	}

	for _, p := range []string{indexTemp, storeIDTemp, blobTemp} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("interrupted-write remnant not cleaned: %s", p)
		}
	}
	if _, err := os.Stat(freshBlobTemp); err != nil {
		t.Errorf("a fresh temp was swept although it may belong to a live writer: %v", err)
	}
	if _, err := os.Stat(legitBlob); err != nil {
		t.Errorf("legitimate blob removed by startup cleanup: %v", err)
	}
}

// strings2 returns a human-readable diff message when a != b, "" otherwise.
func strings2(a, b []string) string {
	if len(a) != len(b) {
		return "length differs"
	}
	for i := range a {
		if a[i] != b[i] {
			return "element differs"
		}
	}
	return ""
}

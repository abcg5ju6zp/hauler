package store_test

// check_session_test.go covers the repeatable check-session contract of
// CheckStore/Checker: a fully verified store, missing blobs, digest
// mismatches, shared blobs under concurrency, cancellation mid-run, and the
// distinction between repeated runs of one session and pre/post-repair
// sessions.

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	goname "github.com/google/go-containerregistry/pkg/name"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	gvtypes "github.com/google/go-containerregistry/pkg/v1/types"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/pkg/store"
)

// findUnit returns a pointer to the report unit whose own manifest digest is
// d, or nil when none exists.
func findUnit(t *testing.T, r *store.CheckReport, d digest.Digest) *store.ArtifactCheck {
	t.Helper()
	for i := range r.Artifacts {
		if r.Artifacts[i].Digest == d.String() {
			return &r.Artifacts[i]
		}
	}
	return nil
}

func unitProblem(u *store.ArtifactCheck, d digest.Digest) *store.BlobResult {
	for i := range u.Problems {
		if u.Problems[i].Digest == d.String() {
			return &u.Problems[i]
		}
	}
	return nil
}

// TestCheckStore_HealthyStoreComplete is the whole-store version of
// TestCheck_HealthyStore: every unit is reached and OK, the report is complete,
// and at least one blob was actually hashed.
func TestCheckStore_HealthyStoreComplete(t *testing.T) {
	s := newCheckTestStore(t)
	host, opts := newCheckTestRegistry(t)

	desc1 := pushAndAddImage(t, s, host, "test/img1", "v1", opts)
	desc2 := pushAndAddImage(t, s, host, "test/img2", "v1", opts)

	c := s.NewChecker()
	if c.SessionID() == "" {
		t.Fatal("session id must be non-empty")
	}

	r := c.CheckStore(context.Background())

	if !r.Complete {
		t.Fatalf("expected a complete run over a healthy store, got unreached=%d failed=%d",
			r.TotalArtifacts-r.ReachedArtifacts, r.FailedArtifacts)
	}
	if r.FailedArtifacts != 0 {
		t.Errorf("expected no failed artifacts, got %d: %+v", r.FailedArtifacts, r.Artifacts)
	}
	if r.TotalArtifacts < 2 {
		t.Fatalf("expected at least the two seeded units, got %d", r.TotalArtifacts)
	}
	for _, d := range []digest.Digest{desc1.Digest, desc2.Digest} {
		u := findUnit(t, r, d)
		if u == nil {
			t.Fatalf("no unit for %s in report", d)
		}
		if !u.Reached || !u.OK || len(u.Problems) != 0 {
			t.Errorf("unit %s = %+v, want reached/OK/no problems", d, u)
		}
	}
	if r.BlobsHashed == 0 {
		t.Error("expected BlobsHashed > 0 for a genuine content verification")
	}
	if r.SessionID != c.SessionID() {
		t.Errorf("report session %q != checker session %q", r.SessionID, c.SessionID())
	}
	if !r.StartedAt.IsZero() && r.FinishedAt.Before(r.StartedAt) {
		t.Errorf("finished-at %v before started-at %v", r.FinishedAt, r.StartedAt)
	}
}

// TestCheckStore_MissingBlob_DoesNotAbortOthers proves the failure-isolation
// contract against both missing leaf blobs and a missing top-level manifest:
// every other artifact is still checked and the run completes, with each
// affected object named explicitly.
func TestCheckStore_MissingBlob_DoesNotAbortOthers(t *testing.T) {
	s := newCheckTestStore(t)
	host, opts := newCheckTestRegistry(t)

	badLayer := pushAndAddImage(t, s, host, "test/missing-layer", "v1", opts)
	healthy := pushAndAddImage(t, s, host, "test/healthy", "v1", opts)
	badManifest := pushAndAddImage(t, s, host, "test/missing-manifest", "v1", opts)

	missingLayer := readManifestBlob(t, s.Root, badLayer.Digest).Layers[0].Digest
	if err := os.Remove(blobPath(s.Root, missingLayer)); err != nil {
		t.Fatalf("remove layer blob: %v", err)
	}
	if err := os.Remove(blobPath(s.Root, badManifest.Digest)); err != nil {
		t.Fatalf("remove manifest blob: %v", err)
	}

	r := s.NewChecker().CheckStore(context.Background())

	if !r.Complete {
		t.Errorf("missing blobs must complete the full run, got incomplete report: %+v", r.Artifacts)
	}
	if r.FailedArtifacts != 2 {
		t.Errorf("FailedArtifacts = %d, want 2 (missing layer + missing manifest)", r.FailedArtifacts)
	}

	u := findUnit(t, r, badLayer.Digest)
	if u == nil || u.OK {
		t.Fatalf("expected a failing unit for the image with the missing layer, got %+v", u)
	}
	if p := unitProblem(u, missingLayer); p == nil || p.Status != store.BlobMissing {
		t.Errorf("expected BlobMissing for layer %s, got %+v", missingLayer, u.Problems)
	}

	if u := findUnit(t, r, badManifest.Digest); u == nil || u.OK {
		t.Fatalf("expected a failing unit for the image whose manifest blob is gone, got %+v", u)
	} else if p := unitProblem(u, badManifest.Digest); p == nil || p.Status != store.BlobMissing {
		t.Errorf("expected BlobMissing for manifest %s, got %+v", badManifest.Digest, u.Problems)
	}

	if u := findUnit(t, r, healthy.Digest); u == nil || !u.OK {
		t.Fatalf("the healthy sibling must still be checked OK, got %+v", u)
	}
}

// TestCheckStore_DigestMismatch proves a same-length in-place corruption is
// caught by real content hashing and attributed to the affected unit while the
// run still completes.
func TestCheckStore_DigestMismatch(t *testing.T) {
	s := newCheckTestStore(t)
	host, opts := newCheckTestRegistry(t)

	desc := pushAndAddImage(t, s, host, "test/corrupt", "v1", opts)
	victim := readManifestBlob(t, s.Root, desc.Digest).Layers[0].Digest
	path := blobPath(s.Root, victim)

	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	corrupted := append([]byte(nil), orig...)
	corrupted[0] ^= 0xFF
	if err := os.WriteFile(path, corrupted, 0o644); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	c := s.NewChecker()
	r := c.CheckStore(context.Background())

	if !r.Complete {
		t.Errorf("expected a complete run, got: %+v", r.Artifacts)
	}
	u := findUnit(t, r, desc.Digest)
	if u == nil || u.OK {
		t.Fatalf("expected a failing unit, got %+v", u)
	}
	p := unitProblem(u, victim)
	if p == nil || p.Status != store.BlobDigestMismatch {
		t.Fatalf("expected BlobDigestMismatch for %s, got %+v", victim, u.Problems)
	}
}

// TestCheckStore_SharedBlobConcurrent_ConsistentOnce is the session-level
// version of the memoization test: under CheckStore's concurrency, a blob
// shared by two images produces one identical verdict for both units and is
// streamed through a verifier exactly once.
func TestCheckStore_SharedBlobConcurrent_ConsistentOnce(t *testing.T) {
	s := newCheckTestStore(t)
	host, opts := newCheckTestRegistry(t)

	sharedLayer := static.NewLayer([]byte(strings.Repeat("shared-layer-content", 100)), gvtypes.OCILayer)
	unique1, err := random.Layer(128, gvtypes.OCILayer)
	if err != nil {
		t.Fatalf("random.Layer: %v", err)
	}
	unique2, err := random.Layer(128, gvtypes.OCILayer)
	if err != nil {
		t.Fatalf("random.Layer: %v", err)
	}
	img1, err := mutate.AppendLayers(empty.Image, sharedLayer, unique1)
	if err != nil {
		t.Fatalf("build img1: %v", err)
	}
	img2, err := mutate.AppendLayers(empty.Image, sharedLayer, unique2)
	if err != nil {
		t.Fatalf("build img2: %v", err)
	}
	desc1 := pushAndAddExistingImage(t, s, host, "test/shared1", "v1", img1, opts)
	desc2 := pushAndAddExistingImage(t, s, host, "test/shared2", "v1", img2, opts)

	sharedHash, err := sharedLayer.Digest()
	if err != nil {
		t.Fatalf("shared digest: %v", err)
	}
	sharedDigest := digest.NewDigestFromEncoded(digest.Algorithm(sharedHash.Algorithm), sharedHash.Hex)

	path := blobPath(s.Root, sharedDigest)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared blob: %v", err)
	}
	corrupt := append([]byte(nil), orig...)
	corrupt[0] ^= 0xFF
	if err := os.WriteFile(path, corrupt, 0o644); err != nil {
		t.Fatalf("corrupt shared blob: %v", err)
	}

	c := s.NewChecker()
	r := c.CheckStore(context.Background())

	for _, d := range []digest.Digest{desc1.Digest, desc2.Digest} {
		u := findUnit(t, r, d)
		if u == nil || u.OK {
			t.Fatalf("expected both sharing units to fail, %s = %+v", d, u)
		}
		p := unitProblem(u, sharedDigest)
		if p == nil || p.Status != store.BlobDigestMismatch {
			t.Errorf("unit %s: expected the shared blob to read digest-mismatch, got %+v", d, u.Problems)
		}
	}
	if got := c.HashCount(sharedDigest.String()); got != 1 {
		t.Errorf("shared blob hashed %d times, want exactly 1", got)
	}

	// A repeated run on the same session is repeatable: identical verdicts
	// under the same SessionID, distinguishable as a run only by its
	// timestamps.
	r2 := c.CheckStore(context.Background())
	if r2.SessionID != r.SessionID {
		t.Errorf("repeated run changed SessionID: %q != %q", r2.SessionID, r.SessionID)
	}
	u1 := findUnit(t, r, desc1.Digest)
	u2 := findUnit(t, r2, desc1.Digest)
	if u2 == nil || u2.OK != u1.OK || len(u2.Problems) != len(u1.Problems) {
		t.Fatalf("repeated run verdict differs: %+v vs %+v", u1, u2)
	}
	if got := c.HashCount(sharedDigest.String()); got != 1 {
		t.Errorf("shared blob re-hashed on repeat: count = %d, want 1", got)
	}
	if r2.StartedAt.Before(r.StartedAt) {
		t.Errorf("repeat run started before the first run: %v < %v", r2.StartedAt, r.StartedAt)
	}
}

// TestCheckStore_CancelledMidRun drives cancellation deterministically --
// immediately before a blob starts hashing -- and asserts the run is reported
// incomplete (never as success), says which units were not covered, and that a
// fresh session re-runs to completion.
func TestCheckStore_CancelledMidRun(t *testing.T) {
	s := newCheckTestStore(t)
	host, opts := newCheckTestRegistry(t)

	desc1 := pushAndAddImage(t, s, host, "test/cancel1", "v1", opts)
	desc2 := pushAndAddImage(t, s, host, "test/cancel2", "v1", opts)

	ctx, cancel := context.WithCancel(context.Background())
	var cancelOnce sync.Once
	hookCtx := store.WithCheckPreHashHook(ctx, func(_ string) {
		cancelOnce.Do(cancel)
	})

	c := s.NewChecker()
	r := c.CheckStore(hookCtx)

	if r.Complete {
		t.Fatal("an interrupted run must not report complete")
	}
	if r.FinishedAt.Before(r.StartedAt) {
		t.Errorf("bad timestamps: finished %v before started %v", r.FinishedAt, r.StartedAt)
	}
	if len(r.Artifacts) != r.TotalArtifacts || r.TotalArtifacts < 2 {
		t.Fatalf("expected every root to appear (reached or not), got %d units", r.TotalArtifacts)
	}

	uncovered := 0
	for _, u := range r.Artifacts {
		if !u.Reached {
			uncovered++
			continue
		}
		for _, p := range u.Problems {
			if p.Status == store.BlobUnverified {
				uncovered++
				continue
			}
			// A reached blob in an interrupted run can only carry an
			// "unverified" verdict; a definitive corruption claim would mean
			// the run ignored its own cancellation.
			t.Errorf("interrupted run cannot prove %s corruption, got status %s", p.Digest, p.Status)
		}
	}
	if uncovered == 0 {
		t.Fatal("expected at least one unit to be not-reached or unverified after cancellation")
	}

	// The two seeded roots must still be represented even when interrupted.
	if findUnit(t, r, desc1.Digest) == nil || findUnit(t, r, desc2.Digest) == nil {
		t.Fatalf("interrupted report must still name all root objects: %+v", r.Artifacts)
	}

	// A fresh session over the unchanged, healthy store runs to completion --
	// the interrupted session poisoned nothing.
	r2 := s.NewChecker().CheckStore(context.Background())
	if !r2.Complete || r2.FailedArtifacts != 0 {
		t.Fatalf("rerun after interruption must complete cleanly, got complete=%v failed=%d",
			r2.Complete, r2.FailedArtifacts)
	}
	if r2.SessionID == r.SessionID {
		t.Error("rerun must be a distinct session")
	}
}

// TestCheckBlob_CancelledAttemptIsNotMemoized proves a cancelled single-blob
// check reads BlobUnverified and does not poison the session: a later
// non-cancelled check of the same blob on the same Checker verifies it.
func TestCheckBlob_CancelledAttemptIsNotMemoized(t *testing.T) {
	s := newCheckTestStore(t)
	host, opts := newCheckTestRegistry(t)

	desc := pushAndAddImage(t, s, host, "test/cancel-blob", "v1", opts)
	victim := readManifestBlob(t, s.Root, desc.Digest).Layers[0].Digest
	victimDesc := ocispec.Descriptor{Digest: victim, Size: blobSize(t, s.Root, victim)}

	c := s.NewChecker()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := c.CheckBlob(ctx, victimDesc)
	if r.Status != store.BlobUnverified {
		t.Fatalf("cancelled CheckBlob = %q, want %q", r.Status, store.BlobUnverified)
	}

	r = c.CheckBlob(context.Background(), victimDesc)
	if r.Status != store.BlobOK {
		t.Fatalf("post-cancel CheckBlob on a healthy blob = %q (%s), want %q", r.Status, r.Detail, store.BlobOK)
	}
}

// TestCheckStore_RepairStartsDistinguishableSession locks in the repair
// contract: a session's verdicts are frozen for its lifetime (repeatable),
// while Reset (a new session) re-verifies the repaired store under a new
// SessionID, so pre- and post-repair results can never be confused.
func TestCheckStore_RepairStartsDistinguishableSession(t *testing.T) {
	s := newCheckTestStore(t)
	host, opts := newCheckTestRegistry(t)

	desc := pushAndAddImage(t, s, host, "test/repair", "v1", opts)
	victim := readManifestBlob(t, s.Root, desc.Digest).Layers[0].Digest
	path := blobPath(s.Root, victim)

	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	corrupt := append([]byte(nil), orig...)
	corrupt[0] ^= 0xFF
	if err := os.WriteFile(path, corrupt, 0o644); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	c := s.NewChecker()
	before := c.CheckStore(context.Background())
	// A fully-observed corruption is a *complete* failing run; that is what
	// makes it distinguishable from an interrupted one.
	if !before.Complete || before.FailedArtifacts != 1 {
		t.Fatalf("pre-repair run: complete=%v failed=%d, want complete=true failed=1",
			before.Complete, before.FailedArtifacts)
	}

	// Repair: drop the corrupt blob and re-add from the registry, which
	// re-downloads the missing content (same-size corruption defeats the
	// size-only write fast path only once the file is gone).
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove corrupt blob: %v", err)
	}
	if _, err := s.AddImage(context.Background(), host+"/test/repair:v1", "", true, "", false, "", opts...); err != nil {
		t.Fatalf("re-add image: %v", err)
	}

	// The old session keeps its verdict: nothing mutates a completed session.
	frozen := c.CheckStore(context.Background())
	if frozen.SessionID != before.SessionID || frozen.FailedArtifacts != 1 {
		t.Fatalf("old session verdict must stay frozen, got session=%s failed=%d",
			frozen.SessionID, frozen.FailedArtifacts)
	}

	// A new session after Reset reflects the repair and is unambiguously
	// different from the pre-repair session.
	oldID := c.SessionID()
	c.Reset()
	if c.SessionID() == oldID {
		t.Fatal("Reset must start a new SessionID")
	}
	after := c.CheckStore(context.Background())
	if !after.Complete || after.FailedArtifacts != 0 {
		t.Fatalf("post-repair run: complete=%v failed=%d, want complete=true failed=0",
			after.Complete, after.FailedArtifacts)
	}
	if after.SessionID == before.SessionID {
		t.Fatal("post-repair session id must differ from pre-repair")
	}
}

// pushMultiArch builds a two-platform random index, pushes it, adds it to the
// store as a full multi-arch index, and returns the stored index descriptor
// plus the child manifest digests.
func pushMultiArch(t *testing.T, s *store.Layout, host, repo, tag string, opts []remote.Option) (ocispec.Descriptor, []digest.Digest) {
	t.Helper()

	img1, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("random.Image 1: %v", err)
	}
	img2, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("random.Image 2: %v", err)
	}
	d1, err := img1.Digest()
	if err != nil {
		t.Fatalf("digest 1: %v", err)
	}
	d2, err := img2.Digest()
	if err != nil {
		t.Fatalf("digest 2: %v", err)
	}
	idx := mutate.AppendManifests(
		mutate.IndexMediaType(empty.Index, gvtypes.OCIImageIndex),
		mutate.IndexAddendum{
			Add: img1,
			Descriptor: gcrv1.Descriptor{
				MediaType: gvtypes.OCIManifestSchema1,
				Digest:    d1,
				Platform:  &gcrv1.Platform{OS: "linux", Architecture: "amd64"},
			},
		},
		mutate.IndexAddendum{
			Add: img2,
			Descriptor: gcrv1.Descriptor{
				MediaType: gvtypes.OCIManifestSchema1,
				Digest:    d2,
				Platform:  &gcrv1.Platform{OS: "linux", Architecture: "arm64"},
			},
		},
	)

	ref, err := goname.NewTag(host+"/"+repo+":"+tag, goname.Insecure)
	if err != nil {
		t.Fatalf("NewTag: %v", err)
	}
	if err := remote.WriteIndex(ref, idx, opts...); err != nil {
		t.Fatalf("remote.WriteIndex: %v", err)
	}
	if _, err := s.AddImage(context.Background(), ref.Name(), "", true, "", false, "", opts...); err != nil {
		t.Fatalf("AddImage: %v", err)
	}

	children := []digest.Digest{
		digest.NewDigestFromEncoded(digest.Algorithm(d1.Algorithm), d1.Hex),
		digest.NewDigestFromEncoded(digest.Algorithm(d2.Algorithm), d2.Hex),
	}
	return findManifestDescForRef(t, s, repo+":"+tag), children
}

func blobSize(t *testing.T, root string, d digest.Digest) int64 {
	t.Helper()
	info, err := os.Stat(blobPath(root, d))
	if err != nil {
		t.Fatalf("stat blob: %v", err)
	}
	return info.Size()
}

// TestCheckStore_MultiArchIndex_PerPlatformUnits checks descriptor traversal
// of an image index: one unit per platform manifest, all sharing the root
// digest; corrupting one platform's layer fails exactly that unit while the
// other platform and the run as a whole stay complete.
func TestCheckStore_MultiArchIndex_PerPlatformUnits(t *testing.T) {
	s := newCheckTestStore(t)
	host, opts := newCheckTestRegistry(t)

	root, childDigests := pushMultiArch(t, s, host, "test/multi", "v1", opts)

	c := s.NewChecker()
	r := c.CheckStore(context.Background())
	if !r.Complete || r.FailedArtifacts != 0 {
		t.Fatalf("healthy index: complete=%v failed=%d", r.Complete, r.FailedArtifacts)
	}

	for _, d := range childDigests {
		u := findUnit(t, r, d)
		if u == nil {
			t.Fatalf("no unit for child %s", d)
		}
		if u.RootDigest != root.Digest.String() {
			t.Errorf("child %s RootDigest = %q, want %q", d, u.RootDigest, root.Digest)
		}
		if u.Platform == "-" || u.Platform == "" {
			t.Errorf("child %s expected a platform label, got %q", d, u.Platform)
		}
	}

	// Corrupt one platform's first layer: only that unit may fail.
	victim := readManifestBlob(t, s.Root, childDigests[0]).Layers[0].Digest
	orig, err := os.ReadFile(blobPath(s.Root, victim))
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	bad := append([]byte(nil), orig...)
	bad[0] ^= 0xFF
	if err := os.WriteFile(blobPath(s.Root, victim), bad, 0o644); err != nil {
		t.Fatalf("corrupt blob: %v", err)
	}

	c2 := s.NewChecker()
	r2 := c2.CheckStore(context.Background())
	if !r2.Complete {
		t.Fatal("corruption must not make the run incomplete")
	}
	badUnit := findUnit(t, r2, childDigests[0])
	if badUnit == nil || badUnit.OK || unitProblem(badUnit, victim) == nil {
		t.Fatalf("expected the affected platform unit to fail: %+v", badUnit)
	}
	goodUnit := findUnit(t, r2, childDigests[1])
	if goodUnit == nil || !goodUnit.OK {
		t.Fatalf("the sibling platform must stay OK: %+v", goodUnit)
	}
}

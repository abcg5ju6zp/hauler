package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
)

// BlobStatus describes the outcome of checking a single blob against its descriptor.
type BlobStatus string

const (
	BlobOK             BlobStatus = "ok"
	BlobMissing        BlobStatus = "missing"
	BlobSizeMismatch   BlobStatus = "size-mismatch"
	BlobDigestMismatch BlobStatus = "digest-mismatch"
	BlobUnreadable     BlobStatus = "unreadable"
	// BlobUnverified means the blob was never fully verified because the
	// check was interrupted (context cancellation) before its content could
	// be hashed. It is neither an OK verdict nor proof of corruption: the
	// owning CheckResult/CheckReport is always marked incomplete when one of
	// these is present, so it can never masquerade as a successful check.
	BlobUnverified BlobStatus = "unverified"
)

// BlobResult is the outcome for one blob. Detail is human-readable context
// (e.g. "expected 4194304 bytes, found 1050624").
type BlobResult struct {
	Digest string
	Status BlobStatus
	Detail string
}

// CheckResult aggregates a single descriptor graph. Problems is empty when OK.
//
// Complete is false when the graph walk was cut short by context cancellation,
// in which case OK is always false as well: an interrupted walk must never be
// reported as a successful verification, regardless of how many blobs happened
// to have been verified before the interruption.
type CheckResult struct {
	OK       bool
	Complete bool
	Problems []BlobResult
}

// ArtifactCheck is the outcome for one checkable unit in the store: either a
// plain top-level manifest or one (possibly nested) platform manifest of an
// image index. All units of one index entry share Reference/RootDigest and the
// root descriptor's annotations; multi-arch images therefore produce one unit
// per platform, exactly as the inventory does.
//
// Reached is false when the session was cancelled before the unit's manifest
// was verified: OK is false and Problems is empty for such a unit, so callers
// can distinguish "known bad" from "never got to it".
type ArtifactCheck struct {
	Reference string
	// Annotations are a private copy of the root index descriptor's
	// annotation map, safe for callers to read after the report is returned.
	Annotations     map[string]string
	RootDigest      string
	Digest          string
	Platform        string
	MediaType       string
	ConfigMediaType string

	OK       bool
	Reached  bool
	Problems []BlobResult
}

// CheckReport is one run of a whole-store check within a Checker session.
//
// A Checker is one repeatable check session: the same Checker run repeatedly
// returns the same per-blob verdicts (memoized) under a stable SessionID, with
// StartedAt/FinishedAt distinguishing the individual runs. Store repairs are
// not visible to an existing session's memoized verdicts; callers create a new
// session (NewChecker or Reset) after mutating the store, and the new SessionID
// makes pre-/post-repair reports unambiguous.
type CheckReport struct {
	// SessionID is stable across repeated CheckStore calls on one Checker and
	// changes on Reset/NewChecker.
	SessionID string

	StartedAt  time.Time
	FinishedAt time.Time

	// Complete is true only when every unit was reached and every verified
	// blob check finished without context cancellation.
	Complete bool

	// Artifacts holds one entry per checkable unit, sorted by Reference,
	// RootDigest and Platform.
	Artifacts []ArtifactCheck

	// Counts over Artifacts (before any caller-side type filtering).
	TotalArtifacts int
	// ReachedArtifacts counts units whose manifest was actually verified.
	ReachedArtifacts int
	// FailedArtifacts counts reached units with at least one problem.
	FailedArtifacts int

	// BlobsChecked is the number of distinct blob digests that reached a
	// definitive verdict (memoized) during the session so far.
	BlobsChecked int
	// BlobsHashed is the number of times blob content was actually streamed
	// through a digest verifier; shared blobs make this smaller than
	// BlobsChecked's per-reference total.
	BlobsHashed int
}

// checkEntry memoizes the verdict for a single digest. Unlike sync.Once, an
// interrupted (BlobUnverified) attempt does not mark the entry done: a later
// caller -- potentially on a non-cancelled context -- re-verifies, while every
// definitive verdict is frozen for the Checker's lifetime, so a blob shared
// across many artifacts yields one identical result for every reference.
type checkEntry struct {
	mu     sync.Mutex
	done   bool
	result BlobResult
}

// Checker recomputes and checks the on-disk content of blobs referenced by a
// Layout's index, detecting blobs left truncated or corrupted by an interrupted
// pull.
//
// A Checker is one repeatable check session intended for the lifetime of a
// single command invocation: it memoizes a definitive verdict per digest so a
// blob referenced repeatedly (e.g. a shared base layer, or the same graph
// checked twice) is only hashed once and every caller observes the same result.
// After repairing the store, start a fresh session with NewChecker or Reset so
// the new run reflects the new on-disk state under a new SessionID.
type Checker struct {
	l *Layout

	// mu guards memo and sessionID.
	mu        sync.Mutex
	memo      map[string]*checkEntry
	sessionID string

	// hashMu/hashCounts track, per-digest, how many times CheckBlob actually
	// streamed a blob's content through a digest verifier (as opposed to
	// short-circuiting on a missing-file or size-mismatch check). This has no
	// effect on check results; it exists so tests can prove that
	// size-mismatch short-circuiting and per-digest memoization avoid redundant
	// hashing of large blobs.
	hashMu     sync.Mutex
	hashCounts map[string]int
}

// NewChecker starts a new check session bound to l.
func (l *Layout) NewChecker() *Checker {
	return &Checker{
		l:          l,
		memo:       make(map[string]*checkEntry),
		sessionID:  uuid.NewString(),
		hashCounts: make(map[string]int),
	}
}

// SessionID returns this check session's stable identifier. Repeated runs on
// the same Checker share it; Reset (or NewChecker) produces a new one.
func (c *Checker) SessionID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
}

// Reset ends the current session and starts a fresh one with an empty verdict
// memo: the next check re-hashes every blob against the store's current
// on-disk state. Use it after repairing (removing/re-adding) artifacts on a
// long-lived Checker; the CLI starts a new Checker per invocation.
func (c *Checker) Reset() {
	c.mu.Lock()
	c.memo = make(map[string]*checkEntry)
	c.sessionID = uuid.NewString()
	c.mu.Unlock()

	c.hashMu.Lock()
	c.hashCounts = make(map[string]int)
	c.hashMu.Unlock()
}

// HashCount returns the number of times the blob identified by digestStr (e.g.
// "sha256:abc...") was actually streamed through a digest verifier.
func (c *Checker) HashCount(digestStr string) int {
	c.hashMu.Lock()
	defer c.hashMu.Unlock()
	return c.hashCounts[digestStr]
}

func (c *Checker) recordHash(digestStr string) {
	c.hashMu.Lock()
	c.hashCounts[digestStr]++
	c.hashMu.Unlock()
}

// checkingReader makes an in-flight hash abort on cancellation between reads
// instead of streaming an already-cancelled blob to completion.
type checkingReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr *checkingReader) Read(p []byte) (int, error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	return cr.r.Read(p)
}

// checkPreHashHookKey carries the optional pre-hash hook in a context.
type checkPreHashHookKey struct{}

// WithCheckPreHashHook returns a copy of ctx carrying fn, which a Checker
// invokes immediately before a blob's content is streamed through its digest
// verifier, with the blob's "algorithm:hex" digest. It lets progress reporting
// observe hash starts, and lets tests drive cancellation deterministically at
// a specific blob.
func WithCheckPreHashHook(ctx context.Context, fn func(blobDigest string)) context.Context {
	return context.WithValue(ctx, checkPreHashHookKey{}, fn)
}

func preHashHook(ctx context.Context) func(string) {
	fn, _ := ctx.Value(checkPreHashHookKey{}).(func(string))
	return fn
}

func unverifiedResult(digestStr, stage string, err error) BlobResult {
	return BlobResult{
		Digest: digestStr,
		Status: BlobUnverified,
		Detail: fmt.Sprintf("check interrupted while %s: %v", stage, err),
	}
}

// CheckBlob checks exactly one blob on disk against its descriptor. It does not
// decode the blob or recurse into anything it references.
//
// Checks run in this order, each short-circuiting the next:
//  1. The blob file must exist at its content-addressed path under
//     <root>/blobs/<algorithm>/<hex>.
//  2. If desc.Size is known (> 0), the file size on disk must match exactly --
//     a mismatch here is reported without ever reading the file's content.
//  3. The file's content is streamed (never fully buffered in memory) through
//     the descriptor's digest verifier, with ctx cancellation aborting the
//     stream as BlobUnverified instead of completing the hash.
func (c *Checker) CheckBlob(ctx context.Context, desc ocispec.Descriptor) BlobResult {
	digestStr := desc.Digest.String()

	if err := ctx.Err(); err != nil {
		return unverifiedResult(digestStr, "starting the check", err)
	}

	blobFile := filepath.Join(c.l.Root, ocispec.ImageBlobsDir, desc.Digest.Algorithm().String(), desc.Digest.Hex())

	info, err := os.Stat(blobFile)
	if err != nil {
		if os.IsNotExist(err) {
			return BlobResult{
				Digest: digestStr,
				Status: BlobMissing,
				Detail: fmt.Sprintf("blob not found at %s", blobFile),
			}
		}
		return BlobResult{
			Digest: digestStr,
			Status: BlobUnreadable,
			Detail: err.Error(),
		}
	}

	if desc.Size > 0 && info.Size() != desc.Size {
		return BlobResult{
			Digest: digestStr,
			Status: BlobSizeMismatch,
			Detail: fmt.Sprintf("expected %d bytes, found %d", desc.Size, info.Size()),
		}
	}

	if !desc.Digest.Algorithm().Available() {
		return BlobResult{
			Digest: digestStr,
			Status: BlobUnreadable,
			Detail: fmt.Sprintf("digest algorithm %q is not available in this build", desc.Digest.Algorithm()),
		}
	}

	if err := ctx.Err(); err != nil {
		return unverifiedResult(digestStr, "opening the blob", err)
	}

	f, err := os.Open(blobFile)
	if err != nil {
		return BlobResult{
			Digest: digestStr,
			Status: BlobUnreadable,
			Detail: err.Error(),
		}
	}
	defer f.Close()

	// dv (go-digest's Verifier) is the hash-comparison API from
	// github.com/opencontainers/go-digest, not this package's Checker type.
	dv := desc.Digest.Verifier()
	if fn := preHashHook(ctx); fn != nil {
		fn(digestStr)
	}
	c.recordHash(digestStr)
	if _, err := io.Copy(dv, &checkingReader{ctx: ctx, r: f}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return unverifiedResult(digestStr, "verifying the blob digest", ctxErr)
		}
		return BlobResult{
			Digest: digestStr,
			Status: BlobUnreadable,
			Detail: fmt.Sprintf("reading blob content: %v", err),
		}
	}

	if !dv.Verified() {
		return BlobResult{
			Digest: digestStr,
			Status: BlobDigestMismatch,
			Detail: "content does not match its digest",
		}
	}

	return BlobResult{Digest: digestStr, Status: BlobOK}
}

// checkMemo returns the definitive verdict for desc.Digest, computing it at
// most once per session even under concurrent calls for the same digest.
// Concurrent callers serialize on the digest's entry, so a shared blob is only
// hashed once and every caller receives the identical result. An interrupted
// attempt is not cached: the blob was never proven anything, so the next caller
// re-verifies instead of inheriting an inconclusive verdict.
func (c *Checker) checkMemo(ctx context.Context, desc ocispec.Descriptor) BlobResult {
	key := desc.Digest.String()

	c.mu.Lock()
	entry, ok := c.memo[key]
	if !ok {
		entry = &checkEntry{}
		c.memo[key] = entry
	}
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.done {
		return entry.result
	}

	r := c.CheckBlob(ctx, desc)
	if r.Status != BlobUnverified {
		entry.result = r
		entry.done = true
	}
	return r
}

// manifestLike captures the fields common to both an OCI image manifest and an OCI
// image index, letting the checker walk either shape uniformly -- a sibling of the
// anonymous decode struct used by Layout.CleanUp, but performing a real byte
// check instead of only marking digests as referenced.
type manifestLike struct {
	Config    ocispec.Descriptor   `json:"config"`
	Layers    []ocispec.Descriptor `json:"layers"`
	Manifests []ocispec.Descriptor `json:"manifests"`
}

// checkedNode is verifyNode's result for one manifest descriptor.
type checkedNode struct {
	desc     ocispec.Descriptor
	manifest manifestLike
	// decoded is false when the manifest blob failed its own check or could
	// not be fetched/decoded, in which case callers must not descend: the
	// bytes cannot be trusted to name children.
	decoded bool
	// problems covers the manifest blob itself plus its config/layers.
	problems []BlobResult
	// complete is false when any part of the node's verification was
	// interrupted by context cancellation.
	complete bool
}

// readManifestBytes fetches and buffers one (typically small) manifest blob.
// It returns a BlobResult describing the failure plus whether the node's
// verification is complete (false on cancellation).
func (c *Checker) readManifestBytes(ctx context.Context, desc ocispec.Descriptor) ([]byte, BlobResult, bool) {
	if err := ctx.Err(); err != nil {
		return nil, unverifiedResult(desc.Digest.String(), "reading the manifest", err), false
	}

	rc, err := c.l.OCI.Fetch(ctx, desc)
	if err != nil {
		return nil, BlobResult{
			Digest: desc.Digest.String(),
			Status: BlobUnreadable,
			Detail: fmt.Sprintf("fetching manifest: %v", err),
		}, true
	}
	defer rc.Close()

	data, err := io.ReadAll(&checkingReader{ctx: ctx, r: rc})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, unverifiedResult(desc.Digest.String(), "reading the manifest", ctxErr), false
		}
		return nil, BlobResult{
			Digest: desc.Digest.String(),
			Status: BlobUnreadable,
			Detail: fmt.Sprintf("reading manifest: %v", err),
		}, true
	}
	return data, BlobResult{}, true
}

// verifyNode verifies the manifest blob itself, decodes it (when trustworthy),
// and concurrently verifies the config and every layer it directly references.
// It never descends into child manifests; callers recurse on
// node.manifest.Manifests themselves.
func (c *Checker) verifyNode(ctx context.Context, desc ocispec.Descriptor) checkedNode {
	node := checkedNode{desc: desc, complete: true}

	self := c.checkMemo(ctx, desc)
	if self.Status != BlobOK {
		// If the manifest blob itself can't be trusted (missing, wrong digest,
		// unreadable) its children cannot be safely named; an interrupted
		// self-check is inconclusive rather than corrupt.
		node.complete = self.Status != BlobUnverified
		node.problems = append(node.problems, self)
		return node
	}

	data, readProblem, readComplete := c.readManifestBytes(ctx, desc)
	node.complete = readComplete
	if readProblem.Status != "" {
		node.problems = append(node.problems, readProblem)
		return node
	}

	if err := json.Unmarshal(data, &node.manifest); err != nil {
		node.problems = append(node.problems, BlobResult{
			Digest: desc.Digest.String(),
			Status: BlobUnreadable,
			Detail: fmt.Sprintf("decoding manifest JSON: %v", err),
		})
		return node
	}
	node.decoded = true

	// Config and layers verify concurrently. The goroutines never return a
	// non-nil error; the errgroup only bounds concurrency and joins them, and
	// one failure deliberately does not cancel the siblings -- every bad blob
	// the manifest names must be reported, not just the first one.
	var (
		problemsMu sync.Mutex
		g          errgroup.Group
	)
	g.SetLimit(runtime.GOMAXPROCS(0))

	addChild := func(child ocispec.Descriptor) {
		if child.Digest.Validate() != nil {
			return
		}
		g.Go(func() error {
			r := c.checkMemo(ctx, child)
			if r.Status != BlobOK {
				problemsMu.Lock()
				node.problems = append(node.problems, r)
				if r.Status == BlobUnverified {
					node.complete = false
				}
				problemsMu.Unlock()
			}
			return nil
		})
	}

	if node.manifest.Config.Digest.Validate() == nil {
		addChild(node.manifest.Config)
	}
	for _, l := range node.manifest.Layers {
		addChild(l)
	}
	_ = g.Wait()

	sortBlobResults(node.problems)
	return node
}

func sortBlobResults(problems []BlobResult) {
	sort.SliceStable(problems, func(i, j int) bool {
		if problems[i].Digest != problems[j].Digest {
			return problems[i].Digest < problems[j].Digest
		}
		return problems[i].Status < problems[j].Status
	})
}

// Check walks the descriptor graph rooted at desc -- the manifest blob itself,
// its config and layers, and (for an image index) each child manifest
// recursively -- and aggregates every blob that fails its check.
//
// If the manifest blob itself fails its check, Check stops descending: a
// manifest whose own bytes don't match its digest cannot be trusted to
// accurately name its children, so attempting to check those children would be
// meaningless.
func (c *Checker) Check(ctx context.Context, desc ocispec.Descriptor) CheckResult {
	result := CheckResult{OK: true, Complete: true}

	// seen guards against descriptor cycles in hand-crafted indexes; the same
	// digest reached twice in one graph contributes its verdict once.
	seen := make(map[string]bool)
	problems := make(map[string]BlobResult)

	var walk func(ocispec.Descriptor)
	walk = func(d ocispec.Descriptor) {
		if d.Digest.Validate() != nil {
			return
		}
		key := d.Digest.String()
		if seen[key] {
			return
		}
		seen[key] = true

		node := c.verifyNode(ctx, d)
		if !node.complete {
			result.Complete = false
		}
		for _, p := range node.problems {
			// A digest has at most one verdict per session (checkMemo), so a
			// digest key is sufficient to dedupe shared blobs in one graph.
			problems[p.Digest] = p
		}
		if !node.decoded {
			return
		}
		for _, child := range node.manifest.Manifests {
			walk(child)
		}
	}
	walk(desc)

	if ctx.Err() != nil {
		result.Complete = false
	}

	for _, p := range problems {
		result.Problems = append(result.Problems, p)
	}
	sortBlobResults(result.Problems)

	result.OK = result.Complete && len(result.Problems) == 0
	return result
}

// CheckStore snapshots the store's index and checks every root artifact --
// recursively through image indexes -- concurrently, aggregating per-unit
// outcomes into one session report.
//
// Artifacts are isolated: a failure (or panic) verifying one artifact is
// recorded on that artifact's units and never aborts the others, so a corrupt
// entry can't mask what the rest of the store looks like. Cancellation marks
// the returned report incomplete; units not reached before cancellation are
// reported with Reached == false, and in-flight blobs with BlobUnverified,
// instead of either a generic success or a mid-run exception.
func (c *Checker) CheckStore(ctx context.Context) *CheckReport {
	report := &CheckReport{
		SessionID: c.SessionID(),
		StartedAt: time.Now(),
		// Optimistic until something proves the run incomplete: a cancelled
		// context, an unreached unit, or an unverified in-flight blob.
		Complete: true,
	}

	var roots []ocispec.Descriptor
	_ = c.l.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		if _, ok := desc.Annotations[ocispec.AnnotationRefName]; ok {
			roots = append(roots, desc)
		}
		return nil
	})

	// Deterministic root order makes repeated runs of a session comparable.
	sort.Slice(roots, func(i, j int) bool {
		ri := roots[i].Annotations[ocispec.AnnotationRefName]
		rj := roots[j].Annotations[ocispec.AnnotationRefName]
		if ri != rj {
			return ri < rj
		}
		return roots[i].Digest.String() < roots[j].Digest.String()
	})

	// Index-aligned slots keep output in root order without appending from
	// goroutines under a shared lock.
	slots := make([][]ArtifactCheck, len(roots))
	var g errgroup.Group
	g.SetLimit(runtime.GOMAXPROCS(0))
	for i := range roots {
		i, root := i, roots[i]
		g.Go(func() error {
			slots[i] = c.checkArtifactUnits(ctx, root)
			return nil
		})
	}
	_ = g.Wait()

	for _, units := range slots {
		report.Artifacts = append(report.Artifacts, units...)
	}
	sort.SliceStable(report.Artifacts, func(i, j int) bool {
		a, b := report.Artifacts[i], report.Artifacts[j]
		if a.Reference != b.Reference {
			return a.Reference < b.Reference
		}
		if a.RootDigest != b.RootDigest {
			return a.RootDigest < b.RootDigest
		}
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		return a.Digest < b.Digest
	})

	if ctx.Err() != nil {
		report.Complete = false
	}

	for _, u := range report.Artifacts {
		report.TotalArtifacts++
		if !u.Reached {
			report.Complete = false
			continue
		}
		report.ReachedArtifacts++
		if len(u.Problems) > 0 {
			report.FailedArtifacts++
			for _, p := range u.Problems {
				if p.Status == BlobUnverified {
					report.Complete = false
				}
			}
		}
	}

	c.mu.Lock()
	report.BlobsChecked = len(c.memo)
	c.mu.Unlock()

	c.hashMu.Lock()
	for _, n := range c.hashCounts {
		report.BlobsHashed += n
	}
	c.hashMu.Unlock()

	report.FinishedAt = time.Now()
	return report
}

// checkArtifactUnits verifies one index entry and returns its unit(s): one unit
// for a plain manifest, one unit per (nested) platform manifest for an index.
// A panic in verification is converted into a problem on this entry instead of
// tearing down the whole check goroutine group.
func (c *Checker) checkArtifactUnits(ctx context.Context, root ocispec.Descriptor) (units []ArtifactCheck) {
	defer func() {
		if r := recover(); r != nil {
			u := newArtifactUnit(root, root, "-", "", "")
			u.Problems = []BlobResult{{
				Digest: root.Digest.String(),
				Status: BlobUnreadable,
				Detail: fmt.Sprintf("internal checker failure: %v", r),
			}}
			units = []ArtifactCheck{u}
		}
	}()

	if err := ctx.Err(); err != nil {
		// Scheduled but never started: distinct from a reached-but-corrupt
		// unit so callers can tell corruption from an unfinished run.
		u := newArtifactUnit(root, root, "-", "", "")
		u.OK = false
		u.Reached = false
		return []ArtifactCheck{u}
	}

	node := c.verifyNode(ctx, root)

	// The root blob itself could not be verified or decoded: its children
	// cannot be safely named, so the entry collapses to a single unit with no
	// known config type.
	if !node.decoded {
		u := newArtifactUnit(root, root, "-", root.MediaType, "")
		u.Problems = cloneResults(node.problems)
		return finalizeUnits(u)
	}

	// The manifest decoded, so its config media type is known even when one of
	// its layers failed -- the type filter must still classify a corrupt chart
	// as a chart, not fall back to "image".
	configMT := node.manifest.Config.MediaType

	// Plain manifest / artifact: one unit.
	if len(node.manifest.Manifests) == 0 {
		u := newArtifactUnit(root, root, "-", root.MediaType, configMT)
		u.Problems = cloneResults(node.problems)
		return finalizeUnits(u)
	}

	// Image index (possibly nested): immediate children verify concurrently;
	// nested indexes expand serially within their own goroutine.
	var (
		unitsMu sync.Mutex
		childG  errgroup.Group
	)
	childG.SetLimit(runtime.GOMAXPROCS(0))

	var visit func(d ocispec.Descriptor)
	visit = func(d ocispec.Descriptor) {
		n := c.verifyNode(ctx, d)
		plat := platformString(d.Platform)

		if n.decoded && len(n.manifest.Manifests) > 0 {
			// A nested index that itself has problems stays visible as its
			// own unit; healthy nested indexes only contribute descendants.
			if len(n.problems) > 0 {
				u := newArtifactUnit(root, d, plat, d.MediaType, "")
				u.Problems = cloneResults(n.problems)
				unitsMu.Lock()
				units = append(units, u)
				unitsMu.Unlock()
			}
			for _, child := range n.manifest.Manifests {
				if child.Digest.Validate() != nil {
					continue
				}
				visit(child)
			}
			return
		}

		configMT := ""
		if n.decoded {
			configMT = n.manifest.Config.MediaType
		}
		u := newArtifactUnit(root, d, plat, d.MediaType, configMT)
		u.Problems = cloneResults(n.problems)

		unitsMu.Lock()
		units = append(units, u)
		unitsMu.Unlock()
	}

	for _, child := range node.manifest.Manifests {
		if child.Digest.Validate() != nil {
			continue
		}
		child := child
		childG.Go(func() error {
			visit(child)
			return nil
		})
	}
	_ = childG.Wait()

	return finalizeUnits(units...)
}

// finalizeUnits fills OK on the given units (defensive: zero-value defaults
// already mean "not OK", so this records the positive verdict), sorts them by
// platform/digest, and returns them.
func finalizeUnits(units ...ArtifactCheck) []ArtifactCheck {
	for i := range units {
		units[i].OK = units[i].Reached && len(units[i].Problems) == 0
	}
	sort.SliceStable(units, func(i, j int) bool {
		if units[i].Platform != units[j].Platform {
			return units[i].Platform < units[j].Platform
		}
		return units[i].Digest < units[j].Digest
	})
	return units
}

func cloneResults(in []BlobResult) []BlobResult {
	if len(in) == 0 {
		return nil
	}
	out := make([]BlobResult, len(in))
	copy(out, in)
	return out
}

// newArtifactUnit builds an ArtifactCheck carrying the root entry's reference
// and annotations (copied) with the unit-specific descriptor's digest,
// platform and media types.
func newArtifactUnit(root, unitDesc ocispec.Descriptor, plat, mediaType, configMT string) ArtifactCheck {
	if plat == "" {
		plat = "-"
	}
	return ArtifactCheck{
		Reference:       root.Annotations[ocispec.AnnotationRefName],
		Annotations:     maps.Clone(root.Annotations),
		RootDigest:      root.Digest.String(),
		Digest:          unitDesc.Digest.String(),
		Platform:        plat,
		MediaType:       mediaType,
		ConfigMediaType: configMT,
		Reached:         true,
	}
}

// platformString renders a descriptor platform as "os/arch[/variant]", or "-"
// when unset.
func platformString(p *ocispec.Platform) string {
	if p == nil || (p.OS == "" && p.Architecture == "") {
		return "-"
	}
	if p.Variant != "" {
		return fmt.Sprintf("%s/%s/%s", p.OS, p.Architecture, p.Variant)
	}
	return fmt.Sprintf("%s/%s", p.OS, p.Architecture)
}

package content

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	goname "github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"

	ccontent "github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/pkg/consts"
	"hauler.dev/go/hauler/v2/pkg/reference"
)

var _ Target = (*OCI)(nil)

// indexCheckpointInterval bounds fsync frequency on the per-artifact save
// path: index.json is rewritten in full on every AddIndex, so fsyncing each
// one costs O(N^2) bytes across a sync (~5 GB for 5,000 artifacts) while
// holding o.mu. Coalescing trades a bounded power-loss/panic exposure window
// for that cost -- an interrupted sync is simply re-run.
const indexCheckpointInterval = 30 * time.Second

// ErrDigestMismatch is returned by WriteBlob (and wrapped with details) when
// the content actually streamed from open() does not hash to the expected
// digest. Callers can retry: the final blob path is never touched on this
// error, so a fresh WriteBlob call will re-download cleanly.
var ErrDigestMismatch = errors.New("content: digest mismatch")

// ctxReader wraps an io.Reader so Read returns ctx.Err() once ctx is done,
// instead of delegating. This makes an in-flight WriteBlob copy abort on
// cancellation, since the underlying reader (v1.Layer's Compressed(), which
// this package doesn't control) has no cancellation hook of its own.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

type OCI struct {
	root    string
	index   *ocispec.Index
	nameMap *sync.Map // map[string]ocispec.Descriptor
	sf      singleflight.Group

	// generation is the committed snapshot identity read from index.json's
	// hauler.dev/snapshot-generation annotation. Every content-changing
	// commit bumps it; SnapshotView/Readers report it so callers and logs can
	// name the exact snapshot a request observed. snapshotTime is the same
	// generation's commit timestamp. Guarded by mu.
	generation   uint64
	snapshotTime string

	// blobSem bounds blob writes in flight across this OCI's two write
	// paths (WriteBlob, ociPusher.Push), scoped per-store. Acquire is
	// ctx-aware, unlike errgroup.SetLimit, so it returns promptly on
	// cancellation instead of leaving a goroutine parked.
	blobSem *semaphore.Weighted

	// blobConcurrency is the ceiling blobSem was built with, retained so
	// reporting can render "peak-inflight=N/ceiling" (semaphore.Weighted
	// doesn't expose its own capacity).
	blobConcurrency int

	// stats accumulates disk-contention counters for this store. See
	// stats.go.
	stats IOStats

	// mu guards index, index.json on disk, and nameMap descriptors'
	// annotation maps. Exported methods are thin lock-then-Locked-variant
	// wrappers; the *Locked methods assume the caller holds mu, letting
	// internal chains (e.g. ociPusher.Push's load-modify-save) re-enter
	// without double-locking (see Walk's doc comment for the related hazard).
	mu sync.Mutex

	// lastDurableSave is when the index was last fsync'd, guarded by mu.
	// The zero value makes the first save of a run durable, which gives an
	// early checkpoint for free.
	lastDurableSave time.Time

	// now is time.Now, replaced in tests so checkpoint-interval behavior
	// can be exercised without sleeping.
	now func() time.Time
}

// lock acquires o.mu, recording time spent blocked into IOStats, so every
// caller measures index-serialization cost in one place. Unlock isn't
// wrapped since it never blocks.
func (o *OCI) lock() {
	start := time.Now()
	o.mu.Lock()
	o.stats.IndexLockWaitNanos.Add(int64(time.Since(start)))
}

// OCIOption configures an OCI store at construction time.
type OCIOption func(*OCI)

// WithBlobConcurrency overrides consts.DefaultBlobConcurrency for this OCI's
// blobSem. n <= 0 is a no-op (keeps the default) rather than an error, so
// callers can pass a possibly-zero value unconditionally.
func WithBlobConcurrency(n int) OCIOption {
	return func(o *OCI) {
		if n > 0 {
			o.blobSem = semaphore.NewWeighted(int64(n))
			o.blobConcurrency = n
		}
	}
}

func NewOCI(root string, opts ...OCIOption) (*OCI, error) {
	o := &OCI{
		root:            root,
		nameMap:         &sync.Map{},
		blobSem:         semaphore.NewWeighted(consts.DefaultBlobConcurrency),
		blobConcurrency: consts.DefaultBlobConcurrency,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o, nil
}

// Stats returns this store's I/O contention counters. The returned pointer
// is live -- counters keep incrementing as work proceeds. Call Snapshot on
// it to take a stable reading.
func (o *OCI) Stats() *IOStats {
	return &o.stats
}

// BlobConcurrency returns the ceiling blobSem was constructed with.
func (o *OCI) BlobConcurrency() int {
	return o.blobConcurrency
}

// nameMapKey derives the nameMap key for an AnnotationRefName-shaped ref
// (e.g. "repo:tag" or "repo@sha256:...") and a kind annotation. AddIndex,
// loadIndexLocked, and ociPusher.Push must all derive this identically: a
// goname.Digest keys by key.Name(), which retains the digest (registry/repo@digest),
// so two different digests in one repository never collide on the same key --
// key.Context().String() is repo-only and once made the second of two such
// writes silently delete the first (see AddIndex's history). A goname.Tag
// keys by its full string; tag entries never carry a digest suffix. ok is
// false for the "--" placeholder ref or an unrecognized reference kind, both
// of which callers treat as "nothing to store under this key."
func nameMapKey(ref, kind string) (key string, ok bool, err error) {
	parsed, err := reference.Parse(ref)
	if err != nil {
		return "", false, err
	}
	if strings.TrimSpace(parsed.String()) == "--" {
		return "", false, nil
	}
	switch parsed.(type) {
	case goname.Digest:
		return fmt.Sprintf("%s-%s", parsed.Name(), kind), true, nil
	case goname.Tag:
		return fmt.Sprintf("%s-%s", parsed.String(), kind), true, nil
	default:
		return "", false, nil
	}
}

// AddIndex adds a descriptor to the index and updates it
//
//	The descriptor must use AnnotationRefName to identify itself
//
// AddIndex is a single-operation snapshot transaction: see BeginTx. Multi-artifact
// updates (an image plus its signatures/referrers, a whole haul load, a batch
// removal) must use an explicit Txn so a failure never publishes half of a
// logical update.
func (o *OCI) AddIndex(desc ocispec.Descriptor) error {
	tx, err := o.BeginTx(context.Background())
	if err != nil {
		return err
	}
	if err := tx.AddIndex(desc); err != nil {
		tx.Rollback()
		return err
	}
	// Per-artifact callers keep the checkpoint (coalesced-fsync) cadence; a
	// rename is atomic either way, so readers still see only complete
	// snapshots even before the fsync checkpoint lands.
	_, err = tx.commit(false)
	return err
}

// snapshotMetaFromIndex reads the generation/time recorded on a committed
// index, tolerating indexes written before snapshots existed.
func snapshotMetaFromIndex(idx *ocispec.Index) (uint64, string) {
	if idx == nil || idx.Annotations == nil {
		return 0, ""
	}
	var gen uint64
	if raw := idx.Annotations[consts.SnapshotGenerationAnnotation]; raw != "" {
		if n, err := strconv.ParseUint(raw, 10, 64); err == nil {
			gen = n
		}
	}
	return gen, idx.Annotations[consts.SnapshotTimeAnnotation]
}

// SnapshotGeneration returns the generation of the index currently held in
// memory (refreshed by LoadIndex/Walk/Resolve and after every commit).
func (o *OCI) SnapshotGeneration() uint64 {
	o.lock()
	defer o.mu.Unlock()
	return o.generation
}

// SnapshotTime returns the commit timestamp of the index held in memory.
func (o *OCI) SnapshotTime() string {
	o.lock()
	defer o.mu.Unlock()
	return o.snapshotTime
}

// SnapshotInfo returns the current generation, its commit timestamp, and the
// count of catalogued descriptors -- the observable snapshot identity used by
// `store info` and recovery checks.
func (o *OCI) SnapshotInfo() (uint64, string, int) {
	o.lock()
	defer o.mu.Unlock()
	count := 0
	o.nameMap.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return o.generation, o.snapshotTime, count
}

// SnapshotView is a read lease on one committed snapshot. Hold it across the
// whole logical request -- index walk plus every subsequent blob fetch/push --
// so an exclusive GC/Flush boundary in this or another process waits until the
// request completes instead of unlinking a blob the request still needs.
// Commits (adds) do not contend with a View: blobs are immutable and index.json
// switches atomically, so the request simply keeps observing the snapshot it
// started on.
type SnapshotView struct {
	o       *OCI
	release leaseRelease
}

// View acquires a shared snapshot lease. The lease is cross-process (flock on
// <root>/.hauler/snapshot.lock) as well as in-process.
func (o *OCI) View(ctx context.Context) (*SnapshotView, error) {
	release, _, err := acquireView(o.root)
	if err != nil {
		return nil, err
	}
	return &SnapshotView{o: o, release: release}, nil
}

// Release ends the read lease, allowing waiting deletion boundaries to proceed.
func (v *SnapshotView) Release() {
	if v.release != nil {
		v.release()
		v.release = nil
	}
}

// Generation reports the snapshot generation as observed at any point while
// the view is held.
func (v *SnapshotView) Generation() uint64 {
	return v.o.SnapshotGeneration()
}

// Txn is one all-or-nothing index.json transition. Stage descriptors while
// streaming their blobs (staged blobs are content-addressed and invisible
// until referenced -- and protected from GC by Txn's shared snapshot lease),
// then Commit once. On any error or Rollback, index.json is untouched and the
// staged blobs remain unreferenced garbage reclaimed by a later GC.
type Txn struct {
	o         *OCI
	viewRel   leaseRelease
	upserts   []stagedEntry
	upsertIdx map[string]int
	removes   map[string]struct{}
	done      bool
}

// stagedEntry pairs a buffered descriptor with the nameMap key it commits to.
type stagedEntry struct {
	key  string
	desc ocispec.Descriptor
}

// BeginTx opens an update transaction holding a shared snapshot lease until
// Commit or Rollback.
func (o *OCI) BeginTx(ctx context.Context) (*Txn, error) {
	release, _, err := acquireView(o.root)
	if err != nil {
		return nil, err
	}
	return &Txn{
		o:         o,
		viewRel:   release,
		upsertIdx: map[string]int{},
		removes:   map[string]struct{}{},
	}, nil
}

// AddIndex buffers one descriptor into the transaction. Validation/parsing is
// identical to the standalone AddIndex it replaces.
func (tx *Txn) AddIndex(desc ocispec.Descriptor) error {
	if tx.done {
		return errors.New("content: transaction already committed")
	}
	if _, ok := desc.Annotations[ocispec.AnnotationRefName]; !ok {
		return fmt.Errorf("descriptor must contain a reference from the annotation: %s", ocispec.AnnotationRefName)
	}

	mapKey, ok, err := nameMapKey(desc.Annotations[ocispec.AnnotationRefName], desc.Annotations[consts.KindAnnotationName])
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	// Clone for the same alias reasons the standalone path clones: callers
	// keep mutating desc after staging it.
	staged := desc
	staged.Annotations = maps.Clone(desc.Annotations)

	if i, exists := tx.upsertIdx[mapKey]; exists {
		tx.upserts[i] = stagedEntry{key: mapKey, desc: staged}
		return nil
	}
	tx.upsertIdx[mapKey] = len(tx.upserts)
	tx.upserts = append(tx.upserts, stagedEntry{key: mapKey, desc: staged})
	delete(tx.removes, mapKey) // upsert-after-remove within one tx means replace
	return nil
}

// Remove buffers a nameMap-key removal into the transaction.
func (tx *Txn) Remove(key string) {
	if tx.done {
		return
	}
	tx.removes[key] = struct{}{}
	if i, ok := tx.upsertIdx[key]; ok {
		tx.upserts = append(tx.upserts[:i], tx.upserts[i+1:]...)
		delete(tx.upsertIdx, key)
		for k, idx := range tx.upsertIdx {
			if idx > i {
				tx.upsertIdx[k] = idx - 1
			}
		}
	}
}

// Empty reports whether the transaction buffers any change.
func (tx *Txn) Empty() bool {
	return tx != nil && len(tx.upserts) == 0 && len(tx.removes) == 0
}

// Commit publishes the transaction: one commit.lock critical section that
// rebuilds the baseline from the index.json committed on disk (so concurrent
// processes can't lose each other's entries), applies the buffered change,
// validates every new descriptor's referenced blobs, then writes index.json
// once with a bumped generation. Durable additionally fsyncs the transition
// (required for whole-unit boundaries like AddImage/load/removal; per-artifact
// auto-transactions use the coalesced checkpoint cadence).
func (tx *Txn) Commit() (uint64, error) {
	return tx.commit(true)
}

func (tx *Txn) commit(durable bool) (uint64, error) {
	if tx.done {
		return 0, errors.New("content: transaction already committed")
	}
	tx.done = true
	defer tx.finish()

	commitRel, _, err := acquireCommit(tx.o.root)
	if err != nil {
		return 0, err
	}
	defer commitRel()

	tx.o.lock()
	defer tx.o.mu.Unlock()

	gen, _, err := tx.o.applyChangesLocked(tx.upserts, tx.removes, durable, false)
	return gen, err
}

// Rollback discards the transaction without touching index.json.
func (tx *Txn) Rollback() {
	if tx == nil || tx.done {
		return
	}
	tx.done = true
	tx.finish()
}

func (tx *Txn) finish() {
	if tx.viewRel != nil {
		tx.viewRel()
		tx.viewRel = nil
	}
}

// Target wraps the OCI target so pushes performed through it buffer manifest
// index entries into tx instead of each saving index.json itself. Blob pushes
// are unchanged. Used to commit a whole CopyAll/load as one snapshot.
func (tx *Txn) Target() Target {
	return &txnTarget{o: tx.o, tx: tx}
}

type txnTarget struct {
	o  *OCI
	tx *Txn
}

func (t *txnTarget) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	return t.o.Resolve(ctx, ref)
}

func (t *txnTarget) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	return t.o.Fetcher(ctx, ref)
}

func (t *txnTarget) Pusher(ctx context.Context, ref string) (remotes.Pusher, error) {
	p, err := t.o.Pusher(ctx, ref)
	if err != nil {
		return nil, err
	}
	if op, ok := p.(*ociPusher); ok {
		op.tx = t.tx
		return op, nil
	}
	return p, nil
}

// Exclusive runs fn while holding snapshot.lock exclusive -- the deletion
// boundary under which no View or staging Txn in any process can be active.
// GC and Flush use it so index transition and blob unlink are observed as one
// indivisible state change.
func (o *OCI) Exclusive(ctx context.Context, fn func() error) error {
	release, _, err := acquireExclusive(o.root)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

// descriptorsEqual reports whether two descriptors are equal in every field
// AddIndex's callers in this codebase populate: MediaType, Digest, Size,
// URLs, ArtifactType, Platform, Data, and Annotations (compared by
// contents, not map identity).
func descriptorsEqual(a, b ocispec.Descriptor) bool {
	if a.MediaType != b.MediaType || a.Digest != b.Digest || a.Size != b.Size || a.ArtifactType != b.ArtifactType {
		return false
	}
	if !maps.Equal(a.Annotations, b.Annotations) {
		return false
	}
	if !slices.Equal(a.URLs, b.URLs) {
		return false
	}
	if !bytes.Equal(a.Data, b.Data) {
		return false
	}
	if (a.Platform == nil) != (b.Platform == nil) {
		return false
	}
	if a.Platform != nil {
		pa, pb := a.Platform, b.Platform
		if pa.Architecture != pb.Architecture || pa.OS != pb.OS || pa.OSVersion != pb.OSVersion || pa.Variant != pb.Variant {
			return false
		}
		if !slices.Equal(pa.OSFeatures, pb.OSFeatures) {
			return false
		}
	}
	return true
}

// LoadIndex will load the index from disk.
func (o *OCI) LoadIndex() error {
	o.lock()
	defer o.mu.Unlock()
	return o.loadIndexLocked()
}

// loadIndexLocked is LoadIndex's implementation. Callers must hold o.mu.
//
// The on-disk index is adopted as authoritative: the in-memory nameMap is
// REPLACED, not merged. Uncommitted state never lives in nameMap (it lives in
// Txn buffers), and replacing means a removal committed by another process
// becomes visible instead of lingering as a stale in-memory ghost.
func (o *OCI) loadIndexLocked() error {
	idx, err := o.readIndexFileLocked()
	if err != nil {
		return err
	}
	o.index = idx
	o.generation, o.snapshotTime = snapshotMetaFromIndex(idx)
	o.nameMap = nameMapFromIndex(idx)
	return nil
}

// readIndexFileLocked decodes index.json from disk; a missing file yields the
// canonical empty index. Callers must hold o.mu (callers are serialized by the
// same commit boundary that swaps the file).
func (o *OCI) readIndexFileLocked() (*ocispec.Index, error) {
	path := o.path(ocispec.ImageIndexFile)
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		return &ocispec.Index{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			MediaType: ocispec.MediaTypeImageIndex,
		}, nil
	}
	defer f.Close()

	idx := &ocispec.Index{}
	if err := json.NewDecoder(f).Decode(idx); err != nil {
		return nil, err
	}
	return idx, nil
}

// nameMapFromIndex normalizes a decoded index's descriptors into a fresh
// nameMap: defaulting/normalizing the kind annotation into per-descriptor
// annotation copies and deriving the same nameMapKey AddIndex/Txn use.
// Malformed entries are skipped rather than making the whole store unreadable.
func nameMapFromIndex(idx *ocispec.Index) *sync.Map {
	m := &sync.Map{}
	if idx == nil {
		return m
	}
	for _, desc := range idx.Manifests {
		// Set default kind if missing... normalize legacy dev.cosignproject.cosign values
		kind := desc.Annotations[consts.KindAnnotationName]
		kind = consts.NormalizeLegacyKind(kind)
		if kind == "" {
			kind = consts.KindAnnotationImage
		}

		// Write normalized kind into a copy of Annotations so Walk() callers
		// see it, without mutating the slice element's shared map.
		normalized := make(map[string]string, len(desc.Annotations)+1)
		maps.Copy(normalized, desc.Annotations)
		normalized[consts.KindAnnotationName] = kind
		desc.Annotations = normalized

		mapKey, ok, err := nameMapKey(desc.Annotations[ocispec.AnnotationRefName], kind)
		if err != nil {
			// skip malformed entries rather than making the entire store unreadable
			continue
		}
		if ok {
			m.Store(mapKey, desc)
		}
	}
	return m
}

// applyChangesLocked is the single commit implementation: rebuild the
// baseline from the index.json committed on disk, validate every new/changed
// descriptor's referenced blobs, apply buffered upserts/removes, and -- when
// anything changed -- bump generation and save index.json once. Callers must
// hold commit.lock (cross-process serialization) and o.mu.
//
// durable requests fsync; forceSave additionally rewrites (and fsyncs)
// index.json even when the content is unchanged -- SaveIndex's contract is to
// make the on-disk index durable regardless, e.g. to flush a coalesced
// checkpoint. A forced, unchanged save does not advance the generation.
//
// Returns the resulting generation and whether content changed.
func (o *OCI) applyChangesLocked(staged []stagedEntry, removes map[string]struct{}, durable, forceSave bool) (uint64, bool, error) {
	idx, err := o.readIndexFileLocked()
	if err != nil {
		return 0, false, err
	}
	disk := nameMapFromIndex(idx)
	gen, _ := snapshotMetaFromIndex(idx)

	// Anything that differs from the committed baseline is about to be
	// published: prove its full descriptor graph is on disk first. A failed
	// validation rejects the whole transition -- no half-published snapshot.
	pending := make([]ocispec.Descriptor, 0, len(staged))
	for _, e := range staged {
		if old, ok := disk.Load(e.key); ok && descriptorsEqual(old.(ocispec.Descriptor), e.desc) {
			continue
		}
		pending = append(pending, e.desc)
	}
	if vErr := o.validateCommittedLocked(pending); vErr != nil {
		return gen, false, vErr
	}

	changed := false
	for _, e := range staged {
		if old, ok := disk.Load(e.key); ok && descriptorsEqual(old.(ocispec.Descriptor), e.desc) {
			continue
		}
		disk.Store(e.key, e.desc)
		changed = true
	}
	for key := range removes {
		if _, loaded := disk.LoadAndDelete(key); loaded {
			changed = true
		}
	}

	// Always adopt the committed baseline in memory, even when this tx changed
	// nothing, so external transitions are observed.
	o.nameMap = disk
	o.index = idx
	o.generation = gen
	if !changed {
		if forceSave {
			// Durable flush of the current state (e.g. coalesced checkpoint):
			// same content, same generation, but fsynced now.
			return gen, false, o.saveIndexLocked(true)
		}
		return gen, false, nil
	}

	o.generation = gen + 1
	o.snapshotTime = o.now().UTC().Format(time.RFC3339Nano)
	if o.index.Annotations == nil {
		o.index.Annotations = map[string]string{}
	}
	o.index.Annotations[consts.SnapshotGenerationAnnotation] = strconv.FormatUint(o.generation, 10)
	o.index.Annotations[consts.SnapshotTimeAnnotation] = o.snapshotTime

	// Preserve the fsync-coalescing checkpoint cadence for high-frequency
	// per-artifact commits (AddIndex): the rename is atomic either way, only
	// power-loss durability is coalesced.
	if !durable && o.now().Sub(o.lastDurableSave) < indexCheckpointInterval {
		durable = false
	} else {
		durable = true
	}
	if err := o.saveIndexLocked(durable); err != nil {
		return gen, false, err
	}
	return o.generation, true, nil
}

// manifestGraphShape captures the child references validation must walk,
// across both image manifests and indexes.
type manifestGraphShape struct {
	Config    ocispec.Descriptor   `json:"config"`
	Layers    []ocispec.Descriptor `json:"layers"`
	Manifests []ocispec.Descriptor `json:"manifests"`
}

// validateCommittedLocked proves every pending descriptor's content graph is
// materially present before it can be published: the blob file exists at its
// content-addressed path and, when the descriptor names a size, matches it.
// Manifest/index blobs are decoded and their config, layers, and child
// manifests checked recursively. Foreign layers (URLs) and inline Data are
// served without local storage and therefore exempt. A digest mismatch of
// actual bytes is a Checker concern; this gate exists so a failed/partial
// update can never publish dangling references.
func (o *OCI) validateCommittedLocked(pending []ocispec.Descriptor) error {
	seen := map[string]bool{}

	var check func(d ocispec.Descriptor) error
	check = func(d ocispec.Descriptor) error {
		if d.Digest.Validate() != nil || len(d.URLs) > 0 || len(d.Data) > 0 {
			return nil
		}
		key := d.Digest.String()
		if seen[key] {
			return nil
		}
		seen[key] = true

		blobPath := filepath.Join(o.path(ocispec.ImageBlobsDir), d.Digest.Algorithm().String(), d.Digest.Hex())
		info, err := os.Stat(blobPath)
		if err != nil {
			return fmt.Errorf("%w: referenced blob %s is not present: %v", ErrSnapshotValidation, key, err)
		}
		if d.Size > 0 && info.Size() != d.Size {
			return fmt.Errorf("%w: referenced blob %s has size %d, descriptor requires %d", ErrSnapshotValidation, key, info.Size(), d.Size)
		}

		switch d.MediaType {
		case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex,
			consts.DockerManifestSchema2, consts.DockerManifestListSchema2:
		default:
			return nil
		}

		raw, err := os.ReadFile(blobPath)
		if err != nil {
			return fmt.Errorf("%w: reading manifest %s for validation: %v", ErrSnapshotValidation, key, err)
		}
		var shape manifestGraphShape
		if err := json.Unmarshal(raw, &shape); err != nil {
			return fmt.Errorf("%w: manifest %s is not valid JSON: %v", ErrSnapshotValidation, key, err)
		}
		if shape.Config.Digest.Validate() == nil {
			if err := check(shape.Config); err != nil {
				return err
			}
		}
		for _, child := range shape.Layers {
			if err := check(child); err != nil {
				return err
			}
		}
		for _, child := range shape.Manifests {
			if err := check(child); err != nil {
				return err
			}
		}
		return nil
	}

	for _, d := range pending {
		if err := check(d); err != nil {
			return err
		}
	}
	return nil
}

// SaveIndex durably persists the in-memory nameMap under commit.lock, merging
// it over whatever index.json another process committed in the meantime.
// Callers that can express their change as add/remove operations should use a
// Txn so deletions can't be resurrected by this merge; SaveIndex is retained
// for "flush what this process holds" callers.
func (o *OCI) SaveIndex() error {
	release, _, err := acquireCommit(o.root)
	if err != nil {
		return err
	}
	defer release()

	o.lock()
	defer o.mu.Unlock()

	var staged []stagedEntry
	o.nameMap.Range(func(key, value interface{}) bool {
		staged = append(staged, stagedEntry{key: key.(string), desc: value.(ocispec.Descriptor)})
		return true
	})
	_, _, err = o.applyChangesLocked(staged, nil, true, true)
	return err
}

// saveIndexLocked is SaveIndex's implementation. Callers must hold o.mu.
//
// The write is atomic: temp file (uniquely named via os.CreateTemp, since
// two hauler processes share no in-process mutex) in the same directory,
// then renamed into place.
//
// durable controls both the temp file's fsync and, after rename, an fsync of
// the containing directory (see syncDir); when false the write is still
// atomic but may not survive power loss until a later save catches up --
// see indexCheckpointInterval.
func (o *OCI) saveIndexLocked(durable bool) error {
	var descs []ocispec.Descriptor
	o.nameMap.Range(func(name, desc interface{}) bool {
		n := desc.(ocispec.Descriptor).Annotations[ocispec.AnnotationRefName]
		d := desc.(ocispec.Descriptor)

		if d.Annotations == nil {
			d.Annotations = make(map[string]string)
		}
		d.Annotations[ocispec.AnnotationRefName] = n
		descs = append(descs, d)
		return true
	})

	// sort index to ensure that images come before any signatures and attestations.
	sort.SliceStable(descs, func(i, j int) bool {
		kindI := descs[i].Annotations["kind"]
		kindJ := descs[j].Annotations["kind"]

		// Objects with the prefix of KindAnnotationImage should be at the top.
		if strings.HasPrefix(kindI, consts.KindAnnotationImage) && !strings.HasPrefix(kindJ, consts.KindAnnotationImage) {
			return true
		} else if !strings.HasPrefix(kindI, consts.KindAnnotationImage) && strings.HasPrefix(kindJ, consts.KindAnnotationImage) {
			return false
		}
		return false // Default: maintain the order.
	})

	o.index.Manifests = descs
	data, err := json.Marshal(o.index)
	if err != nil {
		return err
	}

	indexPath := o.path(ocispec.ImageIndexFile)
	dir := filepath.Dir(indexPath)

	tmp, err := os.CreateTemp(dir, "index-*"+consts.SnapshotIndexTempSuffix)
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	// Unconditional cleanup: harmless ENOENT after a successful rename, and
	// it's the cleanup path for every error branch below -- same idiom as
	// writeBlobOnce.
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// chmod before rename: CreateTemp files are 0600, but index.json must be
	// readable by other consumers (e.g. `hauler store serve` as another user).
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if durable {
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, indexPath); err != nil {
		return err
	}
	// Track the rename unconditionally -- it succeeded regardless of whether
	// the durable branch below (which can still fail on syncDir) completes.
	// IndexDurableWrites stays inside that branch since it must count only
	// fsyncs that actually completed.
	o.stats.IndexWrites.Add(1)
	o.stats.IndexBytesWritten.Add(int64(len(data)))
	if durable {
		if err := syncDir(dir); err != nil {
			return err
		}
		o.lastDurableSave = o.now()
		o.stats.IndexDurableWrites.Add(1)
	}
	return nil
}

// syncDir fsyncs a directory so a rename into it survives power loss;
// fsyncing the file alone doesn't guarantee the directory entry pointing at
// it (containerd's local content store does the same after a blob rename).
// A no-op on Windows, which has no equivalent. EINVAL/ENOTSUP are tolerated
// (some NFS/SMB mounts, common for an air-gapped store root, don't support
// directory fsync) rather than turning a previously working command into a
// hard failure; every other error is still fatal.
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

// Resolve attempts to resolve the reference into a name and descriptor.
//
// The argument `ref` should be a scheme-less URI representing the remote.
// Structurally, it has a host and path. The "host" can be used to directly
// reference a specific host or be matched against a specific handler.
//
// The returned name should be used to identify the referenced entity.
// Dependending on the remote namespace, this may be immutable or mutable.
// While the name may differ from ref, it should itself be a valid ref.
//
// If the resolution fails, an error will be returned.
func (o *OCI) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	o.lock()
	defer o.mu.Unlock()

	if err := o.loadIndexLocked(); err != nil {
		return ocispec.Descriptor{}, err
	}
	d, ok := o.nameMap.Load(ref)
	if !ok {
		return ocispec.Descriptor{}, fmt.Errorf("reference %s not found", ref)
	}
	desc := d.(ocispec.Descriptor)
	return desc, nil
}

// Fetcher returns a new fetcher for the provided reference.
// All content fetched from the returned fetcher will be
// from the namespace referred to by ref.
func (o *OCI) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	o.lock()
	defer o.mu.Unlock()

	if err := o.loadIndexLocked(); err != nil {
		return nil, err
	}
	if _, ok := o.nameMap.Load(ref); !ok {
		return nil, nil
	}
	return o, nil
}

// Fetch is intentionally lock-free: it only touches the filesystem and the
// immutable root field, never index/nameMap. A lock here would deadlock
// store.Layout.CleanUp, which calls Fetch from inside an OCI.Walk callback
// (see Walk's doc comment for the general hazard).
func (o *OCI) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	readerAt, err := o.blobReaderAt(desc)
	if err != nil {
		return nil, err
	}
	return readerAt, nil
}

// FetchManifest is intentionally lock-free -- see Fetch's doc comment.
func (o *OCI) FetchManifest(ctx context.Context, manifest ocispec.Manifest) (io.ReadCloser, error) {
	readerAt, err := o.manifestBlobReaderAt(manifest)
	if err != nil {
		return nil, err
	}
	return readerAt, nil
}

// Pusher returns a new pusher for the provided reference
// The returned Pusher should satisfy content.Ingester and concurrent attempts
// to push the same blob using the Ingester API should result in ErrUnavailable.
func (o *OCI) Pusher(ctx context.Context, ref string) (remotes.Pusher, error) {
	o.lock()
	defer o.mu.Unlock()

	if err := o.loadIndexLocked(); err != nil {
		return nil, err
	}

	var baseRef, hash string
	parts := strings.SplitN(ref, "@", 2)
	baseRef = parts[0]

	if len(parts) > 1 {
		hash = parts[1]
	}

	return &ociPusher{
		oci:    o,
		ref:    baseRef,
		digest: hash,
	}, nil
}

// Walk loads the index, snapshots nameMap under o.mu -- deep-copying each
// descriptor's annotations -- then releases the lock before invoking fn per
// entry. This is load-bearing: store.Layout.CopyAll's self-sync path
// re-enters Copy/Resolve/Fetcher/Pusher on this same OCI from inside a Walk
// callback (CleanUp does the same via Fetch), and a plain mutex held across
// fn would deadlock on that re-entrant Lock() from the same goroutine.
//
// The deep copy means in-place mutation of a callback's descriptor silently
// no-ops instead of corrupting nameMap's shared map; use UpdateAnnotations
// to persist changes.
func (o *OCI) Walk(fn func(reference string, desc ocispec.Descriptor) error) error {
	o.lock()
	if err := o.loadIndexLocked(); err != nil {
		o.mu.Unlock()
		return err
	}

	type entry struct {
		key  string
		desc ocispec.Descriptor
	}
	var snapshot []entry
	o.nameMap.Range(func(key, value interface{}) bool {
		d := value.(ocispec.Descriptor)
		cp := make(map[string]string, len(d.Annotations))
		maps.Copy(cp, d.Annotations)
		d.Annotations = cp
		snapshot = append(snapshot, entry{key: key.(string), desc: d})
		return true
	})
	o.mu.Unlock()

	var errst []string
	for _, e := range snapshot {
		if err := fn(e.key, e.desc); err != nil {
			errst = append(errst, err.Error())
		}
	}
	if errst != nil {
		return fmt.Errorf("%s", strings.Join(errst, "; "))
	}
	return nil
}

// blobReaderAt, manifestBlobReaderAt, blobWriterAt, and ensureBlob are
// lock-free too -- see Fetch's doc comment.
func (o *OCI) blobReaderAt(desc ocispec.Descriptor) (*os.File, error) {
	blobPath, err := o.ensureBlob(desc.Digest.Algorithm().String(), desc.Digest.Hex())
	if err != nil {
		return nil, err
	}
	return os.Open(blobPath)
}

func (o *OCI) manifestBlobReaderAt(manifest ocispec.Manifest) (*os.File, error) {
	blobPath, err := o.ensureBlob(string(manifest.Config.Digest.Algorithm().String()), manifest.Config.Digest.Hex())
	if err != nil {
		return nil, err
	}
	return os.Open(blobPath)
}

func (o *OCI) blobWriterAt(desc ocispec.Descriptor) (*os.File, error) {
	blobPath, err := o.ensureBlob(desc.Digest.Algorithm().String(), desc.Digest.Hex())
	if err != nil {
		return nil, err
	}
	return os.OpenFile(blobPath, os.O_WRONLY|os.O_CREATE, 0644)
}

func (o *OCI) ensureBlob(alg string, hex string) (string, error) {
	dir := o.path(ocispec.ImageBlobsDir, alg)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil && !os.IsExist(err) {
		return "", err
	}
	return filepath.Join(dir, hex), nil
}

// WriteBlob atomically and verifiably writes a blob to the store's blob
// directory, deduplicating concurrent writers of the same digest. It is
// lock-free with respect to o.mu -- see Fetch's doc comment. open is a
// thunk, not a reader, since singleflight must not start the download until
// it wins the flight, and a retry needs a fresh reader.
//
// A file already at the final path with a matching size short-circuits
// WriteBlob without re-hashing, so re-syncs don't become O(store size) in
// disk reads. Otherwise content streams, deduplicated via singleflight, into
// a temp file hashed inline, then chmod'd, fsync'd, and renamed into place.
// On any error the temp file is removed and the final path untouched, so a
// failing writer can't corrupt a peer's completed blob and a retry
// re-downloads cleanly.
//
// singleflight.Do hands the flight winner's error to every waiter, even ones
// on a distinct, still-live ctx -- if that error is context.Canceled but
// this caller's ctx isn't done, WriteBlob retries once on the caller's own
// ctx rather than propagate a cancellation that wasn't its own.
func (o *OCI) WriteBlob(ctx context.Context, expected digest.Digest, size int64, open func() (io.ReadCloser, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	dir := o.path(ocispec.ImageBlobsDir, expected.Algorithm().String())
	if err := os.MkdirAll(dir, os.ModePerm); err != nil && !os.IsExist(err) {
		return err
	}
	blobPath := filepath.Join(dir, expected.Hex())

	// Fast path: trust existing content by size alone, checked and returned
	// before touching blobSem so a cache hit stays free regardless of
	// semaphore saturation.
	if info, err := os.Stat(blobPath); err == nil {
		if size > 0 {
			if info.Size() == size {
				o.noteBlobCached()
				creditCaller(ctx, true)
				return nil
			}
		} else if info.Size() > 0 {
			o.noteBlobCached()
			creditCaller(ctx, true)
			return nil
		}
	}

	err := o.writeBlobShared(ctx, dir, blobPath, expected, size, open)
	if err != nil && errors.Is(err, context.Canceled) && ctx.Err() == nil {
		// See WriteBlob's doc comment: retrying either hits the fast path or
		// this goroutine becomes the new flight leader.
		err = o.writeBlobShared(ctx, dir, blobPath, expected, size, open)
	}
	return err
}

// noteBlobCached records a cache hit on the store-wide IOStats.
func (o *OCI) noteBlobCached() {
	o.stats.BlobsCached.Add(1)
}

// noteBlobWritten is noteBlobCached's counterpart for an actual write.
func (o *OCI) noteBlobWritten() {
	o.stats.BlobsWritten.Add(1)
}

// creditCaller applies a WriteBlob outcome to ctx's per-operation counters (if any), once per caller rather than once per actual write.
func creditCaller(ctx context.Context, cached bool) {
	c := blobCountersFromContext(ctx)
	switch {
	case cached && c.Cached != nil:
		c.Cached.Add(1)
	case !cached && c.Written != nil:
		c.Written.Add(1)
	}
}

// writeBlobShared dedupes concurrent writers of expected via this OCI's singleflight.Group, crediting every caller's own ctx after Do() resolves so a follower's counters aren't skipped just because it didn't do the writing.
func (o *OCI) writeBlobShared(ctx context.Context, dir, blobPath string, expected digest.Digest, size int64, open func() (io.ReadCloser, error)) error {
	ran := false
	v, err, _ := o.sf.Do(expected.String(), func() (interface{}, error) {
		ran = true
		// Acquired inside the singleflight func, not around sf.Do: losers
		// merely waiting on Do() must not hold a permit for someone else's
		// write.
		start := time.Now()
		if err := o.blobSem.Acquire(ctx, 1); err != nil {
			return nil, err
		}
		o.stats.addSemWait(time.Since(start))
		o.stats.enterBlob()
		defer func() {
			o.stats.exitBlob()
			o.blobSem.Release(1)
		}()
		return o.writeBlobOnce(ctx, dir, blobPath, expected, size, open)
	})
	if err == nil {
		cached, _ := v.(bool)
		// Only the caller whose func ran did the write, so everyone who waited on it reuses that download and counts it as cached.
		creditCaller(ctx, cached || !ran)
	}
	return err
}

// writeBlobOnce performs the temp-file-then-rename write and reports whether it was actually a cache hit, for writeBlobShared to credit to every caller sharing the flight.
func (o *OCI) writeBlobOnce(ctx context.Context, dir, blobPath string, expected digest.Digest, size int64, open func() (io.ReadCloser, error)) (cached bool, err error) {
	// Re-check under the flight: a prior, already-completed flight may have
	// written this blob while we were waiting to start.
	if info, statErr := os.Stat(blobPath); statErr == nil {
		if size > 0 && info.Size() == size {
			o.noteBlobCached()
			return true, nil
		}
		if size <= 0 && info.Size() > 0 {
			o.noteBlobCached()
			return true, nil
		}
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	tmp, err := os.CreateTemp(dir, expected.Hex()+".tmp-*")
	if err != nil {
		return false, err
	}
	tmpPath := tmp.Name()
	// Unconditional cleanup: harmless ENOENT after a successful rename, and
	// it's the cleanup path for every error branch below.
	defer os.Remove(tmpPath)

	rc, err := open()
	if err != nil {
		tmp.Close()
		return false, err
	}

	// See ctxReader's doc comment: this makes io.Copy below abort between
	// chunks instead of running an already-cancelled download to completion.
	cr := &ctxReader{ctx: ctx, r: rc}

	dg := digest.Canonical.Digester()
	n, copyErr := io.Copy(io.MultiWriter(tmp, dg.Hash()), cr)
	closeReadErr := rc.Close()

	if copyErr != nil {
		tmp.Close()
		return false, copyErr
	}
	if closeReadErr != nil {
		tmp.Close()
		return false, closeReadErr
	}
	if size > 0 && n != size {
		tmp.Close()
		return false, fmt.Errorf("content: short/long write for %s: wrote %d bytes, expected %d: %w", expected, n, size, ErrDigestMismatch)
	}

	got := dg.Digest()
	if got != expected {
		tmp.Close()
		return false, fmt.Errorf("content: digest mismatch for blob: expected %s, got %s (%d bytes): %w", expected, got, n, ErrDigestMismatch)
	}

	// Commit: chmod 0600->0644 (see saveIndexLocked), fsync, then rename.
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	// os.Rename silently replaces an existing target, which is correct: the
	// content is digest-identical to whatever's already at blobPath.
	if err := os.Rename(tmpPath, blobPath); err != nil {
		return false, err
	}
	o.noteBlobWritten()
	o.stats.BlobBytesWritten.Add(n)
	return false, nil
}

// path and IndexExists are lock-free too -- see Fetch's doc comment.
func (o *OCI) path(elem ...string) string {
	complete := []string{string(o.root)}
	return filepath.Join(append(complete, elem...)...)
}

// IndexExists reports whether the store's OCI layout index.json exists on disk.
func (o *OCI) IndexExists() bool {
	_, err := os.Stat(o.path(ocispec.ImageIndexFile))
	return err == nil
}

type ociPusher struct {
	oci    *OCI
	ref    string
	digest string

	// tx, when set, receives root-manifest index entries instead of each
	// Push saving index.json itself. The owning transaction commits the whole
	// CopyAll/load as one snapshot; when nil a Push auto-commits a
	// single-entry transaction (the checkpoint-cadence path).
	tx *Txn
}

// pusherRef reconstructs the AnnotationRefName-shaped string identifying a
// push driven by Pusher(ctx, ref) -- e.g. "repo:tag" or "repo@sha256:..." --
// so it can be handed to nameMapKey. store.Layout.CopyAll always appends the
// root descriptor's own digest onto the destination ref for verification,
// even for a tag-sourced entry (see its comment), so digest's mere presence
// can't say whether the *original* ref carried a digest or a tag; only ref
// (the part before "@") can, via the same repo-vs-host:port-vs-tag
// disambiguation goname.NewTag applies internally -- checked here first so a
// bare digest-sourced "repo" is never handed to nameMapKey as if it were a
// tagless Tag reference, which would default it to a spurious ":latest".
func pusherRef(ref, digest string) string {
	colonIdx := strings.LastIndex(ref, ":")
	slashIdx := strings.LastIndex(ref, "/")
	if colonIdx >= 0 && colonIdx > slashIdx {
		return ref
	}
	if digest == "" {
		return ref
	}
	return ref + "@" + digest
}

// Push returns a content writer for the given resource identified
// by the descriptor.
func (p *ociPusher) Push(ctx context.Context, d ocispec.Descriptor) (ccontent.Writer, error) {
	// Root-manifest index entries may only be published AFTER the manifest
	// blob itself has been committed: validate/stage the normalized descriptor
	// now, but fire it from the blob writer's successful Close (or immediately
	// when the blob is already present), so commit-time validation always
	// finds every referenced blob on disk.
	var rootManifest *ocispec.Descriptor
	switch d.MediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex, consts.DockerManifestSchema2, consts.DockerManifestListSchema2:
		// if the hash of the content matches that which was provided as the hash for the root, mark it
		if p.digest != "" && p.digest == d.Digest.String() {
			staged, err := p.normalizeRootManifest(d)
			if err != nil {
				return nil, err
			}
			rootManifest = staged
		}
	}

	publish := func() error {
		if rootManifest == nil {
			return nil
		}
		return p.publishRootManifest(*rootManifest)
	}

	blobPath, err := p.oci.ensureBlob(d.Digest.Algorithm().String(), d.Digest.Hex())
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(blobPath); err == nil {
		// Already exists: discard but validate digest. Returned before
		// touching blobSem -- same reasoning as WriteBlob's fast path. The
		// blob is committed already, so publish the index entry immediately.
		if err := publish(); err != nil {
			return nil, err
		}
		return NewIoContentWriter(nopCloser{io.Discard}, WithOutputHash(d.Digest.String())), nil
	}

	// Shares WriteBlob's bound, but held for the writer's whole lifetime
	// (Push through Close) since the caller streams via separate Write
	// calls rather than one owned loop.
	start := time.Now()
	if err := p.oci.blobSem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	p.oci.stats.addSemWait(time.Since(start))
	p.oci.stats.enterBlob()

	w, err := newOCIBlobWriter(filepath.Dir(blobPath), blobPath, d.Digest.String())
	if err != nil {
		p.oci.stats.exitBlob()
		p.oci.blobSem.Release(1)
		return nil, err
	}
	// Fire only after the verified rename, making the index transition's
	// referenced manifest blob guaranteed present.
	w.afterRename = publish
	w.releaseSem = func() {
		p.oci.stats.exitBlob()
		p.oci.blobSem.Release(1)
	}
	return w, nil
}

// normalizeRootManifest applies the same kind normalization and nameMap-key
// derivation the old inline-save path used (see pusherRef/nameMapKey),
// returning nil when the descriptor isn't catalogued under a key.
func (p *ociPusher) normalizeRootManifest(d ocispec.Descriptor) (*ocispec.Descriptor, error) {
	kind := d.Annotations[consts.KindAnnotationName]
	kind = consts.NormalizeLegacyKind(kind)
	if kind == "" {
		kind = consts.KindAnnotationImage
	}

	normalized := d
	normalized.Annotations = make(map[string]string, len(d.Annotations)+1)
	maps.Copy(normalized.Annotations, d.Annotations)
	normalized.Annotations[consts.KindAnnotationName] = kind

	if _, ok, err := nameMapKey(pusherRef(p.ref, p.digest), kind); err != nil {
		return nil, err
	} else if !ok {
		return nil, nil
	}
	return &normalized, nil
}

// publishRootManifest records the pushed root manifest in the bound
// transaction (whole CopyAll/load publishes once), or auto-commits a
// one-entry transaction at the coalesced checkpoint cadence when no tx is
// bound.
func (p *ociPusher) publishRootManifest(d ocispec.Descriptor) error {
	if p.tx != nil {
		return p.tx.AddIndex(d)
	}

	tx, err := p.oci.BeginTx(context.Background())
	if err != nil {
		return err
	}
	if err := tx.AddIndex(d); err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.commit(false)
	return err
}

// ociBlobWriter streams pushed content into a temp file and, on successful
// digest verification at Close, renames it into place -- same on-error
// invariant as content.OCI.WriteBlob (see its doc comment).
type ociBlobWriter struct {
	tmp        *os.File
	tmpPath    string
	finalPath  string
	digester   digest.Digester
	status     ccontent.Status
	outputHash string

	// releaseSem releases the blobSem permit acquired by ociPusher.Push. nil
	// when constructed outside Push (e.g. in tests).
	releaseSem func()

	// afterRename, when set, publishes the root manifest's index entry once
	// the blob rename succeeds -- the point at which the manifest is actually
	// readable. Set by ociPusher.Push; nil for plain blob writers.
	afterRename func() error
}

var _ ccontent.Writer = (*ociBlobWriter)(nil)

func newOCIBlobWriter(dir, finalPath, outputHash string) (*ociBlobWriter, error) {
	tmp, err := os.CreateTemp(dir, filepath.Base(finalPath)+".tmp-*")
	if err != nil {
		return nil, err
	}
	return &ociBlobWriter{
		tmp:        tmp,
		tmpPath:    tmp.Name(),
		finalPath:  finalPath,
		digester:   digest.Canonical.Digester(),
		outputHash: outputHash,
	}, nil
}

func (w *ociBlobWriter) Write(p []byte) (int, error) {
	n, err := w.tmp.Write(p)
	if n > 0 {
		w.digester.Hash().Write(p[:n])
	}
	return n, err
}

// Close verifies the digest and, only on success, chmods, syncs, closes, and
// renames the temp file into place; on failure the temp file is left for
// the deferred os.Remove and the final path is untouched.
func (w *ociBlobWriter) Close() (err error) {
	if w.releaseSem != nil {
		defer w.releaseSem() // released on every path below, success or failure
	}
	defer os.Remove(w.tmpPath) // unconditional: harmless ENOENT after a successful rename

	if w.outputHash != "" {
		if computed := w.digester.Digest().String(); computed != w.outputHash {
			w.tmp.Close()
			return fmt.Errorf("digest mismatch: expected %s, got %s", w.outputHash, computed)
		}
	}

	if err := w.tmp.Chmod(0644); err != nil {
		w.tmp.Close()
		return err
	}
	if err := w.tmp.Sync(); err != nil {
		w.tmp.Close()
		return err
	}
	if err := w.tmp.Close(); err != nil {
		return err
	}

	// os.Rename silently replaces an existing target, which is correct here:
	// the content is digest-verified to match what's expected at finalPath.
	if err := os.Rename(w.tmpPath, w.finalPath); err != nil {
		return err
	}
	// Publish the index entry only after the manifest blob is committed.
	if w.afterRename != nil {
		return w.afterRename()
	}
	return nil
}

func (w *ociBlobWriter) Digest() digest.Digest {
	return w.digester.Digest()
}

func (w *ociBlobWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...ccontent.Opt) error {
	return nil
}

func (w *ociBlobWriter) Status() (ccontent.Status, error) {
	return w.status, nil
}

func (w *ociBlobWriter) Truncate(size int64) error {
	return fmt.Errorf("truncate not supported")
}

// RemoveFromIndex removes ref and publishes the deletion as one durable
// snapshot transaction. Batch callers should use BeginTx with multiple
// Txn.Remove calls and a single Commit instead.
func (o *OCI) RemoveFromIndex(ref string) error {
	tx, err := o.BeginTx(context.Background())
	if err != nil {
		return err
	}
	tx.Remove(ref)
	if tx.Empty() {
		tx.Rollback()
		return nil
	}
	_, err = tx.Commit()
	return err
}

// resetStateLocked clears all in-memory catalog state after an exclusive
// Flush removed the on-disk layout. Callers must hold snapshot.lock exclusive
// and o.mu.
func (o *OCI) resetStateLocked() {
	o.index = &ocispec.Index{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: ocispec.MediaTypeImageIndex,
	}
	o.nameMap = &sync.Map{}
	o.generation = 0
	o.snapshotTime = ""
}

// ResetState clears all in-memory catalog state. It is used by Layout.Flush
// while already holding the exclusive snapshot boundary after the on-disk
// layout has been removed.
func (o *OCI) ResetState() {
	o.lock()
	defer o.mu.Unlock()
	o.resetStateLocked()
}

// UpdateAnnotations locates every descriptor for which match returns true,
// replaces its annotations with a copy that has had apply run over it, and
// persists the index, returning the number matched. The whole pass is one
// commit.lock critical section over the on-disk baseline, so a concurrent
// transaction or push can't interleave a save in between and external
// entries can't be lost; when nothing matches, index.json is not re-saved.
func (o *OCI) UpdateAnnotations(match func(ocispec.Descriptor) bool, apply func(map[string]string)) (int, error) {
	release, _, err := acquireCommit(o.root)
	if err != nil {
		return 0, err
	}
	defer release()

	o.lock()
	defer o.mu.Unlock()

	idx, err := o.readIndexFileLocked()
	if err != nil {
		return 0, err
	}
	disk := nameMapFromIndex(idx)
	gen, _ := snapshotMetaFromIndex(idx)

	matched := 0
	disk.Range(func(key, value interface{}) bool {
		d := value.(ocispec.Descriptor)
		if !match(d) {
			return true
		}
		cp := make(map[string]string, len(d.Annotations))
		maps.Copy(cp, d.Annotations)
		apply(cp)
		d.Annotations = cp
		disk.Store(key, d)
		matched++
		return true
	})

	if matched == 0 {
		// Still adopt the committed baseline so external changes are observed.
		o.nameMap = disk
		o.index = idx
		o.generation = gen
		return 0, nil
	}

	o.nameMap = disk
	o.index = idx
	o.generation = gen + 1
	o.snapshotTime = o.now().UTC().Format(time.RFC3339Nano)
	if o.index.Annotations == nil {
		o.index.Annotations = map[string]string{}
	}
	o.index.Annotations[consts.SnapshotGenerationAnnotation] = strconv.FormatUint(o.generation, 10)
	o.index.Annotations[consts.SnapshotTimeAnnotation] = o.snapshotTime
	return matched, o.saveIndexLocked(true)
}

// ResolvePath returns the absolute path for a given relative path within the OCI root
func (o *OCI) ResolvePath(elem string) string {
	if elem == "" {
		return o.root
	}
	return filepath.Join(o.root, elem)
}

// nopCloser wraps an io.Writer to implement io.WriteCloser
type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

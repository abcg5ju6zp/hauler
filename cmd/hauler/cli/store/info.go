package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/internal/flags"
	"hauler.dev/go/hauler/v2/pkg/consts"
	"hauler.dev/go/hauler/v2/pkg/log"
	"hauler.dev/go/hauler/v2/pkg/reference"
	"hauler.dev/go/hauler/v2/pkg/store"
)

type infoOutput struct {
	StorePath string `json:"store-path"`
	StoreID   string `json:"store-id"`
	// Check is present (non-nil) only for `info --check` runs; it identifies
	// the check session and whether verification finished.
	Check     *checkSummaryOutput `json:"check,omitempty"`
	Artifacts []item              `json:"artifacts"`
}

// checkSummaryOutput is the machine-readable check-session block rendered with
// `info --check -o json`. Complete=false is the signal that the artifacts list
// only covers a partial run and must not be read as a clean bill of health.
type checkSummaryOutput struct {
	Session    string    `json:"session"`
	Complete   bool      `json:"complete"`
	StartedAt  time.Time `json:"started-at"`
	FinishedAt time.Time `json:"finished-at"`

	// Artifacts is the number of checkable units after --type filtering;
	// ArtifactsChecked of them were reached before the run ended, of which
	// ArtifactsFailed had problems and ArtifactsUnreached were never reached.
	Artifacts          int `json:"artifacts"`
	ArtifactsChecked   int `json:"artifacts-checked"`
	ArtifactsFailed    int `json:"artifacts-failed"`
	ArtifactsUnreached int `json:"artifacts-unreached"`

	// BlobsChecked is the number of distinct blobs the session reached a
	// verdict on; BlobsHashed is how many of those were streamed through a
	// digest verifier (shared blobs hash once).
	BlobsChecked int `json:"blobs-checked"`
	BlobsHashed  int `json:"blobs-hashed"`
}

func InfoCmd(ctx context.Context, o *flags.InfoOpts, s *store.Layout) error {
	if o.Check {
		return runStoreCheck(ctx, o, s)
	}
	return runStoreList(ctx, o, s)
}

// runStoreCheck implements `store info --check`: one whole-store check session
// drives the whole report. Per-artifact failures are collected as rows rather
// than aborting the walk, healthy artifacts are omitted, and an interrupted run
// is rendered as a partial report plus a non-nil error instead of a generic
// success.
func runStoreCheck(ctx context.Context, o *flags.InfoOpts, s *store.Layout) error {
	logger := log.FromContext(ctx)

	if o.ListRepos {
		// Repo names come from index annotations alone; no blob hashing needed.
		var refs []item
		_ = s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
			if ref := desc.Annotations[ocispec.AnnotationRefName]; ref != "" {
				refs = append(refs, item{Reference: ref})
			}
			return nil
		})
		buildListRepos(refs...)
		return nil
	}

	var rootTotal int
	_ = s.OCI.Walk(func(_ string, desc ocispec.Descriptor) error {
		if _, ok := desc.Annotations[ocispec.AnnotationRefName]; ok {
			rootTotal++
		}
		return nil
	})
	logger.Infof("checking integrity of %d artifacts... this reads every blob in the store", rootTotal)

	checker := s.NewChecker()
	report := checker.CheckStore(ctx)

	items, summary := buildCheckItems(o, report)

	sort.Sort(byReferenceAndArch(items))

	switch o.OutputFormat {
	case "json":
		out := infoOutput{
			StorePath: s.Root,
			StoreID:   s.StoreID,
			Check:     summary.checkSummary(),
			Artifacts: items,
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		// The failure table lists every known-bad and not-reached unit; a
		// fully healthy run renders no table at all.
		if len(items) > 0 {
			if err := buildFailureTable(s.Root, s.StoreID, items...); err != nil {
				return err
			}
		}
	}

	if !summary.Complete {
		logger.Errorf(
			"integrity check did not finish; results are incomplete: verified %d of %d artifacts (%d failed, %d not reached); re-run the check to cover the rest",
			summary.matched-summary.unreached, summary.matched, summary.failed, summary.unreached,
		)
		if summary.failed > 0 {
			logger.Warnf("to remediate, remove and re-add the affected artifact(s)")
		}
		return fmt.Errorf("store integrity check was interrupted before completion (session %s)", summary.Session)
	}

	if summary.failed > 0 {
		logger.Warnf("%d of %d artifacts failed the integrity check", summary.failed, summary.matched)
		logger.Warnf("to remediate, remove and re-add the affected artifact(s)")
	} else {
		logger.Infof("all %d artifacts passed the integrity check", summary.matched)
	}

	return nil
}

// checkItemAccumulator carries the counters that back checkSummaryOutput while
// buildCheckItems walks the report.
type checkItemAccumulator struct {
	Session    string
	Complete   bool
	StartedAt  time.Time
	FinishedAt time.Time

	matched    int
	failed     int
	unreached  int
	blobsCheck int
	blobsHash  int
}

func (a *checkItemAccumulator) checkSummary() *checkSummaryOutput {
	return &checkSummaryOutput{
		Session:            a.Session,
		Complete:           a.Complete,
		StartedAt:          a.StartedAt,
		FinishedAt:         a.FinishedAt,
		Artifacts:          a.matched,
		ArtifactsChecked:   a.matched - a.unreached,
		ArtifactsFailed:    a.failed,
		ArtifactsUnreached: a.unreached,
		BlobsChecked:       a.blobsCheck,
		BlobsHashed:        a.blobsHash,
	}
}

// buildCheckItems maps a store.CheckReport onto the failure-report item shape,
// applying the --type filter exactly as the non-check inventory does. Healthy
// units are omitted; reached-but-bad units carry their blob problems;
// not-reached units (an interrupted run) carry a distinct "unverified" row so
// the gap in coverage is visible per-object.
func buildCheckItems(o *flags.InfoOpts, report *store.CheckReport) ([]item, *checkItemAccumulator) {
	acc := &checkItemAccumulator{
		Session:    report.SessionID,
		Complete:   report.Complete,
		StartedAt:  report.StartedAt,
		FinishedAt: report.FinishedAt,
		blobsCheck: report.BlobsChecked,
		blobsHash:  report.BlobsHashed,
	}

	items := []item{}

	for _, u := range report.Artifacts {
		synth := ocispec.Descriptor{
			MediaType:   u.MediaType,
			Annotations: u.Annotations,
		}
		ctype := resolveCtype(synth, u.ConfigMediaType)
		if o.TypeFilter != "all" && ctype != o.TypeFilter {
			continue
		}
		acc.matched++

		refName, err := resolveDisplayReference(synth)
		if err != nil {
			continue
		}

		if !u.Reached {
			acc.unreached++
			p := store.BlobResult{
				Digest: u.Digest,
				Status: store.BlobUnverified,
				Detail: "artifact not reached before the check was interrupted",
			}
			items = append(items, item{
				Reference:    refName,
				Type:         ctype,
				Platform:     u.Platform,
				Digest:       u.Digest,
				Problems:     problemStrings([]store.BlobResult{p}),
				blobProblems: []store.BlobResult{p},
			})
			continue
		}

		if len(u.Problems) == 0 {
			continue
		}

		acc.failed++
		items = append(items, item{
			Reference:    refName,
			Type:         ctype,
			Platform:     u.Platform,
			Digest:       u.Digest,
			Problems:     problemStrings(u.Problems),
			blobProblems: u.Problems,
		})
	}

	return items, acc
}

// runStoreList implements the non-check inventory; its shape predates --check
// and is kept separate so check reporting can't alter plain `store info`.
func runStoreList(ctx context.Context, o *flags.InfoOpts, s *store.Layout) error {
	var items []item

	if err := s.Walk(func(_ string, desc ocispec.Descriptor) error {
		if _, ok := desc.Annotations[ocispec.AnnotationRefName]; !ok {
			return nil
		}
		rc, err := s.Fetch(ctx, desc)
		if err != nil {
			return err
		}
		defer rc.Close()

		// handle multi-arch images
		if desc.MediaType == consts.OCIImageIndexSchema || desc.MediaType == consts.DockerManifestListSchema2 {
			var idx ocispec.Index
			if err := json.NewDecoder(rc).Decode(&idx); err != nil {
				return err
			}

			for _, internalDesc := range idx.Manifests {
				plat := fmt.Sprintf("%s/%s", internalDesc.Platform.OS, internalDesc.Platform.Architecture)

				rc, err := s.Fetch(ctx, internalDesc)
				if err != nil {
					return err
				}
				defer rc.Close()

				var internalManifest ocispec.Manifest
				if err := json.NewDecoder(rc).Decode(&internalManifest); err != nil {
					return err
				}

				ctype := resolveCtype(desc, internalManifest.Config.MediaType)
				if o.TypeFilter != "all" && ctype != o.TypeFilter {
					continue
				}

				i := newItemWithDigest(s, internalDesc.Digest.String(), desc, internalManifest, plat, o)
				if i.isEmpty() {
					continue
				}

				items = append(items, i)
			}

			// handle "non" multi-arch images
		} else if desc.MediaType == consts.DockerManifestSchema2 || desc.MediaType == consts.OCIManifestSchema1 {
			var m ocispec.Manifest
			if err := json.NewDecoder(rc).Decode(&m); err != nil {
				return err
			}

			ctype := resolveCtype(desc, m.Config.MediaType)
			if o.TypeFilter != "all" && ctype != o.TypeFilter {
				return nil
			}

			rc2, err := s.FetchManifest(ctx, m)
			if err != nil {
				return err
			}
			defer rc2.Close()

			// unmarshal the oci image content
			var internalManifest ocispec.Image
			if err := json.NewDecoder(rc2).Decode(&internalManifest); err != nil {
				return err
			}

			plat := "-"
			if internalManifest.Architecture != "" {
				plat = fmt.Sprintf("%s/%s", internalManifest.OS, internalManifest.Architecture)
			}

			i := newItem(s, desc, m, plat, o)
			if i.isEmpty() {
				return nil
			}

			items = append(items, i)

			// handle everything else (charts, files, sigs, etc.)
		} else {
			var m ocispec.Manifest
			if err := json.NewDecoder(rc).Decode(&m); err != nil {
				return err
			}

			ctype := resolveCtype(desc, m.Config.MediaType)
			if o.TypeFilter != "all" && ctype != o.TypeFilter {
				return nil
			}

			i := newItem(s, desc, m, "-", o)
			if i.isEmpty() {
				return nil
			}

			items = append(items, i)
		}

		return nil
	}); err != nil {
		return err
	}

	if o.ListRepos {
		buildListRepos(items...)
		return nil
	}

	// sort items by ref and arch
	sort.Sort(byReferenceAndArch(items))

	if items == nil {
		items = []item{}
	}

	switch o.OutputFormat {
	case "json":
		out := infoOutput{
			StorePath: s.Root,
			StoreID:   s.StoreID,
			Artifacts: items,
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	default:
		if err := buildTable(s.Root, s.StoreID, o.ShowDigests, items...); err != nil {
			return err
		}
	}

	return nil
}

func buildListRepos(items ...item) {
	// create map to track unique repository names
	repos := make(map[string]bool)

	for _, i := range items {
		repoName := ""
		for j := 0; j < len(i.Reference); j++ {
			if i.Reference[j] == '/' {
				repoName = i.Reference[:j]
				break
			}
		}
		if repoName == "" {
			repoName = i.Reference
		}
		repos[repoName] = true
	}

	// collect and print unique repository names
	for repoName := range repos {
		fmt.Println(repoName)
	}
}

// buildTable renders the standard (non-check) inventory table: one row per item,
// with the shape unchanged from before the --check redesign.
func buildTable(storePath, storeID string, showDigests bool, items ...item) error {
	table := tablewriter.NewTable(os.Stdout)
	table.Configure(func(cfg *tablewriter.Config) {
		cfg.Header.Alignment.Global = tw.AlignLeft
		cfg.Footer.Alignment.PerColumn = []tw.Align{tw.AlignLeft}
		cfg.Row.Merging.Mode = tw.MergeVertical
		cfg.Row.Merging.ByColumnIndex = tw.NewBoolMapper(0)
	})

	if showDigests {
		table.Header("Reference", "Type", "Platform", "Digest", "# Layers", "Size")
	} else {
		table.Header("Reference", "Type", "Platform", "# Layers", "Size")
	}

	totalSize := int64(0)

	for _, i := range items {
		if i.Type == "" {
			continue
		}

		ref := truncateReference(i.Reference)
		var row []string

		if showDigests {
			digest := i.Digest
			if digest == "" {
				digest = "-"
			}
			row = []string{
				ref,
				i.Type,
				i.Platform,
				digest,
				fmt.Sprintf("%d", i.Layers),
				byteCountSI(i.Size),
			}
		} else {
			row = []string{
				ref,
				i.Type,
				i.Platform,
				fmt.Sprintf("%d", i.Layers),
				byteCountSI(i.Size),
			}
		}

		totalSize += i.Size
		if err := table.Append(row); err != nil {
			return err
		}
	}

	footerLabel := "store-path: " + storePath + "\nstore-id: " + storeID
	if showDigests {
		table.Footer(footerLabel, "", "", "", "Total", byteCountSI(totalSize))
	} else {
		table.Footer(footerLabel, "", "", "Total", byteCountSI(totalSize))
	}

	return table.Render()
}

// issueColumnMaxWidth bounds the failure table's Issue column so a long,
// unbounded issueText value (e.g. a filesystem path embedded in an
// "unreadable: ..." error) can't blow out the whole table's layout in a
// terminal. Chosen to keep the overall table within a normal terminal width
// alongside the Reference/Type/Platform/Digest columns.
const issueColumnMaxWidth = 50

// buildFailureTable renders the --check failure report: a fixed-column table
// (Reference | Type | Platform | Digest | Issue) containing only the artifacts
// that failed their integrity check or were never reached, one row per problem
// so an artifact with multiple bad blobs gets multiple rows. This shape does not
// vary with showDigests/o.ShowDigests -- that flag only affects the non-check
// inventory table produced by buildTable. The Issue column is word-wrapped
// (with mid-token breaks, see the AutoWrap comment below) to a fixed width so an
// unbounded issueText value can't blow out the table layout.
func buildFailureTable(storePath, storeID string, items ...item) error {
	table := tablewriter.NewTable(os.Stdout)
	table.Configure(func(cfg *tablewriter.Config) {
		cfg.Header.Alignment.Global = tw.AlignLeft
		cfg.Footer.Alignment.PerColumn = []tw.Align{tw.AlignLeft}
		cfg.Row.Merging.Mode = tw.MergeVertical
		cfg.Row.Merging.ByColumnIndex = tw.NewBoolMapper(0)

		// The Issue column (index 4) can contain an arbitrary filesystem path or
		// error string with no spaces (e.g. "unreadable: /a/very/long/path...").
		// tw.WrapNormal only breaks on word boundaries, so a long unbroken token
		// would sail straight through it and blow out the table layout -- verified
		// empirically. tw.WrapBreak forces a mid-token break once the column
		// reaches its max width, so use that instead.
		cfg.Row.Formatting.AutoWrap = tw.WrapBreak
		cfg.Row.ColMaxWidths.PerColumn = tw.NewMapper[int, int]().Set(4, issueColumnMaxWidth)
	})

	table.Header("Reference", "Type", "Platform", "Digest", "Issue")

	for _, i := range items {
		if i.Type == "" {
			continue
		}
		ref := truncateReference(i.Reference)

		if len(i.blobProblems) == 0 {
			if err := table.Append([]string{ref, i.Type, i.Platform, "-", "unknown failure"}); err != nil {
				return err
			}
			continue
		}

		for _, p := range i.blobProblems {
			row := []string{ref, i.Type, i.Platform, truncateDigest(p.Digest), issueText(p)}
			if err := table.Append(row); err != nil {
				return err
			}
		}
	}

	table.Footer("store-path: "+storePath+"\nstore-id: "+storeID, "", "", "", "")

	return table.Render()
}

// truncateDigest shortens a "sha256:<hex>" digest string to its first ~12 hex
// characters followed by an ellipsis, for compact display in the failure table's
// Digest column.
func truncateDigest(d string) string {
	const prefix = "sha256:"
	if !strings.HasPrefix(d, prefix) {
		return d
	}
	hex := strings.TrimPrefix(d, prefix)
	if len(hex) > 12 {
		return prefix + hex[:12] + "…"
	}
	return d
}

// issueText renders a store.BlobResult's status/detail as a short human-readable
// reason for the failure table's Issue column.
func issueText(r store.BlobResult) string {
	switch r.Status {
	case store.BlobMissing:
		return "missing"
	case store.BlobSizeMismatch:
		if r.Detail != "" {
			return "size mismatch: " + r.Detail
		}
		return "size mismatch"
	case store.BlobDigestMismatch:
		return "digest mismatch"
	case store.BlobUnverified:
		if r.Detail != "" {
			return "not verified: " + r.Detail
		}
		return "not verified"
	case store.BlobUnreadable:
		if r.Detail != "" {
			return "unreadable: " + r.Detail
		}
		return "unreadable"
	default:
		return string(r.Status)
	}
}

// truncateReference shortens the digest of a reference
func truncateReference(ref string) string {
	const prefix = "@sha256:"
	idx := strings.Index(ref, prefix)
	if idx == -1 {
		return ref
	}
	if len(ref) > idx+len(prefix)+12 {
		return ref[:idx+len(prefix)+12] + "…"
	}
	return ref
}

type item struct {
	Reference string   `json:"reference"`
	Type      string   `json:"type"`
	Platform  string   `json:"platform"`
	Digest    string   `json:"digest,omitempty"`
	Layers    int      `json:"layers"`
	Size      int64    `json:"size"`
	Problems  []string `json:"problems,omitempty"` // populated only for corrupt/unreached items

	// blobProblems holds the same information as Problems but as structured
	// store.BlobResult values, used by buildFailureTable to render one row per
	// problem (Digest/Issue columns). Not exported to JSON.
	blobProblems []store.BlobResult
}

// isEmpty reports whether i is the zero-value item returned by newItem/newItem*
// helpers to signal "filtered out or unparseable ref". item cannot use == because
// Problems is a slice, so callers must use this instead of comparing against a
// zero-value item literal.
func (i item) isEmpty() bool {
	return i.Type == ""
}

type byReferenceAndArch []item

func (a byReferenceAndArch) Len() int      { return len(a) }
func (a byReferenceAndArch) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a byReferenceAndArch) Less(i, j int) bool {
	if a[i].Reference == a[j].Reference {
		if a[i].Type == "image" && a[j].Type == "image" {
			return a[i].Platform < a[j].Platform
		}
		if a[i].Type == "image" {
			return true
		}
		if a[j].Type == "image" {
			return false
		}
		return a[i].Type < a[j].Type
	}
	return a[i].Reference < a[j].Reference
}

// overrides the digest with a specific per platform digest
func newItemWithDigest(s *store.Layout, digestStr string, desc ocispec.Descriptor, m ocispec.Manifest, plat string, o *flags.InfoOpts) item {
	item := newItem(s, desc, m, plat, o)
	item.Digest = digestStr
	return item
}

// resolveDisplayReference returns the fully-qualified reference string to display
// for desc. ContainerdImageNameKey already holds the canonical "registry/repo:tag"
// string exactly as computed when the artifact was stored (see rewriteReference in
// cmd/hauler/cli/store/add.go), so it's used verbatim. Re-parsing it through
// name.ParseReference and calling .Name() would re-trigger go-containerregistry's
// Docker Hub "library/" namespace normalization for any single-segment repo under
// index.docker.io, undoing a rewrite like "hello-world-custom" back to
// "library/hello-world-custom". AnnotationRefName, used as a fallback, has no
// registry component, so it still needs reference.Parse to fill one in.
func resolveDisplayReference(desc ocispec.Descriptor) (string, error) {
	if refName := desc.Annotations[consts.ContainerdImageNameKey]; refName != "" {
		return refName, nil
	}
	ref, err := reference.Parse(desc.Annotations[ocispec.AnnotationRefName])
	if err != nil {
		return "", err
	}
	return ref.Name(), nil
}

func newItem(s *store.Layout, desc ocispec.Descriptor, m ocispec.Manifest, plat string, o *flags.InfoOpts) item {
	var size int64 = 0
	for _, l := range m.Layers {
		size += l.Size
	}

	ctype := resolveCtype(desc, m.Config.MediaType)

	refName, err := resolveDisplayReference(desc)
	if err != nil {
		return item{}
	}

	if o.TypeFilter != "all" && ctype != o.TypeFilter {
		return item{}
	}

	return item{
		Reference: refName,
		Type:      ctype,
		Platform:  plat,
		Digest:    desc.Digest.String(),
		Layers:    len(m.Layers),
		Size:      size,
	}
}

// resolveCtype computes the human-readable content type ("image", "chart", "file", "directory", "git",
// "sigs", "atts", "sbom", "referrer") for a descriptor. configMediaType is the
// manifest's config media type and is used to distinguish image/chart/file when the
// kind annotation doesn't already identify a more specific type; it may be empty
// when the manifest could not be decoded (the --check fallback-row path), in which
// case ctype defaults to "image" unless the kind annotation says otherwise.
func resolveCtype(desc ocispec.Descriptor, configMediaType string) string {
	var ctype string
	switch configMediaType {
	case consts.ChartConfigMediaType:
		ctype = "chart"
	case consts.FileLocalConfigMediaType, consts.FileHttpConfigMediaType:
		ctype = "file"
	case consts.FileDirectoryConfigMediaType:
		ctype = "directory"
	case consts.GitRepoConfigMediaType:
		ctype = "git"
	default:
		ctype = "image"
	}

	kind := desc.Annotations[consts.KindAnnotationName]
	switch ext, _ := consts.SigKindExt(kind); {
	case ext == ".sig":
		ctype = "sigs"
	case ext == ".att":
		ctype = "atts"
	case ext == ".sbom":
		ctype = "sbom"
	case strings.HasPrefix(kind, consts.KindAnnotationReferrers):
		ctype = "referrer"
	}
	return ctype
}

// fallbackItem builds a synthetic failure row directly from desc's index
// annotations -- no blob read beyond what's already been done is required.
// plat defaults to "-".
//
// Type is resolved with an empty configMediaType, since charts/files carry the same
// KindAnnotationImage as regular images in the store index and so cannot be told
// apart from an image once the manifest itself can't be decoded; this is an accepted
// limitation, not a bug.
func fallbackItem(desc ocispec.Descriptor, plat string, problem store.BlobResult) item {
	if plat == "" {
		plat = "-"
	}

	refName, err := resolveDisplayReference(desc)
	if err != nil {
		return item{}
	}

	return item{
		Reference:    refName,
		Type:         resolveCtype(desc, ""),
		Platform:     plat,
		Layers:       0,
		Size:         0,
		Problems:     problemStrings([]store.BlobResult{problem}),
		blobProblems: []store.BlobResult{problem},
	}
}

// problemStrings converts a slice of store.BlobResult problems into human-readable
// strings suitable for JSON output (words, never glyphs).
func problemStrings(problems []store.BlobResult) []string {
	out := make([]string, 0, len(problems))
	for _, p := range problems {
		out = append(out, problemMessage(p))
	}
	return out
}

// problemMessage renders a single store.BlobResult as a human-readable string, e.g.
// "sha256:abc...: digest mismatch (content does not match its digest)".
func problemMessage(r store.BlobResult) string {
	word := string(r.Status)
	switch r.Status {
	case store.BlobMissing:
		word = "blob missing"
	case store.BlobSizeMismatch:
		word = "size mismatch"
	case store.BlobDigestMismatch:
		word = "digest mismatch"
	case store.BlobUnreadable:
		word = "unreadable"
	case store.BlobUnverified:
		word = "not verified"
	}
	if r.Detail != "" {
		return fmt.Sprintf("%s: %s (%s)", r.Digest, word, r.Detail)
	}
	return fmt.Sprintf("%s: %s", r.Digest, word)
}

func byteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

package store

// snapshot_e2e_test.go covers the snapshot boundary end to end through CLI
// commands: atomic rollback of a failed AddImage, and registry serve
// population staying internally consistent while another process handle
// hammers deletion/GC against the same store.

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"hauler.dev/go/hauler/v2/internal/flags"
	"hauler.dev/go/hauler/v2/internal/server"
	v1 "hauler.dev/go/hauler/v2/pkg/apis/hauler.cattle.io/v1"
	"hauler.dev/go/hauler/v2/pkg/consts"
	"hauler.dev/go/hauler/v2/pkg/store"
)

// TestAddImage_FailureRollsBackWholeSnapshot is the strict counterpart to the
// ignore-errors wording test: when an AddImage update fails on related
// artifacts, AddImage returns the error and leaves NOTHING published -- no
// base manifest, no blobs referenced by an index entry. A retry that succeeds
// then publishes image and (absent) extras as one generation.
func TestAddImage_FailureRollsBackWholeSnapshot(t *testing.T) {
	ctx := newTestContext(t)
	host, opts := artifactProbe401Registry(t)
	seedImage(t, host, "rollback/img", "v1", opts...)

	s := newTestStore(t)
	rso, ro := defaultRootOpts(s.Root), defaultCliOpts()

	err := storeImage(ctx, s, v1.Image{Name: host + "/rollback/img:v1"}, "", false, rso, ro, "", "", false)
	if err == nil {
		t.Fatal("expected AddImage to fail on the related-artifact probe, got nil")
	}

	n := 0
	if err := s.Walk(func(_ string, _ ocispec.Descriptor) error {
		n++
		return nil
	}); err != nil {
		t.Fatalf("walk: %v", err)
	}
	if n != 0 {
		t.Fatalf("failed add published %d artifact(s); the snapshot must roll back whole", n)
	}
	if gen := s.Info().Generation; gen != 0 {
		t.Errorf("generation = %d after failed add, want 0", gen)
	}
}

// registryBlob is the subset of an image manifest the pull-verification walks.
type registryManifest struct {
	Config ocispec.Descriptor   `json:"config"`
	Layers []ocispec.Descriptor `json:"layers"`
}

// TestServePopulation_ConsistentUnderConcurrentGC is the serve-side snapshot
// guarantee: the temp-registry population (the CopyCmd ServeRegistryCmd runs
// before serving) reads one store snapshot. A second handle concurrently
// trying to delete/GarbageCollect must wait for the population to finish, so
// every manifest the registry ends up serving has its config and all layers
// pullable -- no manifest-200/blob-404 contradiction.
func TestServePopulation_ConsistentUnderConcurrentGC(t *testing.T) {
	ctx := newTestContext(t)

	srcHost, srcOpts := newLocalhostRegistry(t)
	seedImage(t, srcHost, "snap/app", "v1", srcOpts...)

	s := newTestStore(t)
	rso, ro := defaultRootOpts(s.Root), defaultCliOpts()
	if err := storeImage(ctx, s, v1.Image{Name: srcHost + "/snap/app:v1"}, "", false, rso, ro, "", "", false); err != nil {
		t.Fatalf("storeImage: %v", err)
	}

	// Independent handle = another process deleting from the same store.
	s2, err := store.NewLayout(s.Root)
	if err != nil {
		t.Fatalf("second NewLayout: %v", err)
	}

	registryDir := t.TempDir()
	tr := server.NewTempRegistry(ctx, registryDir)
	if err := tr.Start(); err != nil {
		t.Fatalf("temp registry start: %v", err)
	}
	defer tr.Stop()

	// Hammer GC for the entire population window. Each attempt must either
	// block until the population's read lease releases or find nothing to
	// collect -- it must never unlink a blob mid-population.
	stop := make(chan struct{})
	gcDone := make(chan struct{})
	go func() {
		defer close(gcDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, _, gErr := s2.CleanUp(ctx); gErr != nil {
				t.Errorf("concurrent CleanUp: %v", gErr)
				return
			}
		}
	}()

	copyOpts := &flags.CopyOpts{StoreRootOpts: defaultRootOpts(s.Root), PlainHTTP: true}
	if err := CopyCmd(ctx, copyOpts, s, "registry://"+tr.Registry(), defaultCliOpts()); err != nil {
		t.Fatalf("CopyCmd population under concurrent GC: %v", err)
	}

	close(stop)
	select {
	case <-gcDone:
	case <-time.After(70 * time.Second):
		t.Fatal("GC goroutine did not finish")
	}

	// Pull the populated image the way a client would: manifest first, then
	// every blob it names. This is the contradiction the boundary prevents.
	get := func(path string, accept string) (int, []byte) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+tr.Registry()+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read GET %s: %v", path, err)
		}
		return resp.StatusCode, buf
	}

	status, body := get("/v2/snap/app/manifests/v1",
		consts.OCIManifestSchema1+", "+consts.DockerManifestSchema2)
	if status != http.StatusOK {
		t.Fatalf("manifest pull status = %d, want 200", status)
	}
	var m registryManifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decoding served manifest: %v (raw: %s)", err, string(body))
	}
	if m.Config.Digest.Validate() != nil || len(m.Layers) == 0 {
		t.Fatalf("served manifest names no config/layers: %+v", m)
	}
	for _, blob := range append([]ocispec.Descriptor{m.Config}, m.Layers...) {
		status, got := get("/v2/snap/app/blobs/"+blob.Digest.String(), "")
		if status != http.StatusOK {
			t.Errorf("blob %s pull status = %d, want 200 (manifest/blob contradiction)", blob.Digest, status)
			continue
		}
		if blob.Size > 0 && int64(len(got)) != blob.Size {
			t.Errorf("blob %s served %d bytes, manifest declares %d", blob.Digest, len(got), blob.Size)
		}
	}
}

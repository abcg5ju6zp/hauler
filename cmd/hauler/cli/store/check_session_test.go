package store

// check_session_test.go covers the command-output side of the check session:
// the JSON session block for a healthy run, and a mid-run cancellation that
// must render the partial report (per-object), say so explicitly, and return a
// non-nil error rather than a generic success.

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"hauler.dev/go/hauler/v2/internal/flags"
	"hauler.dev/go/hauler/v2/pkg/store"
)

// checkJSONOutput mirrors infoOutput's JSON shape for assertions.
type checkJSONOutput struct {
	Check *struct {
		Session            string `json:"session"`
		Complete           bool   `json:"complete"`
		Artifacts          int    `json:"artifacts"`
		ArtifactsChecked   int    `json:"artifacts-checked"`
		ArtifactsFailed    int    `json:"artifacts-failed"`
		ArtifactsUnreached int    `json:"artifacts-unreached"`
		BlobsChecked       int    `json:"blobs-checked"`
		BlobsHashed        int    `json:"blobs-hashed"`
	} `json:"check"`
	Artifacts []struct {
		Reference string   `json:"reference"`
		Problems  []string `json:"problems"`
	} `json:"artifacts"`
}

// TestInfoCmd_CheckJSON_SessionBlock verifies a complete healthy run carries
// the machine-readable session block: stable session id, complete=true, and
// the same artifact count semantics as before (empty failure array).
func TestInfoCmd_CheckJSON_SessionBlock(t *testing.T) {
	ctx := newTestContext(t)
	s := newTestStore(t)
	host, opts := newTestRegistry(t)

	seedImage(t, host, "test/session-ok", "v1", opts...)
	if _, err := s.AddImage(ctx, host+"/test/session-ok:v1", "", true, "", false, "", opts...); err != nil {
		t.Fatalf("AddImage: %v", err)
	}

	o := &flags.InfoOpts{
		StoreRootOpts: defaultRootOpts(s.Root),
		OutputFormat:  "json",
		TypeFilter:    "all",
		Check:         true,
	}

	out, err := captureStdout(t, func() error { return InfoCmd(ctx, o, s) })
	if err != nil {
		t.Fatalf("InfoCmd: %v\noutput: %s", err, out)
	}

	var got checkJSONOutput
	if jerr := json.Unmarshal([]byte(out), &got); jerr != nil {
		t.Fatalf("invalid JSON: %v\n%s", jerr, out)
	}
	if got.Check == nil {
		t.Fatal("expected a check session block in JSON")
	}
	if !got.Check.Complete {
		t.Error("expected complete=true for a healthy store")
	}
	if got.Check.Session == "" {
		t.Error("expected a non-empty session id")
	}
	if got.Check.Artifacts == 0 || got.Check.Artifacts != got.Check.ArtifactsChecked {
		t.Errorf("all artifacts must be reached on a healthy run: %+v", got.Check)
	}
	if got.Check.BlobsChecked == 0 {
		t.Error("expected blobs-checked > 0")
	}
	if len(got.Artifacts) != 0 {
		t.Errorf("healthy store must list no failing artifacts, got %+v", got.Artifacts)
	}
}

// TestInfoCmd_CheckCancelled_PartialReportAndError is the CLI contract for a
// check interrupted mid-run: the partial report is still rendered with the
// objects that were/weren't covered, the summary says it did not finish, JSON
// carries complete=false, and InfoCmd returns an error (non-zero exit) instead
// of a misleading success. A follow-up run on the same healthy store completes.
func TestInfoCmd_CheckCancelled_PartialReportAndError(t *testing.T) {
	s := newTestStore(t)
	host, opts := newTestRegistry(t)

	seedImage(t, host, "test/cancel-a", "v1", opts...)
	seedImage(t, host, "test/cancel-b", "v1", opts...)
	baseCtx := newTestContext(t)
	if _, err := s.AddImage(baseCtx, host+"/test/cancel-a:v1", "", true, "", false, "", opts...); err != nil {
		t.Fatalf("AddImage a: %v", err)
	}
	if _, err := s.AddImage(baseCtx, host+"/test/cancel-b:v1", "", true, "", false, "", opts...); err != nil {
		t.Fatalf("AddImage b: %v", err)
	}

	var logBuf bytes.Buffer
	logCtx := newCapturingContext(&logBuf)

	ctx, cancel := context.WithCancel(logCtx)
	var once sync.Once
	hookCtx := store.WithCheckPreHashHook(ctx, func(_ string) {
		once.Do(cancel)
	})

	o := &flags.InfoOpts{
		StoreRootOpts: defaultRootOpts(s.Root),
		OutputFormat:  "json",
		TypeFilter:    "all",
		Check:         true,
	}

	stdout, runErr := captureStdout(t, func() error { return InfoCmd(hookCtx, o, s) })
	if runErr == nil {
		t.Fatal("expected a non-nil error when the check was interrupted, got nil")
	}
	if !strings.Contains(runErr.Error(), "interrupted before completion") {
		t.Errorf("error must say the check was interrupted before completion, got: %v", runErr)
	}

	var got checkJSONOutput
	if jerr := json.Unmarshal([]byte(stdout), &got); jerr != nil {
		t.Fatalf("interrupted run must still emit parseable JSON: %v\n%s", jerr, stdout)
	}
	if got.Check == nil {
		t.Fatal("expected the check block in the partial JSON report")
	}
	if got.Check.Complete {
		t.Error("interrupted run must carry complete=false")
	}
	if got.Check.ArtifactsUnreached == 0 && len(got.Artifacts) == 0 {
		t.Error("partial report must name not-reached/unverified objects")
	}
	var sawNotVerified bool
	for _, a := range got.Artifacts {
		for _, p := range a.Problems {
			if strings.Contains(p, "not verified") {
				sawNotVerified = true
			}
		}
	}
	if got.Check.ArtifactsUnreached == 0 && !sawNotVerified {
		t.Error("expected at least one not-verified row or an unreached count")
	}
	if !strings.Contains(logBuf.String(), "did not finish") {
		t.Errorf("expected an explicit incomplete-run log line, got: %q", logBuf.String())
	}

	// Re-running without cancellation (a new session) completes cleanly and
	// returns nil -- the interruption left nothing poisoned.
	o2 := &flags.InfoOpts{
		StoreRootOpts: defaultRootOpts(s.Root),
		OutputFormat:  "json",
		TypeFilter:    "all",
		Check:         true,
	}
	out2, err2 := captureStdout(t, func() error { return InfoCmd(newTestContext(t), o2, s) })
	if err2 != nil {
		t.Fatalf("rerun must succeed: %v\n%s", err2, out2)
	}
	var got2 checkJSONOutput
	if jerr := json.Unmarshal([]byte(out2), &got2); jerr != nil {
		t.Fatalf("invalid rerun JSON: %v\n%s", jerr, out2)
	}
	if got2.Check == nil || !got2.Check.Complete {
		t.Fatalf("rerun must be complete: %+v", got2.Check)
	}
	if got.Check.Session == got2.Check.Session {
		t.Error("rerun must be a new session with a distinct id")
	}
}

package certify

// preflight_provenance.go refuses a GATING run whose evidence could not be
// traced to the code that produced it or the build it was produced against.
//
// # Why a bundle needs provenance it can PROVE
//
// A certification bundle is a claim about a specific product build, made by a
// specific version of this harness. Both halves have to be pinnable, because the
// bundle outlives the bench: a reader months later, or a lab, has only the files.
// Two failures this file closes were each silent before it:
//
//   - A DIRTY harness tree. The bundle already records git HEAD and a dirty
//     flag (bundle.RunMeta.GitDirty), but recording that the evidence came from
//     an uncommitted tree is not the same as refusing to let that evidence
//     DECIDE a release. Uncommitted changes are, by definition, not reproducible
//     from any commit — the exact grading logic that produced the verdicts
//     cannot be recovered — so a gating bundle built from one rests on code no
//     one can check. -allow-dirty is the deliberate escape hatch for a developer
//     who means it; its use is recorded so the weaker footing is visible.
//
//   - The WRONG DUT build. -dut-build is the operator's statement of which
//     product build is under test. If the DUT on the bench is actually running a
//     different one, every verdict in the bundle is about the wrong artefact, and
//     nothing downstream can tell — the bundle names the operator's build in its
//     DUT record and the reader believes it. So when -dut-build is given, the
//     DUT's own reported build is read (READ-ONLY, over the same -gateway-ssh /
//     -gateway-exec introspection every other preflight uses) and compared, and a
//     mismatch — or a build that could not be read at all — stops a gating run.
//
// # Fail closed on gating, observe on exploratory
//
// The posture is preflight_manifest.go's: on a GATING campaign an unprovable or
// contradicted precondition is FATAL and ends the run before case 1; on an
// exploratory run it is recorded and the run continues. Gating campaigns REQUIRE
// a manifest and are the only bundles that may decide anything, so this is where
// the discipline belongs and where it costs a dev poke nothing.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"csip-tls-test/internal/evidence/bundle"
)

// provenanceOutcome is what the provenance preflight established, carried on the
// RunReport so writeBundle can record it beside the evidence it qualifies.
type provenanceOutcome struct {
	// HarnessHead is the git HEAD commit of the harness tree, or "" when it
	// could not be determined (not a checkout, or git unavailable).
	HarnessHead string
	// Dirty reports whether the harness worktree had uncommitted changes.
	Dirty bool
	// AllowDirtyUsed reports whether -allow-dirty waved a dirty or
	// unidentifiable tree through a gating run.
	AllowDirtyUsed bool
	// DUTBuildFW and DUTBuildID are what the DUT reported about its own build
	// (GET /status: buildinfo.Version and buildid.Resolve), when it was read.
	DUTBuildFW string
	DUTBuildID string
}

// preflightProvenance verifies that this run's evidence can be traced to a clean
// harness tree and, when -dut-build is given, to the DUT build the operator
// declared. It returns an error the caller should abandon a gating run on.
func (r *Runner) preflightProvenance(ctx context.Context, reporter *Reporter) (provenanceOutcome, error) {
	var out provenanceOutcome

	// ── The harness tree this evidence was produced from ──
	//
	// bundle.GitCommit is the SAME reader writeBundle uses to stamp the bundle's
	// git_commit/git_dirty, so the preflight and the recorded fact cannot
	// disagree about whether the tree was clean.
	head, dirty := bundle.GitCommit(".")
	if err := r.checkHarnessTree(reporter, head, dirty, &out); err != nil {
		return out, err
	}

	// ── The DUT build this evidence was produced against ──
	if err := r.verifyDUTBuild(ctx, reporter, &out); err != nil {
		return out, err
	}
	return out, nil
}

// checkHarnessTree decides what a (head, dirty) harness state means for this run,
// recording it on out. It is split from the bundle.GitCommit read above so the
// decision is testable without a controllable git tree: a DIRTY worktree, or one
// whose HEAD cannot even be named, is UNVERIFIABLE provenance — fatal on a gating
// campaign (unless -allow-dirty), a recorded observation on an exploratory run.
func (r *Runner) checkHarnessTree(reporter *Reporter, head string, dirty bool, out *provenanceOutcome) error {
	out.HarnessHead = head
	out.Dirty = dirty
	out.AllowDirtyUsed = r.opts.AllowDirty

	var unverifiable string
	switch {
	case dirty:
		unverifiable = fmt.Sprintf("the harness worktree is DIRTY (git status is non-empty)%s", atHead(head))
	case head == "":
		unverifiable = "the harness HEAD commit could not be determined (this is not a git checkout, or git is unavailable)"
	}
	switch {
	case unverifiable == "":
		reporter.Line("provenance: harness tree clean at HEAD %s", short(head, 12))
	case !r.gatingCampaign():
		reporter.Line("provenance: %s — recorded, but this is an EXPLORATORY run (no -campaign), so it does "+
			"not block; a gating campaign would refuse it", unverifiable)
	case r.opts.AllowDirty:
		reporter.Line("provenance: %s — allowed by -allow-dirty. The bundle records that this GATING "+
			"evidence came from a tree that was not clean%s", unverifiable, atHead(head))
	default:
		return fmt.Errorf("certify: preflight: %s, and this is a GATING campaign (-campaign %s): "+
			"certification evidence must be reproducible from a named commit, and a bundle built from an "+
			"uncommitted or unidentifiable tree cannot be. Commit the harness tree, or pass -allow-dirty to "+
			"record explicitly that this evidence came from a tree that was not clean", unverifiable, r.campaign.Name)
	}
	return nil
}

// verifyDUTBuild reads the DUT's own reported build and, when -dut-build was
// supplied, holds it against that declaration. It always records what the DUT
// reported (provenance worth keeping either way); it only FAILs a gating run
// when a supplied -dut-build cannot be confirmed.
func (r *Runner) verifyDUTBuild(ctx context.Context, reporter *Reporter, out *provenanceOutcome) error {
	gw := r.gateway()
	fw, buildID, readErr := r.readDUTBuild(ctx, gw)
	out.DUTBuildFW = fw
	out.DUTBuildID = buildID

	claimed := strings.TrimSpace(r.opts.DUT.Build)
	if claimed == "" {
		// Nothing to verify against. Record what the DUT reported, when readable.
		if readErr == nil && (fw != "" || buildID != "") {
			reporter.Line("provenance: DUT reports build fw=%s build_id=%s (no -dut-build supplied to verify "+
				"it against)", orNone(fw), orNone(buildID))
		}
		return nil
	}

	if readErr != nil || (fw == "" && buildID == "") {
		reason := "the DUT's build could not be read"
		switch {
		case !gw.Available():
			reason = "no gateway introspection is configured (pass -gateway-ssh or -gateway-exec), so the " +
				"DUT's build could not be read"
		case readErr != nil:
			reason = fmt.Sprintf("the DUT's build could not be read (%v)", readErr)
		default:
			reason = "the DUT's /status reported neither a fw version nor a build_id"
		}
		return r.unprovable(reporter,
			fmt.Sprintf("the DUT build identity (-dut-build %s was supplied but %s)", claimed, reason),
			"The DUT's build is read READ-ONLY from its own GET /status through the gateway transport; a "+
				"gating run may not claim evidence against a build it could not confirm")
	}

	if buildIdentityMatches(claimed, fw, buildID) {
		reporter.Line("provenance: DUT build matches -dut-build %s (DUT reports fw=%s build_id=%s)",
			claimed, orNone(fw), orNone(buildID))
		return nil
	}

	// A MISMATCH is a proven contradiction, not an unproven claim: fatal on a
	// gating campaign, a loud warn on an exploratory poke.
	detail := fmt.Sprintf("the DUT reports fw=%s build_id=%s, which does not match -dut-build %s",
		orNone(fw), orNone(buildID), claimed)
	if r.gatingCampaign() {
		return fmt.Errorf("certify: preflight: DUT BUILD MISMATCH, and this is a GATING campaign "+
			"(-campaign %s): %s. This bundle would record certification evidence against a build that is "+
			"not the one the operator declared. Correct -dut-build, or reflash the DUT to the build under "+
			"certification", r.campaign.Name, detail)
	}
	reporter.Line("provenance: DUT BUILD MISMATCH — %s. This is an EXPLORATORY run (no -campaign), so it is "+
		"a WARNING, not a refusal; a gating campaign would stop here", detail)
	return nil
}

// dutBuildStatus is the subset of the DUT dev API's GET /status this check reads:
// fw (lexa-platform/buildinfo.Version, the product version) and build_id
// (lexa-gw internal/buildid.Resolve, normally the abbreviated git revision with a
// "-dirty" suffix). lexa-gw cmd/api/handlers.go stamps both onto every /status.
type dutBuildStatus struct {
	FW      string `json:"fw"`
	BuildID string `json:"build_id"`
}

// readDUTBuild fetches the DUT's reported build over the READ-ONLY introspection
// transport. It is the same door preflightManifest reads /status through.
func (r *Runner) readDUTBuild(ctx context.Context, gw *Gateway) (fw, buildID string, err error) {
	if !gw.Available() {
		return "", "", fmt.Errorf("no gateway introspection configured")
	}
	body, err := r.devAPIGet(ctx, gw, "/status")
	if err != nil {
		return "", "", err
	}
	var st dutBuildStatus
	if jerr := json.Unmarshal(body, &st); jerr != nil {
		return "", "", fmt.Errorf("the DUT's /status did not decode: %v", jerr)
	}
	return strings.TrimSpace(st.FW), strings.TrimSpace(st.BuildID), nil
}

// buildIdentityMatches reports whether an operator-supplied -dut-build names the
// same build as the DUT's own fw or build_id, tolerantly.
//
// A build id is most often a git revision abbreviated to DIFFERENT lengths on the
// two sides — the operator types the 7-char sha they flashed, buildid.Resolve
// keeps 12, and either may carry a "-dirty" suffix — so an exact match would
// reject genuinely-equal builds. The rule: a case-insensitive full match against
// EITHER reported field, or a prefix match in either direction where the shorter
// side is at least git's own collision-safe minimum (7). It never matches on an
// empty string, so a DUT that reported nothing cannot accidentally "match".
func buildIdentityMatches(claimed, fw, buildID string) bool {
	claimed = strings.TrimSpace(claimed)
	if claimed == "" {
		return false
	}
	return buildTokenMatch(claimed, strings.TrimSpace(fw)) ||
		buildTokenMatch(claimed, strings.TrimSpace(buildID))
}

func buildTokenMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if strings.EqualFold(a, b) {
		return true
	}
	lo, hi := a, b
	if len(lo) > len(hi) {
		lo, hi = hi, lo
	}
	const minAbbrev = 7 // git's own default collision-safe abbreviation
	if len(lo) < minAbbrev {
		return false
	}
	return strings.HasPrefix(strings.ToLower(hi), strings.ToLower(lo))
}

// atHead renders " at HEAD <sha>" when a HEAD is known, and nothing when it is
// not, so a message never trails a bare "at HEAD ".
func atHead(head string) string {
	if head == "" {
		return ""
	}
	return " at HEAD " + short(head, 12)
}

// provenanceNote renders the provenance facts a bundle reader needs STATED —
// the DUT build this evidence was measured against, and whether -allow-dirty
// waved a not-clean tree through — or "" when there is nothing to add. The
// harness HEAD and dirty flag themselves ride RunMeta.GitCommit/GitDirty, set
// from the same bundle.GitCommit reader, so they are not repeated here.
func provenanceNote(p provenanceOutcome) string {
	var parts []string
	if p.DUTBuildFW != "" || p.DUTBuildID != "" {
		parts = append(parts, fmt.Sprintf("DUT build reported fw=%s build_id=%s",
			orNone(p.DUTBuildFW), orNone(p.DUTBuildID)))
	}
	// -allow-dirty is only worth recording when it actually waved something
	// through: a not-clean tree. Passed over a clean tree it was inert.
	switch {
	case p.AllowDirtyUsed && p.Dirty:
		parts = append(parts, "-allow-dirty USED over a DIRTY harness worktree"+atHead(p.HarnessHead)+
			": this evidence's grading logic is not reproducible from a named commit")
	case p.AllowDirtyUsed && p.HarnessHead == "":
		parts = append(parts, "-allow-dirty USED: the harness HEAD could not be determined, so this "+
			"evidence is not pinned to a named commit")
	}
	if len(parts) == 0 {
		return ""
	}
	return "provenance: " + strings.Join(parts, "; ")
}

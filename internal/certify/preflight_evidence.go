package certify

// preflight_evidence.go refuses an EVIDENCE run whose bench cannot produce the
// artefacts that run exists to produce.
//
// # The landmine (LAB29-011)
//
// SS-CSIP-RESULTS v1.1 Chapter 5 requires the submission to carry a raw TLS
// packet trace per COMM-004 certificate scenario, and each trace must contain
// that scenario's whole handshake. csip-tls-test's RPT-060 exports those traces
// from the run's own capture — and it failed, because not one COMM-004 scenario
// in the campaign had an attributable FRESH handshake to export. The sessions
// had been resumed from tickets.
//
// Everything about that failure was late and indirect. The COMM-004 rows
// themselves passed: their certificate criteria correctly report "this window's
// session is a RESUMED TLS 1.2 session, so the chain cannot be read from it" as
// UNAVAILABLE rather than as a device fault, which is the right answer for a
// row measuring a device. So the run looked fine until the very last row in the
// very last document tried to assemble a submission artefact out of eight
// windows that had no certificate exchange in them, and reported the gap as its
// own failure. By then the bench was hours gone.
//
// The cause was a LAUNCH FLAG. gridsim issues session tickets unless started
// with -no-tickets, and holds a connection open forever unless started with
// -idle-timeout-s. Neither is observable from the traffic — the absence of a
// handshake in a window looks identical whether tickets were on or the DUT
// simply had nothing to say — so no amount of care during the run could have
// caught it.
//
// # The rule
//
// -evidence says "this run must produce a submission-grade artefact". Every
// precondition that artefact depends on is then PROVEN BEFORE CASE 1, from the
// simulator's own published posture (gridsim GET /admin/status `tls`, added for
// this), and the run ends here if any of them cannot be established. Same
// discipline, and the same reasoning, as the -gridsim/-gridsim-admin pairing
// preflight and the control-authority preflight it sits beside.
//
// FAIL CLOSED, and in particular: a gridsim that reports NO tls object is
// refused. "Unreported" is an old simulator and "reported false" is a
// misconfigured bench, the refusal says which it found, and neither is a bench
// an evidence run may proceed on.
//
// # What it does NOT do
//
// It does not start, restart or reconfigure the simulator. This harness must not
// mutate the bench it is measuring — the same rule Gateway's read-only allowlist
// enforces one file over — and a simulator restarted mid-campaign invalidates
// the evidence of every case that ran before it. An operator who sees this fail
// relaunches gridsim with the flags the message names and re-runs.

import (
	"context"
	"fmt"
	"strings"
)

// EvidenceParamCOMM004 is the -param key naming the COMM-004 scenarios whose
// traces the submission requires. It is spelled here as well as in the report
// suite because THIS file is what refuses a run without it, and a key spelled
// in two packages is a key that will one day be spelled two ways.
const EvidenceParamCOMM004 = "report.comm004"

// evidenceCOMM004Prefix is the uid prefix a -param report.comm004 value must
// name. A scenario from some other family would export a trace of the wrong
// conversation under a Chapter 5 filename.
const evidenceCOMM004Prefix = "csip-conf-v1.3::COMM-004"

// preflightEvidence establishes an evidence run's bench preconditions, or
// refuses the run.
func (r *Runner) preflightEvidence(ctx context.Context, reporter *Reporter, plan []Planned) error {
	if !r.opts.Evidence {
		return nil
	}

	// The two generic requirements. Both are about the RUN rather than about
	// the bench, so they are checked first and their messages say what the
	// missing thing would have evidenced.
	if r.opts.NoCapture {
		return fmt.Errorf("certify: -evidence with -no-capture: an evidence run's artefacts ARE the " +
			"capture — Chapter 5's per-scenario TLS traces are exported from it — so a run with no " +
			"capture cannot produce any of them. Drop one of the two flags")
	}
	if r.opts.KeyLogPath == "" {
		return fmt.Errorf("certify: -evidence with no -keylog: without the TLS secrets the capture " +
			"cannot be decrypted, so every criterion resting on the 2030.5 transcript loses its citation " +
			"and the bundle fills with PASSes downgraded for want of one. Pass -keylog <path> (and build " +
			"with -tags keylog: `make certify-keylog`)")
	}

	switch r.campaign.Name {
	case CampaignCSIP:
		return r.preflightEvidenceCOMM004(ctx, reporter, plan)
	default:
		reporter.Line("evidence: the %s campaign has no contract beyond the capture and the key log, "+
			"both of which are present — no further precondition is claimed for this bundle",
			r.campaign.Name)
		return nil
	}
}

// preflightEvidenceCOMM004 proves the CSIP campaign's Chapter 5 preconditions.
func (r *Runner) preflightEvidenceCOMM004(ctx context.Context, reporter *Reporter, plan []Planned) error {
	// 1. The scenarios must be NAMED. RPT-060 already FAILs loudly when they
	// are not, but it does so after the whole campaign has run; an evidence run
	// refuses in its first second instead.
	raw, _ := r.opts.Params[EvidenceParamCOMM004]
	var uids []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			uids = append(uids, p)
		}
	}
	if len(uids) == 0 {
		return fmt.Errorf("certify: -evidence -campaign csip needs -param %s=<uid>[,<uid>…]: SS-CSIP-"+
			"RESULTS v1.1 Chapter 5 requires a raw TLS packet trace per COMM-004 certificate scenario, "+
			"and RPT-060 exports one per scenario NAMED here. Unnamed, no trace is written and the "+
			"submission is missing a Chapter 5 requirement — which RPT-060 would report at the end of "+
			"the campaign rather than now", EvidenceParamCOMM004)
	}

	// 2. Each named scenario must actually be going to RUN. A uid that is
	// mistyped, out of scope, or skipped for a missing capability produces no
	// frames, so its trace cannot exist however well the bench is posed.
	willRun := map[string]*Case{}
	for _, p := range plan {
		if p.OutOfScope() || !p.Implemented || p.Skip != "" {
			continue
		}
		willRun[strings.ToLower(p.Case.UID)] = p.Case
		if p.Case.ID != "" {
			willRun[strings.ToLower(p.Case.ID)] = p.Case
		}
	}
	var missing, foreign []string
	for _, u := range uids {
		c, ok := willRun[strings.ToLower(u)]
		if !ok {
			missing = append(missing, u)
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(c.UID), strings.ToUpper(evidenceCOMM004Prefix)) {
			foreign = append(foreign, u)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("certify: -evidence: -param %s names %s, which this run will not execute "+
			"(mistyped, out of scope for the candidate, or skipped for a missing capability). A scenario "+
			"that does not run produces no frames, so no trace can be exported for it and the submission "+
			"would be short a Chapter 5 artefact",
			EvidenceParamCOMM004, strings.Join(missing, ", "))
	}
	if len(foreign) > 0 {
		return fmt.Errorf("certify: -evidence: -param %s names %s, which is not a COMM-004 scenario. "+
			"Chapter 5's traces are per CERTIFICATE scenario; exporting another row's conversation under "+
			"a COMM-004 filename would misdescribe the artefact",
			EvidenceParamCOMM004, strings.Join(foreign, ", "))
	}

	// 3. The bench posture. Read from gridsim's own /admin/status, which is the
	// same response the pairing preflight already proved belongs to the process
	// serving the data plane — so this posture is THAT process's posture and
	// not some other gridsim's.
	admin := r.opts.Targets.GridSimAdmin
	if admin == "" {
		return fmt.Errorf("certify: -evidence -campaign csip has no -gridsim-admin, so the simulator's " +
			"TLS posture cannot be read. Every COMM-004 trace depends on it: a session resumed from a " +
			"ticket carries no Certificate message (RFC 5077 §3.1), and a window that catches one has no " +
			"certificate exchange to export")
	}
	ctx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()

	var st struct {
		PID       int    `json:"pid"`
		PollRateS uint32 `json:"poll_rate_s"`
		TLS       *struct {
			NoTickets    bool `json:"no_tickets"`
			IdleTimeoutS int  `json:"idle_timeout_s"`
		} `json:"tls"`
	}
	if err := NewAdminClient(admin, r.opts.HTTP).Status(ctx, &st); err != nil {
		return fmt.Errorf("certify: -evidence: the 2030.5 server admin API at %s did not answer: %w. "+
			"An evidence run proves its bench posture; it does not assume one", admin, err)
	}
	if st.TLS == nil {
		return fmt.Errorf("certify: -evidence: the 2030.5 server at %s (pid %d) publishes no TLS posture. "+
			"Either it predates gridsim.Server.SetTLSPosture — rebuild it (`make server-keylog`) — or it "+
			"is some other 2030.5 server. Until it says so, THAT EVERY COMM-004 WINDOW WILL CARRY A FULL "+
			"HANDSHAKE IS UNPROVEN, and an unproven precondition is what produced the RPT-060 failure "+
			"this check exists to prevent", admin, st.PID)
	}
	if !st.TLS.NoTickets {
		return fmt.Errorf("certify: -evidence: the 2030.5 server at %s (pid %d) reports "+
			"no_tickets=false: it ISSUES TLS session tickets and keeps a session cache, so the DUT may "+
			"resume instead of handshaking. A resumed session carries no Certificate message (RFC 5077 "+
			"§3.1; RFC 8446 §2.2 for TLS 1.3), so a COMM-004 window that catches one has no certificate "+
			"exchange to trace and Chapter 5's artefact cannot be built from it. Relaunch gridsim with "+
			"-no-tickets (bench: GRIDSIM_NO_TICKETS=1)", admin, st.PID)
	}
	if st.TLS.IdleTimeoutS <= 0 {
		return fmt.Errorf("certify: -evidence: the 2030.5 server at %s (pid %d) reports "+
			"idle_timeout_s=0: it never closes an idle connection, so a 2030.5 client holds ONE session "+
			"across every poll cycle and only the first COMM-004 scenario's window contains a "+
			"ClientHello. Every later scenario would have no handshake of its own to trace. Relaunch "+
			"gridsim with -idle-timeout-s below the poll cadence (bench: GRIDSIM_IDLE_S=30)", admin, st.PID)
	}
	// The case boundary is the advertised poll cadence: that is the interval
	// between one scenario's session and the next, and the idle timeout has to
	// fire INSIDE it or the connection is still open when the next scenario
	// starts. Taking the boundary from the server's own advertisement rather
	// than from a constant here is the same rule preflight.go applies to
	// poll_rate_s — the client paces from what the server advertises, so the
	// server's number is the authoritative one.
	if st.PollRateS == 0 {
		return fmt.Errorf("certify: -evidence: the 2030.5 server at %s (pid %d) advertises no uniform "+
			"pollRate (poll_rate_s=0), so the built-in rates apply — 300 s on /dcap, 900 s on /tm, 60 s "+
			"on the control lists — and there is no single boundary between one COMM-004 scenario's "+
			"session and the next to hold the %d s idle timeout against. A poll_rate_mode=honor DUT also "+
			"paces its whole walk at the slowest of those, which is 900 s. Relaunch gridsim with "+
			"-poll-rate-s (bench: GRIDSIM_POLL_S=60)", admin, st.PID, st.TLS.IdleTimeoutS)
	}
	if uint32(st.TLS.IdleTimeoutS) >= st.PollRateS {
		return fmt.Errorf("certify: -evidence: the 2030.5 server at %s (pid %d) closes an idle "+
			"connection after %d s and advertises a %d s pollRate. The idle timeout must fire INSIDE the "+
			"poll cadence, or the DUT's connection is still open when the next COMM-004 scenario's window "+
			"opens and that scenario has no handshake of its own to trace. Lower -idle-timeout-s below "+
			"the advertised rate (the bench's proven pair is 30 s idle against a 60 s pollRate)",
			admin, st.PID, st.TLS.IdleTimeoutS, st.PollRateS)
	}

	reporter.Line("evidence: gridsim pid %d issues no session tickets and closes idle connections after "+
		"%d s against an advertised %d s pollRate, so each of the %d COMM-004 scenario(s) begins with a "+
		"new ClientHello and carries its own certificate exchange",
		st.PID, st.TLS.IdleTimeoutS, st.PollRateS, len(uids))
	return nil
}

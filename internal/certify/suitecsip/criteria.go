package suitecsip

// criteria.go is how a CSIP test case's pass criteria become assertions.
//
// Every row of CSIP-CONF-v1.3 carries an `observables` list — the extraction's
// enumeration of the wire facts its pass criteria rest on. That list is the
// assertion shopping list, and this file is the machinery that walks it
// honestly:
//
//   - if the fact is visible in the cleartext handshake, assert it with a frame
//     or byte citation (tier 1);
//   - else if the fact is in the decrypted HTTP transcript, assert it with a
//     citation of the TLS records that carried the message (tier 2);
//   - else if gridsim observed it server-side, record it as a Narrative naming
//     gridsim as the source, which the runner will correctly refuse to let
//     stand as an uncited PASS (tier 3);
//   - else emit a SKIP carrying the reason.
//
// The ranking is not a convenience. It is the entire difference between a tool
// whose PASS means "here are the bytes" and one whose PASS means "the thing we
// asked said yes". A criterion never silently falls back a tier: when it does
// fall back, the assertion's Method says which tier produced it.

import (
	"fmt"
	"strings"

	"csip-tls-test/internal/certify"
	"csip-tls-test/internal/evidence/netdis"
)

// Finding is one evaluator's answer about one criterion.
type Finding struct {
	Verdict  certify.Verdict
	Observed string

	// Frames cites capture frames. Cite either Frames or a byte range, not
	// both; the byte range wins when both are set because it is the stronger
	// citation.
	Frames []int

	// Dir/Start/End cite a byte range of a reassembled direction.
	Dir        *netdis.Direction
	Start, End int

	// Unavailable, when non-empty, means this evaluator could not reach a
	// conclusion and says why. It is NOT a failure of the DUT.
	Unavailable string
}

// unavailable is the shorthand for "this evaluator had nothing to work with".
func unavailable(format string, a ...any) Finding {
	return Finding{Unavailable: fmt.Sprintf(format, a...)}
}

// found builds a decided finding with a frame citation.
func found(v certify.Verdict, frames []int, format string, a ...any) Finding {
	return Finding{Verdict: v, Frames: frames, Observed: fmt.Sprintf(format, a...)}
}

// noSessionUnavailable is the tier-3 finding for a server-log evaluator whose
// expected request is absent when the DUT completed NO session at all in the
// window. The emptiness of gridsim's log is then a fact about the handshake, not
// about whether the DUT would have issued the request — so it is unavailable
// (→SKIP), never a FAIL of the DUT. Gate on ServerView.SessionEstablished; a
// window in which a session DID establish but the request is missing keeps its
// FAIL. runs/shakedown-20260729T003843 turned one bench-side handshake fault
// into ~51 such false FAILs.
func noSessionUnavailable() Finding {
	return unavailable("the DUT completed no TLS session to the 2030.5 server in this window, so gridsim " +
		"logged nothing from it; the request-log emptiness is a fact about the handshake, not attributable " +
		"to the DUT, and is reported as unavailable rather than as a failure of the DUT")
}

// tier names where a criterion's evidence comes from, and is printed in the
// assertion's Method so a reader can rank it without reading this file.
type tier string

const (
	tierHandshake  tier = "cleartext TLS handshake in the capture"
	tierTranscript tier = "decrypted HTTP/2030.5 transcript from the capture (NSS key log)"
	tierServer     tier = "gridsim server-side observation (admin API)"
	tierNone       tier = "not observed"
)

// criterion is one pass criterion of a catalog row.
type criterion struct {
	// Claim is the sentence being asserted, phrased in the procedure's language.
	Claim string
	// How describes the technique, and is prefixed with the tier that actually
	// produced the answer when the assertion is minted.
	How string

	// Wire evaluates the criterion against the recovered session. It is called
	// only when a session was recovered.
	//
	// It is handed the whole Evidence as well as the session because some
	// criteria are about the capture rather than about the conversation — an
	// ABSENCE ("the DUT sent no mDNS query") cannot be settled by looking only
	// at the frames the DUT's TLS session produced. Anything the evaluator
	// CITES must still be in this check's own frame set; Evidence.CiteFrames
	// enforces that, and a criterion that reads the whole capture must report
	// its conclusion without a citation, which mint() turns into a Narrative.
	Wire func(ev *certify.Evidence, t *Transcript) Finding
	// NeedsTranscript marks a Wire evaluator that requires the decrypted
	// payload, so it is skipped with the decryption reason rather than being
	// called against a Transcript that has no exchanges.
	NeedsTranscript bool

	// Server is the tier-3 evaluator, called when Wire was unavailable.
	Server func(v *ServerView) Finding

	// Skip is the reason recorded when no evaluator could reach a conclusion
	// and neither produced one of its own.
	Skip string
}

// mint turns a criterion list into assertions, choosing the strongest tier that
// could actually answer each one.
func mint(ev *certify.Evidence, obs *Observation, crits []criterion) ([]certify.Assertion, error) {
	out := make([]certify.Assertion, 0, len(crits))
	for _, c := range crits {
		a, err := c.assert(ev, obs)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (c criterion) assert(ev *certify.Evidence, obs *Observation) (certify.Assertion, error) {
	// Tier 1 / 2.
	if c.Wire != nil && obs.Transcript != nil {
		switch {
		case c.NeedsTranscript && !obs.Transcript.Decrypted:
			// Fall through to tier 3 with the decryption reason recorded.
		default:
			f := c.Wire(ev, obs.Transcript)
			if f.Unavailable == "" {
				t := tierHandshake
				if c.NeedsTranscript {
					t = tierTranscript
				}
				return c.cite(ev, t, f)
			}
			obs.note(c.Claim, f.Unavailable)
		}
	}
	// Tier 3.
	if c.Server != nil && obs.Server.Available {
		f := c.Server(&obs.Server)
		if f.Unavailable == "" {
			a, err := ev.Narrative(c.Claim, string(tierServer)+" — "+c.How, f.Verdict, f.Observed,
				"gridsim admin API at "+obs.Server.BaseURL+"; this is the SERVER's record of the DUT's "+
					"behaviour, not the wire, and cannot be re-derived from the pcap")
			if err != nil {
				return certify.Assertion{}, err
			}
			return a, nil
		}
		obs.note(c.Claim, f.Unavailable)
	}
	// Nothing reached a conclusion.
	return ev.SkipAssertion(c.Claim, string(tierNone)+" — "+c.How, c.skipReason(obs)), nil
}

// cite turns a decided finding into a cited assertion.
func (c criterion) cite(ev *certify.Evidence, t tier, f Finding) (certify.Assertion, error) {
	method := string(t) + " — " + c.How
	if f.Dir != nil && f.End > f.Start {
		a, err := ev.CiteBytes(c.Claim, method, f.Verdict, f.Observed, f.Dir, f.Start, f.End)
		if err != nil {
			return certify.Assertion{}, err
		}
		return a, nil
	}
	if len(f.Frames) > 0 {
		a, err := ev.CiteFrames(c.Claim, method, f.Verdict, f.Observed, f.Frames)
		if err != nil {
			return certify.Assertion{}, err
		}
		return a, nil
	}
	// A decided finding with nothing to cite is a real answer with no wire
	// backing — a fact read off a parsed structure whose own frames the
	// evaluator did not track. It is recorded as a Narrative naming the
	// capture, never as a bare PASS.
	a, err := ev.Narrative(c.Claim, method, f.Verdict, f.Observed,
		"the run's capture, but the evaluator did not record which frames carried the fact")
	if err != nil {
		return certify.Assertion{}, err
	}
	return a, nil
}

// skipReason assembles the honest explanation for an unasserted criterion:
// whatever the evaluators said about why they could not answer, then the
// criterion's own declared reason.
func (c criterion) skipReason(obs *Observation) string {
	var parts []string
	if obs.Transcript == nil && obs.NoSession != "" {
		parts = append(parts, obs.NoSession)
	}
	if obs.Transcript != nil && c.NeedsTranscript && !obs.Transcript.Decrypted {
		parts = append(parts, obs.Transcript.Undecryptable)
	}
	if !obs.Server.Available && c.Server != nil {
		parts = append(parts, "gridsim's admin API was not reachable, so the server-side record is unavailable too")
	}
	if notes := obs.notesFor(c.Claim); len(notes) > 0 {
		parts = append(parts, notes...)
	}
	if c.Skip != "" {
		parts = append(parts, c.Skip)
	}
	if len(parts) == 0 {
		parts = append(parts, "no evaluator for this criterion reached a conclusion in this run")
	}
	return strings.Join(parts, "; ")
}

// citeMessage cites the TLS records that carried one recovered HTTP message.
// This is the standard tier-2 citation and the reason the transcript tracks
// ciphertext offsets at all.
// The byte range is taken from the conversation the message actually travelled
// on (Message.In), not from the one RecoverSession selected. The two differ
// whenever the fact a criterion wants rode a sibling connection of the same
// frame set — a DER self-report PUT, a DERControlResponse POST — and citing the
// selected conversation's directions for a message that was never on them would
// name a byte range that decrypts to something else entirely. When they differ
// the Observed field says so: "these bytes are from another conversation of this
// window" is a fact the reader of a bundle is entitled to.
func citeMessage(t *Transcript, m *Message, v certify.Verdict, format string, a ...any) Finding {
	if m == nil {
		return unavailable("the message this criterion is about is not in the recovered transcript")
	}
	owner := m.In
	if owner == nil {
		owner = t
	}
	dir := owner.ClientDir
	if m.Kind == Response {
		dir = owner.ServerDir
	}
	f := Finding{Verdict: v, Observed: fmt.Sprintf(format, a...), Frames: m.Frames}
	if dir != nil && m.CipherEnd > m.CipherStart {
		f.Dir, f.Start, f.End = dir, m.CipherStart, m.CipherEnd
	}
	return annotate(f, siblingNote(t, owner))
}

// citeExchange cites the request and response frames of one exchange. It is
// used where the claim is about the PAIR ("the GET was answered 200"), for
// which neither single byte range is the whole evidence.
//
// t is the conversation recovered as this window's session, and is used only to
// disclose a citation drawn from a sibling conversation — see siblingNote.
func citeExchange(t *Transcript, e Exchange, v certify.Verdict, format string, a ...any) Finding {
	frames := e.Frames()
	if len(frames) == 0 {
		return unavailable("the exchange this criterion is about carried no attributed frames")
	}
	f := Finding{Verdict: v, Observed: fmt.Sprintf(format, a...), Frames: frames}
	return annotate(f, siblingNote(t, e.In()))
}

// siblingNote is the provenance sentence for a citation whose bytes are in a
// conversation OTHER than the one recovered as this window's session. It is the
// transcript tier's counterpart to handshakeOf's note, and it exists for the
// same reason: a reader must be able to tell WHICH of the window's
// conversations a byte range belongs to without re-deriving it.
func siblingNote(sel, owner *Transcript) string {
	if sel == nil || owner == nil || owner == sel || owner.Stream == nil || sel.Stream == nil {
		return ""
	}
	return fmt.Sprintf(". These bytes are from %s, a SECOND conversation this test case wholly owns: the "+
		"DUT opened it alongside the discovery walk recovered as this window's session (%s), and a frame "+
		"of it is a frame this case may cite", owner.Stream.Key, sel.Stream.Key)
}

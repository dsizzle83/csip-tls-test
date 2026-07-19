import { useMemo, useState } from 'react';
import type { GwBoard, GwReport } from './types';

// Friendly, demo-legible names for the gw-mayhem scenario categories, in the
// order a reviewer reads the safety case: who may command it, then the wire,
// then the control loop, then the DERs, then compound stress, then the board.
const CATEGORY_META: Record<string, { label: string; blurb: string }> = {
  'mbaps-northbound-authz': {
    label: 'Northbound authorization',
    blurb: 'A utility/VPP over Secure Modbus can only do what its X.509 role permits — and an out-of-range or malformed command is refused, never applied to a DER.',
  },
  'mbaps-transport-abuse': {
    label: 'Transport abuse',
    blurb: 'The gateway caps concurrent sessions and never lets a flood starve a legitimate controller.',
  },
  'mbaps-spec': {
    label: 'TLS transport policy',
    blurb: 'Client renegotiation is refused safely; a dropped session resumes; the RBAC grant/deny contract holds.',
  },
  'csip-northbound-malform': {
    label: 'Hostile head-end (CSIP)',
    blurb: 'A malformed or absent IEEE 2030.5 control resource never propagates an absurd setpoint — the gateway holds fail-closed.',
  },
  'southbound-fault-injection': {
    label: 'Misbehaving DER (southbound)',
    blurb: 'A DER that drops, freezes, serves garbage, or presents a bad identity is isolated; its telemetry masks to the sentinel while a commanded setpoint survives.',
  },
  'control-loop': {
    label: 'Control-loop integrity',
    blurb: 'Rapid re-curtailment, reversion timers, and exclusive north/south authority all converge exactly as designed.',
  },
  'compound-fault': {
    label: 'Perfect storm',
    blurb: 'Three faults at once (grid outage + DER comm-loss + hostile write) open no hole a single fault does not.',
  },
  'authority-pki-infra': {
    label: 'Authority / PKI / infra (board)',
    blurb: 'Mode/authority flips, vendor-access privacy, cert rotation, trust-store tamper, and service restarts — armed on the real device.',
  },
};

function verdictClass(r: GwReport): string {
  if (!r.on_pin) return 'gw-v-fail';
  if (r.verdict === 'PASS') return 'gw-v-pass';
  return 'gw-v-skip'; // an EXPECTED non-PASS (board scenarios that skip)
}

function verdictWord(r: GwReport): string {
  if (r.verdict === 'PASS') return 'PASS';
  if (!r.on_pin) return r.verdict;
  return 'SKIP'; // expected INCONCLUSIVE (board-armed elsewhere)
}

function Row({ r }: { r: GwReport }) {
  const [open, setOpen] = useState(false);
  const findings = r.findings ?? [];
  return (
    <div className={`gw-row ${verdictClass(r)}`}>
      <button className="gw-row-head" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <span className={`gw-chip ${verdictClass(r)}`}>{verdictWord(r)}</span>
        <span className="gw-row-id gw-mono">{r.id}</span>
        {r.security ? <span className="gw-sec" title="security-critical">SEC</span> : null}
        <span className="gw-row-desc">{r.desc}</span>
        <span className="gw-row-caret" aria-hidden="true">{open ? '▾' : '▸'}</span>
      </button>
      {open ? (
        <ul className="gw-findings">
          {findings.length ? (
            findings.map((f, i) => (
              <li key={i} className={f.startsWith('FAIL') || f.startsWith('BLIND') ? 'gw-find-bad' : 'gw-find-ok'}>
                {f}
              </li>
            ))
          ) : (
            <li className="gw-find-ok">no findings recorded</li>
          )}
        </ul>
      ) : null}
    </div>
  );
}

export function VerdictBoard({ board }: { board: GwBoard | undefined }) {
  const [secOnly, setSecOnly] = useState(false);

  const groups = useMemo(() => {
    const reps = (board?.reports ?? []).filter((r) => !secOnly || r.security);
    const by = new Map<string, GwReport[]>();
    for (const r of reps) {
      const k = r.category || 'other';
      if (!by.has(k)) by.set(k, []);
      by.get(k)!.push(r);
    }
    const order = Object.keys(CATEGORY_META);
    return [...by.entries()].sort((a, b) => {
      const ia = order.indexOf(a[0]);
      const ib = order.indexOf(b[0]);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });
  }, [board, secOnly]);

  if (!board?.available) {
    return (
      <section className="gw-card">
        <header className="gw-card-head">
          <h2>Adversarial-QA verdict board</h2>
        </header>
        <div className="gw-empty">No report yet — run the suite above to generate one.</div>
      </section>
    );
  }

  return (
    <section className="gw-card">
      <header className="gw-card-head">
        <h2>Adversarial-QA verdict board</h2>
        <label className="gw-toggle">
          <input type="checkbox" checked={secOnly} onChange={(e) => setSecOnly(e.target.checked)} />
          security-critical only
        </label>
      </header>

      {groups.map(([cat, reps]) => {
        const meta = CATEGORY_META[cat] ?? { label: cat, blurb: '' };
        const npass = reps.filter((r) => r.on_pin && r.verdict === 'PASS').length;
        return (
          <div key={cat} className="gw-group">
            <div className="gw-group-head">
              <span className="gw-group-name">{meta.label}</span>
              <span className="gw-group-count gw-mono">
                {npass}/{reps.length}
              </span>
            </div>
            {meta.blurb ? <div className="gw-group-blurb">{meta.blurb}</div> : null}
            {reps.map((r) => (
              <Row key={r.id} r={r} />
            ))}
          </div>
        );
      })}
    </section>
  );
}

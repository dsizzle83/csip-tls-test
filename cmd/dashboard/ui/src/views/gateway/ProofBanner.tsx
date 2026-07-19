import type { GwBoard } from './types';

// ProofBanner — the headline claim, stated plainly and backed by the live
// verdict counts: the gateway refused every adversarial scenario as designed.
export function ProofBanner({ board }: { board: GwBoard | undefined }) {
  const ready = board?.available;
  const green = ready && board!.gate_green;
  const pass = board?.pass ?? 0;
  const fail = board?.fail ?? 0;
  const scored = pass + fail;

  return (
    <div className={`gw-banner${green ? ' gw-banner-green' : ready ? ' gw-banner-red' : ''}`}>
      <div className="gw-banner-mark" aria-hidden="true">
        {green ? '🛡' : ready ? '⚠' : '…'}
      </div>
      <div className="gw-banner-body">
        <div className="gw-banner-title">
          {!ready
            ? 'Awaiting an adversarial-QA report…'
            : green
              ? 'Behaving as designed'
              : `${fail} scenario${fail === 1 ? '' : 's'} outside expected behavior`}
        </div>
        <div className="gw-banner-sub">
          {ready ? (
            <>
              <strong>{pass}</strong> of <strong>{scored}</strong> adversarial scenarios refused/handled
              exactly as specified{board!.skipped ? ` · ${board!.skipped} board-only skipped` : ''} ·{' '}
              <span className="gw-mono">{board!.source}</span>
            </>
          ) : (
            'Run the suite, or drive the standing aggregator, to generate one.'
          )}
        </div>
      </div>
      {ready ? (
        <div className="gw-banner-gate">
          <span className={`gw-gate${green ? ' gw-gate-pass' : ' gw-gate-fail'}`}>
            {green ? 'GATE PASS' : 'GATE FAIL'}
          </span>
        </div>
      ) : null}
    </div>
  );
}

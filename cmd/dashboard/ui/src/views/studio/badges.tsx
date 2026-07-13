// Small shared badges for the Studio. The confidence badge is COLOR-NEUTRAL by
// design (DESIGN_BRIEF.md §4, CONTRACTS.md §7: render the confidence level,
// never hide it — but a colored "estimated" would read as a status verdict,
// which it is not). Letter + hover tooltip carrying provenance.

import type { Confidence } from './types';

const LETTER: Record<Confidence, string> = {
  filed: 'F',
  published: 'P',
  estimated: 'E',
};
const WORD: Record<Confidence, string> = {
  filed: 'Filed',
  published: 'Published',
  estimated: 'Estimated',
};

export function ConfidenceBadge({
  confidence,
  sourceUrl,
  retrieved,
}: {
  confidence: Confidence;
  sourceUrl?: string;
  retrieved?: string;
}) {
  const tip =
    `${WORD[confidence]} confidence` +
    (retrieved ? ` · retrieved ${retrieved}` : '') +
    (sourceUrl ? `\n${sourceUrl}` : '');
  return (
    <span className="st-conf" title={tip} aria-label={`${WORD[confidence]} confidence`}>
      {LETTER[confidence]}
    </span>
  );
}

/** "Credits banked $X" — surfaced when a NEM month's export credit was capped
 *  and the excess banked forward (Bill.credit_carryover_usd). */
export function CreditsBankedChip({ usd }: { usd: number }) {
  return (
    <span
      className="st-credits"
      title={
        'Net-metering credit that exceeded this month’s energy charges and was ' +
        'banked toward future bills. On NEM plans, LEXA’s extra export value shows ' +
        'here rather than in this month’s total.'
      }
    >
      ⚡ Credits banked ${usd.toFixed(2)}
    </span>
  );
}

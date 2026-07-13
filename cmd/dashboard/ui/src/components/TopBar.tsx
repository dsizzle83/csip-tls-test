import { useEffect, useState } from 'react';
import { HealthDots } from './HealthDots';
import { formatClock } from '../lib/format';

/**
 * Top bar (56px, brief §3): logo + product name, bench health dot-row, and a
 * live clock. Clock is wall-time for now — swap the `now` source to the
 * bench's sim-time (gridsim clock offset, when replay/warp is active) once
 * that state is exposed to the shell; the display code doesn't need to change.
 */
export function TopBar() {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-brand">
        <img src="/brand/logo.png" alt="LEXA" className="topbar-logo" />
        <span className="topbar-title">LEXA · Grid Intelligence</span>
      </div>
      <div className="topbar-right">
        <HealthDots />
        <span className="clock" title="Wall clock">
          {formatClock(now)}
        </span>
      </div>
    </header>
  );
}

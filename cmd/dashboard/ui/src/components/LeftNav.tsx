import { useState } from 'react';
import { NavLink } from 'react-router-dom';

interface NavItem {
  to: string;
  label: string;
  icon: string;
}

// Brief §3 order: Studio, Live Ops, Proof, Logs, Bench (+ Present, stretch —
// add its entry here once /present exists; nothing else needs to change).
const ITEMS: NavItem[] = [
  { to: '/studio', label: 'Studio', icon: '⚡' },
  { to: '/ops', label: 'Live Ops', icon: '📡' },
  { to: '/proof', label: 'Proof', icon: '🛡' },
  { to: '/logs', label: 'Logs', icon: '📜' },
  { to: '/bench', label: 'Bench', icon: '🔧' },
];

/**
 * Left nav (200px, collapsible to 56px icons, brief §3). Active item gets a
 * --sage-soft pill + --green-ink text + 3px --bolt left rail via the
 * `.nav-item.active` class (react-router NavLink applies it automatically).
 */
export function LeftNav() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <nav className={`nav${collapsed ? ' collapsed' : ''}`} aria-label="Primary">
      {ITEMS.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
        >
          <span className="nav-icon" aria-hidden="true">
            {item.icon}
          </span>
          <span className="nav-label">{item.label}</span>
        </NavLink>
      ))}
      <button
        type="button"
        className="nav-toggle"
        onClick={() => setCollapsed((c) => !c)}
        aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
        title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
      >
        {collapsed ? '»' : '« Collapse'}
      </button>
    </nav>
  );
}

import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { TopBar } from './components/TopBar';
import { LeftNav } from './components/LeftNav';
import Studio from './views/Studio';
import Ops from './views/Ops';
import Proof from './views/Proof';
import Gateway from './views/Gateway';
import LogsView from './views/LogsView';
import Bench from './views/Bench';

/**
 * App shell (brief §3): top bar + collapsible left nav + a max-width content
 * container. Routed with BrowserRouter (not hash routing) since the Go side
 * (cmd/dashboard/main.go) serves this SPA at "/" with a catch-all fallback
 * to index.html for any unknown non-/api, non-/legacy path — see CONTRACTS.md §6.
 */
export default function App() {
  return (
    <BrowserRouter basename="/">
      <div className="shell">
        <TopBar />
        <div className="shell-body">
          <LeftNav />
          <main className="content">
            <div className="content-inner">
              <Routes>
                <Route path="/" element={<Navigate to="/studio" replace />} />
                <Route path="/studio" element={<Studio />} />
                <Route path="/ops" element={<Ops />} />
                <Route path="/proof" element={<Proof />} />
                <Route path="/gateway" element={<Gateway />} />
                <Route path="/logs" element={<LogsView />} />
                <Route path="/bench" element={<Bench />} />
                <Route path="*" element={<Navigate to="/studio" replace />} />
              </Routes>
            </div>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}

import { useState, useEffect } from 'react';
import './styles/theme.css';
import './styles/components.css';
import './styles/spline-hero.css';

import { ToastProvider } from './components/Toast';
import LoadingScreen from './components/LoadingScreen';
import SplineHero from './components/SplineHero';
import Header from './components/Header';
import Footer from './components/Footer';
import Dashboard from './components/Dashboard';
import ThreatFeed from './components/ThreatFeed';
import LeakDetector from './components/LeakDetector';
import SlangDecoder from './components/SlangDecoder';
import IdentityLinker from './components/IdentityLinker';
import Analytics from './components/Analytics';

// Console easter egg
console.log(`
%c╔═══════════════════════════════════════╗
║       DARKINTEL-AI v1.0.0             ║
║   Threat Intelligence Platform        ║
║   Built by Team DarkIntel             ║
║   HackUp 2026                         ║
╚═══════════════════════════════════════╝
`, 'color: #00F0FF; font-family: monospace; font-size: 12px;');

const PAGES = {
  dashboard: Dashboard,
  threats: ThreatFeed,
  leaks: LeakDetector,
  slang: SlangDecoder,
  identity: IdentityLinker,
  analytics: Analytics,
};

export default function App() {
  const [showHero, setShowHero] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [connected, setConnected] = useState(false);
  const [demoBadge, setDemoBadge] = useState(true);

  // Health check
  useEffect(() => {
    const check = () => {
      fetch('http://localhost:8000/api/health')
        .then(r => { if (r.ok) setConnected(true); else setConnected(false); })
        .catch(() => setConnected(false));
    };
    check();
    const id = setInterval(check, 10000);
    return () => clearInterval(id);
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      if (e.key === 'Escape') { /* do nothing for now */ }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const PageComponent = PAGES[activeTab] || Dashboard;

  return (
    <ToastProvider>
      {showHero ? (
        <SplineHero onEnter={() => setShowHero(false)} />
      ) : (
        <>
          <LoadingScreen />
          <div className="app-background scanline">
            <div className="crt-lines" />
            <Header activeTab={activeTab} onTabChange={setActiveTab} connected={connected} />
            <main className="main-content">
              <PageComponent key={activeTab} />
            </main>
            <Footer />
            {demoBadge && (
              <div className="demo-badge" onClick={() => setDemoBadge(false)}>
                ● Demo Mode
              </div>
            )}
          </div>
        </>
      )}
    </ToastProvider>
  );
}

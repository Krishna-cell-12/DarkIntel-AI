import { useState, useEffect } from 'react';

const TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'threats',   label: 'Threat Feed' },
  { id: 'leaks',     label: 'Leak Detector' },
  { id: 'slang',     label: 'Slang Decoder' },
  { id: 'identity',  label: 'Identity Linker' },
  { id: 'analytics', label: 'Analytics' },
  { id: 'company', label: 'Company Lookup' },
];

export default function Header({ activeTab, onTabChange, connected }) {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  const timeStr = time.toLocaleTimeString('en-US', { hour12: false });

  return (
    <header className="header">
      <div className="header-left">
        <div className="header-logo">
          DARK<span className="accent">INTEL</span>
        </div>
        <span className="header-version">v1.0.0</span>

        <nav className="header-nav">
          {TABS.map(tab => (
            <button
              key={tab.id}
              className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => onTabChange(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="header-right">
        <span className="header-time">{timeStr}</span>
        <div className={`header-status ${connected ? '' : 'offline'}`}>
          <div className="status-dot" />
          {connected ? 'SYSTEM ONLINE' : 'OFFLINE'}
        </div>
      </div>
    </header>
  );
}

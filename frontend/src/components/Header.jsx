import { useState, useEffect } from 'react';
import { fetchAlertsReport } from '../api';
import { IconBell } from './Icons';

const TABS = [
  { id: 'dashboard', label: 'Dashboard', tip: 'Real-time threat overview and health' },
  { id: 'alerts', label: 'Alerts', tip: 'Prioritized risk alerts and notifications' },
  { id: 'company', label: 'Monitor', tip: 'Continuous ingestion, watchlist, and proactive scans' },
  { id: 'threats', label: 'Threat Feed', tip: 'Live intercepted signals and severity' },
  { id: 'leaks', label: 'Leak Detector', tip: 'Detect credentials and financial leaks' },
  { id: 'slang', label: 'Slang Decoder', tip: 'Decode coded dark-web language' },
  { id: 'identity', label: 'Identity Linker', tip: 'Cross-platform actor identity correlation' },
  { id: 'analytics', label: 'Analytics', tip: 'Early warning and threat trend analytics' },
];

export default function Header({ activeTab, onTabChange, connected, lastSync }) {
  const [time, setTime] = useState(new Date());
  const [alertCount, setAlertCount] = useState(0);
  const [criticalCount, setCriticalCount] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  // Fetch alert count for bell badge
  useEffect(() => {
    async function loadAlertCount() {
      try {
        const data = await fetchAlertsReport(50, 'MEDIUM');
        const dist = data.distribution || {};
        setAlertCount(data.total_alerts || 0);
        setCriticalCount((dist.CRITICAL || 0) + (dist.HIGH || 0));
      } catch {
        setAlertCount(0);
        setCriticalCount(0);
      }
    }
    loadAlertCount();
    const interval = setInterval(loadAlertCount, 30000);
    return () => clearInterval(interval);
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
              title={tab.tip}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="header-right">
        {/* Alert Bell Icon */}
        <div
          className="header-bell"
          title={`${alertCount} alerts (${criticalCount} critical/high)`}
          onClick={() => onTabChange('alerts')}
        >
          <IconBell />
          {criticalCount > 0 && (
            <span className="header-bell-badge">{criticalCount > 99 ? '99+' : criticalCount}</span>
          )}
        </div>

        <span className="header-time">{timeStr}</span>
        <div className={`header-status ${connected ? '' : 'offline'}`}>
          <div className="status-dot" />
          {connected ? 'SYSTEM ONLINE' : 'OFFLINE'}
        </div>
        <span className="header-time" title="Latest backend heartbeat">Last Sync: {lastSync || '—'}</span>
      </div>
    </header>
  );
}

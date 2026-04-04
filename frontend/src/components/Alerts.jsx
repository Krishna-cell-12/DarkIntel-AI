import { useState, useEffect } from 'react';
import { fetchAlertsReport, fetchThreatFeed } from '../api';
import { IconBell, IconZap, IconActivity, IconLink } from './Icons';
import { timeAgo } from '../utils/time';

/* ── Alert Card ────────────────────────────────────────────────────── */
function AlertCard({ alert, threats, onSelectThreat }) {
  const [expanded, setExpanded] = useState(false);
  const priority = (alert.priority || 'LOW').toLowerCase();

  const relatedThreats = (alert.related_threat_ids || [])
    .map((id) => threats.find((t) => String(t.id) === String(id)))
    .filter(Boolean);

  return (
    <div
      className={`alert-card ${priority}`}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="alert-card-header">
        <div className="alert-card-left">
          <span className={`badge ${priority}`}>{alert.priority || 'LOW'}</span>
          <span className="alert-card-type">{alert.type === 'correlation_signal' ? 'CORRELATION' : 'RISK'}</span>
        </div>
        <span className="alert-card-time">{timeAgo(alert.created_at)}</span>
      </div>
      <div className="alert-card-title">{alert.title || 'Alert'}</div>
      <div className="alert-card-desc">{alert.description || 'No details.'}</div>
      {expanded && (
        <div className="alert-card-details">
          <div className="alert-card-meta">
            <span>Score: <strong>{alert.score || 0}</strong></span>
            <span>Sources: <strong>{(alert.sources || []).length}</strong></span>
            {relatedThreats.length > 0 && (
              <span>Linked Threats: <strong>{relatedThreats.length}</strong></span>
            )}
          </div>
          {relatedThreats.length > 0 && (
            <div className="alert-card-threats">
              {relatedThreats.slice(0, 3).map((t) => (
                <div
                  key={t.id}
                  className="alert-linked-threat"
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelectThreat?.(t);
                  }}
                >
                  <span className={`badge ${(t.severity || 'LOW').toLowerCase()}`}>{t.severity}</span>
                  <span className="alert-linked-content">{(t.content || '').slice(0, 60)}...</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Main Alerts Page ─────────────────────────────────────────────── */
export default function Alerts() {
  const [alertsData, setAlertsData] = useState({
    alerts: [],
    total_alerts: 0,
    distribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    summary: '',
  });
  const [threats, setThreats] = useState([]);
  const [filter, setFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [selectedThreat, setSelectedThreat] = useState(null);

  useEffect(() => {
    async function load() {
      try {
        const [a, f] = await Promise.all([
          fetchAlertsReport(100, 'LOW'),
          fetchThreatFeed(100),
        ]);
        setAlertsData(a || { alerts: [], total_alerts: 0, distribution: {}, summary: '' });
        setThreats(f.threats || []);
      } catch {
        setAlertsData({ alerts: [], total_alerts: 0, distribution: {}, summary: '' });
        setThreats([]);
      }
      setLoading(false);
    }
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const onEsc = (e) => {
      if (e.key === 'Escape') setSelectedThreat(null);
    };
    window.addEventListener('keydown', onEsc);
    return () => window.removeEventListener('keydown', onEsc);
  }, []);

  const dist = alertsData.distribution || {};
  const allAlerts = alertsData.alerts || [];
  const filtered = filter === 'ALL'
    ? allAlerts
    : allAlerts.filter((a) => (a.priority || 'LOW').toUpperCase() === filter);

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header Stats */}
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconBell style={{ width: 14, height: 14, color: 'var(--critical)' }} />
            Alert Center
          </span>
          <span className="card-header-badge">{alertsData.total_alerts} total alerts</span>
        </div>
        <div className="card-body">
          <div className="alerts-kpi-row">
            <div className="alerts-kpi critical" onClick={() => setFilter('CRITICAL')}>
              <div className="alerts-kpi-num">{dist.CRITICAL || 0}</div>
              <div className="alerts-kpi-label">CRITICAL</div>
            </div>
            <div className="alerts-kpi high" onClick={() => setFilter('HIGH')}>
              <div className="alerts-kpi-num">{dist.HIGH || 0}</div>
              <div className="alerts-kpi-label">HIGH</div>
            </div>
            <div className="alerts-kpi medium" onClick={() => setFilter('MEDIUM')}>
              <div className="alerts-kpi-num">{dist.MEDIUM || 0}</div>
              <div className="alerts-kpi-label">MEDIUM</div>
            </div>
            <div className="alerts-kpi low" onClick={() => setFilter('LOW')}>
              <div className="alerts-kpi-num">{dist.LOW || 0}</div>
              <div className="alerts-kpi-label">LOW</div>
            </div>
          </div>
          <div className="alerts-filter-row">
            <button className={`cyber-btn ${filter === 'ALL' ? 'primary' : 'outline'}`} onClick={() => setFilter('ALL')}>ALL</button>
            <button className={`cyber-btn ${filter === 'CRITICAL' ? 'primary' : 'outline'}`} onClick={() => setFilter('CRITICAL')}>CRITICAL</button>
            <button className={`cyber-btn ${filter === 'HIGH' ? 'primary' : 'outline'}`} onClick={() => setFilter('HIGH')}>HIGH</button>
            <button className={`cyber-btn ${filter === 'MEDIUM' ? 'primary' : 'outline'}`} onClick={() => setFilter('MEDIUM')}>MEDIUM</button>
            <button className={`cyber-btn ${filter === 'LOW' ? 'primary' : 'outline'}`} onClick={() => setFilter('LOW')}>LOW</button>
          </div>
          {alertsData.summary && (
            <div className="alerts-summary">{alertsData.summary}</div>
          )}
        </div>
      </div>

      {/* Alert List */}
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconZap style={{ width: 14, height: 14, color: 'var(--high)' }} />
            {filter === 'ALL' ? 'All Alerts' : `${filter} Alerts`}
          </span>
          <span className="card-header-badge">{filtered.length} shown</span>
        </div>
        <div className="card-body">
          {loading ? (
            <div className="empty-state">Loading alerts...</div>
          ) : filtered.length === 0 ? (
            <div className="empty-state">
              No alerts found. Ingest data or run scans to generate risk signals.
            </div>
          ) : (
            <div className="alerts-list">
              {filtered.map((alert) => (
                <AlertCard
                  key={alert.id}
                  alert={alert}
                  threats={threats}
                  onSelectThreat={setSelectedThreat}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Correlation Info */}
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconLink style={{ width: 14, height: 14, color: 'var(--magenta)' }} />
            How Alerts Work
          </span>
        </div>
        <div className="card-body">
          <div className="alerts-info">
            <div className="alerts-info-item">
              <IconActivity style={{ width: 18, height: 18, color: 'var(--cyan)' }} />
              <div>
                <strong>Correlation Signals</strong>
                <p>Alerts generated when the same entity (email, wallet, IP) appears across multiple sources — indicating coordinated activity.</p>
              </div>
            </div>
            <div className="alerts-info-item">
              <IconZap style={{ width: 18, height: 18, color: 'var(--high)' }} />
              <div>
                <strong>Risk-Based Alerts</strong>
                <p>Alerts triggered when individual sources exceed risk thresholds based on threat score, slang density, and entity extraction.</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Detail Modal */}
      {selectedThreat && (
        <div className="threat-modal-overlay" onClick={() => setSelectedThreat(null)}>
          <div className="threat-modal" onClick={(e) => e.stopPropagation()}>
            <div className="threat-modal-head">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className={`badge ${(selectedThreat.severity || 'LOW').toLowerCase()}`}>
                  {selectedThreat.severity || 'LOW'}
                </span>
                {selectedThreat.is_new && <span className="badge low">NEW</span>}
              </div>
              <button className="cyber-btn ghost" style={{ padding: '6px 10px' }} onClick={() => setSelectedThreat(null)}>
                Close
              </button>
            </div>
            <div className="threat-modal-meta">
              Score: {selectedThreat.threat_score || 0}/100 · Source: {selectedThreat.source || 'unknown'} · {timeAgo(selectedThreat.timestamp)}
            </div>
            <div className="threat-modal-content">
              {selectedThreat.full_content || selectedThreat.content || 'No content.'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

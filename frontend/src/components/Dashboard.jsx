import { useState, useEffect, useRef } from 'react';
import { fetchDashboardStats, fetchThreatFeed, fetchAlertsReport } from '../api';
import StatsBar from './StatsBar';
import { IconZap, IconActivity, IconLink } from './Icons';
import { timeAgo } from '../utils/time';

/* ── SVG Donut Chart ─────────────────────────────────────────── */
function DonutChart({ dist }) {
  const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;
  const segments = [
    { key: 'CRITICAL', color: '#FF0040', count: dist.CRITICAL || 0 },
    { key: 'HIGH', color: '#FF6B00', count: dist.HIGH || 0 },
    { key: 'MEDIUM', color: '#FFD600', count: dist.MEDIUM || 0 },
    { key: 'LOW', color: '#00FF88', count: dist.LOW || 0 },
  ];

  let offset = 0;
  const radius = 60;
  const circumference = 2 * Math.PI * radius;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 28 }}>
      <svg width="160" height="160" viewBox="0 0 160 160">
        {segments.map((seg) => {
          const pct = seg.count / total;
          const dashLen = circumference * pct;
          const dashOffset = circumference * offset;
          offset += pct;
          return (
            <circle
              key={seg.key}
              cx="80" cy="80" r={radius}
              fill="none"
              stroke={seg.color}
              strokeWidth="14"
              strokeDasharray={`${dashLen} ${circumference - dashLen}`}
              strokeDashoffset={-dashOffset}
              strokeLinecap="round"
              style={{
                filter: `drop-shadow(0 0 4px ${seg.color}66)`,
                transition: 'stroke-dasharray 1s ease, stroke-dashoffset 1s ease',
                transformOrigin: 'center',
                transform: 'rotate(-90deg)',
              }}
            />
          );
        })}
        <text x="80" y="74" textAnchor="middle" fill="var(--text-primary)" fontFamily="var(--font-mono)" fontSize="22" fontWeight="700">
          {total}
        </text>
        <text x="80" y="94" textAnchor="middle" fill="var(--text-dim)" fontFamily="var(--font-mono)" fontSize="9" letterSpacing="1.5">
          TOTAL
        </text>
      </svg>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {segments.map(seg => (
          <div key={seg.key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: seg.color, boxShadow: `0 0 6px ${seg.color}55` }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-secondary)', width: 65 }}>{seg.key}</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: seg.color, fontWeight: 700 }}>{seg.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Live Feed (auto-scroll) ─────────────────────────────────── */
function LiveFeed({ threats, onSelectThreat }) {
  const ref = useRef(null);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (paused || !ref.current) return;
    const el = ref.current;
    const id = setInterval(() => {
      if (el.scrollTop + el.clientHeight >= el.scrollHeight - 2) {
        el.scrollTop = 0;
      } else {
        el.scrollTop += 1;
      }
    }, 60);
    return () => clearInterval(id);
  }, [paused, threats]);

  const severityClass = (level) => (level || '').toLowerCase();

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--critical)', animation: 'pulse 1.5s ease-in-out infinite' }} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--critical)', letterSpacing: '1.5px', textTransform: 'uppercase', fontWeight: 700 }}>LIVE</span>
      </div>
      <div
        ref={ref}
        style={{ maxHeight: 310, overflowY: 'auto' }}
        onMouseEnter={() => setPaused(true)}
        onMouseLeave={() => setPaused(false)}
      >
        <div className="stagger-children" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {(!threats || threats.length === 0) ? (
            <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>No real threats ingested yet</div>
          ) : threats.map((t, i) => (
            <div
              key={i}
              style={{
                display: 'flex', alignItems: 'flex-start', gap: 10,
                padding: '10px 12px',
                borderRadius: 'var(--radius-xs)',
                background: 'rgba(255,255,255,0.015)',
                borderLeft: `3px solid ${t.severity === 'CRITICAL' ? 'var(--critical)' : t.severity === 'HIGH' ? 'var(--high)' : t.severity === 'MEDIUM' ? 'var(--medium)' : 'var(--low)'}`,
                transition: 'all 0.2s ease',
                cursor: 'pointer',
              }}
              onClick={() => onSelectThreat?.(t)}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
              onMouseLeave={e => e.currentTarget.style.background = 'rgba(255,255,255,0.015)'}
            >
              <span className={`badge ${severityClass(t.severity)}`} style={{ flexShrink: 0, marginTop: 1 }}>{t.severity}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: '0.78rem', lineHeight: 1.4, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {t.content || t.text || 'Threat detected'}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: 'var(--text-dim)', marginTop: 4 }}>
                  Score: {t.threat_score || t.score || '—'} · {t.source || 'dark-web'}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ── Mini Network Viz ────────────────────────────────────────── */
function MiniNetwork({ threats }) {
  const entitySet = new Set();
  (threats || []).forEach(t => {
    (t.entities || []).forEach(e => {
      if (typeof e === 'string' && e.trim()) entitySet.add(e.trim());
    });
  });
  const labels = Array.from(entitySet).slice(0, 5);
  const fallback = ['No entities', 'Ingest data', 'Run crawl', 'Correlate', 'Alerts'];
  const used = labels.length > 0 ? labels : fallback;

  const nodes = [
    { x: 80, y: 60, label: used[0] || 'node-1', color: 'var(--critical)', r: 18 },
    { x: 230, y: 50, label: used[1] || 'node-2', color: 'var(--high)', r: 15 },
    { x: 155, y: 150, label: used[2] || 'node-3', color: 'var(--cyan)', r: 16 },
    { x: 310, y: 130, label: used[3] || 'node-4', color: 'var(--magenta)', r: 12 },
    { x: 60, y: 180, label: used[4] || 'node-5', color: 'var(--low)', r: 12 },
  ];
  const edges = [[0,2],[1,2],[2,3],[0,4],[1,3]];

  return (
    <svg width="100%" height="220" viewBox="0 0 400 230" style={{ display: 'block' }}>
      {edges.map(([a,b], i) => (
        <line key={i} x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y}
          stroke="var(--border)" strokeWidth="1" opacity="0.5">
          <animate attributeName="opacity" values="0.3;0.7;0.3" dur="3s" repeatCount="indefinite" begin={`${i*0.5}s`} />
        </line>
      ))}
      {nodes.map((n, i) => (
        <g key={i}>
          <circle cx={n.x} cy={n.y} r={n.r} fill={n.color} opacity="0.15">
            <animate attributeName="r" values={`${n.r};${n.r+4};${n.r}`} dur="3s" repeatCount="indefinite" begin={`${i*0.3}s`} />
          </circle>
          <circle cx={n.x} cy={n.y} r={n.r * 0.55} fill={n.color} />
          <text x={n.x} y={n.y + n.r + 14} textAnchor="middle" fill="var(--text-dim)" fontFamily="var(--font-mono)" fontSize="8">{n.label}</text>
        </g>
      ))}
    </svg>
  );
}

/* ── Main Dashboard ──────────────────────────────────────────── */
export default function Dashboard({ onNavigate }) {
  const [stats, setStats] = useState(null);
  const [threats, setThreats] = useState([]);
  const [alertsReport, setAlertsReport] = useState({
    alerts: [],
    total_alerts: 0,
    distribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    summary: '',
  });
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const onEsc = (e) => {
      if (e.key === 'Escape') setSelectedThreat(null);
    };
    window.addEventListener('keydown', onEsc);
    return () => window.removeEventListener('keydown', onEsc);
  }, []);

  useEffect(() => {
    async function load() {
      try {
        const [s, f, a] = await Promise.all([
          fetchDashboardStats(),
          fetchThreatFeed(20),
          fetchAlertsReport(20, 'MEDIUM'),
        ]);
        setStats(s);
        setThreats(f.threats || []);
        setAlertsReport(a || {
          alerts: [],
          total_alerts: 0,
          distribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
          summary: '',
        });
      } catch {
        setStats(null);
        setThreats([]);
        setAlertsReport({
          alerts: [],
          total_alerts: 0,
          distribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
          summary: 'Alerts unavailable.',
        });
      }
      setLoading(false);
    }
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);

  const dist = stats?.threat_distribution || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const alertDist = alertsReport?.distribution || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const topAlerts = alertsReport?.alerts || [];
  const selectedThreatId = selectedThreat ? String(selectedThreat.id || '') : '';
  const selectedThreatRelatedAlerts = selectedThreatId
    ? topAlerts.filter((a) =>
      (a.related_threat_ids || []).map((id) => String(id)).includes(selectedThreatId),
    )
    : [];

  const handleQuickFilter = (severity) => {
    if (!onNavigate) return;
    onNavigate('threats', { severity: severity || 'ALL' });
  };

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Stats */}
      <StatsBar
        stats={stats}
        alertsReport={alertsReport}
        loading={loading}
        onQuickFilter={handleQuickFilter}
      />

      {/* Main Grid */}
      <div className="dash-grid">
        {/* Left: Recent Threats */}
        <div className="glass-card">
          <div className="card-header">
            <span className="card-header-title">
              <IconZap style={{ width: 14, height: 14, color: 'var(--critical)' }} />
              Recent Threats
            </span>
            <span className="card-header-badge">{threats.length} real records</span>
          </div>
          <div className="card-body">
            <LiveFeed threats={threats} onSelectThreat={setSelectedThreat} />
            {!loading && threats.length === 0 ? (
              <div className="empty-state" style={{ marginTop: 12 }}>
                No real threat data yet. Run Tor crawl or ingest files/URLs to start monitoring.
              </div>
            ) : null}
          </div>
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Donut Chart */}
          <div className="glass-card">
            <div className="card-header">
              <span className="card-header-title">
                <IconActivity style={{ width: 14, height: 14, color: 'var(--cyan)' }} />
                Threat Distribution
              </span>
            </div>
            <div className="card-body">
              <DonutChart dist={dist} />
            </div>
          </div>

          {/* Identity Mini-Map */}
          <div className="glass-card">
            <div className="card-header">
              <span className="card-header-title">
                <IconZap style={{ width: 14, height: 14, color: 'var(--high)' }} />
                Alerts Risk Report
              </span>
              <span className="card-header-badge">{alertsReport?.total_alerts || 0} alerts</span>
            </div>
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="dash-alert-kpis">
                <div className="dash-alert-kpi critical">CRITICAL: {alertDist.CRITICAL || 0}</div>
                <div className="dash-alert-kpi high">HIGH: {alertDist.HIGH || 0}</div>
                <div className="dash-alert-kpi medium">MEDIUM: {alertDist.MEDIUM || 0}</div>
                <div className="dash-alert-kpi low">LOW: {alertDist.LOW || 0}</div>
              </div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                {alertsReport?.summary || 'No alert summary yet.'}
              </div>
              {topAlerts.length === 0 ? (
                <div className="empty-state">
                  No active alerts. Ingest or crawl more sources to generate risk signals.
                </div>
              ) : (
                <div className="dash-alert-list">
                  {topAlerts.slice(0, 4).map((a) => (
                    <div
                      key={a.id}
                      className="dash-alert-item"
                      style={{
                        cursor: ((a.related_threat_ids || []).length > 0) ? 'pointer' : 'default',
                      }}
                      onClick={() => {
                        const linkedThreat = (a.related_threat_ids || [])
                          .map((id) => threats.find((t) => String(t.id) === String(id)))
                          .find(Boolean);
                        if (linkedThreat) setSelectedThreat(linkedThreat);
                      }}
                    >
                      <span className={`badge ${(a.priority || 'LOW').toLowerCase()}`}>{a.priority || 'LOW'}</span>
                      <div className="dash-alert-copy">
                        <div className="dash-alert-title">{a.title || 'Alert'}</div>
                        <div className="dash-alert-desc">{a.description || 'No details provided.'}</div>
                        {(a.related_threat_ids || []).length > 0 ? (
                          <div className="dash-alert-link">Linked threats: {(a.related_threat_ids || []).length}</div>
                        ) : null}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="glass-card">
            <div className="card-header">
              <span className="card-header-title">
                <IconLink style={{ width: 14, height: 14, color: 'var(--magenta)' }} />
                Identity Network
              </span>
            </div>
            <div className="card-body" style={{ padding: '12px 8px' }}>
              <MiniNetwork threats={threats} />
            </div>
          </div>
        </div>
      </div>

      {selectedThreat ? (
        <div className="threat-modal-overlay" onClick={() => setSelectedThreat(null)}>
          <div className="threat-modal" onClick={(e) => e.stopPropagation()}>
            <div className="threat-modal-head">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className={`badge ${(selectedThreat.severity || 'LOW').toLowerCase()}`}>
                  {selectedThreat.severity || 'LOW'}
                </span>
                {selectedThreat.is_new ? <span className="badge low">NEW</span> : null}
                {(selectedThreat.occurrences || 1) > 1 ? (
                  <span className="badge medium">Seen {selectedThreat.occurrences}x</span>
                ) : null}
              </div>
              <button className="cyber-btn ghost" style={{ padding: '6px 10px' }} onClick={() => setSelectedThreat(null)}>
                Close
              </button>
            </div>
            <div className="threat-modal-meta">
              Score: {selectedThreat.threat_score || selectedThreat.score || 0}/100 · Source: {selectedThreat.source || 'unknown'} · {timeAgo(selectedThreat.timestamp)}
            </div>
            <div className="threat-modal-content">
              {selectedThreat.full_content || selectedThreat.content || selectedThreat.text || 'Threat details unavailable.'}
            </div>
            <div className="threat-modal-entities">
              {(selectedThreat.entities || []).length === 0 ? (
                <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>No extracted entities.</span>
              ) : (
                (selectedThreat.entities || []).slice(0, 12).map((e, idx) => {
                  const v = typeof e === 'string' ? e : (e?.value || '');
                  return <span key={`${v}_${idx}`} className="tag">{v}</span>;
                })
              )}
            </div>

            <div className="threat-modal-related-wrap">
              <div className="threat-modal-related-title">Related Alerts</div>
              {selectedThreatRelatedAlerts.length === 0 ? (
                <div className="threat-modal-related-empty">
                  No linked alerts yet for this threat.
                </div>
              ) : (
                <div className="threat-modal-related-list">
                  {selectedThreatRelatedAlerts.slice(0, 6).map((a) => (
                    <div key={`rel_${a.id}`} className="threat-modal-related-item">
                      <span className={`badge ${(a.priority || 'LOW').toLowerCase()}`}>{a.priority || 'LOW'}</span>
                      <div className="threat-modal-related-copy">
                        <div className="threat-modal-related-head">{a.title || 'Alert'}</div>
                        <div className="threat-modal-related-desc">{a.description || 'No details provided.'}</div>
                        {(a.related_sources || []).length > 0 ? (
                          <div className="threat-modal-related-srcs">
                            Correlated sources: {(a.related_sources || []).map((s) => s.source).filter(Boolean).join(', ')}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

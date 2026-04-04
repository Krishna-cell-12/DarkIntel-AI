import { useEffect, useMemo, useState } from 'react';
import { fetchDashboardStats, fetchEarlyWarning, fetchThreatFeed } from '../api';
import { IconActivity, IconBarChart } from './Icons';

function normalizeThreats(threats) {
  return (threats || []).map(t => ({
    score: Number(t.threat_score || t.score || 0),
    severity: String(t.severity || t.threat_level || 'LOW').toUpperCase(),
    source: t.source || 'unknown',
    entities: Array.isArray(t.entities) ? t.entities.length : 0,
  }));
}

function RealBarChart({ rows }) {
  const max = Math.max(1, ...rows.map(r => r.value || 0));
  return (
    <div className="bar-chart">
      {rows.map((row, i) => (
        <div className="bar-row" key={i}>
          <span className="bar-label">{row.label}</span>
          <div className="bar-track">
            <div className={`bar-fill ${row.color || 'cyan'}`} style={{ width: `${(row.value / max) * 100}%` }} />
          </div>
          <span className="bar-value">{row.value}</span>
        </div>
      ))}
    </div>
  );
}

export default function Analytics() {
  const [stats, setStats] = useState(null);
  const [threats, setThreats] = useState([]);
  const [warning, setWarning] = useState(null);

  useEffect(() => {
    async function load() {
      const [s, f, w] = await Promise.all([
        fetchDashboardStats(),
        fetchThreatFeed(120),
        fetchEarlyWarning(),
      ]);
      setStats(s);
      setThreats(normalizeThreats(f?.threats || []));
      setWarning(w);
    }
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);

  const severityRows = useMemo(() => {
    const dist = stats?.threat_distribution || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    return [
      { label: 'Critical', value: dist.CRITICAL || 0, color: 'critical' },
      { label: 'High', value: dist.HIGH || 0, color: 'orange' },
      { label: 'Medium', value: dist.MEDIUM || 0, color: 'green' },
      { label: 'Low', value: dist.LOW || 0, color: 'cyan' },
    ];
  }, [stats]);

  const sourceRows = useMemo(() => {
    const buckets = {};
    for (const t of threats) {
      buckets[t.source] = (buckets[t.source] || 0) + 1;
    }
    const top = Object.entries(buckets)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([label, value], i) => ({ label: label.slice(0, 14), value, color: i % 2 ? 'magenta' : 'cyan' }));
    return top;
  }, [threats]);

  const riskRows = useMemo(() => {
    const avgScore = threats.length ? Math.round(threats.reduce((s, t) => s + t.score, 0) / threats.length) : 0;
    const highRisk = threats.filter(t => t.score >= 65).length;
    const entityRich = threats.filter(t => t.entities >= 3).length;
    return [
      { label: 'Avg Score', value: avgScore, color: 'orange' },
      { label: 'High Risk', value: highRisk, color: 'critical' },
      { label: 'Entity Dense', value: entityRich, color: 'magenta' },
      { label: 'Total Signals', value: threats.length, color: 'cyan' },
    ];
  }, [threats]);

  const empty = threats.length === 0;
  const warningLevel = String(warning?.warning_level || 'LOW').toLowerCase();

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconActivity style={{ width: 14, height: 14, color: 'var(--cyan)' }} />
            Real-Time Threat Analytics
          </span>
          <span className="card-header-badge">{threats.length} records</span>
        </div>
        <div className="card-body">
          {empty ? (
            <div className="empty-state">
              No real data available for analytics yet. Ingest files/URLs or run Tor crawl.
            </div>
          ) : (
            <div className="dash-grid">
              <div className="glass-card">
                <div className="card-header"><span className="card-header-title"><IconBarChart style={{ width: 12, height: 12 }} /> Severity Distribution</span></div>
                <div className="card-body"><RealBarChart rows={severityRows} /></div>
              </div>
              <div className="glass-card">
                <div className="card-header"><span className="card-header-title"><IconBarChart style={{ width: 12, height: 12 }} /> Top Sources</span></div>
                <div className="card-body"><RealBarChart rows={sourceRows.length ? sourceRows : [{ label: 'No sources', value: 0, color: 'cyan' }]} /></div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconBarChart style={{ width: 14, height: 14, color: 'var(--magenta)' }} />
            Early Warning Indicators
          </span>
          <span className={`badge ${warningLevel}`}>{warning?.warning_level || 'LOW'}</span>
        </div>
        <div className="card-body">
          {warning?.summary ? <div style={{ marginBottom: 10, color: 'var(--text-secondary)', fontSize: '0.78rem' }}>{warning.summary}</div> : null}
          <RealBarChart rows={riskRows} />
          {(warning?.top_companies || []).length > 0 ? (
            <div style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {warning.top_companies.map((x, i) => (
                <span key={i} className="tag">{x.company} ({x.mentions})</span>
              ))}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

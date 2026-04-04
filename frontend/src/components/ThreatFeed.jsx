import { useState, useEffect } from 'react';
import { fetchThreatFeed } from '../api';
import { IconSearch, IconCopy, IconZap } from './Icons';
import { useToast } from './toast-context';
import { timeAgo } from '../utils/time';

const ALLOWED_FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function ThreatFeed({ initialSeverity }) {
  const [threats, setThreats] = useState(null);
  const [filter, setFilter] = useState(
    ALLOWED_FILTERS.includes(initialSeverity) ? initialSeverity : 'ALL',
  );
  const [search, setSearch] = useState('');
  const [onlyNew, setOnlyNew] = useState(true);
  const toast = useToast();
  const loading = threats === null;

  useEffect(() => {
    let cancelled = false;
    fetchThreatFeed(80, onlyNew, 240)
      .then(d => {
        if (!cancelled) setThreats(d.threats || []);
      })
      .catch(() => {
        if (!cancelled) setThreats([]);
      });
    return () => {
      cancelled = true;
    };
  }, [onlyNew]);

  const filtered = (threats || []).filter(t => {
    if (filter !== 'ALL' && t.severity !== filter) return false;
    if (search && !(t.content || '').toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const severityClass = (l) => (l || '').toLowerCase();
  const copyEntity = (e) => {
    navigator.clipboard.writeText(e).then(() => toast('Copied to clipboard', 'success'));
  };

  const filters = ALLOWED_FILTERS;

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconZap style={{ width: 14, height: 14, color: 'var(--cyan)' }} />
            Threat Intelligence Feed
          </span>
          <span className="card-header-badge">{filtered.length} entries</span>
        </div>
        <div className="card-body">
          {/* Controls */}
          <div className="feed-controls">
            <div className="search-input-wrap" style={{ flex: 1, maxWidth: 360 }}>
              <IconSearch />
              <input
                className="cyber-input"
                placeholder="Search threats..."
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <div className="filter-chips">
                <button
                  className={`cyber-btn ghost ${onlyNew ? 'active' : ''}`}
                  style={{ padding: '6px 12px', fontSize: '0.62rem' }}
                  onClick={() => {
                    setThreats(null);
                    setOnlyNew(v => !v);
                  }}
                >
                  {onlyNew ? 'NEW ONLY' : 'ALL UNIQUE'}
                </button>
              {filters.map(f => (
                <button
                  key={f}
                  className={`cyber-btn ghost ${filter === f ? 'active' : ''}`}
                  style={{ padding: '6px 12px', fontSize: '0.62rem' }}
                  onClick={() => setFilter(f)}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {/* Threat List */}
          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[1,2,3,4].map(i => <div key={i} className="skeleton" style={{ height: 90, borderRadius: 'var(--radius-sm)' }} />)}
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 48, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
              No real threats match your filter. Ingest data or run Tor crawl.
            </div>
          ) : (
            <div className="threat-list stagger-children">
              {filtered.map((t, i) => {
                const score = t.threat_score || t.score || 0;
                const entities = t.entities || [];
                return (
                  <div key={i} className={`threat-card glass-card ${severityClass(t.severity)}`}>
                    <div className="threat-card-head">
                      <span className={`badge ${severityClass(t.severity)}`}>{t.severity}</span>
                      <span className="threat-timestamp">{t.source || 'dark-web'} · {timeAgo(t.timestamp)}</span>
                    </div>
                    <div className="threat-card-body">
                      {t.content || t.text || 'Threat record'}
                    </div>
                    <div className="threat-card-meta">
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        {t.is_new ? <span className="badge low">NEW</span> : null}
                        {(t.occurrences || 1) > 1 ? <span className="badge medium">Seen {t.occurrences}x</span> : null}
                      </div>
                      {/* Entities */}
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', flex: 1 }}>
                        {entities.slice(0, 4).map((e, j) => (
                          <span key={j} className="tag" onClick={() => copyEntity(typeof e === 'string' ? e : e.value || '')}>
                            {(typeof e === 'string' ? e : e.value || '').slice(0, 20)}
                            {(typeof e === 'string' ? e : e.value || '').length > 20 ? '...' : ''}
                          </span>
                        ))}
                      </div>
                      {/* Score bar */}
                      <div className="threat-score-bar">
                        <span className="threat-score-label">{score}/100</span>
                        <div className="progress-bar" style={{ flex: 1 }}>
                          <div
                            className={`fill ${score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low'}`}
                            style={{ width: `${score}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

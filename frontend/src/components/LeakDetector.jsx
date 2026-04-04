import { useState, useEffect } from 'react';
import { scanLeaks, runAutoCorrelation } from '../api';
import { useToast } from './toast-context';
import { IconSearch, IconTrash, IconDatabase, IconLock, IconKey, IconCreditCard, IconCopy } from './Icons';

export default function LeakDetector() {
  const [input, setInput] = useState('');
  const [results, setResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [correlationResults, setCorrelationResults] = useState(null);
  const toast = useToast();

  const doScan = async () => {
    const text = input.trim();
    if (!text) {
      toast('Paste real suspicious content to scan', 'info');
      return;
    }
    setScanning(true);
    setResults(null);
    setCorrelationResults(null);
    try {
      const data = await scanLeaks(text);
      setResults(data);
      toast('Scan complete — ' + (data.total_findings || 0) + ' items found', data.total_findings > 0 ? 'error' : 'success');
    } catch {
      toast('Scan failed — backend offline', 'error');
    } finally {
      setScanning(false);
    }
  };

  const doFullAnalysis = async () => {
    const text = input.trim();
    if (!text) {
      toast('Paste content to run full analysis', 'info');
      return;
    }
    setCorrelating(true);
    setCorrelationResults(null);
    try {
      const [data, leakView] = await Promise.all([
        runAutoCorrelation(text),
        scanLeaks(text),
      ]);
      setCorrelationResults(data);
      setResults(leakView);
      
      const alertCount = data.alerts?.total_alerts || 0;
      const corrCount = data.correlation?.total_correlations || 0;
      toast(
        `Full Analysis: ${data.total_leaks_detected} leaks, ${corrCount} correlations, ${alertCount} alerts`,
        data.input_severity === 'CRITICAL' ? 'error' : 'success',
      );
    } catch {
      toast('Full analysis failed — backend offline', 'error');
    } finally {
      setCorrelating(false);
    }
  };

  const summary = results ? [
    { label: 'Credentials', count: results.credentials?.length || 0, icon: '🔒' },
    { label: 'Financial', count: results.financial?.length || 0, icon: '💳' },
    { label: 'API Keys', count: results.api_keys?.length || 0, icon: '🗝️' },
    { label: 'Crypto', count: results.crypto_wallets?.length || 0, icon: '₿' },
  ] : [];

  const allFindings = results ? [
    ...(results.credentials || []).map(f => ({ ...f, category: 'CREDENTIAL', icon: '🔑' })),
    ...(results.financial || []).map(f => ({ ...f, category: 'FINANCIAL', icon: '💳' })),
    ...(results.api_keys || []).map(f => ({ ...f, category: 'API KEY', icon: '🗝️' })),
    ...(results.crypto_wallets || []).map(f => ({ ...f, category: 'CRYPTO', icon: '₿' })),
  ] : [];

  const copyValue = (val) => {
    navigator.clipboard.writeText(val).then(() => toast('Copied (masked)', 'success'));
  };

  const getSeverityClass = (s) => {
    if (!s) return '';
    const l = s.toLowerCase();
    if (l === 'critical') return 'critical';
    if (l === 'high') return 'high';
    return '';
  };

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconSearch style={{ width: 14, height: 14, color: 'var(--cyan)' }} />
            Leak Detection Engine
          </span>
          <span className="card-header-badge">v1.0</span>
        </div>
        <div className="card-body">
          {/* Input */}
          <textarea
            className="cyber-input"
            style={{ minHeight: 180 }}
            placeholder={'Paste suspicious content here...\nSupports: credentials, credit cards, API keys, crypto wallets, SSN, database URLs'}
            value={input}
            onChange={e => setInput(e.target.value)}
          />

          {/* Action buttons */}
          <div className="leak-action-bar">
            <button className="cyber-btn primary" onClick={doScan} disabled={scanning || correlating}>
              {scanning ? (
                <><span className="spinner" /> Scanning...</>
              ) : (
                <><IconSearch style={{ width: 14, height: 14 }} /> Scan for Leaks</>
              )}
            </button>
            <button className="cyber-btn accent" onClick={doFullAnalysis} disabled={scanning || correlating}>
              {correlating ? (
                <><span className="spinner" /> Analyzing...</>
              ) : (
                <><IconCorrelate style={{ width: 14, height: 14 }} /> Run Full Analysis</>
              )}
            </button>
            <button className="cyber-btn outline" onClick={() => { setInput(''); setResults(null); setCorrelationResults(null); }}>
              <IconTrash style={{ width: 14, height: 14 }} /> Clear
            </button>
          </div>
        </div>
      </div>

      {/* Correlation Results */}
      {correlationResults && (
        <div className="glass-card anim-fade-up" style={{ borderLeft: '3px solid var(--cyan)' }}>
          <div className="card-header">
            <span className="card-header-title" style={{ color: 'var(--cyan)' }}>
              <IconCorrelate style={{ width: 14, height: 14 }} />
              Full Analysis Pipeline
            </span>
            <span className="card-header-badge">{correlationResults.auto_ingested ? 'Auto-Ingested' : 'Analyzed'}</span>
          </div>
          <div className="card-body">
            {/* Pipeline Summary */}
            <div className="dash-grid-4 stagger-children" style={{ marginBottom: 20 }}>
              <div className="leak-summary-item">
                <div className="num" style={{ color: 'var(--critical)' }}>{correlationResults.total_leaks_detected || 0}</div>
                <div className="lbl">Leaks Found</div>
              </div>
              <div className="leak-summary-item">
                <div className="num" style={{ color: 'var(--high)' }}>{correlationResults.correlation?.total_correlations || 0}</div>
                <div className="lbl">Correlations</div>
              </div>
              <div className="leak-summary-item">
                <div className="num" style={{ color: 'var(--medium)' }}>{correlationResults.correlation?.high_confidence_signals || 0}</div>
                <div className="lbl">High Confidence</div>
              </div>
              <div className="leak-summary-item">
                <div className="num" style={{ color: 'var(--cyan)' }}>{correlationResults.alerts?.total_alerts || 0}</div>
                <div className="lbl">Alerts Generated</div>
              </div>
            </div>

            {/* Correlation Signals */}
            {correlationResults.correlation?.signals?.length > 0 && (
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: 10 }}>
                  Correlation Signals
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {correlationResults.correlation.signals.slice(0, 5).map((sig, i) => (
                    <div key={i} style={{
                      padding: '10px 14px', borderRadius: 'var(--radius-sm)',
                      background: 'rgba(0,240,255,0.05)', borderLeft: '2px solid var(--cyan)',
                      fontSize: '0.8rem',
                    }}>
                      <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: 4 }}>
                        {sig.entity || sig.type || 'Signal'} 
                        <span style={{ color: 'var(--text-dim)', fontWeight: 400, marginLeft: 8 }}>
                          Confidence: {sig.confidence || sig.score || '—'}%
                        </span>
                      </div>
                      {sig.sources && (
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                          Sources: {sig.sources.join(', ')}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Alerts Preview */}
            {correlationResults.alerts?.top_alerts?.length > 0 && (
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: 10 }}>
                  Top Alerts
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {correlationResults.alerts.top_alerts.slice(0, 3).map((alert, i) => (
                    <div key={i} style={{
                      padding: '10px 14px', borderRadius: 'var(--radius-sm)',
                      background: alert.priority === 'CRITICAL' ? 'rgba(255,0,64,0.08)' : 'rgba(255,107,0,0.05)',
                      borderLeft: `2px solid var(--${(alert.priority || 'medium').toLowerCase()})`,
                      fontSize: '0.8rem',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span className={`badge ${(alert.priority || 'medium').toLowerCase()}`}>{alert.priority}</span>
                        <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{alert.type || 'Alert'}</span>
                      </div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                        {alert.description || alert.summary || 'Threat detected'}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Correlation Summary */}
            {correlationResults.correlation?.summary && (
              <div style={{ padding: '10px 14px', borderRadius: 'var(--radius-sm)', background: 'rgba(0,240,255,0.03)', fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {correlationResults.correlation.summary}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="glass-card anim-fade-up">
          <div className="card-header">
            <span className="card-header-title" style={{ color: results.total_findings > 0 ? 'var(--critical)' : 'var(--low)' }}>
              <IconAlert style={{ width: 14, height: 14 }} />
              {results.overall_severity || 'LOW'} SEVERITY
            </span>
            <span className="card-header-badge">Found: {results.total_findings || 0} items</span>
          </div>
          <div className="card-body">
            {/* Summary grid */}
            <div className="leak-summary-grid stagger-children">
              {summary.map((s, i) => (
                <SummaryItem key={i} count={s.count} label={s.label} icon={s.icon} delay={i * 100} />
              ))}
            </div>

            {/* Findings list */}
            <div style={{ fontFamily: 'var(--font-display)', fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: 12 }}>
              Detected Items
            </div>
            <div className="leak-findings stagger-children">
              {allFindings.map((f, i) => (
                <div key={i} className={`leak-item glass-card ${getSeverityClass(f.severity)}`}>
                  <div className="leak-item-head">
                    <span className="leak-item-type" style={{ color: f.severity === 'CRITICAL' ? 'var(--critical)' : f.severity === 'HIGH' ? 'var(--high)' : 'var(--text-primary)' }}>
                      {f.icon} {f.category} — {f.type || f.card_type || 'detected'}
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className={`badge ${getSeverityClass(f.severity)}`}>{f.severity}</span>
                      <button className="cyber-btn ghost" style={{ padding: '4px 8px' }} onClick={() => copyValue(f.masked_value || f.value || '')}>
                        <IconCopy style={{ width: 12, height: 12 }} />
                      </button>
                    </div>
                  </div>
                  <div className="leak-item-value">{f.masked_value || f.value || '***'}</div>
                  {f.context && <div className="leak-item-context">Context: "{f.context}"</div>}
                  {f.luhn_valid !== undefined && (
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: f.luhn_valid ? 'var(--low)' : 'var(--text-dim)', marginTop: 4 }}>
                      Luhn: {f.luhn_valid ? '✓ Valid' : '✗ Invalid'}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Impact Estimation */}
            {results.impact && (
              <div style={{ marginTop: 24 }}>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: '0.65rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: 12 }}>
                  Impact Estimation
                </div>
                <div className="dash-grid-3 stagger-children">
                  <div className="leak-summary-item">
                    <div className="num" style={{ color: 'var(--critical)' }}>{results.impact.estimated_affected_users || '—'}</div>
                    <div className="lbl">Affected Users</div>
                  </div>
                  <div className="leak-summary-item">
                    <div className="num" style={{ color: 'var(--high)' }}>{results.impact.business_risk || '—'}</div>
                    <div className="lbl">Business Risk</div>
                  </div>
                  <div className="leak-summary-item">
                    <div className="num" style={{ color: 'var(--medium)' }}>{results.impact.risk_score || '—'}</div>
                    <div className="lbl">Risk Score</div>
                  </div>
                </div>
                
                {/* Financial Exposure */}
                {results.impact.financial_exposure && (
                  <div style={{ marginTop: 14, padding: '12px 16px', borderRadius: 'var(--radius-sm)', background: 'rgba(255,107,0,0.05)', borderLeft: '3px solid var(--high)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: 4 }}>FINANCIAL EXPOSURE</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--high)' }}>{results.impact.financial_exposure}</div>
                  </div>
                )}
                
                {/* Data Types Exposed */}
                {results.impact.data_types && results.impact.data_types.length > 0 && (
                  <div style={{ marginTop: 14 }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: 8 }}>DATA TYPES EXPOSED</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {results.impact.data_types.map((dt, i) => (
                        <span key={i} className="tag" style={{ background: 'rgba(255,0,64,0.1)', color: 'var(--critical)' }}>{dt}</span>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Impact Summary */}
                {results.impact.summary && (
                  <div style={{ marginTop: 14, padding: '10px 14px', borderRadius: 'var(--radius-sm)', background: 'rgba(0,240,255,0.03)', fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {results.impact.summary}
                  </div>
                )}
                
                {results.impact.recommendations && results.impact.recommendations.length > 0 && (
                  <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: 4 }}>RECOMMENDATIONS</div>
                    {results.impact.recommendations.map((r, i) => (
                      <div key={i} style={{
                        padding: '10px 14px', borderRadius: 'var(--radius-sm)',
                        background: 'rgba(255,0,64,0.03)', borderLeft: '2px solid var(--critical)',
                        fontSize: '0.78rem', color: 'var(--text-primary)',
                      }}>
                        ⚠ {r}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryItem({ count, label, icon, delay }) {
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    if (!count) return;
    const timer = setTimeout(() => {
      const start = performance.now();
      const step = (now) => {
        const progress = Math.min((now - start) / 800, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        setDisplay(Math.floor(eased * count));
        if (progress < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }, delay || 0);
    return () => clearTimeout(timer);
  }, [count, delay]);

  return (
    <div className="leak-summary-item">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
        <span style={{ color: 'var(--cyan)', fontSize: '0.9rem' }}>{icon}</span>
        <span className="num">{display}</span>
      </div>
      <div className="lbl">{label}</div>
    </div>
  );
}

function IconAlert(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  );
}

function IconCorrelate(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <circle cx="5" cy="6" r="3"/><circle cx="19" cy="6" r="3"/><circle cx="12" cy="18" r="3"/>
      <line x1="5" y1="9" x2="12" y2="15"/><line x1="19" y1="9" x2="12" y2="15"/>
    </svg>
  );
}

/* Spinner */
const style = document.createElement('style');
style.textContent = `.spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.2);border-top-color:currentColor;border-radius:50%;animation:spin 0.7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}`;
if (typeof document !== 'undefined' && !document.querySelector('#leak-spinner-style')) {
  style.id = 'leak-spinner-style';
  document.head.appendChild(style);
}

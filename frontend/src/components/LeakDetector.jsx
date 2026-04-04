import { useState, useEffect } from 'react';
import { scanLeaks } from '../api';
import { useToast } from './Toast';
import { IconSearch, IconTrash, IconDatabase, IconLock, IconKey, IconCreditCard, IconCopy } from './Icons';
import { useCountUp } from '../hooks/useCountUp';

const SAMPLE_TEXT = `Found this dump on darknet marketplace:
admin@techcorp.com:AdminPass123
john.doe@company.org|SecretKey456
support@acme.io:Welcome2024!

Payment info leaked:
4532-1234-5678-9010 CVV: 123 Exp: 12/25
4111111111111111 CVV: 999

Cloud keys exposed:
AKIAIOSFODNN7EXAMPLE
AKIA5EXAMPLE9KEYHERE

Crypto wallets:
0x742d35Cc6634C0532925a3b844Bc454e4438f44e
bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq

SSN found: 078-05-1120`;

export default function LeakDetector() {
  const [input, setInput] = useState('');
  const [results, setResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const toast = useToast();

  const doScan = async () => {
    const text = input.trim() || SAMPLE_TEXT;
    if (!input.trim()) setInput(SAMPLE_TEXT);
    setScanning(true);
    setResults(null);
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

  const summary = results ? [
    { label: 'Credentials', count: results.credentials?.length || 0, icon: IconLock },
    { label: 'Financial', count: results.financial?.length || 0, icon: IconCreditCard },
    { label: 'API Keys', count: results.api_keys?.length || 0, icon: IconKey },
    { label: 'Crypto', count: results.crypto_wallets?.length || 0, icon: IconDatabase },
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
            <button className="cyber-btn primary" onClick={doScan} disabled={scanning}>
              {scanning ? (
                <><span className="spinner" /> Scanning...</>
              ) : (
                <><IconSearch style={{ width: 14, height: 14 }} /> Scan for Leaks</>
              )}
            </button>
            <button className="cyber-btn outline" onClick={() => { setInput(''); setResults(null); }}>
              <IconTrash style={{ width: 14, height: 14 }} /> Clear
            </button>
            <button className="cyber-btn ghost" onClick={() => setInput(SAMPLE_TEXT)}>
              Load Sample
            </button>
          </div>
        </div>
      </div>

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
                <SummaryItem key={i} count={s.count} label={s.label} Icon={s.icon} delay={i * 100} />
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
                    <div className="num" style={{ color: 'var(--medium)' }}>{(results.impact.data_types || []).length || '—'}</div>
                    <div className="lbl">Data Types</div>
                  </div>
                </div>
                {results.impact.recommendations && results.impact.recommendations.length > 0 && (
                  <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 6 }}>
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

function SummaryItem({ count, label, Icon, delay }) {
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
        <Icon style={{ width: 14, height: 14, color: 'var(--cyan)' }} />
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

/* Spinner */
const style = document.createElement('style');
style.textContent = `.spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.2);border-top-color:currentColor;border-radius:50%;animation:spin 0.7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}`;
if (typeof document !== 'undefined' && !document.querySelector('#leak-spinner-style')) {
  style.id = 'leak-spinner-style';
  document.head.appendChild(style);
}

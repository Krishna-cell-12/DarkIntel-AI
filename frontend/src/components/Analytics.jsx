import { useState, useEffect, useRef, Fragment } from 'react';
import { IconBarChart, IconActivity } from './Icons';

/* ── Animated SVG Line Chart ────────────────────────────────── */
function ThreatTrendLine() {
  const data = [12, 18, 9, 24, 31, 15, 22, 38, 28, 42, 35, 19, 27, 45, 33, 50, 44, 29, 37, 52, 48, 56, 41, 60];
  const max = Math.max(...data);
  const w = 580, h = 160;
  const step = w / (data.length - 1);
  const points = data.map((v, i) => `${i * step},${h - (v / max) * (h - 20) - 10}`).join(' ');
  const pathD = data.map((v, i) => `${i === 0 ? 'M' : 'L'} ${i * step} ${h - (v / max) * (h - 20) - 10}`).join(' ');
  const areaD = pathD + ` L ${w} ${h} L 0 ${h} Z`;
  const ref = useRef(null);
  const [drawn, setDrawn] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setDrawn(true), 200);
    return () => clearTimeout(t);
  }, []);

  return (
    <svg width="100%" height="180" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: 'block' }}>
      {/* Grid lines */}
      {[0.25, 0.5, 0.75].map(pct => (
        <line key={pct} x1="0" y1={h * pct} x2={w} y2={h * pct} stroke="rgba(0,240,255,0.04)" strokeWidth="0.5" />
      ))}
      {/* Area fill */}
      <path d={areaD} fill="url(#areaGrad)" opacity={drawn ? 0.2 : 0} style={{ transition: 'opacity 1.5s ease' }} />
      {/* Line */}
      <polyline
        ref={ref}
        points={points}
        fill="none" stroke="var(--cyan)" strokeWidth="2"
        strokeLinecap="round" strokeLinejoin="round"
        strokeDasharray={drawn ? 'none' : '2000'}
        strokeDashoffset={drawn ? '0' : '2000'}
        style={{ transition: 'stroke-dashoffset 2s ease', filter: 'drop-shadow(0 0 4px rgba(0,240,255,0.5))' }}
      />
      {/* Dots */}
      {drawn && data.map((v, i) => (
        <circle key={i} cx={i * step} cy={h - (v / max) * (h - 20) - 10} r="2.5"
          fill="var(--cyan)" opacity="0.7"
          style={{ animation: `fadeIn 0.3s ease ${i * 0.05}s forwards`, opacity: 0 }}
        />
      ))}
      <defs>
        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--cyan)" stopOpacity="0.3" />
          <stop offset="100%" stopColor="var(--cyan)" stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  );
}

/* ── Bar Chart ──────────────────────────────────────────────── */
function HorizontalBarChart({ data }) {
  const max = Math.max(...data.map(d => d.value));
  const [animated, setAnimated] = useState(false);
  useEffect(() => { const t = setTimeout(() => setAnimated(true), 300); return () => clearTimeout(t); }, []);

  return (
    <div className="bar-chart">
      {data.map((item, i) => (
        <div className="bar-row" key={i}>
          <span className="bar-label">{item.label}</span>
          <div className="bar-track">
            <div className={`bar-fill ${item.color}`} style={{ width: animated ? `${(item.value / max) * 100}%` : '0%' }} />
          </div>
          <span className="bar-value">{item.value}</span>
        </div>
      ))}
    </div>
  );
}

/* ── Heatmap ────────────────────────────────────────────────── */
function SeverityHeatmap() {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const hours = ['00', '04', '08', '12', '16', '20'];
  // Stable heat values for demo
  const heatData = [
    [3, 1, 5, 8, 6, 2],
    [2, 4, 7, 9, 5, 1],
    [1, 3, 6, 7, 8, 3],
    [5, 2, 4, 6, 9, 4],
    [4, 6, 8, 5, 3, 2],
    [0, 1, 2, 3, 1, 0],
    [1, 0, 1, 2, 1, 0],
  ];

  const getColor = (val) => {
    if (val >= 8) return 'rgba(255,0,64,0.6)';
    if (val >= 6) return 'rgba(255,107,0,0.5)';
    if (val >= 4) return 'rgba(255,214,0,0.3)';
    if (val >= 2) return 'rgba(0,240,255,0.15)';
    return 'rgba(255,255,255,0.03)';
  };

  return (
    <div style={{ overflowX: 'auto' }}>
      <div style={{ display: 'grid', gridTemplateColumns: `50px repeat(${hours.length}, 1fr)`, gap: 3 }}>
        {/* Header */}
        <div />
        {hours.map(h => (
          <div key={h} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.58rem', color: 'var(--text-dim)', textAlign: 'center', paddingBottom: 4 }}>{h}:00</div>
        ))}

        {/* Rows */}
        {days.map((day, di) => (
          <Fragment key={di}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--text-dim)', display: 'flex', alignItems: 'center' }}>{day}</div>
            {hours.map((_, hi) => (
              <div
                key={`${di}-${hi}`}
                style={{
                  background: getColor(heatData[di][hi]),
                  borderRadius: 3,
                  height: 28,
                  transition: 'all 0.2s ease',
                  cursor: 'default',
                }}
                title={`${days[di]} ${hours[hi]}:00 — ${heatData[di][hi]} threats`}
                onMouseEnter={e => e.currentTarget.style.transform = 'scale(1.15)'}
                onMouseLeave={e => e.currentTarget.style.transform = 'scale(1)'}
              />
            ))}
          </Fragment>
        ))}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 10, justifyContent: 'flex-end' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.55rem', color: 'var(--text-dim)' }}>Low</span>
        {[0.03, 0.15, 0.3, 0.5, 0.6].map((op, i) => (
          <div key={i} style={{ width: 14, height: 14, borderRadius: 2, background: i < 2 ? `rgba(0,240,255,${op})` : i < 3 ? `rgba(255,214,0,${op})` : i < 4 ? `rgba(255,107,0,${op})` : `rgba(255,0,64,${op})` }} />
        ))}
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.55rem', color: 'var(--text-dim)' }}>High</span>
      </div>
    </div>
  );
}

/* ── Donut Ring ──────────────────────────────────────────────── */
function CategoryDonut() {
  const data = [
    { label: 'Data Breach', value: 35, color: '#FF0040' },
    { label: 'Credential Leak', value: 28, color: '#FF6B00' },
    { label: 'Ransomware', value: 18, color: '#FFD600' },
    { label: 'Phishing Kit', value: 12, color: '#00F0FF' },
    { label: 'Exploit Sale', value: 7, color: '#FF00E5' },
  ];
  const total = data.reduce((a, b) => a + b.value, 0);
  const r = 56, c = 2 * Math.PI * r;
  let offset = 0;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
      <svg width="140" height="140" viewBox="0 0 140 140">
        {data.map((seg, i) => {
          const pct = seg.value / total;
          const dashLen = c * pct;
          const dashOff = c * offset;
          offset += pct;
          return (
            <circle key={i} cx="70" cy="70" r={r} fill="none" stroke={seg.color} strokeWidth="12"
              strokeDasharray={`${dashLen} ${c - dashLen}`} strokeDashoffset={-dashOff}
              style={{ transformOrigin: 'center', transform: 'rotate(-90deg)', filter: `drop-shadow(0 0 3px ${seg.color}44)`, transition: 'all 1s ease' }}
            />
          );
        })}
        <text x="70" y="66" textAnchor="middle" fill="var(--text-primary)" fontFamily="var(--font-mono)" fontSize="18" fontWeight="700">{total}</text>
        <text x="70" y="82" textAnchor="middle" fill="var(--text-dim)" fontFamily="var(--font-mono)" fontSize="8" letterSpacing="1">TOTAL</text>
      </svg>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {data.map((seg, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.72rem' }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: seg.color }} />
            <span style={{ color: 'var(--text-secondary)', width: 100 }}>{seg.label}</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: seg.color, fontWeight: 600 }}>{seg.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Analytics ──────────────────────────────────────────────── */
export default function Analytics() {
  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Row 1 */}
      <div className="dash-grid">
        <div className="glass-card">
          <div className="card-header">
            <span className="card-header-title"><IconActivity style={{ width: 14, height: 14, color: 'var(--cyan)' }} /> Threat Trend (24h)</span>
          </div>
          <div className="card-body">
            <ThreatTrendLine />
          </div>
        </div>

        <div className="glass-card">
          <div className="card-header">
            <span className="card-header-title"><IconBarChart style={{ width: 14, height: 14, color: 'var(--magenta)' }} /> Top Categories</span>
          </div>
          <div className="card-body">
            <CategoryDonut />
          </div>
        </div>
      </div>

      {/* Row 2 */}
      <div className="dash-grid">
        <div className="glass-card">
          <div className="card-header">
            <span className="card-header-title"><IconBarChart style={{ width: 14, height: 14, color: 'var(--low)' }} /> Entity Type Distribution</span>
          </div>
          <div className="card-body">
            <HorizontalBarChart data={[
              { label: 'Emails', value: 142, color: 'cyan' },
              { label: 'Wallets', value: 89, color: 'magenta' },
              { label: 'IPs', value: 67, color: 'orange' },
              { label: 'Domains', value: 45, color: 'green' },
              { label: 'SSN/IDs', value: 23, color: 'cyan' },
            ]} />
          </div>
        </div>

        <div className="glass-card">
          <div className="card-header">
            <span className="card-header-title"><IconActivity style={{ width: 14, height: 14, color: 'var(--high)' }} /> Severity Heatmap (7-day)</span>
          </div>
          <div className="card-body">
            <SeverityHeatmap />
          </div>
        </div>
      </div>

      {/* Row 3 — full width */}
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title"><IconBarChart style={{ width: 14, height: 14, color: 'var(--cyan)' }} /> Module Performance</span>
        </div>
        <div className="card-body">
          <HorizontalBarChart data={[
            { label: 'NLP Engine', value: 97, color: 'cyan' },
            { label: 'Leak Detect', value: 94, color: 'green' },
            { label: 'Slang Decode', value: 91, color: 'magenta' },
            { label: 'Identity Link', value: 88, color: 'orange' },
            { label: 'Impact Est.', value: 85, color: 'cyan' },
          ]} />
        </div>
      </div>
    </div>
  );
}

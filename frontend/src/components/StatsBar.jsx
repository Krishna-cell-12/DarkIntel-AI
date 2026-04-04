import { useCountUp } from '../hooks/useCountUp';
import { IconTarget, IconAlert, IconZap, IconDatabase, IconActivity } from './Icons';

function StatCard({ icon, iconClass, value, label, pulse, onClick }) {
  const safeValue = Math.max(0, Number(value) || 0);
  const display = useCountUp(safeValue, 1200);

  return (
    <div
      className={`stat-card glass-card ${pulse ? 'critical-pulse' : ''} ${onClick ? 'clickable' : ''}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={e => {
        if (onClick && (e.key === 'Enter' || e.key === ' ')) onClick();
      }}
      title={onClick ? `Open threat feed: ${label}` : label}
    >
      <div className={`stat-icon ${iconClass}`}>
        {icon}
      </div>
      <div className="stat-info">
        <div className="stat-value">{display}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

export default function StatsBar({ stats, alertsReport, loading, onQuickFilter }) {
  if (loading) {
    return (
      <div className="stats-grid stagger-children">
        {[1, 2, 3, 4, 5].map(i => (
          <div key={i} className="stat-card glass-card">
            <div className="skeleton" style={{ width: 42, height: 42, borderRadius: 10 }} />
            <div style={{ flex: 1 }}>
              <div className="skeleton" style={{ height: 24, width: '55%', marginBottom: 8 }} />
              <div className="skeleton" style={{ height: 10, width: '75%' }} />
            </div>
          </div>
        ))}
      </div>
    );
  }

  const s = stats || {};
  const dist = s.threat_distribution || {};
  const alertDist = alertsReport?.distribution || {};
  const critCount = Math.max(Number(dist.CRITICAL || 0), Number(alertDist.CRITICAL || 0));
  const highCount = Math.max(Number(dist.HIGH || 0), Number(alertDist.HIGH || 0));

  return (
    <div className="stats-grid stagger-children">
      <StatCard
        icon={<IconTarget style={{ width: 20, height: 20 }} />}
        iconClass="cyan"
        value={s.total_threats_analyzed || 0}
        label="Threats Analyzed"
        onClick={() => onQuickFilter?.('ALL')}
      />
      <StatCard
        icon={<IconAlert style={{ width: 20, height: 20 }} />}
        iconClass="red"
        value={critCount}
        label="Critical Issues"
        pulse={critCount > 0}
        onClick={() => onQuickFilter?.('CRITICAL')}
      />
      <StatCard
        icon={<IconZap style={{ width: 20, height: 20 }} />}
        iconClass="orange"
        value={highCount}
        label="High Severity"
        onClick={() => onQuickFilter?.('HIGH')}
      />
      <StatCard
        icon={<IconDatabase style={{ width: 20, height: 20 }} />}
        iconClass="green"
        value={s.total_entities_extracted || 0}
        label="Entities Extracted"
      />
      <StatCard
        icon={<IconActivity style={{ width: 20, height: 20 }} />}
        iconClass="magenta"
        value={s.modules_active || 5}
        label="Active Modules"
      />
    </div>
  );
}

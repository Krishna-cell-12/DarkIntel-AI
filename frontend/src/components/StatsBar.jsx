import { useCountUp } from '../hooks/useCountUp';
import { IconTarget, IconAlert, IconZap, IconDatabase, IconActivity } from './Icons';

function StatCard({ icon: Icon, iconClass, value, label, pulse }) {
  const display = useCountUp(value, 1200);

  return (
    <div className={`stat-card glass-card ${pulse ? 'critical-pulse' : ''}`}>
      <div className={`stat-icon ${iconClass}`}>
        <Icon style={{ width: 20, height: 20 }} />
      </div>
      <div className="stat-info">
        <div className="stat-value">{display}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

export default function StatsBar({ stats }) {
  const s = stats || {};
  const dist = s.threat_distribution || {};
  const critCount = dist.CRITICAL || 0;
  const highCount = dist.HIGH || 0;

  return (
    <div className="stats-grid stagger-children">
      <StatCard icon={IconTarget} iconClass="cyan" value={s.total_threats_analyzed || 0} label="Threats Analyzed" />
      <StatCard icon={IconAlert} iconClass="red" value={critCount} label="Critical" pulse={critCount > 0} />
      <StatCard icon={IconZap} iconClass="orange" value={highCount} label="High Severity" />
      <StatCard icon={IconDatabase} iconClass="green" value={s.total_entities_extracted || 0} label="Entities Extracted" />
      <StatCard icon={IconActivity} iconClass="magenta" value={s.modules_active || 5} label="Active Modules" />
    </div>
  );
}

import { useMemo, useState } from 'react';
import { fetchRecentIngest, linkIdentities } from '../api';
import { IconLink, IconUser } from './Icons';
import { useToast } from './toast-context';

export default function IdentityLinker() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const toast = useToast();

  async function runLinking() {
    setLoading(true);
    try {
      const recent = await fetchRecentIngest(180);
      const posts = (recent.items || []).map((item, idx) => ({
        id: item.id || `post_${idx}`,
        content: item.text || '',
        platform: item.source || item.source_type || 'unknown',
      }));
      const linked = await linkIdentities(posts);
      setResult(linked);
      if ((linked?.identity_profiles || []).length === 0) {
        toast('No linked identities found in current dataset', 'info');
      } else {
        toast(`Linked ${linked.identity_profiles.length} identity profile(s)`, 'success');
      }
    } finally {
      setLoading(false);
    }
  }

  const topProfiles = useMemo(() => (result?.identity_profiles || []).slice(0, 10), [result]);

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconLink style={{ width: 14, height: 14, color: 'var(--cyan)' }} />
            Cross-Platform Identity Linking
          </span>
          <span className="card-header-badge">Brownie Point</span>
        </div>
        <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="empty-state">
            Builds actor profiles from real ingested/crawled records only.
          </div>
          <div>
            <button className="cyber-btn" onClick={runLinking} disabled={loading}>
              {loading ? 'Linking...' : 'Run Identity Linking'}
            </button>
          </div>
        </div>
      </div>

      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconUser style={{ width: 14, height: 14, color: 'var(--magenta)' }} />
            Linked Identity Profiles
          </span>
          <span className="card-header-badge">{result?.total_identities || 0} identities</span>
        </div>
        <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {!result ? (
            <div className="empty-state">Run identity linking to build profiles from real data.</div>
          ) : topProfiles.length === 0 ? (
            <div className="empty-state">No linked identities found in current real dataset.</div>
          ) : (
            topProfiles.map((p, i) => (
              <div key={i} className="company-evidence-item">
                <div className="company-evidence-head">
                  <span className={`badge ${String(p.risk_level || 'LOW').toLowerCase()}`}>{p.risk_level || 'LOW'}</span>
                  <span className="threat-timestamp">{p.identity_type} · {p.appearances} appearances</span>
                </div>
                <div className="company-evidence-body">{p.identity}</div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

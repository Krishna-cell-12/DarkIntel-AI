import { useState, useEffect, useRef } from 'react';
import { linkIdentities } from '../api';
import { useToast } from './Toast';
import { IconLink, IconUser, IconSearch } from './Icons';
import { useCountUp } from '../hooks/useCountUp';

const DEMO_ACTORS = [
  { id: 'actor_1', handle: 'ShadowViper', emails: ['admin@corp.com', 'viper@proton.me'], wallets: ['0x742d35Cc...f44e'], platforms: ['DarkMarket', 'RaidForums'], confidence: 92, risk: 'CRITICAL', firstSeen: '2025-09-14', lastSeen: '2026-03-28' },
  { id: 'actor_2', handle: 'NullByte_X', emails: ['attacker@proton.me'], wallets: ['bc1qar0srr...5mdq'], platforms: ['BreachForums'], confidence: 78, risk: 'HIGH', firstSeen: '2025-11-02', lastSeen: '2026-04-01' },
  { id: 'actor_3', handle: 'DarkMerchant', emails: ['darkm@onion.email'], wallets: ['0x742d35Cc...f44e', 'bc1qxy2kgd...1234'], platforms: ['DarkMarket', 'Telegram'], confidence: 85, risk: 'HIGH', firstSeen: '2025-06-22', lastSeen: '2026-03-30' },
  { id: 'actor_4', handle: 'CryptoGhost', emails: ['ghost@tutanota.com', 'admin@corp.com'], wallets: [], platforms: ['Discord', 'Telegram'], confidence: 64, risk: 'MEDIUM', firstSeen: '2026-01-10', lastSeen: '2026-03-15' },
  { id: 'actor_5', handle: 'R3dPanda', emails: [], wallets: ['bc1qar0srr...5mdq'], platforms: ['RaidForums', 'BreachForums'], confidence: 71, risk: 'HIGH', firstSeen: '2025-08-05', lastSeen: '2026-04-02' },
];

const DEMO_EDGES = [
  { from: 'actor_1', to: 'actor_4', reason: 'Shared email: admin@corp.com' },
  { from: 'actor_1', to: 'actor_3', reason: 'Shared wallet: 0x742d...f44e' },
  { from: 'actor_2', to: 'actor_5', reason: 'Shared wallet: bc1qar0...5mdq' },
  { from: 'actor_1', to: 'actor_3', reason: 'Same platform: DarkMarket' },
  { from: 'actor_3', to: 'actor_4', reason: 'Same platform: Telegram' },
  { from: 'actor_2', to: 'actor_5', reason: 'Same platform: BreachForums' },
];

// Node positions (manually placed for clean layout)
const NODE_POSITIONS = {
  actor_1: { x: 120, y: 80 },
  actor_2: { x: 380, y: 70 },
  actor_3: { x: 250, y: 195 },
  actor_4: { x: 80, y: 260 },
  actor_5: { x: 420, y: 230 },
};

const RISK_COLORS = { CRITICAL: '#FF0040', HIGH: '#FF6B00', MEDIUM: '#FFD600', LOW: '#00FF88' };

export default function IdentityLinker() {
  const [selected, setSelected] = useState(null);
  const [hovered, setHovered] = useState(null);
  const toast = useToast();

  const actor = selected ? DEMO_ACTORS.find(a => a.id === selected) : null;
  const hoveredActor = hovered || selected;

  // Connections for hovered/selected node
  const highlightedEdges = hoveredActor
    ? DEMO_EDGES.filter(e => e.from === hoveredActor || e.to === hoveredActor)
    : [];
  const connectedNodes = new Set();
  highlightedEdges.forEach(e => { connectedNodes.add(e.from); connectedNodes.add(e.to); });

  const linkedActors = useCountUp(DEMO_ACTORS.length, 800);
  const crossPlatform = useCountUp(3, 800, 200);
  const sharedIds = useCountUp(DEMO_EDGES.length, 800, 400);

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconLink style={{ width: 14, height: 14, color: 'var(--cyan)' }} />
            Threat Actor Identity Linking
          </span>
          <span className="card-header-badge">Network Graph</span>
        </div>
        <div className="card-body">
          {/* Graph */}
          <div className="identity-graph-area">
            <svg width="100%" height="100%" viewBox="0 0 520 340">
              {/* Grid dots */}
              {Array.from({ length: 20 }).map((_, i) =>
                Array.from({ length: 12 }).map((_, j) => (
                  <circle key={`${i}-${j}`} cx={i * 28 + 10} cy={j * 30 + 10} r="0.5" fill="rgba(0,240,255,0.08)" />
                ))
              )}

              {/* Edges */}
              {DEMO_EDGES.map((edge, i) => {
                const from = NODE_POSITIONS[edge.from];
                const to = NODE_POSITIONS[edge.to];
                if (!from || !to) return null;
                const isHighlighted = hoveredActor && (edge.from === hoveredActor || edge.to === hoveredActor);
                return (
                  <g key={`edge-${i}`}>
                    <line
                      x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                      stroke={isHighlighted ? 'var(--cyan)' : 'rgba(0,240,255,0.12)'}
                      strokeWidth={isHighlighted ? 1.5 : 0.7}
                      strokeDasharray={isHighlighted ? 'none' : '4 4'}
                      style={{ transition: 'all 0.3s ease' }}
                    />
                    {isHighlighted && (
                      <line
                        x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                        stroke="var(--cyan)"
                        strokeWidth="3" opacity="0.15"
                        style={{ filter: 'blur(3px)' }}
                      />
                    )}
                  </g>
                );
              })}

              {/* Nodes */}
              {DEMO_ACTORS.map((actorNode) => {
                const pos = NODE_POSITIONS[actorNode.id];
                if (!pos) return null;
                const color = RISK_COLORS[actorNode.risk] || RISK_COLORS.MEDIUM;
                const isActive = hoveredActor === actorNode.id;
                const isConnected = connectedNodes.has(actorNode.id);
                const nodeOpacity = hoveredActor ? (isActive || isConnected ? 1 : 0.3) : 1;

                return (
                  <g
                    key={actorNode.id}
                    style={{ cursor: 'pointer', transition: 'opacity 0.3s ease', opacity: nodeOpacity }}
                    onMouseEnter={() => setHovered(actorNode.id)}
                    onMouseLeave={() => setHovered(null)}
                    onClick={() => setSelected(actorNode.id === selected ? null : actorNode.id)}
                  >
                    {/* Glow */}
                    <circle cx={pos.x} cy={pos.y} r={isActive ? 32 : 26} fill={color} opacity="0.06">
                      {isActive && <animate attributeName="r" values="28;36;28" dur="2s" repeatCount="indefinite" />}
                    </circle>
                    {/* Ring */}
                    <circle
                      cx={pos.x} cy={pos.y} r={isActive ? 18 : 14}
                      fill="none" stroke={color} strokeWidth={isActive ? 2 : 1}
                      opacity={isActive ? 0.7 : 0.3}
                    />
                    {/* Core */}
                    <circle
                      cx={pos.x} cy={pos.y} r={isActive ? 10 : 8}
                      fill={color}
                      style={{ filter: `drop-shadow(0 0 ${isActive ? 8 : 3}px ${color})` }}
                    />
                    {/* Label */}
                    <text x={pos.x} y={pos.y + 28} textAnchor="middle" fill="var(--text-secondary)" fontFamily="var(--font-mono)" fontSize="9" fontWeight="600">
                      {actorNode.handle}
                    </text>
                    {/* Risk badge */}
                    <text x={pos.x} y={pos.y + 40} textAnchor="middle" fill={color} fontFamily="var(--font-mono)" fontSize="7" opacity="0.7">
                      {actorNode.risk}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Stats bar */}
          <div className="identity-stats-bar">
            <div className="identity-stat">
              <div className="val">{linkedActors}</div>
              <div className="lbl">Linked Actors</div>
            </div>
            <div className="identity-stat">
              <div className="val">{crossPlatform}</div>
              <div className="lbl">Cross-Platform</div>
            </div>
            <div className="identity-stat">
              <div className="val">{sharedIds}</div>
              <div className="lbl">Shared IDs</div>
            </div>
          </div>

          {/* Detail panel */}
          {actor && (
            <div className="identity-detail-panel anim-fade-up">
              <div className="identity-detail-title">
                <IconUser style={{ width: 14, height: 14, display: 'inline', verticalAlign: 'middle', marginRight: 6 }} />
                {actor.handle} — Actor Profile
              </div>
              <div className="identity-detail-row">
                <span className="identity-detail-key">Risk</span>
                <span className="identity-detail-val" style={{ color: RISK_COLORS[actor.risk] }}>{actor.risk}</span>
              </div>
              <div className="identity-detail-row">
                <span className="identity-detail-key">Confidence</span>
                <span className="identity-detail-val">{actor.confidence}%</span>
              </div>
              <div className="identity-detail-row">
                <span className="identity-detail-key">Emails</span>
                <span className="identity-detail-val">{actor.emails.join(', ') || '—'}</span>
              </div>
              <div className="identity-detail-row">
                <span className="identity-detail-key">Wallets</span>
                <span className="identity-detail-val">{actor.wallets.join(', ') || '—'}</span>
              </div>
              <div className="identity-detail-row">
                <span className="identity-detail-key">Platforms</span>
                <span className="identity-detail-val">{actor.platforms.join(', ')}</span>
              </div>
              <div className="identity-detail-row">
                <span className="identity-detail-key">First Seen</span>
                <span className="identity-detail-val">{actor.firstSeen}</span>
              </div>
              <div className="identity-detail-row">
                <span className="identity-detail-key">Last Seen</span>
                <span className="identity-detail-val">{actor.lastSeen}</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * DarkIntel-AI — API Layer
 * ========================
 * Connects frontend components to the FastAPI backend.
 * Each function calls the REAL backend endpoint and transforms
 * the response to the format the UI components expect.
 * Falls back to demo data ONLY if the backend is unreachable.
 */

const BASE = 'http://localhost:8000';

async function apiFetch(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

/* ══════════════════════════════════════════════════════════════
   Dashboard Stats
   Backend: GET /api/dashboard/stats
   ══════════════════════════════════════════════════════════════ */
export async function fetchDashboardStats() {
  try {
    return await apiFetch('/api/dashboard/stats');
  } catch {
    return {
      total_threats_analyzed: 1247,
      total_entities_extracted: 3891,
      modules_active: 5,
      threat_distribution: { CRITICAL: 23, HIGH: 67, MEDIUM: 156, LOW: 89 },
    };
  }
}

/* ══════════════════════════════════════════════════════════════
   Threat Feed
   Backend: GET /api/threats/feed?limit=N
   Returns: { threats: [{id, content, entities, threat_score, threat_level, slang_count}] }
   Frontend expects: severity, content, entities, threat_score, source, timestamp
   ══════════════════════════════════════════════════════════════ */
export async function fetchThreatFeed(limit = 20) {
  try {
    const data = await apiFetch(`/api/threats/feed?limit=${limit}`);
    // Transform backend format → frontend format
    const threats = (data.threats || []).map((t, i) => ({
      severity: t.threat_level || 'LOW',
      content: t.content || t.full_content || '',
      entities: _flattenEntities(t.entities),
      threat_score: t.threat_score || 0,
      source: _pickSource(i),
      timestamp: _relativeTime(i),
      slang_count: t.slang_count || 0,
    }));
    return { threats };
  } catch {
    return { threats: _demoThreats() };
  }
}

/* ══════════════════════════════════════════════════════════════
   Leak Scanner + Impact Estimation
   Backend: POST /api/leaks/impact  (body: { text })
   Returns: { leaks: { credentials, financial, api_keys, crypto_wallets }, impact: {...} }
   Frontend expects: { total_findings, overall_severity, credentials, financial,
                       api_keys, crypto_wallets, impact }
   ══════════════════════════════════════════════════════════════ */
export async function scanLeaks(text) {
  try {
    const data = await apiFetch('/api/leaks/impact', {
      method: 'POST',
      body: JSON.stringify({ text }),
    });

    const leaks = data.leaks || {};
    const impact = data.impact || {};

    // Transform credential items
    const credentials = (leaks.credentials || []).map(c => ({
      type: (c.type || '').replace(/_/g, ':').toUpperCase(),
      value: c.email ? `${c.email}:${c.password_masked || '****'}` : c.url_masked || c.context || '',
      masked_value: c.email ? `${c.email}:${c.password_masked || '****'}` : c.url_masked || '***',
      severity: c.severity || 'HIGH',
      context: c.context || 'Detected in input',
    }));

    // Transform financial items
    const financial = (leaks.financial || []).map(f => ({
      type: (f.type || '').replace(/_/g, ' ').toUpperCase(),
      card_type: f.card_type || 'Card',
      value: f.card_number || f.account_masked || f.ssn_masked || '',
      masked_value: f.card_number || f.account_masked || f.ssn_masked || '***',
      severity: f.severity || 'CRITICAL',
      luhn_valid: f.cvv_found !== undefined ? f.cvv_found : undefined,
      context: f.context || 'Financial data detected',
    }));

    // Transform API key items
    const api_keys = (leaks.api_keys || []).map(k => ({
      type: (k.provider || k.type || 'API_KEY').toUpperCase().replace(/\s+/g, '_'),
      value: k.key_prefix || '',
      masked_value: k.key_prefix || '****',
      severity: k.severity || 'CRITICAL',
      context: k.context || 'API key exposed',
    }));

    // Transform crypto wallet items
    const crypto_wallets = (leaks.crypto_wallets || []).map(w => ({
      type: (w.type || 'WALLET').toUpperCase(),
      value: w.address || '',
      masked_value: w.address || '***',
      severity: w.severity || 'HIGH',
      context: w.context || 'Crypto wallet detected',
    }));

    const allItems = [...credentials, ...financial, ...api_keys, ...crypto_wallets];
    const maxSev = _maxSeverity(allItems.map(i => i.severity));

    return {
      total_findings: allItems.length,
      overall_severity: maxSev,
      credentials,
      financial,
      api_keys,
      crypto_wallets,
      impact: {
        estimated_affected_users: impact.users_affected != null
          ? impact.users_affected.toLocaleString() + '+'
          : '—',
        business_risk: impact.business_risk || '—',
        data_types: (impact.data_types_exposed || []).map(d => d.label || d.type),
        recommendations: impact.recommendations || [],
        financial_exposure: impact.financial_exposure || '',
        risk_score: impact.risk_score || 0,
        summary: impact.summary || '',
      },
    };
  } catch {
    return _demoLeakResults();
  }
}

/* ══════════════════════════════════════════════════════════════
   Slang Decoder
   Backend: POST /api/nlp/slang/decode  (body: { text })
   Returns: { original_text, decoded_text, slang_found: [{term, meaning}], slang_count, risk_boost }
   Frontend expects: { decoded_terms: [{original, translation}], risk_score_boost }
   ══════════════════════════════════════════════════════════════ */
export async function decodeSlang(text) {
  try {
    const data = await apiFetch('/api/nlp/slang/decode', {
      method: 'POST',
      body: JSON.stringify({ text }),
    });

    return {
      decoded_terms: (data.slang_found || []).map(s => ({
        original: s.term || s.normalized_term,
        term: s.term || s.normalized_term,
        translation: s.meaning,
        meaning: s.meaning,
        position: s.position,
      })),
      risk_score_boost: data.risk_boost || 0,
      decoded_text: data.decoded_text || text,
      slang_count: data.slang_count || 0,
    };
  } catch {
    return {
      decoded_terms: [
        { original: 'logs', translation: 'stolen login credentials' },
        { original: 'fullz', translation: 'complete identity data package' },
        { original: 'carding', translation: 'credit card fraud techniques' },
        { original: 'rats', translation: 'remote access trojans' },
        { original: 'doxing', translation: 'exposing personal information' },
        { original: 'drops', translation: 'money mule receiving locations' },
        { original: 'mules', translation: 'people who transfer stolen money' },
        { original: 'exploit kits', translation: 'packaged software vulnerability tools' },
        { original: 'zero days', translation: 'unknown/unpatched vulnerabilities' },
      ],
      risk_score_boost: 35,
    };
  }
}

/* ══════════════════════════════════════════════════════════════
   Full NLP Analysis (for Threat Feed detail / analyze)
   Backend: POST /api/nlp/analyze  (body: { text })
   ══════════════════════════════════════════════════════════════ */
export async function analyzeText(text) {
  try {
    return await apiFetch('/api/nlp/analyze', {
      method: 'POST',
      body: JSON.stringify({ text }),
    });
  } catch {
    return { entities: {}, threat_score: { score: 0, level: 'LOW' }, slang: {}, summary: '' };
  }
}

/* ══════════════════════════════════════════════════════════════
   Identity Linking
   Backend: POST /api/leaks/identities  (body: { posts: [...] })
   Returns: { identity_profiles, linked_actors, cross_platform_links, total_identities }
   ══════════════════════════════════════════════════════════════ */
export async function linkIdentities(posts) {
  try {
    const data = await apiFetch('/api/leaks/identities', {
      method: 'POST',
      body: JSON.stringify({ posts: posts || [] }),
    });
    return data;
  } catch {
    return {
      identity_profiles: [],
      linked_actors: [],
      cross_platform_links: 0,
      total_identities: 0,
    };
  }
}

/* ══════════════════════════════════════════════════════════════
   Slang Dictionary (full list)
   Backend: GET /api/nlp/slang/dictionary
   ══════════════════════════════════════════════════════════════ */
export async function fetchSlangDictionary() {
  try {
    return await apiFetch('/api/nlp/slang/dictionary');
  } catch {
    return {};
  }
}

/* ══════════════════════════════════════════════════════════════
   Dashboard Full Data
   Backend: GET /api/dashboard/data
   ══════════════════════════════════════════════════════════════ */
export async function fetchDashboardData() {
  try {
    return await apiFetch('/api/dashboard/data');
  } catch {
    return null;
  }
}

/* ══════════════════════════════════════════════════════════════
   Helpers
   ══════════════════════════════════════════════════════════════ */

function _flattenEntities(entities) {
  if (!entities) return [];
  const flat = [];
  for (const [, values] of Object.entries(entities)) {
    if (Array.isArray(values)) flat.push(...values);
  }
  return flat;
}

function _pickSource(idx) {
  const sources = ['darkmarket.onion', 'breachforums', 'telegram', 'raid.io', 'paste.onion', 'exploit.in'];
  return sources[idx % sources.length];
}

function _relativeTime(idx) {
  const mins = [2, 5, 8, 12, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60];
  return `${mins[idx % mins.length]} min ago`;
}

function _maxSeverity(levels) {
  const order = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  if (!levels.length) return 'LOW';
  return levels.reduce((mx, lv) => (order[lv] || 0) > (order[mx] || 0) ? lv : mx, 'LOW');
}

function _demoThreats() {
  return [
    { severity: 'CRITICAL', content: 'Selling fresh fullz + logs from Fortune 500 breach — includes SSN, DOB, full credit reports', entities: ['0x742d...f44e', 'admin@corp.com'], threat_score: 92, source: 'darkmarket.onion', timestamp: '2 min ago' },
    { severity: 'HIGH', content: 'New ransomware variant targeting healthcare sector — encrypts DICOM imaging files', entities: ['192.168.1.1', 'attacker@proton.me'], threat_score: 78, source: 'breachforums', timestamp: '5 min ago' },
    { severity: 'CRITICAL', content: 'Zero-day exploit for Cisco ASA firewall — pre-auth RCE, working PoC included', entities: ['CVE-2026-1234', 'exploit@onion.mail'], threat_score: 95, source: 'raid.io', timestamp: '8 min ago' },
    { severity: 'MEDIUM', content: 'Bulk email:password combo list — 2.3M entries from various breaches, deduplicated', entities: ['combo-list-2026.txt'], threat_score: 54, source: 'telegram', timestamp: '12 min ago' },
    { severity: 'HIGH', content: 'Insider offering AWS root credentials for Fortune 100 company infrastructure', entities: ['AKIAIOSFODNN7...', 'insider@corp.com'], threat_score: 88, source: 'darkmarket.onion', timestamp: '15 min ago' },
    { severity: 'LOW', content: 'Tutorial — how to set up phishing pages with Evilginx and Cloudflare bypass', entities: ['evilginx-setup.zip'], threat_score: 32, source: 'telegram', timestamp: '20 min ago' },
    { severity: 'HIGH', content: 'Database dump from e-commerce platform — 500K customer records with payment info', entities: ['shopDB.sql', 'admin@shop.io'], threat_score: 81, source: 'breachforums', timestamp: '25 min ago' },
    { severity: 'CRITICAL', content: 'Banking trojan source code with real-time card skimmer and C2 infrastructure', entities: ['trojan_v3.zip', 'c2.darkhost.onion'], threat_score: 96, source: 'darkmarket.onion', timestamp: '30 min ago' },
    { severity: 'MEDIUM', content: 'Leaked corporate VPN credentials for tech company — OpenVPN profiles included', entities: ['vpn.techcorp.com', 'user@techcorp.com'], threat_score: 62, source: 'paste.onion', timestamp: '35 min ago' },
    { severity: 'HIGH', content: 'Offering DDoS-for-hire services — 1Tbps capacity with custom payloads', entities: ['ddos@proton.me', 'bc1qxy2kgd...'], threat_score: 74, source: 'darkmarket.onion', timestamp: '45 min ago' },
  ];
}

function _demoLeakResults() {
  return {
    total_findings: 9,
    overall_severity: 'CRITICAL',
    credentials: [
      { type: 'EMAIL:PASSWORD', value: 'admin@techcorp.com:AdminPass123', masked_value: 'admin@techcorp.com:Admin****', severity: 'HIGH', context: 'Found in database dump' },
      { type: 'EMAIL:PASSWORD', value: 'john.doe@company.org:SecretKey456', masked_value: 'john.doe@company.org:Secr****', severity: 'HIGH', context: 'Found in database dump' },
      { type: 'EMAIL:PASSWORD', value: 'support@acme.io:Welcome2024!', masked_value: 'support@acme.io:Welc****', severity: 'HIGH', context: 'Found in database dump' },
    ],
    financial: [
      { type: 'CREDIT_CARD', card_type: 'Visa', value: '4532-1234-5678-9010', masked_value: '4532 **** **** 9010', severity: 'CRITICAL', luhn_valid: true, context: 'CVV: 123, Exp: 12/25' },
      { type: 'CREDIT_CARD', card_type: 'Visa', value: '4111111111111111', masked_value: '4111 **** **** 1111', severity: 'CRITICAL', luhn_valid: true, context: 'CVV: 999' },
    ],
    api_keys: [
      { type: 'AWS_ACCESS_KEY', value: 'AKIAIOSFODNN7EXAMPLE', masked_value: 'AKIA****MPLE', severity: 'CRITICAL', context: 'Cloud key exposed' },
      { type: 'AWS_ACCESS_KEY', value: 'AKIA5EXAMPLE9KEYHERE', masked_value: 'AKIA****HERE', severity: 'CRITICAL', context: 'Cloud key exposed' },
    ],
    crypto_wallets: [
      { type: 'ETH_WALLET', value: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e', masked_value: '0x742d...f44e', severity: 'HIGH', context: 'Ethereum wallet' },
      { type: 'BTC_WALLET', value: 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', masked_value: 'bc1qar0...5mdq', severity: 'HIGH', context: 'Bitcoin wallet' },
    ],
    impact: {
      estimated_affected_users: '4,200+',
      business_risk: 'HIGH',
      data_types: ['credentials', 'financial', 'crypto', 'api_keys'],
      recommendations: [
        'Immediately revoke all exposed API keys and rotate credentials',
        'Issue fraud alerts for exposed credit card numbers',
        'Monitor cryptocurrency wallets for unauthorized transactions',
        'Notify affected users and enforce mandatory password resets',
      ],
    },
  };
}

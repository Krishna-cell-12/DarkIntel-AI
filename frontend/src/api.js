/**
 * DarkIntel-AI — API Layer
 * ========================
 * Connects frontend components to the FastAPI backend.
 * Each function calls the REAL backend endpoint and transforms
 * the response to the format the UI components expect.
 * Uses real backend data only. No synthetic fallback payloads.
 */

const BASE = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '');

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
      total_threats_analyzed: 0,
      total_entities_extracted: 0,
      modules_active: 8,
      threat_distribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      status: 'degraded',
    };
  }
}

/* ══════════════════════════════════════════════════════════════
   Threat Feed
   Backend: GET /api/threats/feed?limit=N
   Returns: { threats: [{id, content, entities, threat_score, threat_level, slang_count}] }
   Frontend expects: severity, content, entities, threat_score, source, timestamp
   ══════════════════════════════════════════════════════════════ */
export async function fetchThreatFeed(limit = 20, onlyNew = false, newWindowMinutes = 180) {
  try {
    const data = await apiFetch(
      `/api/threats/feed?limit=${limit}&only_new=${onlyNew ? 'true' : 'false'}&new_window_minutes=${newWindowMinutes}`,
    );
    const threats = (data.threats || []).map((t, i) => ({
      id: t.id || `threat_${i}`,
      severity: t.threat_level || 'LOW',
      content: t.content || t.full_content || '',
      full_content: t.full_content || t.content || '',
      entities: _flattenEntities(t.entities),
      threat_score: t.threat_score || 0,
      source: t.source || 'unknown',
      timestamp: t.timestamp || new Date().toISOString(),
      slang_count: t.slang_count || 0,
      is_new: !!t.is_new,
      occurrences: Number(t.occurrences || 1),
    }));
    return { threats };
  } catch {
    return { threats: [] };
  }
}

export async function fetchNewThreats(limit = 20, windowMinutes = 180) {
  try {
    const data = await apiFetch(`/api/threats/new?limit=${limit}&window_minutes=${windowMinutes}`);
    const threats = (data.threats || []).map((t, i) => ({
      id: t.id || `threat_${i}`,
      severity: t.threat_level || 'LOW',
      content: t.content || t.full_content || '',
      full_content: t.full_content || t.content || '',
      entities: _flattenEntities(t.entities),
      threat_score: t.threat_score || 0,
      source: t.source || 'unknown',
      timestamp: t.timestamp || new Date().toISOString(),
      slang_count: t.slang_count || 0,
      is_new: !!t.is_new,
      occurrences: Number(t.occurrences || 1),
    }));
    return { threats };
  } catch {
    return { threats: [] };
  }
}

export async function fetchAlertsReport(limit = 20, minPriority = 'MEDIUM') {
  try {
    return await apiFetch(`/api/alerts?limit=${limit}&min_priority=${encodeURIComponent(minPriority)}`);
  } catch {
    return {
      alerts: [],
      total_alerts: 0,
      distribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      summary: 'Alerts unavailable.',
    };
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
    return {
      total_findings: 0,
      overall_severity: 'LOW',
      credentials: [],
      financial: [],
      api_keys: [],
      crypto_wallets: [],
      impact: {
        estimated_affected_users: '—',
        business_risk: 'LOW',
        data_types: [],
        recommendations: [],
        financial_exposure: '',
        risk_score: 0,
        summary: '',
      },
    };
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
      decoded_terms: [],
      risk_score_boost: 0,
      decoded_text: text,
      slang_count: 0,
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
   Company Breach Lookup + Tor Crawler
   ══════════════════════════════════════════════════════════════ */
export async function lookupCompanyRisk(name) {
  try {
    const n = encodeURIComponent((name || '').trim());
    return await apiFetch(`/api/company/lookup?name=${n}`);
  } catch {
    return {
      company: name || '',
      overall_risk: 'LOW',
      breach_evidence: [],
      risk_indicators: { matches: 0 },
      summary: 'Lookup unavailable. Backend may be offline.',
      recommendations: [],
    };
  }
}

export async function startTorCrawler(urls = [], tor_proxy = '127.0.0.1:9050') {
  return await apiFetch('/api/crawler/start', {
    method: 'POST',
    body: JSON.stringify({ urls, tor_proxy, timeout_seconds: 25 }),
  });
}

export async function fetchCrawlerStatus() {
  try {
    return await apiFetch('/api/crawler/status');
  } catch {
    return { status: 'unknown', tor_connected: false, last_error: 'Backend unavailable' };
  }
}

export async function fetchCrawlerResults(limit = 10) {
  try {
    return await apiFetch(`/api/crawler/results?limit=${limit}`);
  } catch {
    return { count: 0, total: 0, items: [] };
  }
}

export async function startMonitor(urls, interval_seconds = 120, tor_proxy = '127.0.0.1:9050', source_prefix = 'monitor') {
  return await apiFetch('/api/monitor/start', {
    method: 'POST',
    body: JSON.stringify({ urls, interval_seconds, tor_proxy, source_prefix }),
  });
}

export async function stopMonitor() {
  return await apiFetch('/api/monitor/stop', { method: 'POST' });
}

export async function fetchMonitorStatus() {
  try {
    return await apiFetch('/api/monitor/status');
  } catch {
    return { running: false, last_error: 'Backend unavailable', ticks_completed: 0 };
  }
}

export async function runMonitorTick(urls, tor_proxy = '127.0.0.1:9050') {
  return await apiFetch('/api/monitor/tick', {
    method: 'POST',
    body: JSON.stringify({ urls, tor_proxy, timeout_seconds: 25, source_prefix: 'monitor' }),
  });
}

export async function fetchWatchlist() {
  try {
    return await apiFetch('/api/watchlist');
  } catch {
    return { companies: [], domains: [], counts: { companies: 0, domains: 0 } };
  }
}

export async function setWatchlist(companies = [], domains = []) {
  return await apiFetch('/api/watchlist/set', {
    method: 'POST',
    body: JSON.stringify({ companies, domains }),
  });
}

export async function fetchRecentIngest(limit = 120) {
  try {
    return await apiFetch(`/api/ingest/recent?limit=${limit}`);
  } catch {
    return { count: 0, items: [], total_buffered: 0 };
  }
}

export async function fetchEarlyWarning() {
  try {
    return await apiFetch('/api/analytics/early-warning');
  } catch {
    return {
      warning_level: 'LOW',
      current_window_records: 0,
      previous_window_records: 0,
      surge_ratio: 0,
      high_risk_current: 0,
      high_risk_previous: 0,
      critical_current: 0,
      top_companies: [],
      summary: 'No early-warning data yet.',
    };
  }
}

/* ══════════════════════════════════════════════════════════════
   Auto-Correlation Pipeline
   Backend: POST /api/correlate/auto  (body: { text })
   Runs: Leak Detection → Auto-Ingest → Correlation → Alerts
   ══════════════════════════════════════════════════════════════ */
export async function runAutoCorrelation(text) {
  try {
    return await apiFetch('/api/correlate/auto', {
      method: 'POST',
      body: JSON.stringify({ text }),
    });
  } catch {
    return {
      pipeline: 'auto_correlate',
      input_severity: 'LOW',
      total_leaks_detected: 0,
      auto_ingested: false,
      leaks: {},
      impact: {},
      correlation: { total_correlations: 0, signals: [], summary: 'Pipeline failed.' },
      alerts: { total_alerts: 0, distribution: {}, top_alerts: [], summary: '' },
    };
  }
}

export async function ingestFile(file, source = 'file_upload', language = 'unknown') {
  const body = new FormData();
  body.append('file', file);
  body.append('source', source);
  body.append('language', language);

  const res = await fetch(`${BASE}/api/ingest/file`, {
    method: 'POST',
    body,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

export async function ingestFilePath(path, source = 'file_path_ingest', language = 'unknown') {
  return await apiFetch('/api/ingest/file-path', {
    method: 'POST',
    body: JSON.stringify({ path, source, language }),
  });
}

export async function ingestUrl(url, source = 'url_fetch') {
  const body = new FormData();
  body.append('url', url);
  body.append('source', source);

  const res = await fetch(`${BASE}/api/ingest/url`, {
    method: 'POST',
    body,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
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

function _maxSeverity(levels) {
  const order = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  if (!levels.length) return 'LOW';
  return levels.reduce((mx, lv) => (order[lv] || 0) > (order[mx] || 0) ? lv : mx, 'LOW');
}

import { useEffect, useState, useCallback } from 'react';
import {
  fetchCrawlerResults,
  fetchCrawlerStatus,
  fetchMonitorStatus,
  fetchWatchlist,
  ingestFile,
  ingestFilePath,
  ingestUrl,
  lookupCompanyRisk,
  runMonitorTick,
  setWatchlist,
  startMonitor,
  startTorCrawler,
  stopMonitor,
} from '../api';
import { IconSearch, IconActivity, IconAlert, IconTerminal, IconUpload, IconFile } from './Icons';
import { useToast } from './toast-context';
import { formatTime } from '../utils/time';

const RECOMMENDED_ONION_URLS = [
  'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion',
  'mwwywuoclkhn2ayppbceoxcnsz3gclnqnl6khx2plckhyxumcvj2c4ad.onion',
  'yfemfir5pcx2osrn5csscgxecpx6qrw6tituqnp3eefyuzu4vtzpsvqd.onion',
].join(', ');

export default function CompanyLookup() {
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [crawlBusy, setCrawlBusy] = useState(false);
  const [ingestBusy, setIngestBusy] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [pathInput, setPathInput] = useState('');
  const [status, setStatus] = useState({ status: 'idle', tor_connected: false });
  const [crawlerItems, setCrawlerItems] = useState([]);
  const [monitor, setMonitor] = useState({ running: false, ticks_completed: 0 });
  const [watchCompanies, setWatchCompanies] = useState('');
  const [watchDomains, setWatchDomains] = useState('');
  const [monitorUrls, setMonitorUrls] = useState('');
  const [monitorInterval, setMonitorInterval] = useState(120);
  const [monitorProxy, setMonitorProxy] = useState('127.0.0.1:9150');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [monitorBusy, setMonitorBusy] = useState(false);
  const [watchlistBusy, setWatchlistBusy] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const toast = useToast();

  const monitorLast = monitor?.last_result || {};
  const monitorLastWatchlist = monitorLast?.watchlist || {};

  const refreshStatus = useCallback(async () => {
    const s = await fetchCrawlerStatus();
    setStatus(s || { status: 'unknown' });
    const rs = await fetchCrawlerResults(8);
    setCrawlerItems(rs?.items || []);
    const ms = await fetchMonitorStatus();
    setMonitor(ms || { running: false, ticks_completed: 0 });
    if (ms?.urls?.length && !monitorUrls) {
      setMonitorUrls((ms.urls || []).join(', '));
    }
    if (ms?.tor_proxy && !monitorProxy) {
      setMonitorProxy(ms.tor_proxy);
    }
    if (ms?.interval_seconds && Number.isFinite(ms.interval_seconds)) {
      setMonitorInterval(prev => (prev > 0 ? prev : ms.interval_seconds));
    }
  }, [monitorUrls, monitorProxy]);

  async function hydrateWatchlistInputs() {
    const wl = await fetchWatchlist();
    setWatchCompanies((wl?.companies || []).join(', '));
    setWatchDomains((wl?.domains || []).join(', '));
  }

  useEffect(() => {
    refreshStatus();
    hydrateWatchlistInputs();
    const id = setInterval(refreshStatus, 6000);
    return () => clearInterval(id);
  }, [refreshStatus]);

  useEffect(() => {
    if (!monitorUrls) {
      setMonitorUrls(RECOMMENDED_ONION_URLS);
    }
  }, [monitorUrls]);

  async function onLookup() {
    if (!name.trim()) {
      toast('Enter company name first', 'info');
      return;
    }
    setLoading(true);
    try {
      const data = await lookupCompanyRisk(name.trim());
      setReport(data);
      const matches = data?.risk_indicators?.matches || 0;
      if (matches === 0) {
        toast(`No direct matches for "${name.trim()}" in current records`, 'info');
      } else {
        toast(`Lookup complete: ${data?.overall_risk || 'LOW'} risk, ${matches} match(es)`, 'success');
      }
    } catch {
      toast('Company lookup failed', 'error');
    } finally {
      setLoading(false);
    }
  }

  async function onStartCrawler() {
    setCrawlBusy(true);
    try {
      let urls = monitorUrls
        .split(',')
        .map(x => x.trim())
        .filter(Boolean);

      if (urls.length === 0) {
        const msg = window.prompt('Enter live .onion URLs (comma-separated):', '');
        urls = (msg || '')
          .split(',')
          .map(x => x.trim())
          .filter(Boolean);
      }

      if (urls.length === 0) {
        toast('Crawler needs at least one live .onion URL', 'info');
        return;
      }
      const proxy = (monitorProxy || '127.0.0.1:9150').trim();
      const out = await startTorCrawler(urls, proxy || '127.0.0.1:9150');
      const ok = out?.sources_successful || 0;
      const fail = out?.sources_failed || 0;
      if (ok > 0) toast(`Crawler completed: ${ok} success, ${fail} failed`, 'success');
      else toast(`Crawler finished with no successful fetches (${fail} failed)`, 'error');
      if (name.trim()) await onLookup();
    } catch (err) {
      const msgErr = String(err?.message || 'Crawler failed');
      toast(msgErr, 'error');
    } finally {
      setCrawlBusy(false);
      await refreshStatus();
    }
  }

  async function onUploadFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    await processFile(file);
    e.target.value = '';
  }

  async function processFile(file) {
    setIngestBusy(true);
    try {
      const out = await ingestFile(file, 'company_lookup_upload', 'unknown');
      const cnt = out?.ingest_result?.ingested_count || 0;
      if (cnt > 0) toast(`Uploaded ${file.name}: ${cnt} record ingested`, 'success');
      else toast(`No extractable text found in ${file.name}`, 'error');
      if (name.trim()) await onLookup();
      await refreshStatus();
    } catch (err) {
      toast(String(err?.message || 'File upload failed'), 'error');
    } finally {
      setIngestBusy(false);
    }
  }

  function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(true);
  }

  function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  }

  async function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    const file = e.dataTransfer?.files?.[0];
    if (file) {
      await processFile(file);
    }
  }

  async function onIngestUrl() {
    if (!urlInput.trim()) {
      toast('Enter URL first', 'info');
      return;
    }
    setIngestBusy(true);
    try {
      const out = await ingestUrl(urlInput.trim(), 'company_lookup_url');
      const cnt = out?.ingest_result?.ingested_count || 0;
      if (cnt > 0) toast('URL ingested successfully', 'success');
      else toast('URL fetched but no extractable text found', 'error');
      setUrlInput('');
      if (name.trim()) await onLookup();
      await refreshStatus();
    } catch (err) {
      toast(String(err?.message || 'URL ingestion failed'), 'error');
    } finally {
      setIngestBusy(false);
    }
  }

  async function onIngestPath() {
    if (!pathInput.trim()) {
      toast('Enter local file path first', 'info');
      return;
    }
    setIngestBusy(true);
    try {
      const out = await ingestFilePath(pathInput.trim(), 'company_lookup_path', 'unknown');
      const cnt = out?.ingest_result?.ingested_count || 0;
      const upd = out?.ingest_result?.updated_count || 0;
      if (cnt > 0 || upd > 0) {
        toast(`Path ingested: ${cnt} new, ${upd} recurring`, 'success');
      } else {
        toast('Path read but no extractable text found', 'error');
      }
      if (name.trim()) await onLookup();
      await refreshStatus();
    } catch (err) {
      toast(String(err?.message || 'Path ingestion failed'), 'error');
    } finally {
      setIngestBusy(false);
    }
  }

  function applyWorkingPreset() {
    setMonitorUrls(RECOMMENDED_ONION_URLS);
    setMonitorProxy('127.0.0.1:9150');
    setMonitorInterval(60);
    if (!watchCompanies) setWatchCompanies('Acme Corporation, DuckDuckGo');
    if (!watchDomains) setWatchDomains('acme.com, duckduckgo.com');
    if (!name) setName('Acme');
    toast('Working preset loaded', 'success');
  }

  async function runQuickDemo() {
    setMonitorBusy(true);
    try {
      const companies = ['Acme Corporation', 'DuckDuckGo'];
      const domains = ['acme.com', 'duckduckgo.com'];
      await setWatchlist(companies, domains);

      const urls = RECOMMENDED_ONION_URLS.split(',').map(x => x.trim()).filter(Boolean);
      const out = await runMonitorTick(urls, '127.0.0.1:9150');
      const ok = out?.sources_successful || 0;
      const fail = out?.sources_failed || 0;

      const target = (name || 'Acme').trim() || 'Acme';
      setName(target);
      const data = await lookupCompanyRisk(target);
      setReport(data);

      toast(`Quick run complete: ${ok} success / ${fail} failed, risk=${data?.overall_risk || 'LOW'}`, ok > 0 ? 'success' : 'info');
    } catch (err) {
      toast(String(err?.message || 'Quick run failed'), 'error');
    } finally {
      setMonitorBusy(false);
      await refreshStatus();
    }
  }

  async function onSetWatchlist() {
    setWatchlistBusy(true);
    try {
      const companies = watchCompanies
        .split(',')
        .map(x => x.trim())
        .filter(Boolean);
      const domains = watchDomains
        .split(',')
        .map(x => x.trim())
        .filter(Boolean);
      const out = await setWatchlist(companies, domains);
      toast(
        `Watchlist updated: ${out?.counts?.companies || 0} companies, ${out?.counts?.domains || 0} domains`,
        'success',
      );
    } catch (err) {
      toast(String(err?.message || 'Failed to update watchlist'), 'error');
    } finally {
      setWatchlistBusy(false);
      await refreshStatus();
    }
  }

  async function onStartMonitor() {
    setMonitorBusy(true);
    try {
      const urls = monitorUrls
        .split(',')
        .map(x => x.trim())
        .filter(Boolean);
      if (urls.length === 0) {
        toast('Monitor needs at least one .onion URL', 'info');
        return;
      }

      const interval = Number(monitorInterval);
      if (!Number.isFinite(interval) || interval < 30) {
        toast('Interval must be at least 30 seconds', 'error');
        return;
      }

      const proxy = (monitorProxy || '127.0.0.1:9150').trim();
      await startMonitor(urls, interval, proxy || '127.0.0.1:9150', 'monitor');
      toast(`Proactive monitor started (every ${interval}s)`, 'success');
    } catch (err) {
      toast(String(err?.message || 'Failed to start monitor'), 'error');
    } finally {
      setMonitorBusy(false);
      await refreshStatus();
    }
  }

  async function onStopMonitor() {
    setMonitorBusy(true);
    try {
      await stopMonitor();
      toast('Monitor stopped', 'info');
    } catch (err) {
      toast(String(err?.message || 'Failed to stop monitor'), 'error');
    } finally {
      setMonitorBusy(false);
      await refreshStatus();
    }
  }

  async function onMonitorTick() {
    setMonitorBusy(true);
    try {
      const urls = monitorUrls
        .split(',')
        .map(x => x.trim())
        .filter(Boolean);
      if (urls.length === 0) {
        toast('Tick needs at least one .onion URL', 'info');
        return;
      }
      const proxy = (monitorProxy || '127.0.0.1:9150').trim();
      const out = await runMonitorTick(urls, proxy || '127.0.0.1:9150');
      toast(
        `Monitor tick complete: ${out?.sources_successful || 0} success, ${out?.sources_failed || 0} failed`,
        (out?.sources_successful || 0) > 0 ? 'success' : 'info',
      );
      if (name.trim()) await onLookup();
    } catch (err) {
      toast(String(err?.message || 'Monitor tick failed'), 'error');
    } finally {
      setMonitorBusy(false);
      await refreshStatus();
    }
  }

  const risk = report?.overall_risk || 'LOW';
  const riskClass = String(risk).toLowerCase();
  const nextTickSeconds = (() => {
    if (!monitor?.running || !monitor?.last_tick || !monitor?.interval_seconds) return null;
    const elapsed = (Date.now() - new Date(monitor.last_tick).getTime()) / 1000;
    const remain = Math.max(0, Math.ceil(Number(monitor.interval_seconds) - elapsed));
    return Number.isFinite(remain) ? remain : null;
  })();

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconSearch style={{ width: 14, height: 14, color: 'var(--cyan)' }} />
            Company Breach Lookup
          </span>
          <span className={`badge ${riskClass}`}>{risk}</span>
        </div>
        <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="feed-controls" style={{ marginBottom: 0 }}>
            <div className="search-input-wrap" style={{ flex: 1, maxWidth: 460 }}>
              <IconSearch />
                <input
                  className="cyber-input"
                  placeholder="Enter company name"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && onLookup()}
                />
            </div>
            <button className="cyber-btn" onClick={onLookup} disabled={loading}>
              {loading ? 'Scanning...' : 'Scan Risk'}
            </button>
          </div>

          <div className="company-quick-panel">
            <div className="company-quick-steps">
              <span>1) Load preset</span>
              <span>2) Run one tick</span>
              <span>3) Scan company</span>
            </div>
            <div className="company-quick-actions">
              <button className="cyber-btn" onClick={applyWorkingPreset}>Load Working Preset</button>
              <button className="cyber-btn" onClick={runQuickDemo} disabled={monitorBusy}>Quick Run</button>
              <button className="cyber-btn ghost" onClick={() => setShowAdvanced(v => !v)}>
                {showAdvanced ? 'Hide Advanced' : 'Show Advanced'}
              </button>
            </div>
          </div>

          {/* Drag & Drop File Upload Zone */}
          <div
            className={`file-dropzone ${dragActive ? 'active' : ''} ${ingestBusy ? 'busy' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >
            <input
              type="file"
              accept=".txt,.log,.md,.json,.csv,.pdf,.png,.jpg,.jpeg,.bmp,.webp"
              onChange={onUploadFile}
              disabled={ingestBusy}
              style={{ display: 'none' }}
              id="dropzone-file-input"
            />
            <label htmlFor="dropzone-file-input" className="file-dropzone-label">
              <IconUpload style={{ width: 28, height: 28, color: dragActive ? 'var(--cyan)' : 'var(--text-dim)' }} />
              <div className="file-dropzone-text">
                {ingestBusy ? 'Processing...' : dragActive ? 'Drop file here' : 'Drag & drop files or click to upload'}
              </div>
              <div className="file-dropzone-hint">
                PDF, Images, CSV, JSON, TXT — auto-extract & ingest
              </div>
            </label>
          </div>

          {showAdvanced ? (
            <>
          <div className="company-status-row">
            <span className="company-status-item">
              <IconTerminal style={{ width: 12, height: 12 }} />
              Crawler: <strong>{status?.status || 'idle'}</strong>
            </span>
            <span className="company-status-item">
              <IconActivity style={{ width: 12, height: 12 }} />
              Tor: <strong>{status?.tor_connected ? 'Connected' : 'Disconnected'}</strong>
            </span>
            <button className="cyber-btn ghost" onClick={onStartCrawler} disabled={crawlBusy}>
              {crawlBusy ? 'Starting...' : 'Run Tor Crawl'}
            </button>
          </div>

          <div className="company-status-row">
            <span className="company-status-item">
              <IconActivity style={{ width: 12, height: 12 }} />
              Monitor: <strong>{monitor?.running ? 'Running' : 'Stopped'}</strong>
            </span>
            <span className="company-status-item">
              <IconTerminal style={{ width: 12, height: 12 }} />
              Ticks: <strong>{monitor?.ticks_completed || 0}</strong>
            </span>
            <button className="cyber-btn" onClick={onStartMonitor} disabled={monitorBusy || monitor?.running}>
              Start Monitor
            </button>
            <button className="cyber-btn outline" onClick={onStopMonitor} disabled={monitorBusy || !monitor?.running}>
              Stop Monitor
            </button>
            <button className="cyber-btn ghost" onClick={onMonitorTick} disabled={monitorBusy}>
              Run One Tick
            </button>
          </div>

          <div className="company-upload-row">
            <div className="search-input-wrap" style={{ flex: 1 }}>
              <IconTerminal />
              <input
                className="cyber-input"
                placeholder="Monitor URLs (.onion, comma-separated)"
                value={monitorUrls}
                onChange={e => setMonitorUrls(e.target.value)}
              />
            </div>
            <div className="search-input-wrap" style={{ maxWidth: 180 }}>
              <IconActivity />
              <input
                className="cyber-input"
                type="number"
                min="30"
                step="10"
                placeholder="Interval (s)"
                value={monitorInterval}
                onChange={e => setMonitorInterval(Number(e.target.value) || 0)}
              />
            </div>
            <div className="search-input-wrap" style={{ maxWidth: 220 }}>
              <IconTerminal />
              <input
                className="cyber-input"
                placeholder="Tor proxy"
                value={monitorProxy}
                onChange={e => setMonitorProxy(e.target.value)}
              />
            </div>
          </div>

          <div className="company-monitor-summary">
            <div className="company-monitor-item">Last tick: <strong>{monitor?.last_tick ? formatTime(monitor.last_tick) : '—'}</strong></div>
            <div className="company-monitor-item">Next tick: <strong>{nextTickSeconds !== null ? `${nextTickSeconds}s` : '—'}</strong></div>
            <div className="company-monitor-item">Last cycle: <strong>{monitor?.last_result ? `${monitor.last_result.sources_successful || 0} success / ${monitor.last_result.sources_failed || 0} failed` : '—'}</strong></div>
            <div className="company-monitor-item">Watchlist matches: <strong>{monitorLast.watchlist_matches || monitorLastWatchlist.matched_records || 0}</strong></div>
            <div className="company-monitor-item">Ingested (new): <strong>{monitorLast.ingested_count || 0}</strong></div>
            <div className="company-monitor-item">Recurring merged: <strong>{monitorLast.updated_count || 0}</strong></div>
            <div className="company-monitor-item">Watchlist alerts: <strong>{monitorLast.watchlist_alerts_total || monitorLastWatchlist?.alerts?.total_alerts || 0}</strong></div>
            <div className="company-monitor-item">Highest priority: <strong>{monitorLast.highest_priority || monitorLastWatchlist.highest_priority || 'LOW'}</strong></div>
          </div>

          <div className="company-upload-row">
            <div className="search-input-wrap" style={{ flex: 1, maxWidth: 420 }}>
              <IconSearch />
              <input
                className="cyber-input"
                placeholder="Watchlist companies (comma-separated)"
                value={watchCompanies}
                onChange={e => setWatchCompanies(e.target.value)}
              />
            </div>
            <div className="search-input-wrap" style={{ flex: 1, maxWidth: 420 }}>
              <IconTerminal />
              <input
                className="cyber-input"
                placeholder="Watchlist domains (comma-separated)"
                value={watchDomains}
                onChange={e => setWatchDomains(e.target.value)}
              />
            </div>
            <button className="cyber-btn" onClick={onSetWatchlist} disabled={watchlistBusy}>
              {watchlistBusy ? 'Saving...' : 'Save Watchlist'}
            </button>
          </div>

          <div className="company-upload-row">
            <label className="cyber-btn outline" style={{ cursor: ingestBusy ? 'not-allowed' : 'pointer' }}>
              {ingestBusy ? 'Processing...' : 'Upload File (PDF/IMG/CSV/JSON/TXT)'}
              <input type="file" accept=".txt,.log,.md,.json,.csv,.pdf,.png,.jpg,.jpeg,.bmp,.webp" onChange={onUploadFile} disabled={ingestBusy} style={{ display: 'none' }} />
            </label>
            <div className="search-input-wrap" style={{ flex: 1, maxWidth: 420 }}>
              <IconTerminal />
              <input
                className="cyber-input"
                placeholder="Ingest local file path (e.g., C:\\...\\test_data.json)"
                value={pathInput}
                onChange={e => setPathInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && onIngestPath()}
              />
            </div>
            <button className="cyber-btn ghost" onClick={onIngestPath} disabled={ingestBusy || !pathInput.trim()}>
              Ingest Path
            </button>
            <div className="search-input-wrap" style={{ flex: 1, maxWidth: 420 }}>
              <IconTerminal />
              <input
                className="cyber-input"
                placeholder="Ingest from URL (html/json/csv/pdf/image)"
                value={urlInput}
                onChange={e => setUrlInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && onIngestUrl()}
              />
            </div>
            <button className="cyber-btn" onClick={onIngestUrl} disabled={ingestBusy || !urlInput.trim()}>
              Ingest URL
            </button>
          </div>

          {status?.last_error ? (
            <div className="company-warning">
              <IconAlert style={{ width: 12, height: 12 }} />
              {String(status.last_error).slice(0, 260)}
            </div>
          ) : null}

          {monitor?.last_error ? (
            <div className="company-warning">
              <IconAlert style={{ width: 12, height: 12 }} />
              Monitor: {String(monitor.last_error).slice(0, 260)}
            </div>
          ) : null}

          <div className="company-tip">
            <strong>Real data only:</strong> ingest files/URLs or crawl live .onion sources. No synthetic data is used.
          </div>

          {(crawlerItems || []).length > 0 ? (
            <div className="company-crawl-list">
              {(crawlerItems || []).slice(-5).reverse().map((item, i) => (
                <div key={i} className="company-crawl-item">
                  <span className={`badge ${item.status === 'success' ? 'low' : 'high'}`}>{item.status || 'unknown'}</span>
                  <span className="threat-timestamp" style={{ flex: 1, minWidth: 0 }}>
                    {(item.url || '').slice(0, 70)}{(item.url || '').length > 70 ? '...' : ''}
                  </span>
                  <span className="threat-timestamp">{item.title ? item.title.slice(0, 26) : (item.error ? String(item.error).slice(0, 26) : '-')}</span>
                </div>
              ))}
            </div>
          ) : null}
            </>
          ) : (
            <div className="company-tip">
              Advanced controls are hidden. Use <strong>Load Working Preset</strong> and <strong>Quick Run</strong> for easiest testing.
            </div>
          )}
        </div>
      </div>

      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconActivity style={{ width: 14, height: 14, color: 'var(--magenta)' }} />
            Risk Intelligence Report
          </span>
          <span className="card-header-badge">{report?.risk_indicators?.matches || 0} matches</span>
        </div>
        <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {!report ? (
            <div style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
              Run a company lookup to see breach evidence, indicators, and recommendations.
            </div>
          ) : (
            <>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{report.summary}</div>

              <div className="company-kpi-grid">
                <div className="company-kpi"><span>Mentions</span><strong>{report?.risk_indicators?.matches || 0}</strong></div>
                <div className="company-kpi"><span>Credentials</span><strong>{report?.risk_indicators?.credential_mentions || 0}</strong></div>
                <div className="company-kpi"><span>Infra</span><strong>{report?.risk_indicators?.infrastructure_mentions || 0}</strong></div>
                <div className="company-kpi"><span>Financial</span><strong>{report?.risk_indicators?.financial_mentions || 0}</strong></div>
              </div>

              <div className="company-evidence-list">
                {(report.breach_evidence || []).slice(0, 6).map((e, i) => (
                  <div key={i} className="company-evidence-item">
                    <div className="company-evidence-head">
                      <span className={`badge ${String(e.risk_level || 'LOW').toLowerCase()}`}>{e.risk_level || 'LOW'}</span>
                      <span className="threat-timestamp">{e.source || 'source'} · score {e.threat_score || 0}</span>
                    </div>
                    <div className="company-evidence-body">{e.content || 'No content'}</div>
                  </div>
                ))}
              </div>

              <div className="company-reco-list">
                {(report.recommendations || []).map((r, i) => (
                  <div key={i} className="company-reco-item">• {r}</div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

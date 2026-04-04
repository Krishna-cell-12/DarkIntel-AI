import { useEffect, useState } from 'react';
import { fetchCrawlerResults, fetchCrawlerStatus, ingestFile, ingestUrl, lookupCompanyRisk, startTorCrawler } from '../api';
import { IconSearch, IconActivity, IconAlert, IconTerminal } from './Icons';
import { useToast } from './Toast';

export default function CompanyLookup() {
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [crawlBusy, setCrawlBusy] = useState(false);
  const [ingestBusy, setIngestBusy] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [status, setStatus] = useState({ status: 'idle', tor_connected: false });
  const [crawlerItems, setCrawlerItems] = useState([]);
  const toast = useToast();

  async function refreshStatus() {
    const s = await fetchCrawlerStatus();
    setStatus(s || { status: 'unknown' });
    const rs = await fetchCrawlerResults(8);
    setCrawlerItems(rs?.items || []);
  }

  useEffect(() => {
    refreshStatus();
    const id = setInterval(refreshStatus, 6000);
    return () => clearInterval(id);
  }, []);

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
      const msg = window.prompt('Enter live .onion URLs (comma-separated):', '');
      const urls = (msg || '')
        .split(',')
        .map(x => x.trim())
        .filter(Boolean);
      if (urls.length === 0) {
        toast('Crawler needs at least one live .onion URL', 'info');
        return;
      }
      const proxy = window.prompt('Tor proxy (host:port):', '127.0.0.1:9050') || '127.0.0.1:9050';
      const out = await startTorCrawler(urls, proxy.trim() || '127.0.0.1:9050');
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
      e.target.value = '';
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

  const risk = report?.overall_risk || 'LOW';
  const riskClass = String(risk).toLowerCase();

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

          <div className="company-upload-row">
            <label className="cyber-btn outline" style={{ cursor: ingestBusy ? 'not-allowed' : 'pointer' }}>
              {ingestBusy ? 'Processing...' : 'Upload File (PDF/IMG/CSV/JSON/TXT)'}
              <input type="file" accept=".txt,.log,.md,.json,.csv,.pdf,.png,.jpg,.jpeg,.bmp,.webp" onChange={onUploadFile} disabled={ingestBusy} style={{ display: 'none' }} />
            </label>
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

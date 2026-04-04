import { useState, useMemo } from 'react';
import { decodeSlang } from '../api';
import { useToast } from './toast-context';
import { IconKey, IconSearch } from './Icons';

export default function SlangDecoder() {
  const [input, setInput] = useState('');
  const [results, setResults] = useState(null);
  const [decoded, setDecoded] = useState('');
  const [loading, setLoading] = useState(false);
  const [dictSearch, setDictSearch] = useState('');
  const toast = useToast();

  const doDecode = async () => {
    const text = input.trim();
    if (!text) {
      toast('Enter real intercepted text to decode', 'info');
      return;
    }
    setLoading(true);
    try {
      const data = await decodeSlang(text);
      setResults(data);
      setDecoded(text);
      toast(`Decoded ${data.decoded_terms?.length || 0} slang terms`, 'success');
    } catch {
      toast('Decode failed — backend offline', 'error');
    } finally {
      setLoading(false);
    }
  };

  // Build dictionary from results
  const dictionary = useMemo(() => {
    const terms = results?.decoded_terms || [];
    if (dictSearch) {
      return terms.filter(t =>
        (t.original || t.term || '').toLowerCase().includes(dictSearch.toLowerCase()) ||
        (t.translation || t.meaning || '').toLowerCase().includes(dictSearch.toLowerCase())
      );
    }
    return terms;
  }, [results, dictSearch]);

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="glass-card">
        <div className="card-header">
          <span className="card-header-title">
            <IconKey style={{ width: 14, height: 14, color: 'var(--magenta)' }} />
            Dark Web Slang Decoder
          </span>
        </div>
        <div className="card-body">
          <div className="slang-layout">
            {/* Input side */}
            <div>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: '0.6rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: 10 }}>
                Input
              </div>
              <textarea
                className="cyber-input"
                style={{ minHeight: 160 }}
                placeholder="Paste dark web text with coded language to decode..."
                value={input}
                onChange={e => setInput(e.target.value)}
              />
              <div style={{ display: 'flex', gap: 10, marginTop: 12 }}>
                <button className="cyber-btn primary" onClick={doDecode} disabled={loading} style={{ background: 'linear-gradient(135deg, var(--magenta), #8800cc)' }}>
                  {loading ? 'Decoding...' : '↻ Decode Message'}
                </button>
              </div>
            </div>

            {/* Output side */}
            <div>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: '0.6rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: 10 }}>
                Decoded Output
              </div>
              <div className="slang-output-text">
                {decoded ? (
                  <DecodedText text={decoded} terms={results?.decoded_terms || []} />
                ) : (
                  <span style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>
                    Decoded text will appear here...
                  </span>
                )}
              </div>
              {results && (
                <div className="slang-stats">
                  <div className="slang-stat">
                    <strong>{results.decoded_terms?.length || 0}</strong> terms found
                  </div>
                  <div className="slang-stat">
                    <strong style={{ color: 'var(--critical)' }}>+{results.risk_score_boost || 0}</strong> risk boost
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Dictionary */}
          {results && results.decoded_terms && results.decoded_terms.length > 0 && (
            <div className="slang-dict-section">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: '0.6rem', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '2px' }}>
                  Slang Dictionary
                </div>
                <div className="search-input-wrap" style={{ maxWidth: 220 }}>
                  <IconSearch />
                  <input
                    className="cyber-input"
                    style={{ padding: '6px 12px 6px 34px', fontSize: '0.72rem' }}
                    placeholder="Filter terms..."
                    value={dictSearch}
                    onChange={e => setDictSearch(e.target.value)}
                  />
                </div>
              </div>
              <div className="slang-dict-grid stagger-children">
                {dictionary.map((t, i) => (
                  <div key={i} className="slang-dict-card">
                    <div className="slang-dict-term">"{t.original || t.term}"</div>
                    <div className="slang-dict-def">{t.translation || t.meaning}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* Highlight decoded terms in text */
function DecodedText({ text, terms }) {
  if (!terms || terms.length === 0) return <span>{text}</span>;

  // Highlight matched slang terms directly in output text.
  let chunks = [{ text, highlighted: false, meaning: null }];

  const uniqueTerms = terms
    .map(t => ({
      raw: String(t.original || t.term || '').trim(),
      meaning: String(t.translation || t.meaning || '').trim(),
    }))
    .filter(t => t.raw.length > 0);

  uniqueTerms.forEach(term => {
    const escaped = term.raw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`\\b${escaped}\\b`, 'gi');

    chunks = chunks.flatMap(chunk => {
      if (chunk.highlighted) return [chunk];
      const parts = [];
      let last = 0;
      let match;
      while ((match = re.exec(chunk.text)) !== null) {
        if (match.index > last) {
          parts.push({ text: chunk.text.slice(last, match.index), highlighted: false, meaning: null });
        }
        parts.push({ text: chunk.text.slice(match.index, match.index + match[0].length), highlighted: true, meaning: term.meaning });
        last = match.index + match[0].length;
      }
      if (last < chunk.text.length) {
        parts.push({ text: chunk.text.slice(last), highlighted: false, meaning: null });
      }
      return parts.length ? parts : [chunk];
    });
  });

  return (
    <>
      {chunks.map((chunk, i) => (
        chunk.highlighted ? (
          <span key={i} className="slang-highlight" title={chunk.meaning || 'Decoded slang'}>
            {chunk.text}
          </span>
        ) : (
          <span key={i}>{chunk.text}</span>
        )
      ))}
    </>
  );
}

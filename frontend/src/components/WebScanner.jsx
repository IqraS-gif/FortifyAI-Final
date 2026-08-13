import React, { useState, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Globe, Search, ShieldAlert, ShieldCheck, EyeOff, Tag,
  AlertCircle, ExternalLink, X, ChevronRight, Link2,
  Code2, Camera, GitBranch, Layers
} from 'lucide-react';

const API_BASE = 'http://localhost:8000/api';

const PHASE_LABELS = [
  { key: 'fetch',    icon: Globe,      label: 'Fetching Page via Headless Browser' },
  { key: 'dom',      icon: Code2,      label: 'Extracting Hidden DOM Content' },
  { key: 'ocr',      icon: Camera,     label: 'Running Screenshot OCR' },
  { key: 'pipeline', icon: Layers,     label: 'Analyzing Threats via AI Pipeline' },
];

export default function WebScanner({ onScanComplete }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [phaseIndex, setPhaseIndex] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const inputRef = useRef(null);

  const runPhases = async () => {
    for (let i = 0; i < PHASE_LABELS.length; i++) {
      setPhaseIndex(i);
      await new Promise(r => setTimeout(r, i === 0 ? 800 : 600));
    }
  };

  const handleScan = async () => {
    const trimmed = url.trim();
    if (!trimmed) return;
    setLoading(true);
    setError('');
    setResult(null);
    setPhaseIndex(0);

    // Animate phases in parallel with actual fetch
    runPhases();

    try {
      const resp = await fetch(`${API_BASE}/scan/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed, sensitivity_profile: 'BALANCED' }),
      });
      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || 'Scan failed');
      }
      const data = await resp.json();
      setResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (e) {
      setError(e.message || 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleScan();
  };

  const openModal = (threat) => {
    setSelectedThreat(threat);
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    setSelectedThreat(null);
  };

  const isBlocked = result?.action === 'BLOCKED';
  const webScan = result?.web_scan || {};
  const indicators = result?.structured_indicators || [];
  const invisibleFindings = result?.document_meta?.invisible_text_findings || [];

  // Deduplicate by indicator title
  const seen = new Set();
  const deduped = [...indicators, ...invisibleFindings.map(f => ({
    title: f.indicator || f.field,
    description: f.reason || '',
    evidence: f.value || '',
    severity: f.confidence === 'HIGH' ? 'CRITICAL' : 'MEDIUM',
  }))].filter(item => {
    const key = item.title;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '28px', alignItems: 'start' }}>

      {/* ── Left panel ── */}
      <div>
        {/* Header */}
        <div style={{ marginBottom: '28px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
            <div style={{ background: 'linear-gradient(135deg, #1a1a2e, #16213e)', borderRadius: '10px', padding: '10px', display: 'flex' }}>
              <Globe size={22} color="#7B8CDE" />
            </div>
            <h2 style={{ fontSize: '1.4rem', fontWeight: 800, margin: 0 }}>Web URL Scanner</h2>
          </div>
          <p style={{ color: 'var(--text-dim)', fontSize: '0.9rem', margin: 0, lineHeight: 1.6 }}>
            Detects <strong>indirect prompt injection</strong> hidden in webpages — CSS tricks, HTML comments,
            invisible attributes, obfuscated JS, and visual steganography.
          </p>
        </div>

        {/* URL Input */}
        <div style={{
          border: '2px solid #7B8CDE',
          borderRadius: '10px',
          padding: '4px 4px 4px 16px',
          display: 'flex',
          alignItems: 'center',
          background: '#0f0f1a',
          marginBottom: '16px',
          boxShadow: '0 0 20px rgba(123,140,222,0.08)',
          transition: 'box-shadow 0.2s ease',
        }}>
          <Link2 size={18} color="#7B8CDE" style={{ marginRight: '10px', flexShrink: 0 }} />
          <input
            ref={inputRef}
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="https://example.com/report"
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: '#e2e8f0',
              fontSize: '0.95rem',
              fontFamily: 'var(--font-mono)',
              padding: '10px 0',
            }}
          />
          <button
            onClick={handleScan}
            disabled={!url.trim() || loading}
            style={{
              background: loading ? '#2d2d4e' : 'linear-gradient(135deg, #7B8CDE, #5a67d8)',
              border: 'none',
              borderRadius: '8px',
              color: '#fff',
              padding: '10px 20px',
              fontWeight: 700,
              fontSize: '0.85rem',
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              letterSpacing: '0.05em',
              transition: 'all 0.2s ease',
            }}
          >
            <Search size={15} />
            {loading ? 'SCANNING...' : 'SCAN URL'}
          </button>
        </div>

        {/* Phase Progress */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              style={{ marginBottom: '20px' }}
            >
              {PHASE_LABELS.map((phase, i) => {
                const PhaseIcon = phase.icon;
                const active = i === phaseIndex;
                const done = i < phaseIndex;
                return (
                  <div key={phase.key} style={{
                    display: 'flex', alignItems: 'center', gap: '12px',
                    padding: '8px 12px', marginBottom: '4px',
                    borderRadius: '8px',
                    background: active ? 'rgba(123,140,222,0.12)' : 'transparent',
                    opacity: done ? 0.4 : active ? 1 : 0.3,
                    transition: 'all 0.3s ease',
                  }}>
                    <PhaseIcon size={14} color={active ? '#7B8CDE' : done ? '#48bb78' : '#4a5568'} />
                    <span style={{ fontSize: '0.8rem', color: active ? '#c3caf7' : '#718096', fontWeight: active ? 700 : 400 }}>
                      {done ? '✓ ' : active ? '⟳ ' : ''}{phase.label}
                    </span>
                  </div>
                );
              })}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error */}
        {error && (
          <div style={{ padding: '12px', background: 'rgba(197,48,48,0.08)', border: '1px solid #C53030', borderRadius: '8px', color: '#fc8181', fontSize: '0.85rem', marginBottom: '16px' }}>
            {error}
          </div>
        )}

        {/* Result Verdict */}
        <AnimatePresence>
          {result && (
            <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}>

              {/* Verdict banner */}
              <div style={{
                padding: '20px 24px',
                borderRadius: '12px',
                border: `2px solid ${isBlocked ? '#C53030' : '#276749'}`,
                background: isBlocked ? 'rgba(197,48,48,0.06)' : 'rgba(39,103,73,0.06)',
                marginBottom: '20px',
                display: 'flex', alignItems: 'center', gap: '16px',
              }}>
                {isBlocked
                  ? <ShieldAlert size={32} color="#C53030" />
                  : <ShieldCheck size={32} color="#48bb78" />}
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 800, fontSize: '1.1rem', color: isBlocked ? '#fc8181' : '#68d391', marginBottom: '2px' }}>
                    {isBlocked ? '⚠ THREAT DETECTED' : '✓ CLEAN PAGE'}
                  </div>
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-dim)' }}>
                    {webScan.page_title || webScan.url}
                  </div>
                </div>
                {/* Risk score badge */}
                <div style={{
                  background: isBlocked ? 'rgba(197,48,48,0.15)' : 'rgba(39,103,73,0.15)',
                  border: `1px solid ${isBlocked ? '#C53030' : '#276749'}`,
                  borderRadius: '8px', padding: '8px 16px', textAlign: 'center',
                }}>
                  <div style={{ fontSize: '1.5rem', fontWeight: 900, color: isBlocked ? '#fc8181' : '#68d391', lineHeight: 1 }}>
                    {result.risk_score}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', fontWeight: 600, letterSpacing: '0.05em' }}>RISK</div>
                </div>
              </div>

              {/* Scan stats */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', marginBottom: '20px' }}>
                {[
                  { label: 'HIDDEN DOM', value: webScan.hidden_findings_count ?? 0, icon: EyeOff },
                  { label: 'OCR HITS', value: webScan.ocr_findings_count ?? 0, icon: Camera },
                  { label: 'REDIRECTS', value: webScan.redirect_findings_count ?? 0, icon: GitBranch },
                ].map(stat => {
                  const StatIcon = stat.icon;
                  return (
                    <div key={stat.label} style={{
                      background: '#0f0f1a', border: '1px solid #1e2235',
                      borderRadius: '8px', padding: '12px', textAlign: 'center',
                    }}>
                      <StatIcon size={16} color="#7B8CDE" style={{ marginBottom: '4px' }} />
                      <div style={{ fontSize: '1.3rem', fontWeight: 800, color: stat.value > 0 ? '#fc8181' : '#68d391' }}>{stat.value}</div>
                      <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', fontWeight: 600, letterSpacing: '0.05em' }}>{stat.label}</div>
                    </div>
                  );
                })}
              </div>

              {/* Threat cards */}
              {deduped.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: '10px' }}>
                    DETECTED THREATS ({deduped.length})
                  </h4>
                  {deduped.map((threat, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.06 }}
                      onClick={() => openModal(threat)}
                      style={{
                        background: '#100a0a',
                        border: '1px solid rgba(197,48,48,0.3)',
                        borderLeft: '3px solid #C53030',
                        borderRadius: '8px',
                        padding: '12px 16px',
                        marginBottom: '8px',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        transition: 'background 0.15s ease',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = '#180d0d'}
                      onMouseLeave={e => e.currentTarget.style.background = '#100a0a'}
                    >
                      <AlertCircle size={16} color="#C53030" style={{ flexShrink: 0 }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontWeight: 700, fontSize: '0.88rem', color: '#fc8181' }}>{threat.title}</div>
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)', marginTop: '2px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {threat.description}
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 }}>
                        <span style={{ fontSize: '0.65rem', background: 'rgba(197,48,48,0.15)', color: '#fc8181', borderRadius: '4px', padding: '2px 6px', fontWeight: 700 }}>
                          VIEW ↗
                        </span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}

              {deduped.length === 0 && !isBlocked && (
                <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                  <ShieldCheck size={32} color="#48bb78" style={{ marginBottom: '8px' }} />
                  <div>No hidden injection threats found in this page.</div>
                </div>
              )}

            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ── Right panel: Screenshot preview ── */}
      <div>
        <div style={{
          background: '#0a0a14',
          border: '1px solid #1e2235',
          borderRadius: '12px',
          overflow: 'hidden',
          minHeight: '400px',
          display: 'flex',
          flexDirection: 'column',
        }}>
          {/* Browser chrome mockup */}
          <div style={{ background: '#111827', padding: '10px 16px', display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #1e2235' }}>
            <div style={{ display: 'flex', gap: '6px' }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444' }} />
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#f59e0b' }} />
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#22c55e' }} />
            </div>
            <div style={{
              flex: 1, background: '#1f2937', borderRadius: '6px', padding: '4px 12px',
              fontSize: '0.75rem', color: '#6b7280', fontFamily: 'var(--font-mono)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {webScan.url || url || 'https://'}
            </div>
          </div>

          {/* Screenshot or placeholder */}
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {webScan.screenshot_b64 ? (
              <img
                src={`data:image/png;base64,${webScan.screenshot_b64}`}
                alt="Page screenshot"
                style={{ width: '100%', display: 'block', maxHeight: '600px', objectFit: 'cover', objectPosition: 'top' }}
              />
            ) : loading ? (
              <div style={{ textAlign: 'center', padding: '48px 24px', color: 'var(--text-dim)' }}>
                <div style={{ marginBottom: '16px' }}>
                  <Globe size={40} color="#7B8CDE" style={{ animation: 'spin 1.5s linear infinite' }} />
                </div>
                <div style={{ fontSize: '0.85rem' }}>Rendering page...</div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '48px 24px', color: 'var(--text-dim)' }}>
                <Globe size={40} color="#2d3a6b" style={{ marginBottom: '16px' }} />
                <div style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '6px' }}>Page Preview</div>
                <div style={{ fontSize: '0.78rem', color: '#4a5568' }}>
                  Enter a URL above to scan.<br />A screenshot will appear here.
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Redirect chain */}
        {webScan.redirects && webScan.redirects.length > 0 && (
          <div style={{ marginTop: '16px', background: '#0f0f1a', border: '1px solid #1e2235', borderRadius: '8px', padding: '12px 16px' }}>
            <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: '8px' }}>
              REDIRECT CHAIN
            </div>
            {webScan.redirects.map((r, i) => (
              <div key={i} style={{ fontSize: '0.75rem', color: '#718096', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
                → {r}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Threat Detail Modal ── */}
      <AnimatePresence>
        {showModal && selectedThreat && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}
            onClick={closeModal}
          >
            <motion.div
              initial={{ scale: 0.92, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.92, opacity: 0 }}
              onClick={e => e.stopPropagation()}
              style={{ background: '#0f0f1a', border: '1px solid #C53030', borderRadius: '14px', maxWidth: '700px', width: '100%', maxHeight: '80vh', overflow: 'auto', padding: '28px' }}
            >
              {/* Modal header */}
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '20px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                    <AlertCircle size={18} color="#C53030" />
                    <span style={{ fontWeight: 800, fontSize: '1rem', color: '#fc8181' }}>{selectedThreat.title}</span>
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                    Severity: <strong style={{ color: selectedThreat.severity === 'CRITICAL' ? '#fc8181' : '#f6ad55' }}>{selectedThreat.severity || 'MEDIUM'}</strong>
                  </div>
                </div>
                <button onClick={closeModal} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4a5568', padding: '4px' }}>
                  <X size={20} />
                </button>
              </div>

              {/* Exact payload */}
              <div style={{ marginBottom: '16px' }}>
                <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-dim)', letterSpacing: '0.1em', marginBottom: '8px' }}>
                  EXACT PAYLOAD
                </div>
                <pre style={{ background: '#1a0a0a', border: '1px solid rgba(197,48,48,0.3)', borderRadius: '8px', padding: '14px', fontSize: '0.78rem', color: '#fc8181', whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'var(--font-mono)', margin: 0 }}>
                  {selectedThreat.evidence || selectedThreat.description || '—'}
                </pre>
              </div>

              {/* WHY THIS WAS FLAGGED */}
              <div style={{ background: 'rgba(123,140,222,0.05)', border: '1px solid rgba(123,140,222,0.2)', borderRadius: '8px', padding: '14px' }}>
                <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#7B8CDE', letterSpacing: '0.1em', marginBottom: '6px' }}>
                  WHY THIS WAS FLAGGED
                </div>
                <div style={{ fontSize: '0.82rem', color: '#a0aec0', lineHeight: 1.6 }}>
                  {selectedThreat.description || 'Hidden content detected that may carry prompt injection instructions targeting AI agents.'}
                </div>
                {selectedThreat.verdict && (
                  <div style={{ marginTop: '8px', fontSize: '0.78rem', color: '#7B8CDE', fontWeight: 600 }}>
                    {selectedThreat.verdict}
                  </div>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}

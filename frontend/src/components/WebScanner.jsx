import React, { useState, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Globe, Search, ShieldAlert, ShieldCheck, EyeOff, Tag,
  AlertCircle, ExternalLink, X, ChevronRight, Link2,
  Code2, Camera, GitBranch, Layers, FileText, ArrowRight, Scan
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

  const threatList = [];
  const seenKeys = new Set();

  const formatLocation = (loc) => {
    if (!loc) return 'HTML Page Source';
    if (loc.includes('Comment')) return 'HTML Comment (<!-- -->)';
    if (loc.includes('CSS') || loc.includes('Class')) return 'CSS Hidden Element (display:none)';
    if (loc.includes('JavaScript') || loc.includes('script')) return 'JavaScript (<script> Tag)';
    if (loc.includes('Attribute') || loc.includes('alt')) return 'HTML Attribute (alt / title)';
    if (loc.includes('Zero-Width')) return 'Zero-Width Unicode Characters';
    if (loc.includes('SVG')) return 'SVG Graphic Text Element';
    if (loc.includes('OCR')) return 'Screenshot OCR Text';
    return loc;
  };

  // 1. Process discrete invisible DOM findings (individual raw payload + exact location)
  if (invisibleFindings.length > 0) {
    invisibleFindings.forEach((f, idx) => {
      const rawLocation = f.field || f.type || 'DOM Element';
      const location = formatLocation(rawLocation);
      const title = f.indicator || `${rawLocation} Injection`;
      const val = (f.value || '').trim();
      const key = `${location}-${val.substring(0, 40)}`;

      if (!seenKeys.has(key) && val) {
        seenKeys.add(key);
        threatList.push({
          id: idx,
          title: title,
          location: location,
          one_liner: f.reason || `Hidden payload directive embedded inside ${location}`,
          description: f.reason || `Hidden payload or directive detected in ${location}`,
          evidence: val,
          verdict: '→ Security boundary violation detected',
          severity: f.confidence === 'HIGH' ? 'CRITICAL' : 'MEDIUM',
        });
      }
    });
  }

  // 2. If no individual findings found, use high-level pipeline indicators
  if (indicators.length > 0) {
    indicators.forEach((ind, idx) => {
      const title = ind.title || 'Instruction Violation';
      const key = `ind-${title}-${(ind.evidence || '').substring(0, 30)}`;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        threatList.push({
          id: threatList.length + idx,
          title: title,
          location: formatLocation(ind.location || 'HTML Page Source'),
          one_liner: ind.description || 'Prompt override pattern detected in page text.',
          description: ind.description || 'Attempt to supersede system instructions',
          evidence: ind.evidence || (ind.quote ? ind.quote.replace(/^"|"$/g, '') : ''),
          verdict: ind.verdict || '→ Override attempt detected',
          severity: ind.severity || 'CRITICAL',
        });
      }
    });
  }

  const deduped = threatList;

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto', fontFamily: 'var(--font-sans)', color: '#1e293b' }}>
      
      {/* ── Top URL Search Input Bar ── */}
      <div style={{
        background: '#ffffff',
        borderRadius: '16px',
        padding: '8px 12px 8px 20px',
        display: 'flex',
        alignItems: 'center',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
        border: '1px solid #e2e8f0',
        marginBottom: '24px',
        transition: 'all 0.2s ease',
      }}>
        <Globe size={20} color="#64748b" style={{ marginRight: '14px', flexShrink: 0 }} />
        <input
          ref={inputRef}
          value={url}
          onChange={e => setUrl(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="https://www.vengenceui.com/components/books-showcase"
          style={{
            flex: 1,
            background: 'transparent',
            border: 'none',
            outline: 'none',
            color: '#0f172a',
            fontSize: '0.95rem',
            fontWeight: 500,
            padding: '10px 0',
          }}
        />
        <button
          onClick={handleScan}
          disabled={!url.trim() || loading}
          style={{
            background: loading ? '#94a3b8' : 'linear-gradient(135deg, #4f46e5, #4338ca)',
            border: 'none',
            borderRadius: '12px',
            color: '#ffffff',
            padding: '12px 24px',
            fontWeight: 700,
            fontSize: '0.9rem',
            cursor: loading ? 'not-allowed' : 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            boxShadow: '0 4px 12px rgba(79, 70, 229, 0.25)',
            transition: 'all 0.2s ease',
          }}
        >
          <Scan size={18} />
          <span>{loading ? 'Scanning...' : 'Start Scan'}</span>
        </button>
      </div>

      {/* Phase Progress Loader */}
      <AnimatePresence>
        {loading && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            style={{
              background: '#ffffff',
              borderRadius: '14px',
              padding: '16px 20px',
              border: '1px solid #e2e8f0',
              marginBottom: '24px',
            }}
          >
            <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#475569', marginBottom: '12px' }}>
              SCANNING WEBPAGE DOM & MEDIA
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
              {PHASE_LABELS.map((phase, i) => {
                const PhaseIcon = phase.icon;
                const active = i === phaseIndex;
                const done = i < phaseIndex;
                return (
                  <div key={phase.key} style={{
                    display: 'flex', alignItems: 'center', gap: '10px',
                    padding: '10px 14px', borderRadius: '10px',
                    background: active ? '#eff6ff' : done ? '#f0fdf4' : '#f8fafc',
                    border: `1px solid ${active ? '#bfdbfe' : done ? '#bbf7d0' : '#f1f5f9'}`,
                    transition: 'all 0.3s ease',
                  }}>
                    <PhaseIcon size={16} color={active ? '#2563eb' : done ? '#16a34a' : '#94a3b8'} />
                    <span style={{ fontSize: '0.8rem', color: active ? '#1e40af' : done ? '#15803d' : '#64748b', fontWeight: active ? 700 : 500 }}>
                      {phase.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Error Banner */}
      {error && (
        <div style={{
          padding: '16px 20px', background: '#fef2f2', border: '1px solid #fecaca',
          borderRadius: '12px', color: '#991b1b', fontSize: '0.9rem', fontWeight: 600, marginBottom: '24px'
        }}>
          {error}
        </div>
      )}

      {/* Grid Layout: Main Left Cards + Right Preview Panel */}
      <div style={{ display: 'grid', gridTemplateColumns: result ? '1fr 480px' : '1fr', gap: '24px', alignItems: 'start' }}>

        <div>
          {/* Main Threat Result Banner (Top Red/Green Box) */}
          {result && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
              
              <div style={{
                background: isBlocked
                  ? 'linear-gradient(135deg, #fff5f5 0%, #ffeef0 100%)'
                  : 'linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%)',
                border: `1px solid ${isBlocked ? '#fecaca' : '#bbf7d0'}`,
                borderRadius: '20px',
                padding: '24px 32px',
                marginBottom: '20px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                position: 'relative',
                overflow: 'hidden',
                boxShadow: isBlocked ? '0 8px 30px rgba(239, 68, 68, 0.08)' : '0 8px 30px rgba(34, 197, 94, 0.08)',
              }}>

                {/* Left Side Info */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
                  {/* Concentric Circle Target Icon */}
                  <div style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <div style={{
                      width: '72px', height: '72px', borderRadius: '50%',
                      border: `1.5px dashed ${isBlocked ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center'
                    }}>
                      <div style={{
                        width: '54px', height: '54px', borderRadius: '50%',
                        background: isBlocked ? '#ef4444' : '#22c55e',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        boxShadow: isBlocked ? '0 4px 14px rgba(239,68,68,0.35)' : '0 4px 14px rgba(34,197,94,0.35)'
                      }}>
                        {isBlocked
                          ? <ShieldAlert size={28} color="#ffffff" />
                          : <ShieldCheck size={28} color="#ffffff" />}
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 style={{
                      fontSize: '1.4rem', fontWeight: 900, letterSpacing: '-0.02em',
                      color: isBlocked ? '#dc2626' : '#15803d', margin: '0 0 4px 0'
                    }}>
                      {isBlocked ? 'THREAT DETECTED' : 'CLEAN DOCUMENT'}
                    </h3>
                    <div style={{ fontSize: '0.9rem', color: '#64748b', fontWeight: 500, marginBottom: '10px' }}>
                      {webScan.page_title || 'Web Document Page'} <span style={{ color: '#cbd5e1' }}>•</span> {webScan.url ? new URL(webScan.url).hostname : ''}
                    </div>
                    <span style={{
                      fontSize: '0.75rem', fontWeight: 700,
                      background: isBlocked ? '#ffe4e6' : '#dcfce7',
                      color: isBlocked ? '#e11d48' : '#16a34a',
                      borderRadius: '20px', padding: '4px 12px',
                      display: 'inline-block'
                    }}>
                      {isBlocked ? 'Malicious Content Found' : 'No Threat Found'}
                    </span>
                  </div>
                </div>

                {/* Right Side Ring Score */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <div style={{
                    width: '84px', height: '84px', borderRadius: '50%',
                    border: `6px solid ${isBlocked ? '#ef4444' : '#22c55e'}`,
                    display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                    background: '#ffffff',
                    boxShadow: '0 4px 12px rgba(0,0,0,0.05)',
                    marginBottom: '8px'
                  }}>
                    <span style={{ fontSize: '1.6rem', fontWeight: 900, color: isBlocked ? '#dc2626' : '#15803d', lineHeight: 1 }}>
                      {result.risk_score}
                    </span>
                    <span style={{ fontSize: '0.65rem', color: '#94a3b8', fontWeight: 700 }}>/100</span>
                  </div>
                  <div style={{ fontSize: '0.65rem', fontWeight: 800, color: '#64748b', letterSpacing: '0.05em', marginBottom: '4px' }}>
                    RISK SCORE
                  </div>
                  <span style={{
                    fontSize: '0.7rem', fontWeight: 700,
                    background: isBlocked ? '#fee2e2' : '#dcfce7',
                    color: isBlocked ? '#991b1b' : '#166534',
                    borderRadius: '12px', padding: '2px 8px'
                  }}>
                    {isBlocked ? 'High Risk' : 'Low Risk'}
                  </span>
                </div>

              </div>

              {/* 3 Stat Cards Row */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '28px' }}>
                
                {/* Card 1: Hidden Elements */}
                <div style={{
                  background: '#ffffff', borderRadius: '16px', padding: '20px',
                  border: '1px solid #e2e8f0', boxShadow: '0 2px 10px rgba(0,0,0,0.02)',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                }}>
                  <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                    <div style={{
                      width: '44px', height: '44px', borderRadius: '12px',
                      background: '#eff6ff', display: 'flex', alignItems: 'center', justifyContent: 'center'
                    }}>
                      <EyeOff size={22} color="#3b82f6" />
                    </div>
                    <div>
                      <div style={{ fontSize: '1.6rem', fontWeight: 900, color: '#1d4ed8', lineHeight: 1 }}>
                        {webScan.hidden_findings_count ?? 0}
                      </div>
                      <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#1e293b', marginTop: '2px' }}>
                        Hidden Elements
                      </div>
                      <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '2px' }}>
                        Potentially hidden content detected
                      </div>
                    </div>
                  </div>
                  <ChevronRight size={18} color="#cbd5e1" />
                </div>

                {/* Card 2: OCR Hits */}
                <div style={{
                  background: '#ffffff', borderRadius: '16px', padding: '20px',
                  border: '1px solid #e2e8f0', boxShadow: '0 2px 10px rgba(0,0,0,0.02)',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                }}>
                  <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                    <div style={{
                      width: '44px', height: '44px', borderRadius: '12px',
                      background: '#f3e8ff', display: 'flex', alignItems: 'center', justifyContent: 'center'
                    }}>
                      <FileText size={22} color="#a855f7" />
                    </div>
                    <div>
                      <div style={{ fontSize: '1.6rem', fontWeight: 900, color: '#7e22ce', lineHeight: 1 }}>
                        {webScan.ocr_findings_count ?? 0}
                      </div>
                      <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#1e293b', marginTop: '2px' }}>
                        OCR Hits
                      </div>
                      <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '2px' }}>
                        Text extracted from images
                      </div>
                    </div>
                  </div>
                  <ChevronRight size={18} color="#cbd5e1" />
                </div>

                {/* Card 3: Redirects */}
                <div style={{
                  background: '#ffffff', borderRadius: '16px', padding: '20px',
                  border: '1px solid #e2e8f0', boxShadow: '0 2px 10px rgba(0,0,0,0.02)',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                }}>
                  <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                    <div style={{
                      width: '44px', height: '44px', borderRadius: '12px',
                      background: '#f0fdf4', display: 'flex', alignItems: 'center', justifyContent: 'center'
                    }}>
                      <GitBranch size={22} color="#22c55e" />
                    </div>
                    <div>
                      <div style={{ fontSize: '1.6rem', fontWeight: 900, color: '#15803d', lineHeight: 1 }}>
                        {webScan.redirect_findings_count ?? 0}
                      </div>
                      <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#1e293b', marginTop: '2px' }}>
                        Redirects
                      </div>
                      <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '2px' }}>
                        No suspicious redirects found
                      </div>
                    </div>
                  </div>
                  <ChevronRight size={18} color="#cbd5e1" />
                </div>

              </div>

              {/* Detected Threats Section */}
              <div style={{ marginBottom: '24px' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 800, color: '#0f172a', marginBottom: '14px' }}>
                  Detected Threats ({deduped.length})
                </h4>

                {deduped.length > 0 ? (
                  deduped.map((threat, i) => (
                    <div
                      key={i}
                      onClick={() => openModal(threat)}
                      style={{
                        background: '#ffffff',
                        borderRadius: '16px',
                        borderLeft: '4px solid #ef4444',
                        borderTop: '1px solid #e2e8f0',
                        borderRight: '1px solid #e2e8f0',
                        borderBottom: '1px solid #e2e8f0',
                        padding: '16px 20px',
                        marginBottom: '12px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        cursor: 'pointer',
                        boxShadow: '0 2px 8px rgba(0,0,0,0.02)',
                        transition: 'transform 0.15s ease, boxShadow 0.15s ease',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                        <div style={{
                          width: '36px', height: '36px', borderRadius: '50%',
                          background: '#fef2f2', border: '1px solid #fecaca',
                          display: 'flex', alignItems: 'center', justifyContent: 'center'
                        }}>
                          <AlertCircle size={20} color="#ef4444" />
                        </div>
                        <div>
                          <div style={{ fontWeight: 800, fontSize: '0.95rem', color: '#dc2626' }}>
                            {threat.title}
                          </div>
                          <div style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '2px' }}>
                            {threat.description || 'Sequence pattern requiring validation.'}
                          </div>
                        </div>
                      </div>

                      <button
                        onClick={(e) => { e.stopPropagation(); openModal(threat); }}
                        style={{
                          background: '#ffffff',
                          border: '1px solid #fca5a5',
                          borderRadius: '20px',
                          color: '#ef4444',
                          padding: '6px 14px',
                          fontWeight: 700,
                          fontSize: '0.78rem',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}
                      >
                        <span>View Details</span>
                        <ChevronRight size={14} />
                      </button>
                    </div>
                  ))
                ) : (
                  <div style={{ background: '#ffffff', borderRadius: '16px', border: '1px solid #e2e8f0', padding: '32px', textAlign: 'center', color: '#64748b' }}>
                    <ShieldCheck size={36} color="#22c55e" style={{ marginBottom: '8px' }} />
                    <div style={{ fontSize: '0.9rem', fontWeight: 600 }}>No active threats detected on this page.</div>
                  </div>
                )}
              </div>

            </motion.div>
          )}

          {!result && !loading && (
            <div style={{ background: '#ffffff', borderRadius: '20px', border: '1px solid #e2e8f0', padding: '48px 32px', textAlign: 'center' }}>
              <div style={{
                width: '64px', height: '64px', borderRadius: '50%', background: '#eff6ff',
                display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px auto'
              }}>
                <Globe size={32} color="#3b82f6" />
              </div>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#0f172a', margin: '0 0 6px 0' }}>
                Web URL & Indirect Prompt Injection Scanner
              </h3>
              <p style={{ fontSize: '0.88rem', color: '#64748b', maxWidth: '500px', margin: '0 auto 20px auto', lineHeight: 1.6 }}>
                Enter any webpage URL above to perform a 5-layer security audit for hidden DOM payloads,
                obfuscated JavaScript, visual steganography, and indirect prompt injections.
              </p>
            </div>
          )}

        </div>

        {/* ── Right Panel: Rendered Screenshot & Page Preview ── */}
        {result && (
          <div>
            <div style={{
              background: '#ffffff',
              border: '1px solid #e2e8f0',
              borderRadius: '20px',
              overflow: 'hidden',
              boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
            }}>
              {/* Browser chrome Header */}
              <div style={{ background: '#f8fafc', padding: '12px 16px', display: 'flex', alignItems: 'center', gap: '10px', borderBottom: '1px solid #e2e8f0' }}>
                <div style={{ display: 'flex', gap: '6px' }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444' }} />
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#f59e0b' }} />
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#22c55e' }} />
                </div>
                <div style={{
                  flex: 1, background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: '8px', padding: '4px 12px',
                  fontSize: '0.75rem', color: '#475569', fontFamily: 'var(--font-mono)',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {webScan.url || url || 'https://'}
                </div>
              </div>

              {/* Screenshot display */}
              <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
                {webScan.screenshot_b64 ? (
                  <img
                    src={`data:image/png;base64,${webScan.screenshot_b64}`}
                    alt="Page Screenshot"
                    style={{ width: '100%', display: 'block' }}
                  />
                ) : (
                  <div style={{ padding: '48px 24px', textAlign: 'center', color: '#94a3b8' }}>
                    No preview screenshot available.
                  </div>
                )}
              </div>
            </div>
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
            style={{
              position: 'fixed', inset: 0, background: 'rgba(15, 23, 42, 0.6)',
              backdropFilter: 'blur(4px)', zIndex: 1000,
              display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px'
            }}
            onClick={closeModal}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={e => e.stopPropagation()}
              style={{
                background: '#ffffff', borderRadius: '20px', border: '1px solid #e2e8f0',
                maxWidth: '650px', width: '100%', maxHeight: '85vh', overflow: 'auto', padding: '28px',
                boxShadow: '0 20px 40px rgba(0, 0, 0, 0.15)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '20px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                    <AlertCircle size={20} color="#ef4444" />
                    <span style={{ fontWeight: 900, fontSize: '1.15rem', color: '#dc2626' }}>{selectedThreat.title}</span>
                  </div>
                  {/* One-liner summary */}
                  <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#334155', margin: '4px 0 8px 0' }}>
                    {selectedThreat.one_liner || selectedThreat.description}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                    <span>Severity Level: <strong style={{ color: selectedThreat.severity === 'CRITICAL' ? '#dc2626' : '#d97706' }}>{selectedThreat.severity || 'MEDIUM'}</strong></span>
                    <span style={{ color: '#cbd5e1' }}>•</span>
                    <span style={{
                      fontSize: '0.75rem', fontWeight: 700, background: '#eff6ff',
                      color: '#1d4ed8', border: '1px solid #bfdbfe', borderRadius: '6px', padding: '3px 10px'
                    }}>
                      📍 Found in: {selectedThreat.location || 'HTML Page Source'}
                    </span>
                  </div>
                </div>
                <button onClick={closeModal} style={{ background: '#f1f5f9', border: 'none', borderRadius: '50%', width: '32px', height: '32px', cursor: 'pointer', color: '#64748b', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <X size={18} />
                </button>
              </div>

              {/* Exact Payload Box */}
              <div style={{ marginBottom: '20px' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 800, color: '#475569', letterSpacing: '0.05em', marginBottom: '8px' }}>
                  EXACT UNTRUNCATED PAYLOAD
                </div>
                <pre style={{
                  background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '12px',
                  padding: '16px', fontSize: '0.82rem', color: '#991b1b',
                  whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'var(--font-mono)', margin: 0
                }}>
                  {selectedThreat.evidence || selectedThreat.quote || selectedThreat.description || '—'}
                </pre>
              </div>

              {/* Why Flagged Box */}
              <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: '12px', padding: '16px' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 800, color: '#334155', letterSpacing: '0.05em', marginBottom: '6px' }}>
                  SECURITY ANALYSIS & DIAGNOSTICS
                </div>
                <div style={{ fontSize: '0.85rem', color: '#475569', lineHeight: 1.6 }}>
                  {selectedThreat.description || 'Hidden text or sequence anomaly detected that violates prompt security policies.'}
                </div>
                {selectedThreat.verdict && (
                  <div style={{ marginTop: '8px', fontSize: '0.8rem', color: '#2563eb', fontWeight: 700 }}>
                    {selectedThreat.verdict}
                  </div>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

    </div>
  );
}

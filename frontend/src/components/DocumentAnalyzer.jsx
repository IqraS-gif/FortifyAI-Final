import React, { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Upload, FileCode, ShieldAlert, ShieldCheck, EyeOff, Tag, FileText, AlertCircle, Target, ChevronRight, ExternalLink, X } from 'lucide-react';

export default function DocumentAnalyzer({ onScanComplete }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      handleDocumentScan(selectedFile);
    }
  };

  const handleDocumentScan = async (selectedFile = file) => {
    if (!selectedFile) return;
    setLoading(true);
    setError('');

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('sensitivity_profile', 'BALANCED');

    try {
      const res = await fetch('/api/scan/document', {
        method: 'POST',
        body: formData
      });

      if (!res.ok) throw new Error('Document scan failed.');
      const data = await res.json();
      setResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err) {
      setError(err.message || 'Error processing document file.');
    } finally {
      setLoading(false);
    }
  };

  const openThreatModal = (threat = null) => {
    setSelectedThreat(threat);
    setShowModal(true);
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      {/* Upload Box & File Controls */}
      <div className="shiny-card" style={{ padding: '28px', background: '#FFFFFF', borderRadius: '16px' }}>
        <div style={{ marginBottom: '20px' }}>
          <h2 style={{ fontSize: '1.2rem', marginBottom: '4px', color: 'var(--color-black)' }}>Document & Code Security Scanner</h2>
          <p className="text-dim" style={{ fontSize: '0.85rem' }}>
            Scans uploaded PDFs, DOCX, Code Files (.py, .js, .ts, .java, .cpp, .sh, .sql), TXT, and HTML fed to AI models for hidden prompt injections, code execution exploits, secret leakage, and metadata injection.
          </p>
        </div>

        {/* Dropzone */}
        <div
          style={{
            border: '2px dashed #6F4E37',
            borderRadius: '10px',
            padding: '36px 20px',
            textAlign: 'center',
            background: '#FDFBF7',
            cursor: 'pointer',
            marginBottom: '20px',
            transition: 'all 0.2s ease'
          }}
          onClick={() => document.getElementById('fileUploadInput').click()}
        >
          <Upload size={36} color="#6F4E37" style={{ marginBottom: '12px' }} />
          <h3 style={{ fontSize: '1.0rem', marginBottom: '6px', color: 'var(--color-black)' }}>
            {file ? file.name : 'Select or Drop Document or Code File'}
          </h3>
          <p className="mono-text text-dim" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
            SUPPORTED FORMATS: .PY, .JS, .TS, .JAVA, .CPP, .SH, .XML, .JSON, .PDF, .DOCX, .HTML, .TXT
          </p>
          <input
            id="fileUploadInput"
            type="file"
            accept=".pdf,.docx,.doc,.html,.htm,.txt,.py,.js,.ts,.jsx,.tsx,.java,.cpp,.c,.cs,.go,.rs,.sh,.php,.rb,.json,.yaml,.yml,.xml,.sql"
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
        </div>

        <button
          className="btn-primary"
          onClick={() => handleDocumentScan()}
          disabled={!file || loading}
          style={{ width: '100%', justifyContent: 'center', background: '#6F4E37', borderColor: '#5C4033', padding: '12px', borderRadius: '8px', fontWeight: 700 }}
        >
          <FileCode size={16} />
          <span>{loading ? 'ANALYZING DOCUMENT...' : 'ANALYZE DOCUMENT'}</span>
        </button>

        {error && (
          <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(197, 48, 48, 0.08)', border: '1px solid var(--status-blocked)', borderRadius: '6px', fontSize: '0.85rem', color: 'var(--status-blocked)', fontWeight: 600 }}>
            {error}
          </div>
        )}
      </div>

      {/* Result Diagnostics */}
      <div>
        {result ? (
          <div style={{
            background: '#FFFFFF',
            borderRadius: '16px',
            border: '1px solid #E2E8F0',
            boxShadow: '0 8px 30px rgba(0, 0, 0, 0.04)',
            padding: '28px',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px'
          }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #E2E8F0', paddingBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{
                  width: '44px',
                  height: '44px',
                  borderRadius: '10px',
                  background: result.action === 'BLOCKED' ? 'rgba(197, 48, 48, 0.08)' : 'rgba(13, 148, 136, 0.08)',
                  border: `1px solid ${result.action === 'BLOCKED' ? 'rgba(197, 48, 48, 0.2)' : 'rgba(13, 148, 136, 0.2)'}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  {result.action === 'BLOCKED' ? (
                    <ShieldAlert size={26} color="#C53030" />
                  ) : (
                    <ShieldCheck size={26} color="#0D9488" />
                  )}
                </div>
                <div>
                  <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: result.action === 'BLOCKED' ? '#C53030' : '#0D9488' }}>
                    {result.action}
                  </h2>
                  <div className="mono-text" style={{ fontSize: '0.76rem', color: '#64748B', fontWeight: 700 }}>
                    TYPE: {result.layer_breakdown?.layer_3_document?.document_type || 'DOCUMENT'}
                  </div>
                </div>
              </div>

              <div style={{ textAlign: 'right' }}>
                <div className="mono-text" style={{ fontSize: '1.25rem', fontWeight: 800, color: '#09090B' }}>
                  {result.latency?.total_duration_ms} ms
                </div>
                <div className="mono-text" style={{ fontSize: '0.68rem', fontWeight: 600, color: '#0D9488' }}>
                  SCAN LATENCY
                </div>
              </div>
            </div>

            {/* Risk Score */}
            <div style={{ background: '#F8F9FA', border: '1px solid #E2E8F0', borderRadius: '12px', padding: '16px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div className="mono-text" style={{ fontSize: '0.68rem', color: '#64748B', fontWeight: 800 }}>DOCUMENT RISK SCORE</div>
                <div className="mono-text" style={{ fontSize: '1.8rem', fontWeight: 900, color: result.action === 'BLOCKED' ? '#C53030' : '#0D9488' }}>
                  {result.risk_score} <span style={{ fontSize: '1.2rem', color: '#64748B' }}>/ 100</span>
                </div>
              </div>
              <span className={`badge ${result.action === 'BLOCKED' ? 'badge-blocked' : 'badge-allowed'}`}>
                {result.action === 'BLOCKED' ? 'THREAT DETECTED' : 'CLEAN DOCUMENT'}
              </span>
            </div>

            {/* Human Explanation Summary */}
            <div style={{
              background: result.action === 'BLOCKED' ? '#FFF5F5' : '#F0FDF4',
              border: `1px solid ${result.action === 'BLOCKED' ? '#FED7D7' : '#BBF7D0'}`,
              borderRadius: '10px',
              padding: '12px 16px',
              display: 'flex',
              alignItems: 'center',
              gap: '10px'
            }}>
              <AlertCircle size={18} color={result.action === 'BLOCKED' ? '#C53030' : '#0D9488'} style={{ flexShrink: 0 }} />
              <div style={{ fontSize: '0.86rem', fontWeight: 600, color: result.action === 'BLOCKED' ? '#9B2C2C' : '#115E59', lineHeight: '1.4' }}>
                {result.human_summary_one_liner}
              </div>
            </div>

            {/* Detected Indicators Evidence */}
            {result.structured_indicators && result.structured_indicators.length > 0 && (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <div className="mono-text" style={{ fontSize: '0.78rem', fontWeight: 800, color: '#09090B', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Target size={16} color="#6F4E37" /> DETECTED INJECTION THREATS
                  </div>
                  <button
                    onClick={() => openThreatModal(result.structured_indicators[0])}
                    className="btn-preset"
                    style={{ fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '4px' }}
                  >
                    <ExternalLink size={12} /> EXPAND EVIDENCE
                  </button>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {result.structured_indicators.map((ind, idx) => (
                    <div
                      key={idx}
                      style={{
                        background: '#F8F9FA',
                        border: '1px solid #E2E8F0',
                        borderRadius: '10px',
                        padding: '14px',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease'
                      }}
                      onClick={() => openThreatModal(ind)}
                      onMouseEnter={(e) => e.currentTarget.style.borderColor = '#C53030'}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#E2E8F0'}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ fontSize: '0.88rem', fontWeight: 800, color: '#C53030' }}>
                          {ind.title}
                        </div>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#6F4E37', display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <ExternalLink size={12} /> VIEW FULL TEXT
                        </span>
                      </div>
                      {ind.description && (
                        <div style={{ fontSize: '0.8rem', color: '#475569', marginTop: '4px', fontWeight: 500 }}>
                          {ind.description}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Invisible Text Findings */}
            <div>
              <div className="mono-text" style={{ fontSize: '0.78rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 800, color: '#09090B' }}>
                <EyeOff size={15} color="#C53030" /> INVISIBLE / HIDDEN TEXT THREATS
              </div>
              {result.document_threat_details?.invisible_text_findings && result.document_threat_details.invisible_text_findings.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {result.document_threat_details.invisible_text_findings.map((inv, idx) => (
                    <div
                      key={idx}
                      style={{ background: '#F8F9FA', border: '1px solid #E2E8F0', padding: '12px 14px', borderRadius: '8px', cursor: 'pointer', transition: 'all 0.15s ease' }}
                      onClick={() => openThreatModal({
                        title: inv.type || inv.element || 'Hidden Text Threat',
                        quote: inv.text,
                        verdict: '→ Security boundary violation detected',
                        description: typeof inv.reason === 'string' && inv.reason.length < 120 ? inv.reason : 'Document contains hidden prompt injection payload engineered to alter model behavior.'
                      })}
                      onMouseEnter={(e) => e.currentTarget.style.borderColor = '#C53030'}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#E2E8F0'}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ fontSize: '0.88rem', fontWeight: 800, color: '#C53030' }}>
                          {inv.type || inv.element || 'Hidden Text Payload'}
                        </div>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#6F4E37', display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <ExternalLink size={12} /> VIEW FULL TEXT
                        </span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: '#475569', marginTop: '4px', fontWeight: 500 }}>
                        Injection payload detected in document — click to view full text
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mono-text" style={{ fontSize: '0.8rem', background: '#F8F9FA', border: '1px solid #E2E8F0', padding: '10px', borderRadius: '6px', color: '#0D9488', fontWeight: 600 }}>
                  No invisible text or microscopic font payloads found.
                </div>
              )}
            </div>

            {/* Metadata Findings */}
            <div>
              <div className="mono-text" style={{ fontSize: '0.78rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 800, color: '#09090B' }}>
                <Tag size={15} color="#6F4E37" /> METADATA FIELD THREATS
              </div>
              {result.document_threat_details?.metadata_findings && result.document_threat_details.metadata_findings.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {result.document_threat_details.metadata_findings.map((m, idx) => (
                    <div
                      key={idx}
                      style={{ background: '#F8F9FA', border: '1px solid #E2E8F0', padding: '12px 14px', borderRadius: '8px', cursor: 'pointer', transition: 'all 0.15s ease' }}
                      onClick={() => openThreatModal({
                        title: `Metadata: ${m.field}`,
                        quote: m.value,
                        verdict: '→ Metadata injection threat detected',
                        description: typeof m.reason === 'string' && m.reason.length < 120 ? m.reason : `Prompt injection payload hidden inside metadata field '${m.field}'.`
                      })}
                      onMouseEnter={(e) => e.currentTarget.style.borderColor = '#C53030'}
                      onMouseLeave={(e) => e.currentTarget.style.borderColor = '#E2E8F0'}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ fontSize: '0.88rem', fontWeight: 800, color: '#C53030' }}>
                          FIELD: {m.field}
                        </div>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#6F4E37', display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <ExternalLink size={12} /> VIEW FULL TEXT
                        </span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: '#475569', marginTop: '4px', fontWeight: 500 }}>
                        Suspicious metadata payload detected in field — click to view full text
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mono-text" style={{ fontSize: '0.8rem', background: '#F8F9FA', border: '1px solid #E2E8F0', padding: '10px', borderRadius: '6px', color: '#0D9488', fontWeight: 600 }}>
                  No prompt injections found in document metadata fields.
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="shiny-card" style={{ padding: '40px 24px', textAlign: 'center', background: '#FFFFFF', borderRadius: '16px' }}>
            <FileText size={40} color="var(--text-muted)" style={{ marginBottom: '16px' }} />
            <h3 style={{ fontSize: '1.1rem', marginBottom: '8px', color: 'var(--color-black)' }}>Document Security Inspector</h3>
            <p className="text-dim" style={{ fontSize: '0.85rem' }}>
              Upload a document to inspect hidden text layers, white font payloads, XML tags, and PDF metadata fields.
            </p>
          </div>
        )}
      </div>

      {/* Framer-Motion Animated Bounce Modal Popup for Document Injection Text */}
      <AnimatePresence>
        {showModal && result && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'rgba(9, 9, 11, 0.65)',
              backdropFilter: 'blur(8px)',
              zIndex: 10000,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '24px'
            }}
            onClick={() => setShowModal(false)}
          >
            {/* Bounce Card Container */}
            <motion.div
              initial={{ scale: 0.85, opacity: 0, y: 30 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.85, opacity: 0, y: 30 }}
              transition={{ type: 'spring', stiffness: 350, damping: 25 }}
              style={{
                background: '#FFFFFF',
                borderRadius: '24px',
                maxWidth: '720px',
                width: '100%',
                maxHeight: '90vh',
                overflowY: 'auto',
                padding: '32px',
                border: '1px solid #CBD5E1',
                boxShadow: '0 25px 60px rgba(0, 0, 0, 0.25)',
                display: 'flex',
                flexDirection: 'column',
                gap: '24px'
              }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #E2E8F0', paddingBottom: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <ShieldAlert size={26} color="#C53030" />
                  <div>
                    <h2 style={{ fontSize: '1.25rem', fontWeight: 900, color: '#09090B', margin: 0 }}>
                      Document Threat Evidence & Exact Injection Payload
                    </h2>
                  </div>
                </div>
                <button
                  onClick={() => setShowModal(false)}
                  style={{
                    background: '#F1F3F5',
                    border: 'none',
                    borderRadius: '50%',
                    width: '36px',
                    height: '36px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}
                >
                  <X size={18} color="#09090B" />
                </button>
              </div>

              {/* Exact Threat Payload Box */}
              <div>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 800, color: '#09090B', marginBottom: '10px' }}>
                  {selectedThreat ? selectedThreat.title : "Detected Prompt Injection Payload"}
                </h3>
                <div
                  className="mono-text"
                  style={{
                    background: '#FFF5F5',
                    border: '1px solid #FEB2B2',
                    color: '#C53030',
                    padding: '16px 20px',
                    borderRadius: '12px',
                    fontSize: '0.9rem',
                    fontWeight: 600,
                    lineHeight: '1.6',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                    maxHeight: '260px',
                    overflowY: 'auto'
                  }}
                >
                  {selectedThreat ? (selectedThreat.quote || selectedThreat.text) : (result.structured_indicators?.[0]?.quote || "Prompt injection text")}
                </div>
                {/* WHY it was flagged */}
                {selectedThreat && (
                  <div style={{
                    background: '#F8FAFC',
                    border: '1px solid #E2E8F0',
                    borderRadius: '10px',
                    padding: '12px 16px',
                    marginTop: '10px',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px'
                  }}>
                    <span style={{ fontSize: '1rem', marginTop: '1px' }}>💡</span>
                    <div>
                      <div style={{ fontSize: '0.75rem', fontWeight: 800, color: '#94A3B8', letterSpacing: '0.06em', marginBottom: '3px' }}>
                        WHY THIS WAS FLAGGED
                      </div>
                      <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#1E293B', lineHeight: '1.5' }}>
                        {selectedThreat.description && selectedThreat.description.length < 150
                          ? selectedThreat.description
                          : (selectedThreat.reason && selectedThreat.reason.length < 150
                              ? selectedThreat.reason
                              : "Pattern detected violates security guidelines and attempts unauthorized instruction manipulation.")}
                      </div>
                      {selectedThreat.verdict && selectedThreat.verdict.length < 100 && selectedThreat.verdict !== selectedThreat.description && (
                        <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#C53030', marginTop: '6px' }}>
                          {selectedThreat.verdict}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* ModernBERT ML Classification Breakdown */}
              <div>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 800, color: '#09090B', marginBottom: '10px' }}>
                  ML Classification Evidence
                </h3>
                <div style={{ background: '#F8F9FA', border: '1px solid #E2E8F0', borderRadius: '14px', padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 900, color: '#09090B' }}>
                        ModernBERT Sequence Classifier
                      </div>
                      <div className="mono-text" style={{ fontSize: '0.88rem', color: '#C53030', fontWeight: 700, marginTop: '2px' }}>
                        {result.layer_breakdown?.layer_2_modernbert?.confidence_score > 0.3 ? 'Prompt Injection' : 'Clean'} · {((result.layer_breakdown?.layer_2_modernbert?.confidence_score || 0.75) * 100).toFixed(0)}% confidence
                      </div>
                    </div>
                    <span className="badge badge-blocked" style={{ fontSize: '0.78rem' }}>
                      ML EVIDENCE
                    </span>
                  </div>
                  {result.layer_breakdown?.layer_2_modernbert?.explanation && (
                    <div style={{ fontSize: '0.86rem', color: '#475569', fontWeight: 500, lineHeight: '1.4', borderTop: '1px solid #E2E8F0', paddingTop: '8px' }}>
                      → {result.layer_breakdown.layer_2_modernbert.explanation}
                    </div>
                  )}
                </div>
              </div>

              {/* Close Button */}
              <div style={{ textAlign: 'right', marginTop: '4px' }}>
                <button
                  onClick={() => setShowModal(false)}
                  className="btn-primary"
                  style={{ background: '#6F4E37', borderColor: '#5C4033', padding: '10px 24px', borderRadius: '8px', fontWeight: 700 }}
                >
                  <span>CLOSE THREAT EVIDENCE</span>
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

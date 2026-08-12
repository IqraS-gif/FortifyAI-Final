import React, { useState } from 'react';
import { Upload, FileCode, ShieldAlert, ShieldCheck, EyeOff, Tag, FileText, AlertCircle, Target, ChevronRight } from 'lucide-react';

export default function DocumentAnalyzer({ onScanComplete }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

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

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      {/* Upload Box & File Controls */}
      <div className="shiny-card" style={{ padding: '28px', background: '#FFFFFF', borderRadius: '16px' }}>
        <div style={{ marginBottom: '20px' }}>
          <h2 style={{ fontSize: '1.2rem', marginBottom: '4px', color: 'var(--color-black)' }}>Document Security & Hidden Prompt Scanner</h2>
          <p className="text-dim" style={{ fontSize: '0.85rem' }}>
            Scans uploaded PDFs, DOCX, TXT, and HTML web content fed to AI models for hidden instructions, XML breakouts, invisible text, and metadata injection.
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
            {file ? file.name : 'Select or Drop Document File'}
          </h3>
          <p className="mono-text text-dim" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
            SUPPORTED FORMATS: .PDF, .DOCX, .HTML, .TXT
          </p>
          <input
            id="fileUploadInput"
            type="file"
            accept=".pdf,.docx,.doc,.html,.htm,.txt"
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
        </div>

        <button
          className="btn-primary"
          onClick={handleDocumentScan}
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
                    TYPE: {result.layer_breakdown.layer_3_document.document_type}
                  </div>
                </div>
              </div>

              <div style={{ textAlign: 'right' }}>
                <div className="mono-text" style={{ fontSize: '1.25rem', fontWeight: 800, color: '#09090B' }}>
                  {result.latency.total_duration_ms} ms
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
                <div className="mono-text" style={{ fontSize: '0.78rem', fontWeight: 800, color: '#09090B', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Target size={16} color="#6F4E37" /> DETECTED INJECTION THREATS
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {result.structured_indicators.map((ind, idx) => (
                    <div key={idx} style={{ background: '#F8F9FA', border: '1px solid #E2E8F0', borderRadius: '10px', padding: '12px 14px' }}>
                      <div style={{ fontSize: '0.88rem', fontWeight: 800, color: '#C53030' }}>
                        {ind.title}
                      </div>
                      <div className="mono-text" style={{ background: '#FFF5F5', border: '1px solid #FEB2B2', color: '#C53030', padding: '4px 8px', borderRadius: '6px', fontSize: '0.82rem', marginTop: '4px', display: 'inline-block' }}>
                        {ind.quote || 'Matched document snippet'}
                      </div>
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
              {result.document_threat_details.invisible_text_findings && result.document_threat_details.invisible_text_findings.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {result.document_threat_details.invisible_text_findings.map((inv, idx) => (
                    <div key={idx} style={{ background: '#FFF5F5', border: '1px solid #FED7D7', padding: '10px 14px', borderRadius: '8px' }}>
                      <div className="mono-text" style={{ fontSize: '0.8rem', color: '#C53030', fontWeight: 700 }}>
                        [ALERT] {inv.reason}
                      </div>
                      {inv.text && (
                        <div className="mono-text" style={{ fontSize: '0.82rem', color: '#09090B', marginTop: '4px', fontWeight: 500 }}>
                          "{inv.text}"
                        </div>
                      )}
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
              {result.document_threat_details.metadata_findings && result.document_threat_details.metadata_findings.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {result.document_threat_details.metadata_findings.map((m, idx) => (
                    <div key={idx} style={{ background: '#FFF5F5', border: '1px solid #FED7D7', padding: '10px 14px', borderRadius: '8px' }}>
                      <div className="mono-text" style={{ fontSize: '0.8rem', color: '#C53030', fontWeight: 700 }}>
                        FIELD: {m.field} — {m.reason}
                      </div>
                      <div className="mono-text" style={{ fontSize: '0.82rem', color: '#09090B', marginTop: '4px', fontWeight: 500 }}>
                        VALUE: "{m.value}"
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
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import { Search } from 'lucide-react';

export default function AuditAnalytics() {
  const [summary, setSummary] = useState(null);
  const [logs, setLogs] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchData = async () => {
    try {
      const sumRes = await fetch('/api/analytics/summary');
      if (sumRes.ok) setSummary(await sumRes.json());

      const logRes = await fetch('/api/analytics/logs');
      if (logRes.ok) {
        const data = await logRes.json();
        setLogs(data.logs || []);
      }
    } catch (e) {}
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const filteredLogs = logs.filter(l =>
    (l.input_preview || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (l.action || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Metric Cards */}
      {summary && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: '16px' }}>
          <div className="shiny-card" style={{ padding: '20px' }}>
            <div className="mono-text text-dim" style={{ fontSize: '0.72rem', marginBottom: '4px', fontWeight: 700 }}>TOTAL PROMPT SCANS</div>
            <div className="mono-text" style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-black)' }}>{summary.total_scans}</div>
            <div className="mono-text text-dim" style={{ fontSize: '0.68rem', marginTop: '4px' }}>REAL-TIME AUDIT LOG</div>
          </div>

          <div className="shiny-card-maroon" style={{ padding: '20px' }}>
            <div className="mono-text text-dim" style={{ fontSize: '0.72rem', marginBottom: '4px', fontWeight: 700 }}>ATTACKS BLOCKED</div>
            <div className="mono-text text-maroon" style={{ fontSize: '1.8rem', fontWeight: 800 }}>{summary.blocked_scans}</div>
            <div className="mono-text text-dim" style={{ fontSize: '0.68rem', marginTop: '4px', fontWeight: 600 }}>BLOCK RATE: {summary.block_rate_pct}%</div>
          </div>

          <div className="shiny-card" style={{ padding: '20px' }}>
            <div className="mono-text text-dim" style={{ fontSize: '0.72rem', marginBottom: '4px', fontWeight: 700 }}>AVERAGE LATENCY</div>
            <div className="mono-text" style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--status-allowed)' }}>{summary.avg_latency_ms} ms</div>
            <div className="mono-text text-dim" style={{ fontSize: '0.68rem', marginTop: '4px' }}>SLA TARGET: &lt;100ms</div>
          </div>

          <div className="shiny-card" style={{ padding: '20px' }}>
            <div className="mono-text text-dim" style={{ fontSize: '0.72rem', marginBottom: '4px', fontWeight: 700 }}>SLA COMPLIANCE</div>
            <div className="mono-text" style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-black)' }}>{summary.sla_compliance_pct}%</div>
            <div className="mono-text text-dim" style={{ fontSize: '0.68rem', marginTop: '4px' }}>SUB-100MS GUARANTEE</div>
          </div>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="shiny-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '1.1rem', color: 'var(--color-black)' }}>Security Audit Stream</h2>
            <p className="text-dim" style={{ fontSize: '0.8rem' }}>Immutable event logs for enterprise compliance & security audits</p>
          </div>

          <div style={{ width: '280px', position: 'relative' }}>
            <input
              type="text"
              placeholder="Search audit logs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ paddingLeft: '36px', height: '36px', fontSize: '0.82rem', background: '#FFFFFF' }}
            />
            <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '10px' }} />
          </div>
        </div>

        {/* Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-pitch)' }}>
                <th className="mono-text text-dim" style={{ padding: '12px', fontSize: '0.72rem', fontWeight: 700 }}>ACTION</th>
                <th className="mono-text text-dim" style={{ padding: '12px', fontSize: '0.72rem', fontWeight: 700 }}>RISK SCORE</th>
                <th className="mono-text text-dim" style={{ padding: '12px', fontSize: '0.72rem', fontWeight: 700 }}>PROFILE</th>
                <th className="mono-text text-dim" style={{ padding: '12px', fontSize: '0.72rem', fontWeight: 700 }}>PROMPT PREVIEW</th>
                <th className="mono-text text-dim" style={{ padding: '12px', fontSize: '0.72rem', fontWeight: 700 }}>MATCHED PATTERNS</th>
                <th className="mono-text text-dim" style={{ padding: '12px', fontSize: '0.72rem', fontWeight: 700 }}>LATENCY</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.length > 0 ? (
                filteredLogs.map((log, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <td style={{ padding: '12px' }}>
                      <span className={`badge ${log.action === 'BLOCKED' ? 'badge-blocked' : 'badge-allowed'}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="mono-text" style={{ padding: '12px', fontWeight: 800, color: log.risk_score >= 50 ? 'var(--status-blocked)' : 'var(--color-black)' }}>
                      {log.risk_score}
                    </td>
                    <td className="mono-text text-dim" style={{ padding: '12px', fontSize: '0.78rem', fontWeight: 600 }}>
                      {log.sensitivity_profile}
                    </td>
                    <td className="mono-text" style={{ padding: '12px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--color-black)', fontWeight: 500 }}>
                      {log.input_preview}
                    </td>
                    <td style={{ padding: '12px' }}>
                      {log.matched_patterns && log.matched_patterns.length > 0 ? (
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {log.matched_patterns.map((p, i) => (
                            <span key={i} className="highlight-snippet" style={{ fontSize: '0.7rem' }}>{p}</span>
                          ))}
                        </div>
                      ) : (
                        <span className="mono-text text-dim" style={{ fontSize: '0.75rem' }}>—</span>
                      )}
                    </td>
                    <td className="mono-text" style={{ padding: '12px', fontSize: '0.78rem', color: log.within_sla ? 'var(--status-allowed)' : 'var(--status-warning)', fontWeight: 700 }}>
                      {log.total_duration_ms} ms
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} style={{ padding: '24px', textAlign: 'center' }} className="mono-text text-dim">
                    No security audit records logged yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

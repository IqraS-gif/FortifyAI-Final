import React, { useState, useEffect } from 'react';
import { RefreshCw, Flame, PlusCircle, Database, Play } from 'lucide-react';

export default function RetrainingHub() {
  const [stats, setStats] = useState(null);
  const [feedbackPrompt, setFeedbackPrompt] = useState('');
  const [feedbackLabel, setFeedbackLabel] = useState(1);
  const [simCategory, setSimCategory] = useState('JAILBREAK');
  const [simResult, setSimResult] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const [retrainStatus, setRetrainStatus] = useState('');

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/retrain/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (e) {}
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleSubmitFeedback = async () => {
    if (!feedbackPrompt.trim()) return;
    try {
      const res = await fetch('/api/retrain/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt_text: feedbackPrompt,
          label: feedbackLabel,
          source: 'user_feedback',
          notes: 'Manually logged feedback sample'
        })
      });
      if (res.ok) {
        setFeedbackPrompt('');
        fetchStats();
      }
    } catch (e) {}
  };

  const handleSimulateRedTeam = async () => {
    setSimulating(true);
    setSimResult(null);
    try {
      const res = await fetch('/api/redteam/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_category: simCategory })
      });
      if (res.ok) {
        const data = await res.json();
        setSimResult(data);
        fetchStats();
      }
    } catch (e) {}
    setSimulating(false);
  };

  const handleTriggerRetrain = async () => {
    setRetrainStatus('DISPATCHING MODERNBERT FINE-TUNING PIPELINE...');
    try {
      const res = await fetch('/api/retrain/trigger', { method: 'POST' });
      if (res.ok) {
        setRetrainStatus('FINE-TUNING DISPATCHED! QUEUED SAMPLES INTEGRATED.');
        setTimeout(() => setRetrainStatus(''), 4000);
        fetchStats();
      }
    } catch (e) {
      setRetrainStatus('Failed to trigger training.');
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
      {/* Left Column: Datasets & Red Team Simulator */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        {/* Datasets integrated */}
        <div className="shiny-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <Database size={22} color="var(--accent-maroon)" />
            <div>
              <h2 style={{ fontSize: '1.1rem', color: 'var(--color-black)' }}>ModernBERT Training Datasets</h2>
              <p className="text-dim" style={{ fontSize: '0.8rem' }}>Integrated benchmark datasets & live feedback stream</p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' }}>
            {['jayavibhav/prompt-injection', 'reshabhs/SPML_Chatbot_Prompt_Injection', 'cyberprince/prompt-injection-and-benign-prompt-dataset'].map((ds, idx) => (
              <div key={idx} style={{ background: 'var(--bg-pitch)', padding: '10px 14px', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="mono-text" style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--color-black)' }}>{ds}</span>
                <span className="badge badge-maroon">INTEGRATED</span>
              </div>
            ))}
          </div>

          {stats && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', background: 'var(--color-black)', color: '#FFFFFF', padding: '12px', borderRadius: '6px' }}>
              <div>
                <div className="mono-text" style={{ fontSize: '0.7rem', color: '#A0A0B0', fontWeight: 600 }}>QUEUED FEEDBACK SAMPLES</div>
                <div className="mono-text" style={{ fontSize: '1.4rem', fontWeight: 800, color: '#FF9999' }}>{stats.queued_samples}</div>
              </div>
              <div>
                <div className="mono-text" style={{ fontSize: '0.7rem', color: '#A0A0B0', fontWeight: 600 }}>TOTAL INJECTION SAMPLES</div>
                <div className="mono-text" style={{ fontSize: '1.4rem', fontWeight: 800, color: '#FFFFFF' }}>{stats.injection_samples}</div>
              </div>
            </div>
          )}
        </div>

        {/* Red Team Simulator */}
        <div className="shiny-card-maroon" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <Flame size={22} color="var(--accent-maroon)" />
            <div>
              <h2 style={{ fontSize: '1.1rem', color: 'var(--color-black)' }}>Automated Red-Teaming Simulator</h2>
              <p className="text-dim" style={{ fontSize: '0.8rem' }}>Generates adversarial attack vectors & auto-feeds bypasses to dataset</p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
            <select value={simCategory} onChange={(e) => setSimCategory(e.target.value)} style={{ height: '38px', padding: '0 12px', fontWeight: 600 }}>
              <option value="JAILBREAK">Jailbreak Attacks (DAN)</option>
              <option value="SYSTEM_PROMPT_LEAK">System Prompt Extraction</option>
              <option value="INDIRECT_INJECTION">Indirect Code/Base64 Vectors</option>
              <option value="ALL">All Categories</option>
            </select>
            <button className="btn-primary" onClick={handleSimulateRedTeam} disabled={simulating}>
              <Play size={15} />
              <span>{simulating ? 'ATTACKING...' : 'RUN ATTACK SIMULATION'}</span>
            </button>
          </div>

          {simResult && (
            <div style={{ background: 'var(--bg-pitch)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span className="mono-text text-dim" style={{ fontSize: '0.72rem', fontWeight: 700 }}>PAYLOAD TESTED:</span>
                <span className={`badge ${simResult.bypassed_guardrails ? 'badge-blocked' : 'badge-allowed'}`}>
                  {simResult.bypassed_guardrails ? 'GUARDRAIL BYPASSED' : 'GUARDRAIL BLOCKED'}
                </span>
              </div>
              <div className="mono-text" style={{ fontSize: '0.85rem', marginBottom: '8px', color: 'var(--color-black)', fontWeight: 500 }}>
                "{simResult.payload_tested}"
              </div>
              {simResult.retraining_feed && (
                <div className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--accent-maroon)', fontWeight: 700 }}>
                  ▶ Auto-queued bypass sample to Continuous Re-Training Dataset.
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Right Column: Feedback Submitter & Trigger Controls */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        {/* Feedback logger */}
        <div className="shiny-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <PlusCircle size={22} color="var(--color-black)" />
            <div>
              <h2 style={{ fontSize: '1.1rem', color: 'var(--color-black)' }}>Log Attack / False Negative Sample</h2>
              <p className="text-dim" style={{ fontSize: '0.8rem' }}>Manually submit novel prompt injection payloads to the training dataset</p>
            </div>
          </div>

          <div style={{ marginBottom: '16px' }}>
            <textarea
              rows={5}
              value={feedbackPrompt}
              onChange={(e) => setFeedbackPrompt(e.target.value)}
              placeholder="Paste novel prompt injection or benign false-positive text..."
              style={{ background: '#FFFFFF', color: 'var(--color-black)', border: '1px solid var(--border-shiny)' }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <select
              value={feedbackLabel}
              onChange={(e) => setFeedbackLabel(Number(e.target.value))}
              style={{ width: '200px', height: '38px', padding: '0 12px', fontWeight: 600 }}
            >
              <option value={1}>Label: Prompt Injection (1)</option>
              <option value={0}>Label: Safe Prompt (0)</option>
            </select>

            <button className="btn-secondary" onClick={handleSubmitFeedback}>
              <span>SUBMIT TO QUEUE</span>
            </button>
          </div>
        </div>

        {/* Trigger re-training */}
        <div className="shiny-card" style={{ padding: '24px', textAlign: 'center' }}>
          <RefreshCw size={36} color="var(--accent-maroon)" style={{ marginBottom: '12px' }} />
          <h2 style={{ fontSize: '1.2rem', marginBottom: '6px', color: 'var(--color-black)' }}>Continuous Re-Training Pipeline</h2>
          <p className="text-dim" style={{ fontSize: '0.85rem', marginBottom: '20px' }}>
            Executes fine-tuning of ModernBERT on all queued samples, continuously improving classification accuracy over time.
          </p>

          <button className="btn-primary" onClick={handleTriggerRetrain} style={{ margin: '0 auto' }}>
            <RefreshCw size={16} />
            <span>TRIGGER MODERNBERT FINE-TUNING</span>
          </button>

          {retrainStatus && (
            <div className="mono-text" style={{ marginTop: '16px', fontSize: '0.8rem', color: 'var(--status-allowed)', fontWeight: 700 }}>
              {retrainStatus}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

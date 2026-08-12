import React, { useState } from 'react';
import { Sliders, Wallet, Headset, Code2, Save, Check } from 'lucide-react';

export default function SensitivityManager({ activeProfile = 'BALANCED', onProfileChange }) {
  const [selectedProfile, setSelectedProfile] = useState(activeProfile);
  const [customThreshold, setCustomThreshold] = useState(
    activeProfile === 'FINANCE_STRICT' ? 35 : activeProfile === 'SUPPORT_LENIENT' ? 85 : 60
  );
  const [savedMsg, setSavedMsg] = useState('');

  const PROFILES = [
    {
      id: 'FINANCE_STRICT',
      name: 'Finance Agent / Wallet Access',
      icon: Wallet,
      threshold: 35,
      badge: 'STRICT SCANS',
      color: 'var(--status-blocked)',
      description: 'Zero tolerance for system override or credential probes. Max protection against wallet drain and financial prompt manipulation.'
    },
    {
      id: 'BALANCED',
      name: 'Code Reviewer / General AI',
      icon: Code2,
      threshold: 60,
      badge: 'BALANCED',
      color: 'var(--accent-maroon)',
      description: 'Balanced risk scoring for internal enterprise tools, developers, and code evaluation assistants.'
    },
    {
      id: 'SUPPORT_LENIENT',
      name: 'Customer Support Bot',
      icon: Headset,
      threshold: 85,
      badge: 'LENIENT (LOW FPR)',
      color: 'var(--status-allowed)',
      description: 'Higher false-positive tolerance so customer queries are rarely blocked while catching major jailbreak attempts.'
    }
  ];

  const handleSelect = (pId, pThreshold) => {
    setSelectedProfile(pId);
    setCustomThreshold(pThreshold);
    if (onProfileChange) {
      onProfileChange(pId);
    }
  };

  const handleSaveProfile = async () => {
    try {
      const target = PROFILES.find(p => p.id === selectedProfile);
      const res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile_id: selectedProfile,
          name: target ? target.name : selectedProfile,
          risk_threshold: customThreshold,
          description: target ? target.description : 'Custom Sensitivity Profile'
        })
      });

      if (res.ok) {
        if (onProfileChange) onProfileChange(selectedProfile);
        setSavedMsg(`Active policy set to '${target ? target.name : selectedProfile}' across all user scans!`);
        setTimeout(() => setSavedMsg(''), 4000);
      }
    } catch (e) {
      setSavedMsg('Failed to save profile.');
    }
  };

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
      <div className="shiny-card" style={{ padding: '24px', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
          <Sliders size={24} color="var(--accent-maroon)" />
          <div>
            <h2 style={{ fontSize: '1.2rem', color: 'var(--color-black)' }}>Admin Policy & Sensitivity Profile Manager</h2>
            <p className="text-dim" style={{ fontSize: '0.85rem' }}>
              Select and save the global sensitivity policy applied to all user-facing AI prompt scans.
            </p>
          </div>
        </div>

        {/* Profile Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px', marginBottom: '24px' }}>
          {PROFILES.map((p) => {
            const Icon = p.icon;
            const isSelected = selectedProfile === p.id;
            return (
              <div
                key={p.id}
                onClick={() => handleSelect(p.id, p.threshold)}
                style={{
                  background: isSelected ? 'var(--accent-maroon-subtle)' : '#FFFFFF',
                  border: isSelected ? `2px solid ${p.color}` : '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '20px',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  boxShadow: isSelected ? `0 4px 14px rgba(128, 0, 32, 0.12)` : 'none'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
                  <Icon size={22} color={p.color} />
                  <span className="mono-text" style={{ fontSize: '0.7rem', background: '#FFFFFF', padding: '2px 8px', borderRadius: '4px', border: '1px solid var(--border-shiny)', color: p.color, fontWeight: 700 }}>
                    {p.badge}
                  </span>
                </div>
                <h3 style={{ fontSize: '1.0rem', marginBottom: '8px', color: 'var(--color-black)' }}>{p.name}</h3>
                <p className="text-dim" style={{ fontSize: '0.8rem', lineHeight: '1.4', marginBottom: '12px' }}>
                  {p.description}
                </p>
                <div className="mono-text" style={{ fontSize: '1.1rem', fontWeight: 800, color: p.color }}>
                  THRESHOLD: {p.threshold}
                </div>
              </div>
            );
          })}
        </div>

        {/* Custom Threshold Slider */}
        <div style={{ background: 'var(--bg-pitch)', padding: '20px', borderRadius: '8px', border: '1px solid var(--border-subtle)', marginBottom: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div>
              <span className="mono-text" style={{ fontSize: '0.9rem', fontWeight: 800, color: 'var(--color-black)' }}>FINE-TUNE CUSTOM RISK CUTOFF: </span>
              <span className="mono-text text-maroon" style={{ fontSize: '1.2rem', fontWeight: 800, marginLeft: '8px' }}>
                {customThreshold}
              </span>
            </div>
            <span className="mono-text text-dim" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
              RANGE: 10 (MAX STRICT) TO 90 (MAX LENIENT)
            </span>
          </div>

          <input
            type="range"
            min="10"
            max="90"
            value={customThreshold}
            onChange={(e) => setCustomThreshold(Number(e.target.value))}
            style={{ width: '100%', accentColor: 'var(--accent-maroon)', height: '6px', cursor: 'pointer' }}
          />

          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '12px', fontSize: '0.75rem', fontWeight: 600 }} className="mono-text text-dim">
            <span>◄ STRICTER (Fewer Attacks Bypassed)</span>
            <span>MORE LENIENT (Fewer False Alarms) ►</span>
          </div>
        </div>

        {/* Save Controls */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          {savedMsg ? (
            <span className="mono-text" style={{ fontSize: '0.85rem', color: 'var(--status-allowed)', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700 }}>
              <Check size={16} /> {savedMsg}
            </span>
          ) : (
            <span />
          )}

          <button className="btn-primary" onClick={handleSaveProfile}>
            <Save size={16} />
            <span>APPLY GLOBAL ADMIN POLICY</span>
          </button>
        </div>
      </div>
    </div>
  );
}

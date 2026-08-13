import React from 'react';
import { Shield, Activity, Sliders, RefreshCw, FileSearch, Lock, LogOut, Globe } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, userRole, onLoginClick, onLogoutClick }) {
  const userTabs = [
    { id: 'scanner', label: 'Prompt Scanner', icon: Shield },
    { id: 'document', label: 'Document Analyzer', icon: FileSearch },
    { id: 'webscanner', label: 'Web URL Scanner', icon: Globe },
  ];

  const adminTabs = [
    { id: 'sensitivity', label: 'Sensitivity Profiles', icon: Sliders },
    { id: 'retrain', label: 'Continuous Re-Training', icon: RefreshCw },
    { id: 'analytics', label: 'Audit Analytics', icon: Activity },
  ];

  // User side gets first 2 tabs; Admin side gets last 3 tabs (first 2 tabs hidden for admin)
  const visibleTabs = userRole === 'admin' ? adminTabs : userTabs;

  return (
    <header style={{
      borderBottom: '1px solid var(--border-subtle)',
      background: '#FFFFFF',
      boxShadow: '0 1px 4px rgba(0, 0, 0, 0.04)',
      position: 'sticky',
      top: 0,
      zIndex: 100
    }}>
      <div style={{
        maxWidth: '1400px',
        margin: '0 auto',
        padding: '0 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        height: '70px'
      }}>
        {/* Brand Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '8px',
            background: 'var(--accent-maroon)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 2px 10px rgba(128, 0, 32, 0.25)'
          }}>
            <Shield size={22} color="#FFFFFF" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.03em', color: 'var(--color-black)' }}>FORTIFY</span>
              <span className="mono-text" style={{ fontSize: '1.1rem', color: 'var(--accent-maroon)', fontWeight: 800 }}>AI</span>
            </div>
            <div className="mono-text" style={{ fontSize: '0.68rem', color: 'var(--text-muted)', letterSpacing: '0.08em', fontWeight: 600 }}>
              ENTERPRISE SECURITY ENGINE
            </div>
          </div>
        </div>

        {/* Tab Navigation (Role-based tab separation) */}
        <nav style={{ display: 'flex', gap: '6px' }}>
          {visibleTabs.map((t) => {
            const Icon = t.icon;
            const isActive = activeTab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                style={{
                  background: isActive ? 'var(--accent-maroon-subtle)' : 'transparent',
                  border: isActive ? '1px solid var(--accent-maroon)' : '1px solid transparent',
                  color: isActive ? 'var(--accent-maroon)' : 'var(--text-dim)',
                  padding: '8px 16px',
                  borderRadius: '6px',
                  fontFamily: 'var(--font-sans)',
                  fontSize: '0.88rem',
                  fontWeight: isActive ? 700 : 500,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  transition: 'all 0.15s ease'
                }}
              >
                <Icon size={16} color={isActive ? 'var(--accent-maroon)' : 'var(--text-muted)'} />
                <span>{t.label}</span>
              </button>
            );
          })}
        </nav>

        {/* User / Admin Authentication Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          {userRole === 'admin' ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="badge badge-maroon" style={{ fontSize: '0.75rem', padding: '6px 10px' }}>
                ADMIN MODE
              </span>
              <button
                onClick={onLogoutClick}
                className="btn-secondary"
                style={{ padding: '6px 12px', fontSize: '0.82rem' }}
                title="Exit Admin Mode"
              >
                <LogOut size={14} />
                <span>LOGOUT</span>
              </button>
            </div>
          ) : (
            <button
              onClick={onLoginClick}
              className="btn-primary"
              style={{ padding: '7px 14px', fontSize: '0.84rem' }}
            >
              <Lock size={14} />
              <span>ADMIN LOGIN</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
}

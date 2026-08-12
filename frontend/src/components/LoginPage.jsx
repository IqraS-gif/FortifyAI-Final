import React, { useState } from 'react';
import { Shield, Lock, User, ArrowRight } from 'lucide-react';

export default function LoginPage({ onLoginSuccess, onCancel }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();
    if ((username === 'admin' && password === 'admin123') || (username === 'admin' && password === 'admin')) {
      onLoginSuccess();
    } else if (!username || !password) {
      setError('Please enter admin credentials.');
    } else {
      setError('Invalid admin credentials. (Demo: admin / admin123)');
    }
  };

  const handleQuickDemoLogin = () => {
    setUsername('admin');
    setPassword('admin123');
    onLoginSuccess();
  };

  return (
    <div style={{
      maxWidth: '440px',
      margin: '40px auto',
      padding: '32px',
      background: '#FFFFFF',
      borderRadius: '12px',
      border: '1px solid var(--border-shiny)',
      boxShadow: '0 8px 30px rgba(0, 0, 0, 0.08)'
    }}>
      <div style={{ textAlign: 'center', marginBottom: '24px' }}>
        <div style={{
          width: '48px',
          height: '48px',
          borderRadius: '10px',
          background: 'var(--accent-maroon)',
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          marginBottom: '12px',
          boxShadow: '0 4px 14px rgba(128, 0, 32, 0.25)'
        }}>
          <Shield size={26} color="#FFFFFF" />
        </div>
        <h2 style={{ fontSize: '1.4rem', color: 'var(--color-black)', marginBottom: '4px' }}>Security Admin Authentication</h2>
        <p className="text-dim" style={{ fontSize: '0.85rem' }}>
          Access enterprise security policy management & audit logs
        </p>
      </div>

      <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <label className="mono-text text-dim" style={{ fontSize: '0.75rem', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
            ADMIN USERNAME
          </label>
          <div style={{ position: 'relative' }}>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              style={{ paddingLeft: '38px', height: '42px' }}
            />
            <User size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '13px' }} />
          </div>
        </div>

        <div>
          <label className="mono-text text-dim" style={{ fontSize: '0.75rem', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
            ADMIN PASSWORD
          </label>
          <div style={{ position: 'relative' }}>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              style={{ paddingLeft: '38px', height: '42px' }}
            />
            <Lock size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '13px' }} />
          </div>
        </div>

        {error && (
          <div style={{ padding: '10px', background: 'rgba(197, 48, 48, 0.08)', border: '1px solid var(--status-blocked)', borderRadius: '6px', fontSize: '0.82rem', color: 'var(--status-blocked)', fontWeight: 600 }}>
            {error}
          </div>
        )}

        <button type="submit" className="btn-primary" style={{ width: '100%', justifyContent: 'center', height: '42px', marginTop: '8px' }}>
          <span>AUTHENTICATE ADMIN</span>
          <ArrowRight size={16} />
        </button>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '8px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
          <button type="button" onClick={handleQuickDemoLogin} className="btn-preset" style={{ fontSize: '0.78rem' }}>
            ⚡ QUICK DEMO ADMIN LOGIN
          </button>
          <button type="button" onClick={onCancel} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', fontSize: '0.82rem', cursor: 'pointer', fontWeight: 600 }}>
            CANCEL
          </button>
        </div>
      </form>
    </div>
  );
}

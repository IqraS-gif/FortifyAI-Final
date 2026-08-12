import React, { useState } from 'react';
import Navbar from './components/Navbar';
import PromptScanner from './components/PromptScanner';
import DocumentAnalyzer from './components/DocumentAnalyzer';
import SensitivityManager from './components/SensitivityManager';
import RetrainingHub from './components/RetrainingHub';
import AuditAnalytics from './components/AuditAnalytics';
import LoginPage from './components/LoginPage';

export default function App() {
  const [userRole, setUserRole] = useState('user'); // 'user' or 'admin'
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [activeTab, setActiveTab] = useState('scanner');
  const [activeProfile, setActiveProfile] = useState('BALANCED');
  const [lastScanResult, setLastScanResult] = useState(null);

  const handleAdminLoginSuccess = () => {
    setUserRole('admin');
    setShowLoginModal(false);
    setActiveTab('sensitivity'); // Default to sensitivity manager for admin
  };

  const handleAdminLogout = () => {
    setUserRole('user');
    setActiveTab('scanner');
  };

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-pitch)', color: 'var(--text-dark)' }}>
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        userRole={userRole}
        onLoginClick={() => setShowLoginModal(true)}
        onLogoutClick={handleAdminLogout}
      />

      {/* Main Content View Container */}
      <main style={{ maxWidth: '1400px', margin: '0 auto', padding: '32px 24px' }}>
        {showLoginModal ? (
          <LoginPage
            onLoginSuccess={handleAdminLoginSuccess}
            onCancel={() => setShowLoginModal(false)}
          />
        ) : (
          <>
            {activeTab === 'scanner' && (
              <PromptScanner
                activeProfile={activeProfile}
                onScanComplete={(res) => setLastScanResult(res)}
              />
            )}
            {activeTab === 'document' && (
              <DocumentAnalyzer
                onScanComplete={(res) => setLastScanResult(res)}
              />
            )}
            {/* Admin-only tabs (Sensitivity Profiles, Continuous Re-Training, Audit Analytics) */}
            {userRole === 'admin' && activeTab === 'sensitivity' && (
              <SensitivityManager
                activeProfile={activeProfile}
                onProfileChange={(newProf) => setActiveProfile(newProf)}
              />
            )}
            {userRole === 'admin' && activeTab === 'retrain' && (
              <RetrainingHub />
            )}
            {userRole === 'admin' && activeTab === 'analytics' && (
              <AuditAnalytics />
            )}
          </>
        )}
      </main>
    </div>
  );
}

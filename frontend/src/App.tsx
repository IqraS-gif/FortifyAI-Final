import { useEffect, useState } from 'react';
import { getConfigs } from './api';
import { useScan } from './useScan';
import OverviewPanel from './components/OverviewPanel';
import RunControlPanel from './components/RunControlPanel';
import RiskSummary from './components/RiskSummary';
import CoreModulesSection from './components/CoreModulesSection';
import UniqueTechSection from './components/UniqueTechSection';
import FindingsExplorer from './components/FindingsExplorer';
import HeatmapAndExport from './components/HeatmapAndExport';

export default function App() {
  const [availableConfigs, setAvailableConfigs] = useState<string[]>([]);
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    getConfigs()
      .then(r => setAvailableConfigs(r.data.configs))
      .catch(() => setAvailableConfigs(['config_final.yaml']));
  }, []);

  const scan = useScan();

  const hasReport = !!scan.report;

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
    // Also attempt native if supported
    if (!document.fullscreenElement && !isFullscreen) {
      document.documentElement.requestFullscreen().catch(() => {
        /* ignore, fallback to CSS */
      });
    } else if (document.fullscreenElement && isFullscreen) {
      document.exitFullscreen().catch(() => {});
    }
  };

  useEffect(() => {
    const handleFsChange = () => {
      if (!document.fullscreenElement) setIsFullscreen(false);
    };
    document.addEventListener('fullscreenchange', handleFsChange);
    return () => document.removeEventListener('fullscreenchange', handleFsChange);
  }, []);

  return (
    <div className={`bg-surface-900 ${isFullscreen ? 'fixed inset-0 z-[9999] overflow-y-auto' : 'min-h-screen'}`}>
      {/* Header */}
      <header className="sticky top-0 z-50 bg-surface-900/90 backdrop-blur border-b border-surface-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🛡️</span>
            <div>
              <h1 className="text-base font-bold text-white leading-tight">LLM08 Vector Security Scanner</h1>
              <p className="text-xs text-gray-500">OWASP LLM08 · Qdrant Embedding Auditor</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {scan.isDemoMode && (
              <span className="text-xs px-2.5 py-1 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 font-medium hidden sm:block print:hidden">
                📦 Demo Mode
              </span>
            )}
            <button 
              onClick={toggleFullscreen}
              className="btn-ghost text-xs px-2 py-1 flex items-center gap-1 print:hidden"
              title="Toggle Fullscreen"
            >
              {isFullscreen ? '⛶ Exit' : '⛶ Fullscreen'}
            </button>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6">
        <OverviewPanel />

        <RunControlPanel
          isDemoMode={scan.isDemoMode}
          setIsDemoMode={scan.setIsDemoMode}
          cachedScans={scan.cachedScans}
          selectedCachedId={scan.selectedCachedId}
          setSelectedCachedId={scan.setSelectedCachedId}
          selectedFile={scan.selectedFile}
          setSelectedFile={scan.setSelectedFile}
          triggerScan={scan.triggerScan}
          phase={scan.phase}
          currentModule={scan.currentModule}
          errorMessage={scan.errorMessage}
        />

        {!hasReport && scan.phase !== 'running' && (
          <div className="card text-center py-16 text-gray-600">
            <p className="text-3xl mb-3">📊</p>
            <p className="text-sm">No report loaded yet.</p>
            <p className="text-xs mt-1">Run a live scan or enable Demo Mode to see results.</p>
          </div>
        )}

        {!hasReport && scan.phase === 'running' && (
          <div className="card text-center py-16 text-gray-500">
            <p className="text-3xl mb-3 animate-pulse">⏳</p>
            <p className="text-sm">Scan in progress — results will appear when complete.</p>
          </div>
        )}

        {hasReport && scan.report && (
          <>
            <RiskSummary report={scan.report} />
            <CoreModulesSection report={scan.report} />
            <UniqueTechSection report={scan.report} />
            <FindingsExplorer report={scan.report} />
            {scan.scanId && (
              <HeatmapAndExport
                scanId={scan.scanId}
                heatmapPath={scan.report.heatmap_path}
              />
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-surface-700 mt-12 py-8 print:hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="text-lg opacity-80">🛡️</span>
            <span className="text-sm font-bold text-gray-300 tracking-wide">LLM08 Scanner</span>
          </div>
          <p className="text-xs text-gray-500 font-medium">
            Automated Vector & Embedding Security Auditing for RAG Pipelines.
          </p>
          <div className="flex items-center gap-4 text-xs text-gray-500 font-mono">
            <span className="flex items-center gap-1.5 px-2 py-1 bg-surface-700 rounded-md">
              <span className="w-1.5 h-1.5 rounded-full bg-severity-low shadow-[0_0_8px_rgba(0,230,118,0.6)]"></span> 
              Engine Online
            </span>
            <span>v1.0.0</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

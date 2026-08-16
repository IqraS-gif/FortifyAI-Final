import { useEffect, useState } from 'react';
import { getConfigs } from './api';
import { useScan } from './useScan';
import Sidebar from './components/Sidebar';
import OverviewPanel from './components/OverviewPanel';
import RunControlPanel from './components/RunControlPanel';
import RiskSummary from './components/RiskSummary';
import CoreModulesSection from './components/CoreModulesSection';
import UniqueTechSection from './components/UniqueTechSection';
import FindingsExplorer from './components/FindingsExplorer';
import HeatmapAndExport from './components/HeatmapAndExport';
import { ChartBarIcon } from './components/Icons';

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
    if (!document.fullscreenElement && !isFullscreen) {
      document.documentElement.requestFullscreen().catch(() => {});
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
    <div className="flex min-h-screen bg-[#faf8f5] text-slate-900 font-sans antialiased">
      {/* Left Navigation Sidebar */}
      <Sidebar />

      {/* Main Content Area */}
      <div className={`flex-1 flex flex-col min-w-0 ${isFullscreen ? 'fixed inset-0 z-[9999] bg-[#faf8f5] overflow-y-auto' : ''}`}>
        {/* Top Navigation Header */}
        <header className="bg-white border-b border-slate-200/80 sticky top-0 z-30 shadow-2xs">
          <div className="max-w-7xl mx-auto px-4 sm:px-8 py-3.5 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 text-white flex items-center justify-center shadow-xs">
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 4a3 3 0 0 1 3 3c0 1.25-.77 2.32-1.86 2.76.62 1.34 1.86 3.24 3.86 3.24H7c2 0 3.24-1.9 3.86-3.24A3.001 3.001 0 0 1 12 5z" />
                </svg>
              </div>
              <div>
                <h1 className="text-base font-extrabold text-slate-900 leading-tight tracking-tight">
                  LLM08 Vector Security Scanner
                </h1>
                <p className="text-xs text-slate-500 font-medium">
                  OWASP LLM08 · Qdrant Embedding Auditor
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={toggleFullscreen}
                className="px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold flex items-center gap-1.5 shadow-2xs transition-all"
                title="Toggle Fullscreen"
              >
                <svg className="w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 8V4m0 0h4M4 4l5 5m11-5h-4m4 0v4m0-4l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
                </svg>
                <span>Fullscreen</span>
              </button>
            </div>
          </div>
        </header>

        {/* Dashboard Body */}
        <main className="max-w-7xl w-full mx-auto px-4 sm:px-8 py-6 flex-1">
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
            <div className="card text-center py-16 text-slate-500">
              <div className="w-12 h-12 rounded-2xl bg-slate-100 border border-slate-200 flex items-center justify-center mx-auto mb-3 text-slate-400">
                <ChartBarIcon className="w-6 h-6 text-slate-500" />
              </div>
              <p className="text-sm font-bold text-slate-800">No report loaded yet</p>
              <p className="text-xs mt-1 text-slate-500">Run a live scan or enable Demo Mode to see results.</p>
            </div>
          )}

          {!hasReport && scan.phase === 'running' && (
            <div className="card text-center py-16 text-slate-500">
              <div className="animate-spin w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full mx-auto mb-3" />
              <p className="text-sm font-bold text-slate-800">Scan in progress…</p>
              <p className="text-xs mt-1 text-slate-500">Results will appear when scan completes.</p>
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
        <footer className="border-t border-slate-200/80 bg-white py-5 print:hidden mt-auto">
          <div className="max-w-7xl mx-auto px-4 sm:px-8 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 rounded bg-blue-600 text-white flex items-center justify-center text-xs font-bold">
                🛡️
              </div>
              <span className="text-xs font-bold text-slate-800 tracking-wide">LLM08 Security Scanner</span>
            </div>
            <p className="text-xs text-slate-500">
              Automated Vector &amp; Embedding Security Auditing for RAG Pipelines.
            </p>
            <div className="flex items-center gap-3 text-xs text-slate-500 font-mono">
              <span className="flex items-center gap-1.5 px-2.5 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> 
                Engine Online
              </span>
              <span>v1.0.0</span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}

import React from 'react';
import type { CachedScan } from '../api';
import type { ScanPhase } from '../useScan';
import { CORE_MODULES, UNIQUE_TECH_MODULES, MODULE_LABELS, MODULE_ICONS, formatTimestamp } from '../utils';

interface Props {
  isDemoMode: boolean;
  setIsDemoMode: (v: boolean) => void;
  cachedScans: CachedScan[];
  selectedCachedId: string | null;
  setSelectedCachedId: (id: string) => void;
  selectedFile: File | null;
  setSelectedFile: (f: File | null) => void;
  triggerScan: () => void;
  phase: ScanPhase;
  currentModule: string | null;
  errorMessage: string | null;
}

const ALL_MODULES = [...CORE_MODULES, ...UNIQUE_TECH_MODULES];

function moduleStatus(mod: string, currentModule: string | null, phase: ScanPhase): 'done' | 'active' | 'waiting' {
  const idx = ALL_MODULES.indexOf(mod as typeof ALL_MODULES[number]);
  const cur = currentModule ? ALL_MODULES.indexOf(currentModule as typeof ALL_MODULES[number]) : -1;
  if (phase === 'completed') return 'done';
  if (idx < cur) return 'done';
  if (idx === cur) return 'active';
  return 'waiting';
}

export default function RunControlPanel(props: Props) {
  const {
    isDemoMode, setIsDemoMode,
    cachedScans, selectedCachedId, setSelectedCachedId,
    selectedFile, setSelectedFile,
    triggerScan, phase, currentModule, errorMessage,
  } = props;

  const activeCached = cachedScans.find(c => c.scan_id === selectedCachedId);

  return (
    <section className="card mb-6">
      {/* Header + Demo Toggle */}
      <div className="flex items-center justify-between mb-5 flex-wrap gap-3">
        <h2 className="text-lg font-bold text-white">Scan Controls</h2>
        <div className="flex items-center gap-3">
          {isDemoMode && activeCached && (
            <span className="text-xs px-2.5 py-1 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 font-medium">
              📦 Demo Mode · Cached scan from {formatTimestamp(activeCached.timestamp)}
            </span>
          )}
          <button
            onClick={() => setIsDemoMode(!isDemoMode)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 focus:outline-none ${
              isDemoMode ? 'bg-amber-500' : 'bg-surface-600'
            }`}
            aria-label="Toggle Demo Mode"
          >
            <span
              className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform duration-200 ${
                isDemoMode ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
          <span className="text-sm text-gray-400 font-medium">Demo Mode</span>
        </div>
      </div>

      {isDemoMode ? (
        /* --- Demo Mode: cached scan selector --- */
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-sm text-gray-400">Cached scan:</label>
          {cachedScans.length === 0 ? (
            <span className="text-sm text-gray-500 italic">No cached scans found.</span>
          ) : (
            <select
              className="bg-surface-700 border border-surface-600 text-white text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent"
              value={selectedCachedId ?? ''}
              onChange={e => setSelectedCachedId(e.target.value)}
            >
              {cachedScans.map(c => (
                <option key={c.scan_id} value={c.scan_id}>
                  {formatTimestamp(c.timestamp)} — {c.config_file} [{c.risk_level}]
                </option>
              ))}
            </select>
          )}
        </div>
      ) : (
        /* --- Live mode --- */
        <div className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <label className="text-sm text-gray-400">Config:</label>
            <input
              type="file"
              accept=".yaml,.yml"
              onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
              className="bg-surface-700 text-sm text-gray-300 rounded-lg px-3 py-2 border border-surface-600 focus:outline-none focus:border-accent file:mr-4 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-surface-600 file:text-accent-light hover:file:bg-surface-500 cursor-pointer"
            />
            <button
              className="btn-primary"
              onClick={triggerScan}
              disabled={phase === 'running' || !selectedFile}
            >
              {phase === 'running' ? (
                <span className="flex items-center gap-2">
                  <span className="animate-spin">⟳</span> Scanning…
                </span>
              ) : '▶ Run Live Scan'}
            </button>
          </div>

          {/* Progress stepper */}
          {(phase === 'running' || phase === 'completed') && (
            <div className="flex flex-wrap gap-2 pt-1">
              {/* Core modules */}
              <span className="text-xs text-gray-500 self-center mr-1 font-mono">CORE</span>
              {CORE_MODULES.map(mod => {
                const s = moduleStatus(mod, currentModule, phase);
                return (
                  <div key={mod} className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                    s === 'done'   ? 'bg-severity-low/15 border-severity-low/30 text-severity-low shadow-[0_0_10px_rgba(0,230,118,0.15)]' :
                    s === 'active' ? 'bg-accent/20 border-accent/40 text-accent-light shadow-[0_0_15px_rgba(110,86,207,0.3)] animate-pulse' :
                    'bg-surface-700 border-surface-600 text-gray-500'
                  }`}>
                    {s === 'done' ? '✓' : s === 'active' ? '◉' : '○'}
                    {MODULE_ICONS[mod]} {MODULE_LABELS[mod]}
                  </div>
                );
              })}
              <span className="text-xs text-gray-500 self-center mx-1 font-mono">TECH</span>
              {UNIQUE_TECH_MODULES.map(mod => {
                const s = moduleStatus(mod, currentModule, phase);
                return (
                  <div key={mod} className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                    s === 'done'   ? 'bg-severity-low/15 border-severity-low/30 text-severity-low shadow-[0_0_10px_rgba(0,230,118,0.15)]' :
                    s === 'active' ? 'bg-accent/20 border-accent/40 text-accent-light shadow-[0_0_15px_rgba(110,86,207,0.3)] animate-pulse' :
                    'bg-surface-700 border-surface-600 text-gray-500'
                  }`}>
                    {s === 'done' ? '✓' : s === 'active' ? '◉' : '○'}
                    {MODULE_ICONS[mod]} {MODULE_LABELS[mod]}
                  </div>
                );
              })}
            </div>
          )}

          {/* Error banner */}
          {phase === 'failed' && errorMessage && (
            <div className="bg-severity-critical/10 border border-severity-critical/30 rounded-lg p-4 mt-2">
              <p className="text-severity-critical font-semibold text-sm mb-1">❌ Scan Failed</p>
              <pre className="text-gray-400 text-xs font-mono whitespace-pre-wrap overflow-auto max-h-32">{errorMessage}</pre>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

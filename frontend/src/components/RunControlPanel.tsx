import type { CachedScan } from '../api';
import type { ScanPhase } from '../useScan';
import { CORE_MODULES, UNIQUE_TECH_MODULES, MODULE_LABELS, formatTimestamp } from '../utils';
import { ModuleIcon, PlayIcon, AlertTriangleIcon } from './Icons';

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
    <section className="bg-indigo-50/50 border border-indigo-100 rounded-2xl p-6 mb-8 shadow-2xs">
      <div className="flex items-center justify-between flex-wrap gap-4">
        {/* Left Title */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-indigo-100 text-indigo-600 flex items-center justify-center font-bold">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
            </svg>
          </div>
          <h3 className="text-base sm:text-lg font-black text-slate-900">Scan Controls</h3>
        </div>

        {/* Center Cached selector or live upload */}
        {isDemoMode ? (
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-xs font-bold text-slate-500 uppercase tracking-wide">Cached scan</span>
            {cachedScans.length === 0 ? (
              <span className="text-sm text-slate-400 italic">No cached scans found.</span>
            ) : (
              <div className="relative flex items-center">
                <svg className="w-4 h-4 text-slate-400 absolute left-3.5 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
                <select
                  className="bg-white border border-slate-200 text-slate-900 text-xs sm:text-sm font-bold rounded-xl pl-10 pr-9 py-2.5 focus:outline-none focus:border-blue-500 shadow-2xs cursor-pointer"
                  value={selectedCachedId ?? ''}
                  onChange={e => setSelectedCachedId(e.target.value)}
                >
                  {cachedScans.map(c => (
                    <option key={c.scan_id} value={c.scan_id}>
                      {formatTimestamp(c.timestamp)} | {c.config_file} [{c.risk_level}]
                    </option>
                  ))}
                </select>
                <svg className="w-4 h-4 text-slate-400 absolute right-3 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-3 flex-wrap">
            <label className="text-xs font-bold text-slate-600 uppercase tracking-wide">Config File:</label>
            <input
              type="file"
              accept=".yaml,.yml"
              onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
              className="bg-white text-xs text-slate-700 rounded-xl px-3 py-2 border border-slate-200 focus:outline-none focus:border-blue-500 file:mr-3 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-bold file:bg-slate-100 file:text-slate-700 cursor-pointer shadow-2xs"
            />
            <button
              className="btn-primary flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs sm:text-sm px-5 py-2.5 rounded-xl shadow-xs transition-all"
              onClick={triggerScan}
              disabled={phase === 'running' || !selectedFile}
            >
              {phase === 'running' ? (
                <>
                  <span className="animate-spin border-2 border-white border-t-transparent w-4 h-4 rounded-full" />
                  Scanning…
                </>
              ) : (
                <>
                  <PlayIcon className="w-4 h-4 text-white" />
                  Run Live Scan
                </>
              )}
            </button>
          </div>
        )}

        {/* Right Side Demo Mode Pill & Toggle */}
        <div className="flex items-center gap-4">
          {isDemoMode && activeCached && (
            <span className="text-xs px-3.5 py-2 rounded-xl bg-purple-100/70 text-purple-700 border border-purple-200/80 font-bold hidden md:flex items-center gap-2">
              <svg className="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
              Demo Mode | {formatTimestamp(activeCached.timestamp)}
            </span>
          )}

          <div className="flex items-center gap-3">
            <span className="text-xs sm:text-sm text-slate-900 font-extrabold">Demo Mode</span>
            <button
              onClick={() => setIsDemoMode(!isDemoMode)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 focus:outline-none ${
                isDemoMode ? 'bg-blue-600' : 'bg-slate-300'
              }`}
              aria-label="Toggle Demo Mode"
            >
              <span
                className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform duration-200 ${
                  isDemoMode ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Progress Stepper */}
      {(phase === 'running' || phase === 'completed') && (
        <div className="flex flex-wrap gap-2.5 pt-5 mt-5 border-t border-indigo-100">
          <span className="text-xs text-slate-400 self-center mr-1 font-mono font-bold">CORE</span>
          {CORE_MODULES.map(mod => {
            const s = moduleStatus(mod, currentModule, phase);
            return (
              <div key={mod} className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-bold border transition-all ${
                s === 'done'   ? 'bg-emerald-50 border-emerald-200 text-emerald-800' :
                s === 'active' ? 'bg-blue-600 border-blue-600 text-white shadow-xs animate-pulse' :
                'bg-white border-slate-200 text-slate-400'
              }`}>
                <ModuleIcon name={mod} className="w-3.5 h-3.5" />
                <span>{MODULE_LABELS[mod]}</span>
              </div>
            );
          })}
          <span className="text-xs text-slate-400 self-center mx-1 font-mono font-bold">TECH</span>
          {UNIQUE_TECH_MODULES.map(mod => {
            const s = moduleStatus(mod, currentModule, phase);
            return (
              <div key={mod} className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-bold border transition-all ${
                s === 'done'   ? 'bg-emerald-50 border-emerald-200 text-emerald-800' :
                s === 'active' ? 'bg-blue-600 border-blue-600 text-white shadow-xs animate-pulse' :
                'bg-white border-slate-200 text-slate-400'
              }`}>
                <ModuleIcon name={mod} className="w-3.5 h-3.5" />
                <span>{MODULE_LABELS[mod]}</span>
              </div>
            );
          })}
        </div>
      )}

      {/* Error banner */}
      {phase === 'failed' && errorMessage && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 mt-4">
          <p className="text-red-700 font-bold text-xs flex items-center gap-1.5 mb-1">
            <AlertTriangleIcon className="w-4 h-4 text-red-600" />
            Scan Failed
          </p>
          <pre className="text-slate-700 text-xs font-mono whitespace-pre-wrap overflow-auto max-h-32">{errorMessage}</pre>
        </div>
      )}
    </section>
  );
}

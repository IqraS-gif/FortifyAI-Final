import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell, ReferenceLine,
} from 'recharts';
import type { Report, ModuleResult } from '../api';
import { CORE_MODULES, MODULE_LABELS, MODULE_ICONS, severityBg, severityColor, getSeverity } from '../utils';

interface Props { report: Report }

const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: { payload: ModuleResult & { weight: number } }[] }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-surface-800 border border-surface-600 rounded-lg p-3 text-sm shadow-xl">
      <p className="font-semibold text-white">{MODULE_LABELS[d.module_name]}</p>
      <p className="text-gray-400">Score: <span className="text-white font-mono">{d.score.toFixed(1)}</span></p>
      <p className="text-gray-400">Severity: <span style={{ color: severityColor(d.severity) }}>{d.severity || 'N/A'}</span></p>
      <p className="text-gray-400">Weight: <span className="text-accent">{(d.weight * 100).toFixed(0)}%</span></p>
      {d.error && <p className="text-severity-critical text-xs mt-1">⚠ {d.error}</p>}
    </div>
  );
};

export default function CoreModulesSection({ report }: Props) {
  const { module_results, weights } = report.overall_score;

  const coreResults = CORE_MODULES.map(name => {
    const r = module_results.find(m => m.module_name === name);
    if (r) {
      const sev = r.severity || getSeverity(r.score);
      return { ...r, severity: sev, weight: weights[name] ?? 0 };
    }
    return { module_name: name, severity: 'INFO', score: 0, findings: [], evidence: {}, duration_ms: 0, error: 'Did not run', weight: weights[name] ?? 0 };
  });

  return (
    <section className="mb-6">
      <h3 className="text-base font-bold text-white mb-3">Core Module Scores
        <span className="ml-2 text-xs text-gray-500 font-normal">(weighted — contribute to overall risk)</span>
      </h3>

      {/* Bar chart */}
      <div className="card mb-4">
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={coreResults} margin={{ top: 10, right: 20, bottom: 5, left: 0 }} barSize={32}>
            <XAxis
              dataKey="module_name"
              tick={{ fill: '#8b949e', fontSize: 11 }}
              tickFormatter={n => MODULE_LABELS[n] ?? n}
            />
            <YAxis domain={[0, 100]} tick={{ fill: '#8b949e', fontSize: 11 }} width={30} />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
            <ReferenceLine y={80} stroke="#ff4d4d" strokeDasharray="3 3" label={{ value: 'CRITICAL', fill: '#ff4d4d', fontSize: 10 }} />
            <ReferenceLine y={60} stroke="#ff8c42" strokeDasharray="3 3" />
            <ReferenceLine y={40} stroke="#ffd166" strokeDasharray="3 3" />
            <Bar dataKey="score" radius={[4, 4, 0, 0]}>
              {coreResults.map(r => (
                <Cell key={r.module_name} fill={severityColor(r.severity)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Module cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        {coreResults.map((r, i) => (
          <div key={r.module_name} className="card card-hoverable flex flex-col gap-2 relative overflow-hidden animate-slide-up" style={{ animationDelay: `${i * 100}ms` }}>
            {/* Soft background glow based on severity */}
            <div className="absolute top-0 right-0 w-24 h-24 blur-2xl opacity-10 rounded-full pointer-events-none" style={{ backgroundColor: severityColor(r.severity) }}></div>
            
            <div className="flex items-center justify-between relative z-10">
              <span className="text-lg">{MODULE_ICONS[r.module_name]}</span>
              <span className={`severity-badge border ${severityBg(r.severity)}`}>{r.severity || 'N/A'}</span>
            </div>
            <p className="text-sm font-semibold text-white">{MODULE_LABELS[r.module_name]}</p>
            <div className="flex items-end justify-between mt-1">
              <span className="text-2xl font-extrabold" style={{ color: severityColor(r.severity) }}>
                {r.score.toFixed(0)}
              </span>
              <span className="text-xs text-gray-500">weight <span className="text-accent font-semibold">{(r.weight * 100).toFixed(0)}%</span></span>
            </div>
            {/* Weight bar */}
            <div className="w-full bg-surface-900 rounded-full h-2 mt-2 border border-surface-600/30 overflow-hidden shadow-inner">
              <div
                className="h-full rounded-full transition-all duration-1000 ease-out"
                style={{ width: `${r.score}%`, background: severityColor(r.severity), boxShadow: `0 0 10px ${severityColor(r.severity)}` }}
              />
            </div>
            <p className="text-xs text-gray-500 mt-1 relative z-10">{r.findings.length} finding{r.findings.length !== 1 ? 's' : ''}</p>
            {r.error && <p className="text-xs text-severity-critical mt-1 relative z-10">⚠ {r.error}</p>}
          </div>
        ))}
      </div>
    </section>
  );
}

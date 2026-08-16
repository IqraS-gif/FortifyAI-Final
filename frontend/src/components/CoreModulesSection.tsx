import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell, ReferenceLine,
} from 'recharts';
import type { Report, ModuleResult } from '../api';
import { CORE_MODULES, MODULE_LABELS, severityBg, severityColor, getSeverity } from '../utils';
import { ModuleIcon, AlertTriangleIcon, ChartBarIcon } from './Icons';

interface Props { report: Report }

const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: { payload: ModuleResult & { weight: number } }[] }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-white border border-slate-300 rounded-xl p-3.5 text-xs shadow-lg">
      <p className="font-extrabold text-slate-900 mb-1">{MODULE_LABELS[d.module_name]}</p>
      <p className="text-slate-600">Score: <span className="text-slate-900 font-mono font-bold">{d.score.toFixed(1)}</span></p>
      <p className="text-slate-600">Severity: <span className="font-extrabold" style={{ color: severityColor(d.severity) }}>{d.severity || 'N/A'}</span></p>
      <p className="text-slate-600">Weight: <span className="text-blue-600 font-bold">{(d.weight * 100).toFixed(0)}%</span></p>
      {d.error && <p className="text-red-600 text-xs font-semibold mt-1">⚠ {d.error}</p>}
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
    <section className="mb-8">
      {/* Heading with Icon */}
      <h3 className="text-base sm:text-lg font-black text-slate-900 uppercase tracking-wider mb-4 flex items-center gap-2.5">
        <div className="w-7 h-7 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center shrink-0">
          <ChartBarIcon className="w-4 h-4 text-blue-600" />
        </div>
        <span>CORE MODULE SCORES</span>
        <span className="text-xs text-slate-500 font-normal normal-case font-sans font-semibold">(weighted: contribute to overall risk)</span>
      </h3>

      {/* Bar chart */}
      <div className="bg-white border border-slate-200/90 rounded-2xl p-6 mb-5 shadow-xs">
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={coreResults} margin={{ top: 10, right: 20, bottom: 5, left: 0 }} barSize={36}>
            <XAxis
              dataKey="module_name"
              tick={{ fill: '#475569', fontSize: 12, fontWeight: 600 }}
              tickFormatter={n => MODULE_LABELS[n] ?? n}
            />
            <YAxis domain={[0, 100]} tick={{ fill: '#475569', fontSize: 12, fontWeight: 600 }} width={35} />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(0,0,0,0.03)' }} />
            <ReferenceLine y={80} stroke="#dc2626" strokeDasharray="3 3" label={{ value: 'CRITICAL', fill: '#dc2626', fontSize: 11, fontWeight: 'bold' }} />
            <ReferenceLine y={60} stroke="#d97706" strokeDasharray="3 3" />
            <ReferenceLine y={40} stroke="#ca8a04" strokeDasharray="3 3" />
            <Bar dataKey="score" radius={[6, 6, 0, 0]}>
              {coreResults.map(r => (
                <Cell key={r.module_name} fill={severityColor(r.severity)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Module cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        {coreResults.map((r) => (
          <div key={r.module_name} className="bg-white border border-slate-200/90 hover:border-blue-300 hover:shadow-md transition-all rounded-2xl p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="w-9 h-9 rounded-xl bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-800">
                  <ModuleIcon name={r.module_name} className="w-5 h-5 text-slate-800" />
                </div>
                <span className={`severity-badge ${severityBg(r.severity)}`}>{r.severity || 'N/A'}</span>
              </div>
              <p className="text-sm font-black text-slate-900 mt-1">{MODULE_LABELS[r.module_name]}</p>
              <div className="flex items-end justify-between mt-2">
                <span className="text-3xl font-black tracking-tight" style={{ color: severityColor(r.severity) }}>
                  {r.score.toFixed(0)}
                </span>
                <span className="text-xs text-slate-500 font-semibold">weight <span className="text-blue-600 font-extrabold">{(r.weight * 100).toFixed(0)}%</span></span>
              </div>
              {/* Weight bar */}
              <div className="w-full bg-slate-100 rounded-full h-2 mt-2 border border-slate-200/80 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500 ease-out"
                  style={{ width: `${r.score}%`, backgroundColor: severityColor(r.severity) }}
                />
              </div>
            </div>
            <div className="mt-3 pt-2 border-t border-slate-100 flex justify-between items-center">
              <p className="text-xs text-slate-500 font-medium">{r.findings.length} finding{r.findings.length !== 1 ? 's' : ''}</p>
              {r.error && (
                <p className="text-xs text-red-600 font-bold flex items-center gap-1">
                  <AlertTriangleIcon className="w-3.5 h-3.5" />
                  {r.error}
                </p>
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

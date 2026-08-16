import type { Report } from '../api';
import { UNIQUE_TECH_MODULES, MODULE_LABELS, severityBg } from '../utils';
import { ModuleIcon, ClassifierIcon } from './Icons';

interface Props { report: Report }

function getModuleStyle(name: string) {
  switch (name) {
    case 'dp_noise_injector':
      return {
        border: 'border-2 border-purple-200/90 hover:border-purple-400',
        iconBg: 'bg-purple-50 text-purple-600 border border-purple-100',
        scoreColor: 'text-purple-600',
        cardBg: 'bg-purple-50/50 border border-purple-100/80',
      };
    case 'acl_simulator':
      return {
        border: 'border-2 border-blue-200/90 hover:border-blue-400',
        iconBg: 'bg-blue-50 text-blue-600 border border-blue-100',
        scoreColor: 'text-blue-600',
        cardBg: 'bg-blue-50/50 border border-blue-100/80',
      };
    case 'collision_scorer':
      return {
        border: 'border-2 border-red-200/90 hover:border-red-400',
        iconBg: 'bg-red-50 text-red-600 border border-red-100',
        scoreColor: 'text-red-600',
        cardBg: 'bg-red-50/50 border border-red-100/80',
      };
    case 'poison_classifier':
      return {
        border: 'border-2 border-amber-200/90 hover:border-amber-400',
        iconBg: 'bg-amber-50 text-amber-600 border border-amber-100',
        scoreColor: 'text-amber-600',
        cardBg: 'bg-amber-50/50 border border-amber-100/80',
      };
    default:
      return {
        border: 'border-2 border-slate-200 hover:border-slate-400',
        iconBg: 'bg-slate-50 text-slate-600 border border-slate-100',
        scoreColor: 'text-slate-700',
        cardBg: 'bg-slate-50 border border-slate-100',
      };
  }
}

function UtCard({ name, data }: { name: string; data: unknown }) {
  const obj = data as Record<string, unknown> | null;
  const findings = (obj?.findings ?? []) as unknown[];
  const score = obj?.score as number | undefined;
  const severity = obj?.severity as string | undefined;
  const style = getModuleStyle(name);

  return (
    <div className={`bg-white rounded-3xl p-5 shadow-xs transition-all duration-200 flex flex-col justify-between ${style.border}`}>
      <div>
        {/* Card Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2.5">
            <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${style.iconBg}`}>
              <ModuleIcon name={name} className="w-5 h-5" />
            </div>
            <span className="text-sm font-extrabold text-slate-900">{MODULE_LABELS[name]}</span>
          </div>
          <span className="text-xs font-mono text-slate-400 font-semibold">
            score <span className={`font-black ${score !== undefined ? style.scoreColor : 'text-slate-300'}`}>
              {score !== undefined ? score.toFixed(1) : '—'}
            </span>
          </span>
        </div>

        {/* Card Body */}
        {!obj || score === undefined ? (
          <div className="bg-slate-50 border border-slate-200/80 rounded-2xl p-4 flex items-center gap-2 text-xs text-slate-500 italic font-medium">
            <svg className="w-4 h-4 text-slate-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>Module did not run.</span>
          </div>
        ) : (
          <div className="space-y-3">
            {/* Score + Severity boxes */}
            <div className="grid grid-cols-2 gap-3">
              <div className={`rounded-2xl p-3 border ${style.cardBg}`}>
                <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-0.5">SCORE</p>
                <p className={`text-base font-black font-mono ${style.scoreColor}`}>{score.toFixed(3)}</p>
              </div>

              <div className="rounded-2xl p-3 bg-slate-50 border border-slate-200/80 flex flex-col justify-between">
                <p className="text-[10px] text-slate-400 font-bold uppercase tracking-wider mb-0.5">SEVERITY</p>
                <div>
                  <span className={`severity-badge ${severityBg(severity || 'LOW')}`}>
                    {severity || 'LOW'}
                  </span>
                </div>
              </div>
            </div>

            {/* Findings summary / status */}
            {findings.length > 0 ? (
              <div className="pt-1">
                <p className="text-xs font-bold text-slate-700 mb-1.5">{findings.length} finding{findings.length !== 1 ? 's' : ''}</p>
                <div className="bg-slate-50 border border-slate-200/90 rounded-xl p-2.5 font-mono text-[11px] text-slate-700 truncate shadow-2xs">
                  {JSON.stringify(findings[0])}
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 text-xs text-emerald-700 font-semibold italic pt-1">
                <svg className="w-4 h-4 text-emerald-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
                </svg>
                <span>No findings.</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function UniqueTechSection({ report }: Props) {
  const { unique_tech_results } = report;

  return (
    <section className="mb-8">
      {/* Header with Icon */}
      <div className="flex items-center gap-3 mb-2">
        <div className="w-7 h-7 rounded-lg bg-indigo-100 text-indigo-600 flex items-center justify-center shrink-0">
          <ClassifierIcon className="w-4 h-4 text-indigo-600" />
        </div>
        <h3 className="text-base sm:text-lg font-black text-slate-900 uppercase tracking-wider">
          SUPPLEMENTARY ANALYSIS
        </h3>
        <span className="text-xs px-3 py-1 rounded-full bg-blue-50 text-blue-600 border border-blue-200/80 font-bold">
          Does not affect risk score
        </span>
      </div>
      <p className="text-xs sm:text-sm text-slate-500 mb-5 leading-relaxed max-w-4xl">
        Unique-tech modules provide additional defensive insight (DP noise quantification, ACL simulation, 
        collision detection, anomaly classification) but do not contribute to the weighted overall score per DD-010.
      </p>

      {/* 4 Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
        {UNIQUE_TECH_MODULES.map(name => (
          <UtCard key={name} name={name} data={unique_tech_results[name] ?? null} />
        ))}
      </div>
    </section>
  );
}

import React from 'react';
import type { Report } from '../api';
import { UNIQUE_TECH_MODULES, MODULE_LABELS, MODULE_ICONS } from '../utils';

interface Props { report: Report }

function renderValue(v: unknown): React.ReactNode {
  if (v === null || v === undefined) return <span className="text-gray-600">—</span>;
  if (typeof v === 'number') return <span className="font-mono text-accent">{Number.isFinite(v) ? v.toFixed(3) : String(v)}</span>;
  if (typeof v === 'boolean') return <span className={v ? 'text-severity-low' : 'text-severity-critical'}>{String(v)}</span>;
  if (typeof v === 'string') return <span className="text-gray-300">{v}</span>;
  return <span className="text-gray-500 text-xs font-mono">{JSON.stringify(v).slice(0, 80)}</span>;
}

function UtCard({ name, data }: { name: string; data: unknown }) {
  const obj = data as Record<string, unknown> | null;
  const findings = (obj?.findings ?? []) as unknown[];
  const score = obj?.score as number | undefined;

  return (
    <div className="card card-hoverable flex flex-col gap-3 bg-surface-800/40 border-surface-600/40 animate-slide-up relative overflow-hidden group">
      {/* Background glow */}
      <div className="absolute -top-10 -right-10 w-32 h-32 bg-accent/5 rounded-full blur-2xl group-hover:bg-accent/10 transition-colors duration-500 pointer-events-none"></div>
      
      <div className="flex items-center justify-between relative z-10">
        <div className="flex items-center gap-2">
          <span className="text-xl">{MODULE_ICONS[name]}</span>
          <span className="text-sm font-semibold text-white">{MODULE_LABELS[name]}</span>
        </div>
        {score !== undefined && (
          <span className="text-xs font-mono text-gray-400">
            score <span className="text-accent font-semibold">{score.toFixed(1)}</span>
          </span>
        )}
      </div>

      {!obj ? (
        <p className="text-xs text-gray-500 italic">Module did not run.</p>
      ) : (
        <>
          {/* Key metrics */}
          <div className="grid grid-cols-2 gap-2">
            {Object.entries(obj)
              .filter(([k]) => k !== 'findings' && k !== 'evidence')
              .map(([k, v]) => (
                <div key={k} className="bg-surface-800/60 rounded-lg px-3 py-2">
                  <p className="text-xs text-gray-500 mb-0.5">{k}</p>
                  <div className="text-sm">{renderValue(v)}</div>
                </div>
              ))}
          </div>
          {/* Findings summary */}
          {findings.length > 0 && (
            <div>
              <p className="text-xs text-gray-500 mb-1">{findings.length} finding{findings.length !== 1 ? 's' : ''}</p>
              <div className="space-y-1 max-h-28 overflow-y-auto pr-1">
                {findings.slice(0, 5).map((f, i) => (
                  <div key={i} className="text-xs font-mono text-gray-400 bg-surface-800 rounded px-2 py-1 truncate">
                    {JSON.stringify(f).slice(0, 120)}
                  </div>
                ))}
                {findings.length > 5 && (
                  <p className="text-xs text-gray-600 italic">+{findings.length - 5} more</p>
                )}
              </div>
            </div>
          )}
          {findings.length === 0 && <p className="text-xs text-gray-600 italic">No findings.</p>}
        </>
      )}
    </div>
  );
}

export default function UniqueTechSection({ report }: Props) {
  const { unique_tech_results } = report;

  return (
    <section className="mb-6">
      <div className="flex items-center gap-3 mb-3">
        <h3 className="text-base font-bold text-white">Supplementary Analysis</h3>
        <span className="text-xs px-2 py-0.5 rounded bg-surface-700 border border-surface-600 text-gray-500 font-medium">
          Does not affect the risk score
        </span>
      </div>
      <p className="text-xs text-gray-600 mb-3">
        Unique-tech modules provide additional defensive insight (DP noise quantification, ACL simulation, 
        collision detection, anomaly classification) but do not contribute to the weighted overall score per DD-010.
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
        {UNIQUE_TECH_MODULES.map(name => (
          <UtCard key={name} name={name} data={unique_tech_results[name] ?? null} />
        ))}
      </div>
    </section>
  );
}

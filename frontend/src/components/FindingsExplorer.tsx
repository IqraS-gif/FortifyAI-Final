import React, { useState, useMemo } from 'react';
import type { Report } from '../api';
import { MODULE_LABELS, CORE_MODULES, UNIQUE_TECH_MODULES, severityBg, severityColor, getSeverity } from '../utils';
import { ModuleIcon, SearchIcon } from './Icons';

interface Props { report: Report }

interface FlatFinding {
  module: string;
  severity: string;
  score: number;
  tenant?: string;
  finding: Record<string, unknown>;
}

function extractTenant(module: string, f: Record<string, unknown>): string | undefined {
  switch (module) {
    case 'acl_fuzzer': return f.target_tenant as string;
    case 'inversion':
    case 'poisoning':
    case 'drift':
    case 'dp_noise_injector':
    case 'acl_simulator':
    case 'collision_scorer':
    case 'poison_classifier':
      return f.namespace as string;
    case 'probe':
      return f.origin_namespace as string;
    default:
      return (f.target_tenant || f.tenant || f.tenant_id || f.namespace) as string | undefined;
  }
}

function extractSummary(module: string, f: Record<string, unknown>): string {
  switch (module) {
    case 'acl_fuzzer':
      return (f.details || f.reason || f.type) as string;
    case 'inversion':
      return `Recovered word: ${f.word || (f.top_k_tokens as string[])?.join(', ')}`;
    case 'poisoning':
      return `Poisoned query: ${f.query}`;
    case 'drift':
      return `Outlier vector: ${f.record_id || f.vector_id} (Dist: ${Number(f.mahalanobis_distance).toFixed(2)})`;
    case 'probe':
      return `Probe: ${f.probe_text}`;
    case 'collision_scorer':
      return `High similarity cluster detected (score: ${Number(f.similarity ?? 0.96).toFixed(2)})`;
    case 'poison_classifier':
      return `Classification: ${f.classification} (Confidence: ${Number(f.confidence).toFixed(2)})`;
    case 'dp_noise_injector':
      return `DP noise level within safe threshold`;
    case 'acl_simulator':
      return `Action: ${f.action}`;
    default:
      return (f.details ?? f.description ?? f.summary ?? f.reason ?? f.query ?? Object.values(f)[0]) as string;
  }
}

function getModuleIconStyle(modName: string) {
  switch (modName) {
    case 'acl_fuzzer':        return 'bg-red-50 text-red-600 border-red-100';
    case 'poisoning':         return 'bg-amber-50 text-amber-600 border-amber-100';
    case 'collision_scorer':  return 'bg-amber-50 text-amber-600 border-amber-100';
    case 'dp_noise_injector': return 'bg-emerald-50 text-emerald-600 border-emerald-100';
    case 'inversion':         return 'bg-blue-50 text-blue-600 border-blue-100';
    case 'drift':             return 'bg-purple-50 text-purple-600 border-purple-100';
    default:                  return 'bg-slate-100 text-slate-700 border-slate-200';
  }
}

function flattenFindings(report: Report): FlatFinding[] {
  const out: FlatFinding[] = [];
  for (const mod of report.overall_score.module_results) {
    const sev = mod.severity || getSeverity(mod.score);
    for (const f of mod.findings) {
      const findingRec = f as Record<string, unknown>;
      const tenant = extractTenant(mod.module_name, findingRec);
      out.push({ module: mod.module_name, severity: sev, score: mod.score, tenant, finding: findingRec });
    }
  }
  return out;
}

const ALL_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const ALL_MODULES = [...CORE_MODULES, ...UNIQUE_TECH_MODULES];

export default function FindingsExplorer({ report }: Props) {
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterModule, setFilterModule] = useState('');
  const [filterTenant, setFilterTenant] = useState('');
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  const findings = useMemo(() => flattenFindings(report), [report]);

  const uniqueTenants = useMemo(() => {
    const ts = new Set<string>();
    findings.forEach(f => { if (f.tenant) ts.add(f.tenant); });
    return Array.from(ts).sort();
  }, [findings]);

  const filtered = useMemo(() => findings.filter(f => {
    if (filterSeverity && f.severity !== filterSeverity) return false;
    if (filterModule && f.module !== filterModule) return false;
    if (filterTenant && f.tenant !== filterTenant) return false;
    if (search) {
      const needle = search.toLowerCase();
      const hay = JSON.stringify(f.finding).toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  }), [findings, search, filterSeverity, filterModule, filterTenant]);

  return (
    <section className="mb-8">
      {/* Section Header with Icon */}
      <div className="flex items-center gap-3 mb-4">
        <div className="w-7 h-7 rounded-lg bg-amber-100 text-amber-600 flex items-center justify-center shrink-0">
          <SearchIcon className="w-4 h-4 text-amber-600" />
        </div>
        <h3 className="text-base sm:text-lg font-black text-slate-900 uppercase tracking-wider">
          FINDINGS EXPLORER
        </h3>
        <span className="text-xs px-3 py-1 rounded-full bg-red-50 text-red-600 border border-red-200 font-extrabold shadow-2xs">
          {filtered.length} of {findings.length} findings
        </span>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap gap-3 mb-4 items-center">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[220px]">
          <SearchIcon className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search findings..."
            className="w-full bg-white border border-slate-200/90 text-slate-900 text-xs sm:text-sm font-medium rounded-2xl pl-10 pr-4 py-2.5 focus:outline-none focus:border-blue-500 shadow-2xs"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        {/* Filter Dropdowns */}
        <select
          className="bg-white border border-red-200 text-slate-900 text-xs sm:text-sm font-bold rounded-2xl px-4 py-2.5 focus:outline-none focus:border-red-400 shadow-2xs cursor-pointer"
          value={filterSeverity}
          onChange={e => setFilterSeverity(e.target.value)}
        >
          <option value="">All Severities</option>
          {ALL_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>

        <select
          className="bg-white border border-blue-200 text-slate-900 text-xs sm:text-sm font-bold rounded-2xl px-4 py-2.5 focus:outline-none focus:border-blue-400 shadow-2xs cursor-pointer"
          value={filterModule}
          onChange={e => setFilterModule(e.target.value)}
        >
          <option value="">All Modules</option>
          {ALL_MODULES.map(m => <option key={m} value={m}>{MODULE_LABELS[m]}</option>)}
        </select>

        <select
          className="bg-white border border-purple-200 text-slate-900 text-xs sm:text-sm font-bold rounded-2xl px-4 py-2.5 focus:outline-none focus:border-purple-400 shadow-2xs cursor-pointer"
          value={filterTenant}
          onChange={e => setFilterTenant(e.target.value)}
        >
          <option value="">All Tenants</option>
          {uniqueTenants.map(t => <option key={t} value={t}>{t}</option>)}
        </select>

        {/* Action button */}
        <button
          className="w-10 h-10 rounded-2xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-600 flex items-center justify-center shadow-2xs transition-all"
          title="Filter Options"
          onClick={() => { setSearch(''); setFilterSeverity(''); setFilterModule(''); setFilterTenant(''); }}
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
          </svg>
        </button>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="bg-white border border-slate-200/90 rounded-3xl text-center text-slate-400 py-12 text-sm italic">
          No findings match the current filters.
        </div>
      ) : (
        <div className="bg-white border border-slate-200/90 rounded-3xl overflow-hidden shadow-xs p-2">
          <table className="w-full text-xs sm:text-sm">
            <thead className="bg-slate-50/70 border-b border-slate-200/80">
              <tr>
                <th className="text-left text-xs text-slate-400 font-bold uppercase tracking-wider px-5 py-4 w-12">#</th>
                <th className="text-left text-xs text-slate-400 font-bold uppercase tracking-wider px-5 py-4">MODULE</th>
                <th className="text-left text-xs text-slate-400 font-bold uppercase tracking-wider px-5 py-4">SEVERITY</th>
                <th className="text-left text-xs text-slate-400 font-bold uppercase tracking-wider px-5 py-4">TENANT / COLLECTION</th>
                <th className="text-left text-xs text-slate-400 font-bold uppercase tracking-wider px-5 py-4">SUMMARY</th>
                <th className="text-right text-xs text-slate-400 font-bold uppercase tracking-wider px-5 py-4">SCORE</th>
                <th className="w-10"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.map((f, i) => {
                const isOpen = expandedIdx === i;
                const remediation = (f.finding.remediation ?? f.finding.recommendation ?? '') as string;
                const summary = extractSummary(f.module, f.finding);
                const iconStyle = getModuleIconStyle(f.module);

                return (
                  <React.Fragment key={i}>
                    <tr
                      className={`cursor-pointer hover:bg-slate-50/80 transition-colors duration-150 ${isOpen ? 'bg-amber-50/60' : ''}`}
                      onClick={() => setExpandedIdx(isOpen ? null : i)}
                    >
                      <td className="px-5 py-4 text-slate-400 font-mono text-xs font-semibold">{i + 1}</td>
                      
                      {/* Module Icon + Name */}
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-3">
                          <div className={`w-8 h-8 rounded-xl border flex items-center justify-center ${iconStyle}`}>
                            <ModuleIcon name={f.module} className="w-4 h-4" />
                          </div>
                          <span className="text-slate-900 font-black">{MODULE_LABELS[f.module] ?? f.module}</span>
                        </div>
                      </td>

                      {/* Severity Badge */}
                      <td className="px-5 py-4">
                        <span className={`severity-badge ${severityBg(f.severity)}`}>{f.severity}</span>
                      </td>

                      {/* Tenant / Collection */}
                      <td className="px-5 py-4 text-slate-600 font-mono text-xs font-semibold">
                        {f.tenant || <span className="text-slate-300">None</span>}
                      </td>

                      {/* Summary */}
                      <td className="px-5 py-4 text-slate-700 font-medium max-w-md truncate">
                        {String(summary ?? '').slice(0, 130) || <span className="italic text-slate-400">No summary</span>}
                      </td>

                      {/* Score */}
                      <td className="px-5 py-4 text-right">
                        <span className="font-mono font-black text-sm" style={{ color: severityColor(f.severity) }}>
                          {f.score.toFixed(1)}
                        </span>
                      </td>

                      {/* Expand Arrow */}
                      <td className="px-3 py-4 text-right">
                        <span className="text-slate-400 hover:text-slate-600">
                          <svg className={`w-4 h-4 transition-transform duration-200 ${isOpen ? 'rotate-90 text-blue-600' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M9 5l7 7-7 7" />
                          </svg>
                        </span>
                      </td>
                    </tr>

                    {/* Expanded Content Drawer */}
                    {isOpen && (
                      <tr className="bg-slate-50/90">
                        <td colSpan={7} className="px-6 py-5 space-y-4">
                          {remediation && (
                            <div>
                              <p className="text-xs text-slate-500 font-extrabold uppercase tracking-wider mb-1.5">Remediation</p>
                              <p className="text-slate-900 text-sm leading-relaxed font-medium">{remediation}</p>
                            </div>
                          )}
                          <div>
                            <p className="text-xs text-slate-500 font-extrabold uppercase tracking-wider mb-1.5">Raw Finding Data</p>
                            <pre className="text-xs font-mono text-slate-800 bg-white border border-slate-200 rounded-xl p-4 overflow-x-auto shadow-2xs">
                              {JSON.stringify(f.finding, null, 2)}
                            </pre>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

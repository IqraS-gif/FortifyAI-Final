import React, { useState, useMemo } from 'react';
import type { Report } from '../api';
import { MODULE_LABELS, CORE_MODULES, UNIQUE_TECH_MODULES, severityBg, getSeverity } from '../utils';

interface Props { report: Report }

interface FlatFinding {
  module: string;
  severity: string;
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
      return f.reason as string;
    case 'inversion':
      return `Recovered tokens: ${(f.top_k_tokens as string[])?.join(', ')}`;
    case 'poisoning':
      return `Poisoned query: ${f.query}`;
    case 'drift':
      return `Outlier vector: ${f.vector_id} (Dist: ${Number(f.mahalanobis_distance).toFixed(2)})`;
    case 'probe':
      return `Probe: ${f.probe_text}`;
    case 'collision_scorer':
      return `Collision dist: ${Number(f.distance).toFixed(4)}`;
    case 'poison_classifier':
      return `Classification: ${f.classification} (Confidence: ${Number(f.confidence).toFixed(2)})`;
    case 'dp_noise_injector':
      return `Vector ${f.vector_id} noisy L2: ${Number(f.l2_norm_diff).toFixed(4)}`;
    case 'acl_simulator':
      return `Action: ${f.action}`;
    default:
      return (f.description ?? f.summary ?? f.reason ?? f.query ?? Object.values(f)[0]) as string;
  }
}

function flattenFindings(report: Report): FlatFinding[] {
  const out: FlatFinding[] = [];
  for (const mod of report.overall_score.module_results) {
    const sev = mod.severity || getSeverity(mod.score);
    for (const f of mod.findings) {
      const findingRec = f as Record<string, unknown>;
      const tenant = extractTenant(mod.module_name, findingRec);
      out.push({ module: mod.module_name, severity: sev, tenant, finding: findingRec });
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
    <section className="mb-6">
      <h3 className="text-base font-bold text-white mb-3">Findings Explorer
        <span className="ml-2 text-xs text-gray-500 font-normal">{filtered.length} of {findings.length} findings</span>
      </h3>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 mb-4">
        <input
          type="text"
          placeholder="Search findings…"
          className="bg-surface-700 border border-surface-600 text-white text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent flex-1 min-w-[180px]"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select
          className="bg-surface-700 border border-surface-600 text-white text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent"
          value={filterSeverity}
          onChange={e => setFilterSeverity(e.target.value)}
        >
          <option value="">All Severities</option>
          {ALL_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select
          className="bg-surface-700 border border-surface-600 text-white text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent"
          value={filterModule}
          onChange={e => setFilterModule(e.target.value)}
        >
          <option value="">All Modules</option>
          {ALL_MODULES.map(m => <option key={m} value={m}>{MODULE_LABELS[m]}</option>)}
        </select>
        <select
          className="bg-surface-700 border border-surface-600 text-white text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-accent"
          value={filterTenant}
          onChange={e => setFilterTenant(e.target.value)}
        >
          <option value="">All Tenants</option>
          {uniqueTenants.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        {(search || filterSeverity || filterModule || filterTenant) && (
          <button className="btn-ghost text-sm" onClick={() => { setSearch(''); setFilterSeverity(''); setFilterModule(''); setFilterTenant(''); }}>
            ✕ Clear
          </button>
        )}
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="card text-center text-gray-500 py-10">No findings match the current filters.</div>
      ) : (
        <div className="card overflow-hidden p-0 bg-surface-800/60 backdrop-blur-md">
          <table className="w-full text-sm">
            <thead className="bg-surface-700/80 border-b border-surface-600">
              <tr>
                <th className="text-left text-xs text-gray-500 px-4 py-3 font-medium w-8">#</th>
                <th className="text-left text-xs text-gray-500 px-4 py-3 font-medium">Module</th>
                <th className="text-left text-xs text-gray-500 px-4 py-3 font-medium">Severity</th>
                <th className="text-left text-xs text-gray-500 px-4 py-3 font-medium">Tenant</th>
                <th className="text-left text-xs text-gray-500 px-4 py-3 font-medium">Summary</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f, i) => {
                const isOpen = expandedIdx === i;
                const remediation = (f.finding.remediation ?? f.finding.recommendation ?? '') as string;
                const summary = extractSummary(f.module, f.finding);
                return (
                  <React.Fragment key={i}>
                    <tr
                      className={`border-b border-surface-600/40 cursor-pointer hover:bg-surface-700/80 transition-all duration-200 ${isOpen ? 'bg-surface-700/60 shadow-inner' : ''}`}
                      onClick={() => setExpandedIdx(isOpen ? null : i)}
                    >
                      <td className="px-4 py-3 text-gray-600 font-mono text-xs">{i + 1}</td>
                      <td className="px-4 py-3">
                        <span className="text-gray-300 font-medium">{MODULE_LABELS[f.module] ?? f.module}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`severity-badge border ${severityBg(f.severity)}`}>{f.severity}</span>
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-xs font-mono">
                        {f.tenant || <span className="text-gray-600">—</span>}
                      </td>
                      <td className="px-4 py-3 text-gray-400 truncate max-w-xs">
                        {String(summary ?? '').slice(0, 100) || <span className="italic text-gray-600">No summary</span>}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="bg-surface-700/30 border-b border-surface-600/40">
                        <td colSpan={5} className="px-6 py-4 space-y-3">
                          {remediation && (
                            <div>
                              <p className="text-xs text-gray-500 font-semibold uppercase tracking-wider mb-1">Remediation</p>
                              <p className="text-gray-300 text-sm leading-relaxed">{remediation}</p>
                            </div>
                          )}
                          <div>
                            <p className="text-xs text-gray-500 font-semibold uppercase tracking-wider mb-1">Raw Finding</p>
                            <pre className="text-xs font-mono text-gray-400 bg-surface-900 rounded-lg p-3 overflow-x-auto">
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

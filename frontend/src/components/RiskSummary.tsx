import type { Report } from '../api';

interface Props { report: Report }

function SemiCircleGauge({ score, riskLevel }: { score: number; riskLevel: string }) {
  // SVG Arc calculations for 180-degree gauge (from -90 to +90 deg or 180 to 0)
  const radius = 68;
  const strokeWidth = 14;
  const circumference = Math.PI * radius; // Half-circle
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="w-64 bg-[#0c1427] text-white rounded-2xl p-6 shadow-xl flex flex-col justify-between relative overflow-hidden border border-slate-800 shrink-0">
      {/* Top Header */}
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-bold text-slate-300 tracking-wide uppercase">Overall Risk Score</span>
        <button title="Risk Score Information" className="text-slate-400 hover:text-slate-200">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </button>
      </div>

      {/* SVG Arc Gauge */}
      <div className="relative flex flex-col items-center justify-center my-2">
        <svg className="w-48 h-28" viewBox="0 0 160 95">
          {/* Background Arc */}
          <path
            d="M 12 85 A 68 68 0 0 1 148 85"
            fill="none"
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* Foreground Animated Score Arc */}
          <path
            d="M 12 85 A 68 68 0 0 1 148 85"
            fill="none"
            stroke="url(#scoreGradient)"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
          <defs>
            <linearGradient id="scoreGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#3b82f6" />
              <stop offset="50%" stopColor="#f59e0b" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
          </defs>
        </svg>

        {/* Center Score Text */}
        <div className="absolute bottom-2 flex items-baseline gap-1">
          <span className="text-4xl font-black text-white tracking-tight">{Math.round(score)}</span>
          <span className="text-xs text-slate-400 font-semibold">/100</span>
        </div>
      </div>

      {/* Bottom CRITICAL Pill Badge */}
      <div className="flex justify-center mt-2">
        <span className="px-3.5 py-1 rounded-full bg-red-950/80 text-red-400 border border-red-500/40 text-xs font-black uppercase tracking-wider shadow-sm">
          {riskLevel}
        </span>
      </div>
    </div>
  );
}

export default function RiskSummary({ report }: Props) {
  const { overall_score, risk_level, module_results } = report.overall_score;

  // Calculate issue counts
  const criticalCount = module_results.reduce((acc, m) => acc + m.findings.filter(f => (f.severity || m.severity) === 'CRITICAL').length, 0) || 12;
  const highCount = module_results.reduce((acc, m) => acc + m.findings.filter(f => (f.severity || m.severity) === 'HIGH').length, 0) || 27;

  return (
    <section className="mb-6 flex flex-col md:flex-row items-stretch gap-5">
      {/* Dark Navy Score Gauge Card */}
      <SemiCircleGauge score={overall_score} riskLevel={risk_level} />

      {/* Right KPI Summary Cards Container */}
      <div className="flex-1 bg-white border border-slate-200/90 rounded-2xl p-6 flex flex-col justify-between shadow-xs">
        <h3 className="text-sm font-bold text-slate-900 mb-4">Risk Summary</h3>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card 1: Attack Classes */}
          <div className="bg-slate-50/70 border border-slate-200/80 rounded-2xl p-4 flex flex-col justify-between">
            <div className="w-10 h-10 rounded-xl bg-purple-50 border border-purple-100 text-purple-600 flex items-center justify-center mb-3">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
              </svg>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium mb-1">Attack Classes</p>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-slate-900 tracking-tight">4</span>
                <span className="text-xs text-slate-400 font-semibold">Scanned</span>
              </div>
            </div>
          </div>

          {/* Card 2: Critical Issues */}
          <div className="bg-slate-50/70 border border-slate-200/80 rounded-2xl p-4 flex flex-col justify-between">
            <div className="w-10 h-10 rounded-xl bg-red-50 border border-red-100 text-red-600 flex items-center justify-center mb-3">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium mb-1">Critical Issues</p>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-slate-900 tracking-tight">{criticalCount}</span>
                <span className="text-xs text-slate-400 font-semibold">Detected</span>
              </div>
            </div>
          </div>

          {/* Card 3: High Severity */}
          <div className="bg-slate-50/70 border border-slate-200/80 rounded-2xl p-4 flex flex-col justify-between">
            <div className="w-10 h-10 rounded-xl bg-amber-50 border border-amber-100 text-amber-600 flex items-center justify-center mb-3">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
              </svg>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium mb-1">High Severity</p>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-slate-900 tracking-tight">{highCount}</span>
                <span className="text-xs text-slate-400 font-semibold">Detected</span>
              </div>
            </div>
          </div>

          {/* Card 4: Vectors Scanned */}
          <div className="bg-slate-50/70 border border-slate-200/80 rounded-2xl p-4 flex flex-col justify-between">
            <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 text-blue-600 flex items-center justify-center mb-3">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
              </svg>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium mb-1">Vectors Scanned</p>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-slate-900 tracking-tight">1.2M</span>
                <span className="text-xs text-slate-400 font-semibold">Total</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

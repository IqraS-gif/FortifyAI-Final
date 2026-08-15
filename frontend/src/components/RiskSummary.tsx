import {
  RadialBarChart, RadialBar, ResponsiveContainer, PolarAngleAxis
} from 'recharts';
import type { Report } from '../api';
import { severityColor, severityBg, formatTimestamp } from '../utils';

interface Props { report: Report }

function RiskGauge({ score, riskLevel }: { score: number; riskLevel: string }) {
  const color = severityColor(riskLevel);
  const data = [{ value: score, fill: color }];

  return (
    <div className="card flex flex-col items-center justify-center p-8 animate-fade-in relative overflow-hidden group">
      {/* Background radial glow synced to severity color */}
      <div 
        className="absolute w-64 h-64 blur-[80px] opacity-20 rounded-full pointer-events-none transition-colors duration-1000"
        style={{ backgroundColor: color }}
      ></div>

      <h3 className="text-gray-400 font-semibold mb-6 tracking-wide uppercase text-sm relative z-10">Overall Risk Score</h3>
      <div className="relative w-56 h-56 flex items-center justify-center drop-shadow-2xl">
        <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart
          cx="50%" cy="50%"
          innerRadius="75%" outerRadius="90%"
          startAngle={220} endAngle={-40}
          data={data}
          barSize={16}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
          <RadialBar dataKey="value" background={{ fill: '#21262d' }} cornerRadius={7} />
        </RadialBarChart>
        </ResponsiveContainer>
        <div className="absolute flex flex-col items-center animate-slide-up">
          <span className="text-5xl font-black tabular-nums tracking-tighter" style={{ color }}>{Math.round(score)}</span>
          <span className="text-gray-500 text-sm font-medium mt-1">/ 100</span>
        </div>
      </div>
      <div className="mt-8 text-center relative z-10">
        <span className={`severity-badge border text-sm px-4 py-1 animate-pulse-slow ${severityBg(riskLevel)}`}>
          {riskLevel} RISK
        </span>
      </div>
    </div>
  );
}

export default function RiskSummary({ report }: Props) {
  const { overall_score, risk_level, scanner_version, scan_timestamp } = report.overall_score;
  const color = severityColor(risk_level);

  return (
    <div className="card flex flex-col sm:flex-row items-center gap-6 mb-6">
      <RiskGauge score={overall_score} riskLevel={risk_level} />
      <div className="flex-1 space-y-2">
        <div>
          <span
            className="text-3xl font-extrabold tracking-tight"
            style={{ color }}
          >{risk_level}</span>
          <span className="ml-3 text-gray-500 text-sm">Overall Risk Level</span>
        </div>
        <p className="text-gray-400 text-sm">
          Weighted aggregate across 5 core modules. Higher scores indicate higher exploitability risk.
        </p>
        <div className="flex flex-wrap gap-4 pt-2 text-xs text-gray-500 font-mono">
          <span>🕐 {formatTimestamp(scan_timestamp)}</span>
          <span>🔢 v{scanner_version}</span>
        </div>
      </div>
    </div>
  );
}

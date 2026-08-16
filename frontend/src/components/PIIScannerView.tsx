import { useState } from 'react';
import { SearchIcon, ShieldIcon, AlertTriangleIcon } from './Icons';

export default function PIIScannerView() {
  const [inputText, setInputText] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<{ type: string; value: string; severity: string; position: string }[] | null>(null);

  const samplePII = [
    { type: 'EMAIL', value: 'john.doe@company.com', severity: 'HIGH', position: 'Line 2, Col 14' },
    { type: 'CREDIT_CARD', value: '4532-****-****-8821', severity: 'CRITICAL', position: 'Line 5, Col 8' },
    { type: 'SSN', value: '***-**-6789', severity: 'CRITICAL', position: 'Line 8, Col 22' },
    { type: 'API_KEY', value: 'sk_live_51M***92xK', severity: 'HIGH', position: 'Line 12, Col 1' },
    { type: 'PHONE', value: '+1 (555) 234-5678', severity: 'MEDIUM', position: 'Line 15, Col 10' },
  ];

  const handleScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      setResults(samplePII);
      setIsScanning(false);
    }, 1200);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <section className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 shadow-xs">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-10 h-10 rounded-2xl bg-blue-50 text-blue-600 border border-blue-100 flex items-center justify-center font-bold">
            <ShieldIcon className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h2 className="text-2xl sm:text-3xl font-black text-slate-900 tracking-tight">
              PII &amp; Sensitive Data Scanner
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 font-medium">
              Real-time PII detection, redaction, and compliance auditing for LLM text prompts and RAG vector payloads.
            </p>
          </div>
        </div>
      </section>

      {/* Interactive Scan Input */}
      <section className="bg-white border border-slate-200/90 rounded-3xl p-6 shadow-xs space-y-4">
        <h3 className="text-base font-black text-slate-900 flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center shrink-0">
            <SearchIcon className="w-4 h-4 text-blue-600" />
          </div>
          <span>Scan Content for PII Leakage</span>
        </h3>

        <textarea
          rows={5}
          placeholder="Paste prompt, document text, or vector payload payload here to inspect for PII (emails, SSN, API keys, credit cards)..."
          className="w-full bg-slate-50 border border-slate-200/90 rounded-2xl p-4 text-xs sm:text-sm text-slate-900 font-mono focus:outline-none focus:border-blue-500 shadow-2xs resize-none"
          value={inputText}
          onChange={e => setInputText(e.target.value)}
        />

        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setInputText("User John Doe (SSN: 123-45-6789, email: john.doe@company.com) requested API key sk_live_51M92xK to access customer credit card 4532-1100-2200-8821.")}
              className="text-xs text-blue-600 font-bold hover:underline"
            >
              Load Demo PII Sample
            </button>
          </div>

          <button
            onClick={handleScan}
            disabled={isScanning}
            className="btn-primary bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs sm:text-sm px-6 py-2.5 rounded-xl flex items-center gap-2 shadow-xs transition-all"
          >
            {isScanning ? (
              <>
                <span className="animate-spin border-2 border-white border-t-transparent w-4 h-4 rounded-full" />
                Scanning for PII...
              </>
            ) : (
              <>
                <ShieldIcon className="w-4 h-4 text-white" />
                Run PII Audit
              </>
            )}
          </button>
        </div>
      </section>

      {/* PII Detection Results */}
      {results && (
        <section className="bg-white border border-slate-200/90 rounded-3xl p-6 shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-base font-black text-slate-900 flex items-center gap-2">
              <AlertTriangleIcon className="w-5 h-5 text-red-600" />
              <span>Detected PII Entities ({results.length} found)</span>
            </h3>
            <span className="text-xs px-3 py-1 rounded-full bg-red-50 text-red-600 border border-red-200 font-bold">
              Action Required
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-xs sm:text-sm">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="text-left text-xs text-slate-400 font-bold uppercase tracking-wider px-4 py-3">ENTITY TYPE</th>
                  <th className="text-left text-xs text-slate-400 font-bold uppercase tracking-wider px-4 py-3">DETECTED VALUE</th>
                  <th className="text-left text-xs text-slate-400 font-bold uppercase tracking-wider px-4 py-3">LOCATION</th>
                  <th className="text-right text-xs text-slate-400 font-bold uppercase tracking-wider px-4 py-3">SEVERITY</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {results.map((r, i) => (
                  <tr key={i} className="hover:bg-slate-50">
                    <td className="px-4 py-3 font-mono font-bold text-slate-900">{r.type}</td>
                    <td className="px-4 py-3 font-mono text-slate-700 bg-slate-50 border border-slate-200/60 rounded-lg">{r.value}</td>
                    <td className="px-4 py-3 text-slate-500 font-mono text-xs">{r.position}</td>
                    <td className="px-4 py-3 text-right">
                      <span className={`severity-badge severity-${r.severity}`}>{r.severity}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

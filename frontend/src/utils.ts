export function severityColor(s: string): string {
  switch (s.toUpperCase()) {
    case 'CRITICAL': return '#dc2626';
    case 'HIGH':     return '#d97706';
    case 'MEDIUM':   return '#ca8a04';
    case 'LOW':      return '#059669';
    default:         return '#2563eb';
  }
}

export function severityBg(s: string): string {
  switch (s.toUpperCase()) {
    case 'CRITICAL': return 'bg-red-50 text-red-700 border-red-200';
    case 'HIGH':     return 'bg-amber-50 text-amber-800 border-amber-200';
    case 'MEDIUM':   return 'bg-yellow-50 text-yellow-800 border-yellow-200';
    case 'LOW':      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    default:         return 'bg-blue-50 text-blue-700 border-blue-200';
  }
}

export const CORE_MODULES = ['acl_fuzzer', 'inversion', 'poisoning', 'drift', 'probe'] as const;
export const UNIQUE_TECH_MODULES = ['dp_noise_injector', 'acl_simulator', 'collision_scorer', 'poison_classifier'] as const;

export const MODULE_LABELS: Record<string, string> = {
  acl_fuzzer:       'ACL Fuzzer',
  inversion:        'Inversion Tester',
  poisoning:        'Poisoning Simulator',
  drift:            'Drift Detector',
  probe:            'Probe Generator',
  dp_noise_injector:'DP Noise Injector',
  acl_simulator:    'ACL Simulator',
  collision_scorer: 'Collision Scorer',
  poison_classifier:'Poison Classifier',
};

export function formatTimestamp(ts: string): string {
  try {
    const clean = ts.replace(/(\d{8})T(\d{2})(\d{2})(\d{2})_.*/, '$1T$2:$3:$4Z');
    const d = new Date(clean);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit', hour12: true,
    });
  } catch {
    return ts;
  }
}

export function getSeverity(score: number): string {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  if (score >= 20) return 'LOW';
  return 'INFO';
}

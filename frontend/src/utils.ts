export function severityColor(s: string): string {
  switch (s.toUpperCase()) {
    case 'CRITICAL': return '#ff2a5f';
    case 'HIGH':     return '#ff7b00';
    case 'MEDIUM':   return '#ffc800';
    case 'LOW':      return '#00e676';
    default:         return '#4d88ff';
  }
}

export function severityBg(s: string): string {
  switch (s.toUpperCase()) {
    case 'CRITICAL': return 'bg-severity-critical/10 text-severity-critical border-severity-critical/30';
    case 'HIGH':     return 'bg-severity-high/10 text-severity-high border-severity-high/30';
    case 'MEDIUM':   return 'bg-severity-medium/10 text-severity-medium border-severity-medium/30';
    case 'LOW':      return 'bg-severity-low/10 text-severity-low border-severity-low/30';
    default:         return 'bg-severity-info/10 text-severity-info border-severity-info/30';
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

export const MODULE_ICONS: Record<string, string> = {
  acl_fuzzer:        '🔐',
  inversion:         '🔍',
  poisoning:         '☣️',
  drift:             '📈',
  probe:             '🎯',
  dp_noise_injector: '🔊',
  acl_simulator:     '🛡️',
  collision_scorer:  '💥',
  poison_classifier: '🧬',
};

export function formatTimestamp(ts: string): string {
  // "20260815T095902_434934+0000" → readable
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

import axios from 'axios';

const api = axios.create({ baseURL: 'http://127.0.0.1:8000' });

export const getConfigs = () => api.get<{ configs: string[] }>('/api/configs');

export const startScan = (config_file: string) =>
  api.post<{ scan_id: string; status: string }>('/api/scans', { config_file });

export const uploadAndStartScan = (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post<{ scan_id: string; status: string }>('/api/scans/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
};

export const getScanStatus = (scan_id: string) =>
  api.get<ScanStatus>(`/api/scans/${scan_id}/status`);

export const getReport = (scan_id: string) =>
  api.get<Report>(`/api/scans/${scan_id}/report`);

export const getCached = () =>
  api.get<CachedScan[]>('/api/scans/cached');

export const heatmapUrl = (scan_id: string) =>
  `http://127.0.0.1:8000/api/scans/${scan_id}/heatmap`;

export const getHeatmapData = (scan_id: string) =>
  api.get<HeatmapData>(`/api/scans/${scan_id}/heatmap`);

export const pdfUrl = (scan_id: string) =>
  `http://127.0.0.1:8000/api/scans/${scan_id}/pdf`;

// --- Types ---
export interface ScanStatus {
  scan_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  current_module: string | null;
  error_message: string | null;
}

export interface CachedScan {
  scan_id: string;
  timestamp: string;
  score: number | null;
  risk_level: string;
  config_file: string;
}

export interface ModuleResult {
  module_name: string;
  severity: string;
  score: number;
  findings: Finding[];
  evidence: Record<string, unknown>;
  duration_ms: number;
  error: string | null;
}

export interface Finding {
  [key: string]: unknown;
}

export interface OverallRiskScore {
  overall_score: number;
  risk_level: string;
  module_results: ModuleResult[];
  scan_timestamp: string;
  config_snapshot: Record<string, unknown>;
  scanner_version: string;
  weights: Record<string, number>;
}

export interface Report {
  overall_score: OverallRiskScore;
  unique_tech_results: Record<string, unknown>;
  heatmap_path: string | null;
}

// --- Heatmap types ---
export interface HeatmapPoint {
  record_id: number | string;
  namespace: string;
  x: number;
  y: number;
  is_anomalous: boolean;
  anomaly_score: number;
  detectors_fired: string[];
  payload_summary: Record<string, unknown>;
}

export interface HeatmapData {
  points: HeatmapPoint[];
  reducer: 'umap' | 'tsne' | null;
  total_points: number;
  anomalous_count: number;
}

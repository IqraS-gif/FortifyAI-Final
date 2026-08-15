import { useState, useEffect, useRef, useCallback } from 'react';
import {
  startScan, uploadAndStartScan, getScanStatus, getReport, getCached,
  type ScanStatus, type Report, type CachedScan,
} from './api';

export type ScanPhase = 'idle' | 'running' | 'completed' | 'failed';

export interface UseScanReturn {
  // Demo mode
  isDemoMode: boolean;
  setIsDemoMode: (v: boolean) => void;
  cachedScans: CachedScan[];
  selectedCachedId: string | null;
  setSelectedCachedId: (id: string | null) => void;

  // Live scan
  selectedFile: File | null;
  setSelectedFile: (f: File | null) => void;
  triggerScan: () => Promise<void>;
  phase: ScanPhase;
  currentModule: string | null;
  errorMessage: string | null;

  // Data
  scanId: string | null;
  report: Report | null;
}

const POLL_INTERVAL = 3000;

export function useScan(): UseScanReturn {
  const [isDemoMode, setIsDemoMode] = useState(true);
  const [cachedScans, setCachedScans] = useState<CachedScan[]>([]);
  const [selectedCachedId, setSelectedCachedId] = useState<string | null>(null);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [phase, setPhase] = useState<ScanPhase>('idle');
  const [currentModule, setCurrentModule] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // On mount: load cached scans and auto-select most recent
  useEffect(() => {
    getCached()
      .then(r => {
        setCachedScans(r.data);
        if (r.data.length > 0) setSelectedCachedId(r.data[0].scan_id);
      })
      .catch(() => setCachedScans([]));
  }, []);

  // Load report when cached scan changes in demo mode
  useEffect(() => {
    if (!isDemoMode || !selectedCachedId) return;
    setReport(null);
    getReport(selectedCachedId)
      .then(r => setReport(r.data))
      .catch(() => setReport(null));
  }, [isDemoMode, selectedCachedId]);

  // Polling for live scan
  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startPolling = useCallback((id: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const s = (await getScanStatus(id)).data;
        setCurrentModule(s.current_module);
        if (s.status === 'completed') {
          stopPolling();
          setPhase('completed');
          const r = await getReport(id);
          setReport(r.data);
        } else if (s.status === 'failed') {
          stopPolling();
          setPhase('failed');
          setErrorMessage(s.error_message ?? 'Scan failed for unknown reason.');
        }
      } catch {
        // keep polling — transient network hiccup
      }
    }, POLL_INTERVAL);
  }, [stopPolling]);

  const triggerScan = useCallback(async () => {
    if (!selectedFile) return;
    setPhase('running');
    setReport(null);
    setErrorMessage(null);
    setCurrentModule(null);
    try {
      const res = await uploadAndStartScan(selectedFile);
      const id = res.data.scan_id;
      setScanId(id);
      startPolling(id);
    } catch (e: unknown) {
      setPhase('failed');
      setErrorMessage(String(e));
    }
  }, [selectedFile, startPolling]);

  useEffect(() => () => stopPolling(), [stopPolling]);

  return {
    isDemoMode, setIsDemoMode,
    cachedScans, selectedCachedId, setSelectedCachedId,
    selectedFile, setSelectedFile,
    triggerScan, phase, currentModule, errorMessage,
    scanId: isDemoMode ? selectedCachedId : scanId,
    report,
  };
}

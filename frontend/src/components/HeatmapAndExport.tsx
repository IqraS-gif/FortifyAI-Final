import { useState, useEffect, useMemo } from 'react';
import Plot from 'react-plotly.js';
import { getHeatmapData, pdfUrl } from '../api';
import type { HeatmapPoint, HeatmapData } from '../api';
import { DocumentDownloadIcon, AlertTriangleIcon, ChartBarIcon } from './Icons';

interface Props {
  scanId: string;
  heatmapPath: string | null;
}

const OKABE_ITO = [
  '#2563eb', // royal blue
  '#059669', // emerald green
  '#d97706', // amber
  '#9333ea', // purple
  '#0284c7', // sky blue
  '#ca8a04', // gold
  '#dc2626', // vermillion/red
  '#1c1917', // dark stone
];

function nsColor(ns: string, allNs: string[]): string {
  const idx = allNs.indexOf(ns);
  return OKABE_ITO[idx % OKABE_ITO.length];
}

function dist2d(p1: HeatmapPoint, p2: HeatmapPoint) {
  const dx = p1.x - p2.x;
  const dy = p1.y - p2.y;
  return Math.sqrt(dx * dx + dy * dy);
}

function buildNetworkTraces(
  points: HeatmapPoint[],
  allNs: string[],
  showAnomaliesOnly: boolean,
  viewMode: 'network' | 'scatter'
) {
  const visible = showAnomaliesOnly ? points.filter(p => p.is_anomalous) : points;
  if (visible.length === 0) return [];

  const traces: Plotly.Data[] = [];

  if (viewMode === 'network' && !showAnomaliesOnly) {
    // ── 1. Cluster Neighborhood Edges (k-NN Mesh) ─────────────────────────
    const edgeX: (number | null)[] = [];
    const edgeY: (number | null)[] = [];

    for (const ns of allNs) {
      const nsPoints = visible.filter(p => p.namespace === ns && !p.is_anomalous);
      for (let i = 0; i < nsPoints.length; i++) {
        const p1 = nsPoints[i];
        const neighbors = nsPoints
          .filter((_, idx) => idx !== i)
          .map(p2 => ({ p: p2, d: dist2d(p1, p2) }))
          .sort((a, b) => a.d - b.d)
          .slice(0, 2);

        for (const n of neighbors) {
          edgeX.push(p1.x, n.p.x, null);
          edgeY.push(p1.y, n.p.y, null);
        }
      }
    }

    if (edgeX.length > 0) {
      traces.push({
        type: 'scatter',
        mode: 'lines',
        name: 'Topology Edges',
        x: edgeX,
        y: edgeY,
        line: { color: 'rgba(148, 163, 184, 0.35)', width: 1 },
        hoverinfo: 'skip',
        showlegend: false,
      } as Plotly.Data);
    }

    // ── 2. Threat Vector Edges (Red dashed lines from anomalies to targets) ──
    const threatX: (number | null)[] = [];
    const threatY: (number | null)[] = [];

    const anomalies = points.filter(p => p.is_anomalous);
    const normals = points.filter(p => !p.is_anomalous);

    for (const anom of anomalies) {
      const targets = normals
        .map(norm => ({ p: norm, d: dist2d(anom, norm) }))
        .sort((a, b) => a.d - b.d)
        .slice(0, 2);

      for (const t of targets) {
        threatX.push(anom.x, t.p.x, null);
        threatY.push(anom.y, t.p.y, null);
      }
    }

    if (threatX.length > 0) {
      traces.push({
        type: 'scatter',
        mode: 'lines',
        name: 'Threat Vectors',
        x: threatX,
        y: threatY,
        line: { color: 'rgba(239, 68, 68, 0.65)', width: 1.5, dash: 'dot' },
        hoverinfo: 'skip',
        showlegend: true,
      } as Plotly.Data);
    }

    // ── 3. Namespace Cluster Centroid Hub Nodes ──────────────────────────
    const centroidX: number[] = [];
    const centroidY: number[] = [];
    const centroidLabels: string[] = [];
    const centroidColors: string[] = [];

    for (const ns of allNs) {
      const nsPoints = visible.filter(p => p.namespace === ns);
      if (nsPoints.length === 0) continue;
      const avgX = nsPoints.reduce((s, p) => s + p.x, 0) / nsPoints.length;
      const avgY = nsPoints.reduce((s, p) => s + p.y, 0) / nsPoints.length;

      centroidX.push(avgX);
      centroidY.push(avgY);
      centroidLabels.push(`HUB: ${ns}`);
      centroidColors.push(nsColor(ns, allNs));
    }

    if (centroidX.length > 0) {
      traces.push({
        type: 'scatter',
        mode: 'markers+text',
        name: 'Namespace Hubs',
        x: centroidX,
        y: centroidY,
        text: centroidLabels,
        textposition: 'top center',
        textfont: { size: 11, color: '#0f172a', family: 'Inter, sans-serif' },
        marker: {
          symbol: 'hexagon',
          size: 18,
          color: centroidColors,
          line: { color: '#ffffff', width: 2 },
          opacity: 0.9,
        },
        hovertemplate: '<b>Cluster Hub:</b> %{text}<extra></extra>',
        showlegend: false,
      } as Plotly.Data);
    }
  }

  // ── 4. Normal Vector Nodes (by Namespace) ───────────────────────────────
  if (!showAnomaliesOnly) {
    for (const ns of allNs) {
      const nsPoints = visible.filter(p => p.namespace === ns && !p.is_anomalous);
      if (nsPoints.length === 0) continue;

      traces.push({
        type: 'scatter',
        mode: 'markers',
        name: ns,
        x: nsPoints.map(p => p.x),
        y: nsPoints.map(p => p.y),
        marker: {
          color: nsColor(ns, allNs),
          size: 10,
          opacity: 0.85,
          line: { color: '#ffffff', width: 1 },
        },
        customdata: nsPoints.map(p => [
          p.record_id,
          p.namespace,
          p.anomaly_score.toFixed(3),
          p.detectors_fired.join(', ') || 'none',
          JSON.stringify(p.payload_summary),
        ]),
        hovertemplate:
          '<b>RECORD:</b> %{customdata[0]}<br>' +
          '<b>NAMESPACE:</b> %{customdata[1]}<br>' +
          '<b>ANOMALY SCORE:</b> %{customdata[2]}<br>' +
          '<b>DETECTORS:</b> %{customdata[3]}<br>' +
          '<b>PAYLOAD:</b> %{customdata[4]}' +
          '<extra></extra>',
      } as Plotly.Data);
    }
  }

  // ── 5. Anomalous Vector Nodes (Glowing Star / Ring Markers) ─────────────
  const anomPoints = visible.filter(p => p.is_anomalous);
  if (anomPoints.length > 0) {
    traces.push({
      type: 'scatter',
      mode: 'markers',
      name: 'Anomalous Vector',
      x: anomPoints.map(p => p.x),
      y: anomPoints.map(p => p.y),
      marker: {
        symbol: 'star-diamond',
        size: 16,
        color: anomPoints.map(p => p.anomaly_score),
        colorscale: [
          [0, '#fef08a'],   // light yellow
          [0.5, '#f97316'], // orange
          [1, '#dc2626'],   // deep red
        ],
        cmin: 0,
        cmax: 1,
        showscale: true,
        colorbar: {
          title: 'Anomaly Score',
          thickness: 12,
          len: 0.75,
          x: 1.02,
          titlefont: { size: 11, color: '#475569' },
          tickfont: { size: 10, color: '#475569' },
        },
        line: { color: '#7f1d1d', width: 1.5 },
        opacity: 0.95,
      },
      customdata: anomPoints.map(p => [
        p.record_id,
        p.namespace,
        p.anomaly_score.toFixed(3),
        p.detectors_fired.join(', ') || 'unknown',
        JSON.stringify(p.payload_summary),
      ]),
      hovertemplate:
        '<b>🚨 ANOMALY THREAT DETECTED</b><br>' +
        '<b>RECORD:</b> %{customdata[0]}<br>' +
        '<b>NAMESPACE:</b> %{customdata[1]}<br>' +
        '<b>ANOMALY SCORE:</b> %{customdata[2]}<br>' +
        '<b>FIRED DETECTORS:</b> %{customdata[3]}<br>' +
        '<b>PAYLOAD:</b> %{customdata[4]}' +
        '<extra></extra>',
    } as Plotly.Data);
  }

  return traces;
}

export default function HeatmapAndExport({ scanId }: Props) {
  const [data, setData] = useState<HeatmapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState(false);
  const [viewMode, setViewMode] = useState<'network' | 'scatter'>('network');

  useEffect(() => {
    setLoading(true);
    setError(null);
    setData(null);
    getHeatmapData(scanId)
      .then(res => {
        setData(res.data);
        setLoading(false);
      })
      .catch(err => {
        const msg = err?.response?.status === 404
          ? 'Heatmap data not yet available for this scan.'
          : `Failed to load heatmap: ${err.message}`;
        setError(msg);
        setLoading(false);
      });
  }, [scanId]);

  const allNs = useMemo(() => {
    if (!data) return [];
    return Array.from(new Set(data.points.map(p => p.namespace)));
  }, [data]);

  const traces = useMemo(() => {
    if (!data || data.points.length === 0) return [];
    return buildNetworkTraces(data.points, allNs, showAnomaliesOnly, viewMode);
  }, [data, allNs, showAnomaliesOnly, viewMode]);

  const reducerLabel = data?.reducer === 'umap' ? 'UMAP' : 't-SNE';

  const edgeCount = useMemo(() => {
    if (!data) return 0;
    const normals = data.points.filter(p => !p.is_anomalous).length;
    const anoms = data.points.filter(p => p.is_anomalous).length;
    return (normals * 2) + (anoms * 2);
  }, [data]);

  return (
    <section className="mb-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Network Graph Panel */}
      <div className="lg:col-span-2 bg-white border border-slate-200/90 rounded-3xl p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
          <div>
            <h3 className="text-base font-black text-slate-900 flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-blue-100 text-blue-600 flex items-center justify-center shrink-0">
                <ChartBarIcon className="w-4 h-4 text-blue-600" />
              </div>
              <span>Vector Space Network Graph</span>
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-600 border border-blue-200 font-extrabold">
                {viewMode === 'network' ? 'Interactive Graph' : '2D Projection'}
              </span>
            </h3>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              {reducerLabel} topological graph visualization. Hexagons represent namespace hubs, solid lines denote k-NN vector neighborhood links, and dashed red lines highlight threat collision vectors.
            </p>
          </div>

          {/* View Mode Switch + Anomaly Filter Toggle */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="bg-slate-100 p-1 rounded-xl flex items-center border border-slate-200">
              <button
                onClick={() => setViewMode('network')}
                className={`text-xs font-extrabold px-3 py-1.5 rounded-lg transition-all ${
                  viewMode === 'network'
                    ? 'bg-white text-blue-600 shadow-2xs'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                Network
              </button>
              <button
                onClick={() => setViewMode('scatter')}
                className={`text-xs font-extrabold px-3 py-1.5 rounded-lg transition-all ${
                  viewMode === 'scatter'
                    ? 'bg-white text-blue-600 shadow-2xs'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                Scatter
              </button>
            </div>

            {data && data.anomalous_count > 0 && (
              <label className="flex items-center gap-2 cursor-pointer shrink-0">
                <div
                  className={`relative w-9 h-5 rounded-full transition-colors duration-200 ${showAnomaliesOnly ? 'bg-red-600' : 'bg-slate-300'}`}
                  onClick={() => setShowAnomaliesOnly(v => !v)}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200 ${showAnomaliesOnly ? 'translate-x-4' : ''}`}
                  />
                </div>
                <span className="text-xs text-slate-700 font-bold whitespace-nowrap">Threats Only</span>
              </label>
            )}
          </div>
        </div>

        {/* Loading */}
        {loading && (
          <div className="flex items-center justify-center h-72 text-slate-500 text-sm gap-3">
            <span className="animate-spin border-2 border-blue-600 border-t-transparent w-5 h-5 rounded-full" />
            Computing topological graph embedding...
          </div>
        )}

        {/* Error */}
        {!loading && error && (
          <div className="flex items-center justify-center h-52 bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-sm italic">
            {error}
          </div>
        )}

        {/* No data */}
        {!loading && !error && data && data.points.length === 0 && (
          <div className="flex items-center justify-center h-52 bg-slate-50 border border-slate-200 rounded-2xl text-slate-500 text-sm italic">
            No vector data available for this scan.
          </div>
        )}

        {/* Zero anomalies info banner */}
        {!loading && !error && data && data.points.length > 0 && data.anomalous_count === 0 && (
          <div className="mb-4 px-4 py-3 rounded-2xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs sm:text-sm font-semibold flex items-center gap-2">
            <svg className="w-4 h-4 text-emerald-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
            </svg>
            <span>No anomalies detected: all {data.total_points} vectors are within normal distribution bounds.</span>
          </div>
        )}

        {/* Plot */}
        {!loading && !error && data && data.points.length > 0 && traces.length > 0 && (
          <>
            <div className="flex flex-wrap gap-2.5 mb-2 text-xs">
              <span className="px-3 py-1 rounded-xl bg-slate-100 text-slate-800 border border-slate-200 font-extrabold">
                {data.total_points.toLocaleString()} Nodes
              </span>
              {viewMode === 'network' && (
                <span className="px-3 py-1 rounded-xl bg-blue-50 text-blue-700 border border-blue-200 font-extrabold">
                  {edgeCount} Network Edges
                </span>
              )}
              {data.anomalous_count > 0 && (
                <span className="px-3 py-1 rounded-xl bg-red-50 text-red-700 border border-red-200 font-extrabold flex items-center gap-1.5">
                  <AlertTriangleIcon className="w-3.5 h-3.5 text-red-600" />
                  {data.anomalous_count} Anomalous Threats ({((data.anomalous_count / data.total_points) * 100).toFixed(1)}%)
                </span>
              )}
              <span className="px-3 py-1 rounded-xl bg-slate-100 text-slate-800 border border-slate-200 font-extrabold">
                {allNs.length} Namespace Hubs
              </span>
            </div>

            <Plot
              data={traces}
              layout={{
                paper_bgcolor: '#ffffff',
                plot_bgcolor: '#ffffff',
                font: { color: '#0f172a', size: 12, family: 'Inter, sans-serif' },
                xaxis: {
                  title: `${reducerLabel} Dimension 1`,
                  showticklabels: false,
                  showgrid: false,
                  zeroline: false,
                  color: '#64748b',
                },
                yaxis: {
                  title: `${reducerLabel} Dimension 2`,
                  showticklabels: false,
                  showgrid: false,
                  zeroline: false,
                  color: '#64748b',
                },
                legend: {
                  orientation: 'h',
                  x: 0,
                  y: 1.12,
                  bgcolor: 'rgba(255,255,255,0)',
                  font: { size: 11, color: '#334155', weight: 600 },
                },
                margin: { t: 35, b: 35, l: 35, r: 65 },
                autosize: true,
                hoverlabel: {
                  bgcolor: '#ffffff',
                  bordercolor: '#cbd5e1',
                  font: { color: '#0f172a', size: 12, family: 'Inter, sans-serif' },
                },
              }}
              config={{
                displayModeBar: false,
                responsive: true,
                toImageButtonOptions: { format: 'png', filename: `network_graph_${scanId}` },
              }}
              style={{ width: '100%', height: '460px' }}
              useResizeHandler
            />
          </>
        )}
      </div>

      {/* Export panel */}
      <div className="bg-white border border-slate-200/90 rounded-3xl p-6 shadow-xs flex flex-col justify-between">
        <div>
          <h3 className="text-base font-black text-slate-900 mb-2 flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-emerald-100 text-emerald-600 flex items-center justify-center shrink-0">
              <DocumentDownloadIcon className="w-4 h-4 text-emerald-600" />
            </div>
            <span>Export Security Report</span>
          </h3>
          <p className="text-xs sm:text-sm text-slate-600 mb-5 leading-relaxed font-medium">
            Download the full structured PDF report generated by the scanner,
            including all security findings, evidence, topological graph metrics, and code remediation steps.
          </p>
          {data && (
            <div className="space-y-3 mb-6 text-xs sm:text-sm text-slate-700 bg-slate-50 border border-slate-200/80 rounded-2xl p-4">
              <p className="flex justify-between items-center">
                <span>Total Vectors:</span>
                <span className="font-extrabold text-slate-900">{data.total_points.toLocaleString()}</span>
              </p>
              <p className="flex justify-between items-center">
                <span>Anomalies Flagged:</span>
                <span className="font-extrabold text-red-600">{data.anomalous_count}</span>
              </p>
              <p className="flex justify-between items-center">
                <span>Graph Topology Edges:</span>
                <span className="font-extrabold text-blue-600">{edgeCount}</span>
              </p>
              <p className="flex justify-between items-center">
                <span>Projection Reducer:</span>
                <span className="font-mono font-extrabold text-slate-900">{data.reducer?.toUpperCase()}</span>
              </p>
            </div>
          )}
        </div>
        <a
          href={pdfUrl(scanId)}
          target="_blank"
          rel="noopener noreferrer"
          className="btn-primary bg-blue-600 hover:bg-blue-700 text-white font-bold text-sm py-3 px-4 rounded-2xl flex items-center justify-center gap-2 text-center shadow-xs transition-all"
        >
          <DocumentDownloadIcon className="w-4 h-4 text-white" />
          <span>Download PDF Report</span>
        </a>
      </div>
    </section>
  );
}

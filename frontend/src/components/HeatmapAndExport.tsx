import { useState, useEffect, useMemo } from 'react';
import Plot from 'react-plotly.js';
import { getHeatmapData, pdfUrl } from '../api';
import type { HeatmapPoint, HeatmapData } from '../api';

interface Props {
  scanId: string;
  heatmapPath: string | null;
}

// Okabe-Ito colorblind-safe categorical palette (8 distinct colors)
const OKABE_ITO = [
  '#E69F00', // orange
  '#56B4E9', // sky blue
  '#009E73', // bluish green
  '#F0E442', // yellow
  '#0072B2', // blue
  '#D55E00', // vermillion
  '#CC79A7', // reddish purple
  '#000000', // black
];

function nsColor(ns: string, allNs: string[]): string {
  const idx = allNs.indexOf(ns);
  return OKABE_ITO[idx % OKABE_ITO.length];
}

function buildTraces(
  points: HeatmapPoint[],
  allNs: string[],
  showAnomaliesOnly: boolean,
) {
  const visible = showAnomaliesOnly ? points.filter(p => p.is_anomalous) : points;

  const traces: Plotly.Data[] = [];

  // ── One trace per namespace (normal points only) ─────────────────────────
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
          size: 6,
          opacity: 0.65,
          line: { width: 0 },
        },
        customdata: nsPoints.map(p => [
          p.record_id,
          p.namespace,
          p.anomaly_score.toFixed(3),
          p.detectors_fired.join(', ') || 'none',
          JSON.stringify(p.payload_summary),
        ]),
        hovertemplate:
          '<b>record_id:</b> %{customdata[0]}<br>' +
          '<b>namespace:</b> %{customdata[1]}<br>' +
          '<b>anomaly_score:</b> %{customdata[2]}<br>' +
          '<b>detectors:</b> %{customdata[3]}<br>' +
          '<b>payload:</b> %{customdata[4]}' +
          '<extra></extra>',
      } as Plotly.Data);
    }
  }

  // ── Anomalous points — continuous color scale by anomaly_score ───────────
  const anomPoints = visible.filter(p => p.is_anomalous);
  if (anomPoints.length > 0) {
    traces.push({
      type: 'scatter',
      mode: 'markers',
      name: 'Anomalous',
      x: anomPoints.map(p => p.x),
      y: anomPoints.map(p => p.y),
      marker: {
        symbol: 'star',
        size: 10,
        color: anomPoints.map(p => p.anomaly_score),
        colorscale: [
          [0, '#ffffb2'],   // light yellow (low anomaly score)
          [0.5, '#fd8d3c'], // orange
          [1, '#b10026'],   // deep red (high anomaly score)
        ],
        cmin: 0,
        cmax: 1,
        showscale: true,
        colorbar: {
          title: 'Anomaly Score',
          thickness: 12,
          len: 0.6,
          titlefont: { size: 11, color: '#9ca3af' },
          tickfont: { size: 10, color: '#9ca3af' },
        },
        line: { color: '#7f1d1d', width: 0.8 },
        opacity: 0.9,
      },
      customdata: anomPoints.map(p => [
        p.record_id,
        p.namespace,
        p.anomaly_score.toFixed(3),
        p.detectors_fired.join(', ') || 'unknown',
        JSON.stringify(p.payload_summary),
      ]),
      hovertemplate:
        '<b>⚠ ANOMALY</b><br>' +
        '<b>record_id:</b> %{customdata[0]}<br>' +
        '<b>namespace:</b> %{customdata[1]}<br>' +
        '<b>anomaly_score:</b> %{customdata[2]}<br>' +
        '<b>detectors:</b> %{customdata[3]}<br>' +
        '<b>payload:</b> %{customdata[4]}' +
        '<extra></extra>',
    } as Plotly.Data);
  }

  return traces;
}

export default function HeatmapAndExport({ scanId, heatmapPath }: Props) {
  const [data, setData] = useState<HeatmapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState(false);

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
    return buildTraces(data.points, allNs, showAnomaliesOnly);
  }, [data, allNs, showAnomaliesOnly]);

  const reducerLabel = data?.reducer === 'umap' ? 'UMAP' : 't-SNE';

  return (
    <section className="mb-6 grid grid-cols-1 lg:grid-cols-3 gap-4">
      {/* Heatmap panel */}
      <div className="lg:col-span-2 card">
        <div className="flex items-start justify-between mb-3">
          <div>
            <h3 className="text-base font-bold text-white">Vector Space Heatmap</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              {reducerLabel} projection of all vectors.
              Stars are confirmed anomalies coloured by score (yellow → red).
              Each trace represents a namespace/tenant — click legend to toggle.
            </p>
          </div>

          {/* "Show anomalies only" toggle */}
          {data && data.anomalous_count > 0 && (
            <label className="flex items-center gap-2 cursor-pointer ml-4 shrink-0">
              <div
                className={`relative w-9 h-5 rounded-full transition-colors duration-200 ${showAnomaliesOnly ? 'bg-red-500' : 'bg-surface-600'}`}
                onClick={() => setShowAnomaliesOnly(v => !v)}
              >
                <span
                  className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200 ${showAnomaliesOnly ? 'translate-x-4' : ''}`}
                />
              </div>
              <span className="text-xs text-gray-400 whitespace-nowrap">Anomalies only</span>
            </label>
          )}
        </div>

        {/* Loading */}
        {loading && (
          <div className="flex items-center justify-center h-64 text-gray-500 text-sm gap-3">
            <span className="animate-spin text-xl">⏳</span>
            Computing projection…
          </div>
        )}

        {/* Error */}
        {!loading && error && (
          <div className="flex items-center justify-center h-48 bg-surface-700/40 border border-surface-600 rounded-lg text-gray-500 text-sm italic">
            {error}
          </div>
        )}

        {/* No anomalies, no data */}
        {!loading && !error && data && data.points.length === 0 && (
          <div className="flex items-center justify-center h-48 bg-surface-700/40 border border-surface-600 rounded-lg text-gray-500 text-sm italic">
            No vector data available for this scan.
          </div>
        )}

        {/* Zero anomalies info banner */}
        {!loading && !error && data && data.points.length > 0 && data.anomalous_count === 0 && (
          <div className="mb-2 px-3 py-2 rounded-lg bg-green-900/30 border border-green-700/40 text-green-400 text-xs">
            ✅ No anomalies detected — all {data.total_points} vectors are within normal distribution bounds.
          </div>
        )}

        {/* Plot */}
        {!loading && !error && data && data.points.length > 0 && traces.length > 0 && (
          <>
            {/* Summary badge row */}
            <div className="flex flex-wrap gap-3 mb-3 text-xs">
              <span className="px-2 py-0.5 rounded bg-surface-700 text-gray-400 border border-surface-600">
                {data.total_points.toLocaleString()} vectors
              </span>
              {data.anomalous_count > 0 && (
                <span className="px-2 py-0.5 rounded bg-red-900/40 text-red-400 border border-red-700/40">
                  {data.anomalous_count} anomalies ({((data.anomalous_count / data.total_points) * 100).toFixed(1)}%)
                </span>
              )}
              <span className="px-2 py-0.5 rounded bg-surface-700 text-gray-400 border border-surface-600">
                {allNs.length} namespace{allNs.length !== 1 ? 's' : ''}
              </span>
              <span className="px-2 py-0.5 rounded bg-surface-700 text-gray-500 border border-surface-600 font-mono">
                {data.reducer?.toUpperCase()}
              </span>
            </div>

            <Plot
              data={traces}
              layout={{
                paper_bgcolor: 'rgba(0,0,0,0)',
                plot_bgcolor: 'rgba(15,17,23,0.6)',
                font: { color: '#9ca3af', size: 11 },
                xaxis: {
                  title: `${reducerLabel} Dimension 1`,
                  showticklabels: false,
                  showgrid: false,
                  zeroline: false,
                  color: '#6b7280',
                },
                yaxis: {
                  title: `${reducerLabel} Dimension 2`,
                  showticklabels: false,
                  showgrid: false,
                  zeroline: false,
                  color: '#6b7280',
                },
                legend: {
                  bgcolor: 'rgba(15,17,23,0.85)',
                  bordercolor: '#374151',
                  borderwidth: 1,
                  font: { size: 10, color: '#d1d5db' },
                },
                margin: { t: 10, b: 40, l: 50, r: 10 },
                autosize: true,
                hoverlabel: {
                  bgcolor: '#1f2937',
                  bordercolor: '#4b5563',
                  font: { color: '#f3f4f6', size: 12 },
                },
              }}
              config={{
                displayModeBar: true,
                modeBarButtonsToRemove: ['select2d', 'lasso2d'],
                responsive: true,
                toImageButtonOptions: { format: 'png', filename: `heatmap_${scanId}` },
              }}
              style={{ width: '100%', height: '420px' }}
              useResizeHandler
            />
          </>
        )}
      </div>

      {/* Export panel */}
      <div className="card flex flex-col justify-between">
        <div>
          <h3 className="text-base font-bold text-white mb-2">Export</h3>
          <p className="text-xs text-gray-500 mb-4">
            Download the full structured PDF report generated by the scanner,
            including all findings, evidence, and remediation steps.
          </p>
          {data && (
            <div className="space-y-2 mb-4 text-xs text-gray-500">
              <p>📊 <span className="text-gray-300">{data.total_points.toLocaleString()}</span> vectors projected</p>
              <p>⚠ <span className="text-gray-300">{data.anomalous_count}</span> anomalies flagged</p>
              <p>🔬 Reducer: <span className="text-gray-300 font-mono">{data.reducer?.toUpperCase()}</span></p>
            </div>
          )}
        </div>
        <a
          href={pdfUrl(scanId)}
          target="_blank"
          rel="noopener noreferrer"
          className="btn-primary text-center block"
        >
          📄 Download Full PDF Report
        </a>
      </div>
    </section>
  );
}

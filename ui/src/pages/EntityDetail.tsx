import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, Tooltip
} from 'recharts';
import {
  ArrowLeft, AlertTriangle, CheckCircle, Download,
  ChevronDown, ChevronUp, Info
} from 'lucide-react';

const API = '/api';
const CYCLE = 'DEMO';

type Component = {
  weight: number;
  fi_value: number;
  contribution: number;
  flagged: boolean;
  statistic?: number;
  p_value?: number;
  score?: number;
  confidence_note?: string;
  status: string;
};

type RiskScore = {
  score: number;
  band: string;
  components: Record<string, Component>;
  weights_version: string;
};

type DetectorResult = {
  detector_id: string;
  detector_name: string;
  test_name: string;
  statistic: number;
  p_value: number | null;
  score: number;
  flag: boolean;
  threshold_tier: string;
  confidence_note: string;
  sample_size: number;
  parameters: Record<string, unknown>;
  fi_value: number;
  linked_alert_ids?: string[];
  linked_analyst_ids?: string[];
  asymmetric_cells?: unknown[];
};

type ManifestRow = {
  alert_id: string;
  stratum: string;
  priority_rank: number;
  detector_score: number;
  sampled_by: string;
};

type ManifestData = {
  total: number;
  n_flagged: number;
  n_random: number;
  seed: number;
  rows: ManifestRow[];
};

const BAND_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e',
};

const DETECTOR_LABELS: Record<string, string> = {
  G1: 'Velocity Distortion', G2: 'Severity Laundering', G3: 'Temporal Clustering',
  G4: 'Template Collapse', G5: 'Workload Inconsistency', G6: 'Silent Loop',
  L1_SLA: 'SLA Violations', L1_NS: 'Negative Space',
};

function DetectorCard({ result }: { result: DetectorResult }) {
  const [expanded, setExpanded] = useState(false);
  const flagColor = result.flag ? 'var(--critical)' : 'var(--low)';

  return (
    <div className={`detector-card ${result.flag ? 'flagged' : ''}`}>
      <div className="det-header">
        <div>
          <div className="det-id">{result.detector_id}</div>
          <div className="det-name">{result.detector_name}</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {result.flag
            ? <AlertTriangle size={16} color="var(--critical)" />
            : <CheckCircle size={16} color="var(--low)" />}
          <span style={{ fontSize: 11, color: flagColor, fontWeight: 700 }}>
            {result.flag ? 'FLAGGED' : 'CLEAR'}
          </span>
        </div>
      </div>

      <div className="det-stat">
        <span><strong>{result.test_name}</strong></span>
      </div>

      <div className="det-stat">
        <span>Statistic: <strong className="font-mono">{result.statistic?.toFixed(4) ?? '—'}</strong></span>
        {result.p_value != null && (
          <span>p-value: <strong className="font-mono">{result.p_value?.toFixed(4)}</strong></span>
        )}
        <span>F<sub>i</sub>: <strong className="font-mono">{result.fi_value?.toFixed(3)}</strong></span>
        <span>n: <strong>{result.sample_size}</strong></span>
      </div>

      {/* Score bar */}
      <div className="score-bar-track" style={{ marginBottom: 8 }}>
        <div
          className="score-bar-fill"
          style={{
            width: `${(result.fi_value ?? 0) * 100}%`,
            background: result.flag ? 'var(--critical)' : 'var(--accent)',
          }}
        />
      </div>

      <button
        className="btn btn-ghost"
        style={{ width: '100%', justifyContent: 'center', fontSize: 11, padding: '5px' }}
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        {expanded ? 'Hide details' : 'Show details'}
      </button>

      {expanded && (
        <div style={{ marginTop: 12 }}>
          {result.confidence_note && (
            <div className="confidence-note">
              <Info size={11} style={{ display: 'inline', marginRight: 4 }} />
              {result.confidence_note}
            </div>
          )}
          {result.linked_alert_ids && result.linked_alert_ids.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>
                LINKED ALERTS ({result.linked_alert_ids.length})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {result.linked_alert_ids.slice(0, 12).map(id => (
                  <code key={id} style={{
                    background: 'var(--bg)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    padding: '2px 6px',
                    fontSize: 10,
                    color: 'var(--accent)',
                  }}>{id}</code>
                ))}
                {result.linked_alert_ids.length > 12 && (
                  <span style={{ fontSize: 10, color: 'var(--text-dim)', padding: '2px 4px' }}>
                    +{result.linked_alert_ids.length - 12} more
                  </span>
                )}
              </div>
            </div>
          )}
          {result.linked_analyst_ids && result.linked_analyst_ids.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600 }}>
                LINKED ANALYSTS
              </div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {result.linked_analyst_ids.map(id => (
                  <span key={id} style={{
                    background: 'var(--bg)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    padding: '2px 6px',
                    fontSize: 10,
                    color: 'var(--text-muted)',
                  }}>{id}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function EntityDetail() {
  const { entityId } = useParams<{ entityId: string }>();
  const [entity, setEntity] = useState<{ entity_id: string; name: string; sector: string; asset_class: string } | null>(null);
  const [riskScore, setRiskScore] = useState<RiskScore | null>(null);
  const [detectorResults, setDetectorResults] = useState<DetectorResult[]>([]);
  const [manifest, setManifest] = useState<ManifestData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!entityId) return;
    Promise.all([
      fetch(`${API}/entities/${entityId}?cycle_id=${CYCLE}`).then(r => r.json()),
      fetch(`${API}/detectors/${entityId}?cycle_id=${CYCLE}`).then(r => r.json()),
      fetch(`${API}/sampling/${entityId}/manifest?cycle_id=${CYCLE}`).then(r => r.json()),
    ]).then(([entData, detData, mfData]) => {
      setEntity(entData.entity);
      setRiskScore(entData.risk_score);
      setDetectorResults(detData.results ?? []);
      setManifest(mfData);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [entityId]);

  const downloadManifest = () => {
    window.open(`${API}/sampling/${entityId}/manifest/csv?cycle_id=${CYCLE}`);
  };

  if (loading) return (
    <div className="loading-state"><div className="spinner" /><span>Loading entity…</span></div>
  );

  if (!entity) return (
    <div className="loading-state">
      <AlertTriangle color="var(--critical)" />
      <span>Entity not found</span>
    </div>
  );

  // Radar data
  const radarData = Object.keys(DETECTOR_LABELS).map((id) => {
    const comp = riskScore?.components[id];
    return { subject: id, value: comp ? comp.fi_value * 100 : 0, fullMark: 100 };
  });

  const bandColor = BAND_COLORS[riskScore?.band ?? 'LOW'];

  return (
    <div>
      {/* ── Breadcrumb ── */}
      <div style={{ marginBottom: 20 }}>
        <Link to="/" style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 13, color: 'var(--text-muted)' }}>
          <ArrowLeft size={14} /> Dashboard
        </Link>
      </div>

      {/* ── Entity header ── */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 6 }}>
              {entity.sector} · {entity.asset_class}
            </div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
              {entity.name}
            </h1>
            <code style={{ fontSize: 12, color: 'var(--accent)' }}>{entity.entity_id}</code>
          </div>
          {riskScore && (
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 42, fontWeight: 800, color: bandColor, lineHeight: 1 }}>
                {riskScore.score.toFixed(1)}
              </div>
              <div style={{ marginTop: 6 }}>
                <span className={`band-badge band-${riskScore.band}`}>{riskScore.band}</span>
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>
                weights v{riskScore.weights_version}
              </div>
            </div>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20, marginBottom: 20 }}>
        {/* ── Radar chart ── */}
        <div className="card">
          <div className="section-header">
            <div className="section-title">Detector Scores — Spider View</div>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="var(--border)" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: 'var(--text-dim)', fontSize: 9 }} />
              <Radar name="Fi" dataKey="value" stroke={bandColor} fill={bandColor} fillOpacity={0.15} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* ── Component breakdown ── */}
        <div className="card">
          <div className="section-header">
            <div className="section-title">Score Components</div>
          </div>
          {riskScore && Object.entries(riskScore.components).map(([id, comp]) => (
            <div key={id} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                <span style={{ color: 'var(--text)' }}>
                  <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{id}</span>
                  {' '}<span className="text-muted">(w={comp.weight})</span>
                </span>
                <span style={{ color: comp.flagged ? 'var(--critical)' : 'var(--text-muted)', fontWeight: 700 }}>
                  +{comp.contribution.toFixed(2)}
                </span>
              </div>
              <div className="score-bar-track">
                <div
                  className="score-bar-fill"
                  style={{
                    width: `${comp.fi_value * 100}%`,
                    background: comp.flagged ? 'var(--critical)' : 'var(--accent)',
                  }}
                />
              </div>
            </div>
          ))}
          {riskScore && (
            <div style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', fontWeight: 700 }}>
              <span className="text-muted" style={{ fontSize: 12 }}>TOTAL SCORE</span>
              <span style={{ color: bandColor, fontSize: 15 }}>{riskScore.score.toFixed(2)}</span>
            </div>
          )}
        </div>
      </div>

      {/* ── Detector cards ── */}
      <div className="section-header" style={{ marginBottom: 16 }}>
        <div className="section-title">Detector Results</div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {detectorResults.filter(r => r.flag).length} / {detectorResults.length} flagged
        </div>
      </div>
      <div className="detector-grid" style={{ marginBottom: 24 }}>
        {detectorResults.map(r => <DetectorCard key={r.detector_id} result={r} />)}
      </div>

      {/* ── Review Manifest ── */}
      {manifest && (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="section-header" style={{ padding: '16px 20px 0' }}>
            <div className="section-title">
              Review Manifest — {manifest.total} Alerts
              <span style={{ fontSize: 11, color: 'var(--text-dim)', fontWeight: 400, marginLeft: 6 }}>
                ({manifest.n_flagged} flagged · {manifest.n_random} random · seed={manifest.seed})
              </span>
            </div>
            <button className="btn btn-ghost" onClick={downloadManifest}>
              <Download size={13} /> Export CSV
            </button>
          </div>
          <table className="data-table" style={{ marginTop: 12 }}>
            <thead>
              <tr>
                <th>#</th>
                <th>Alert ID</th>
                <th>Stratum</th>
                <th>Sampled By</th>
                <th>Detector Score</th>
              </tr>
            </thead>
            <tbody>
              {manifest.rows.slice(0, 30).map(row => (
                <tr key={row.alert_id}>
                  <td className="text-muted">{row.priority_rank}</td>
                  <td className="font-mono" style={{ color: 'var(--accent)' }}>{row.alert_id}</td>
                  <td>
                    <span style={{
                      background: row.stratum === 'RANDOM' ? 'var(--bg)' : 'var(--critical-bg)',
                      color: row.stratum === 'RANDOM' ? 'var(--text-muted)' : 'var(--critical)',
                      border: `1px solid ${row.stratum === 'RANDOM' ? 'var(--border)' : 'var(--critical)'}`,
                      borderRadius: 4,
                      padding: '1px 7px',
                      fontSize: 11,
                      fontWeight: 600,
                    }}>{row.stratum}</span>
                  </td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {row.sampled_by === 'FLAGGED_80PCT' ? '🎯 80% Flagged' : '🎲 20% Random'}
                  </td>
                  <td className="font-mono">{row.detector_score.toFixed(3)}</td>
                </tr>
              ))}
              {manifest.rows.length > 30 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-dim)', fontSize: 12 }}>
                    +{manifest.rows.length - 30} more rows — download CSV for full manifest
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

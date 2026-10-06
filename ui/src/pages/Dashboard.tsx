import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import {
  AlertTriangle, Shield, TrendingUp, Users, ChevronRight
} from 'lucide-react';

const API = '/api';
const CYCLE = 'DEMO';

type Entity = {
  entity_id: string;
  name: string;
  sector: string;
  asset_class: string;
  size_band: string;
  score: number | null;
  band: string | null;
  run_ts: string | null;
};

type FlagSummary = { detector_id: string; flagged_count: number };

const BAND_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

const DETECTOR_LABELS: Record<string, string> = {
  G1: 'G1 Velocity',
  G2: 'G2 Severity Laundering',
  G3: 'G3 Temporal',
  G4: 'G4 Template',
  G5: 'G5 Workload',
  G6: 'G6 Silent Loop',
  L1_SLA: 'L1 SLA',
  L1_NS: 'L1 Neg. Space',
};

function ScoreBar({ score, band }: { score: number; band: string }) {
  const color = BAND_COLORS[band] ?? '#64748b';
  return (
    <div className="score-bar-wrap" style={{ minWidth: 80 }}>
      <div className="score-bar-track">
        <div
          className="score-bar-fill"
          style={{ width: `${score}%`, background: color }}
        />
      </div>
      <div style={{ fontSize: 11, color, fontWeight: 700, marginTop: 2 }}>
        {score.toFixed(1)}
      </div>
    </div>
  );
}

function BandBadge({ band }: { band: string }) {
  return <span className={`band-badge band-${band}`}>{band}</span>;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [entities, setEntities] = useState<Entity[]>([]);
  const [flagSummary, setFlagSummary] = useState<FlagSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [sector, setSector] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams({ cycle_id: CYCLE });
    if (sector) params.set('sector', sector);

    Promise.all([
      fetch(`${API}/entities/?${params}`).then(r => r.json()),
      fetch(`${API}/detectors/summary/flagged?cycle_id=${CYCLE}`).then(r => r.json()),
    ])
      .then(([entData, flagData]) => {
        setEntities(entData.entities ?? []);
        setFlagSummary(
          (flagData.flagged_by_detector ?? []).map((d: FlagSummary) => ({
            ...d,
            name: DETECTOR_LABELS[d.detector_id] ?? d.detector_id,
          }))
        );
        setLoading(false);
      })
      .catch(e => { setError(String(e)); setLoading(false); });
  }, [sector]);

  const byBand = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].reduce<Record<string, number>>(
    (acc, b) => ({ ...acc, [b]: entities.filter(e => e.band === b).length }),
    {}
  );
  const sectors = [...new Set(entities.map(e => e.sector))].sort();

  if (loading) return (
    <div className="loading-state">
      <div className="spinner" />
      <span>Loading risk data…</span>
    </div>
  );

  if (error) return (
    <div className="loading-state">
      <AlertTriangle size={32} color="#ef4444" />
      <span style={{ color: '#ef4444' }}>API error: {error}</span>
      <span style={{ color: 'var(--text-dim)', fontSize: 12 }}>
        Run: <code>satsa run</code> then <code>satsa serve</code>
      </span>
    </div>
  );

  return (
    <div>
      {/* ── Stat strip ── */}
      <div className="stat-grid">
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(band => (
          <div className="stat-card" key={band}>
            <div className="stat-label">{band}</div>
            <div className="stat-value" style={{ color: BAND_COLORS[band] }}>
              {byBand[band] ?? 0}
            </div>
            <div className="stat-sub">entities</div>
          </div>
        ))}
        <div className="stat-card">
          <div className="stat-label">Total Entities</div>
          <div className="stat-value">{entities.length}</div>
          <div className="stat-sub">in cycle</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20, marginBottom: 24 }}>
        {/* ── Detector flag heatmap ── */}
        <div className="card">
          <div className="section-header">
            <div className="section-title">
              <Shield size={15} className="icon" />
              Flagged Entities by Detector
            </div>
          </div>
          {flagSummary.length === 0 ? (
            <div className="loading-state" style={{ padding: '30px 0' }}>
              <span className="text-muted">No detectors have run yet</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={flagSummary} margin={{ left: -10, right: 10, top: 5, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis
                  dataKey="name"
                  tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    borderRadius: 8,
                    color: 'var(--text)',
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="flagged_count" fill="var(--critical)" radius={[4, 4, 0, 0]} name="Flagged" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* ── Band distribution ── */}
        <div className="card">
          <div className="section-header">
            <div className="section-title">
              <TrendingUp size={15} className="icon" />
              Risk Distribution
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 8 }}>
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(band => {
              const count = byBand[band] ?? 0;
              const pct = entities.length > 0 ? (count / entities.length) * 100 : 0;
              return (
                <div key={band}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
                    <BandBadge band={band} />
                    <span style={{ color: 'var(--text-muted)' }}>{count} ({pct.toFixed(0)}%)</span>
                  </div>
                  <div className="score-bar-track">
                    <div
                      className="score-bar-fill"
                      style={{ width: `${pct}%`, background: BAND_COLORS[band] }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Entity table ── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="section-header" style={{ padding: '16px 20px 0' }}>
          <div className="section-title">
            <Users size={15} className="icon" />
            All Entities — Sorted by Risk Score
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <select
              id="sector-filter"
              value={sector}
              onChange={e => setSector(e.target.value)}
              style={{
                background: 'var(--bg-hover)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text)',
                padding: '5px 10px',
                fontSize: 12,
              }}
            >
              <option value="">All Sectors</option>
              {sectors.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>

        <table className="data-table" style={{ marginTop: 12 }}>
          <thead>
            <tr>
              <th>Entity ID</th>
              <th>Name</th>
              <th>Sector</th>
              <th>Asset Class</th>
              <th>Risk Score</th>
              <th>Band</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {entities.map(ent => (
              <tr
                key={ent.entity_id}
                style={{ cursor: 'pointer' }}
                onClick={() => navigate(`/entity/${ent.entity_id}`)}
              >
                <td className="font-mono" style={{ color: 'var(--accent)' }}>{ent.entity_id}</td>
                <td>{ent.name}</td>
                <td><span className="text-muted">{ent.sector}</span></td>
                <td><span className="text-muted">{ent.asset_class}</span></td>
                <td>
                  {ent.score != null
                    ? <ScoreBar score={ent.score} band={ent.band!} />
                    : <span className="text-muted">—</span>}
                </td>
                <td>
                  {ent.band
                    ? <BandBadge band={ent.band} />
                    : <span className="text-muted">No score</span>}
                </td>
                <td>
                  <ChevronRight size={14} style={{ color: 'var(--text-dim)' }} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

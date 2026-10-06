import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area
} from 'recharts';
import {
  AlertTriangle, Shield, TrendingUp, Users, ChevronRight, Activity, Zap
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

type FlagSummary = { detector_id: string; flagged_count: number; name?: string };

const BAND_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#ca8a04',
  LOW: '#16a34a',
};

const DETECTOR_LABELS: Record<string, string> = {
  G1: 'G1 Velocity',
  G2: 'G2 Severity',
  G3: 'G3 Temporal',
  G4: 'G4 Template',
  G5: 'G5 Workload',
  G6: 'G6 Silent Loop',
  L1_SLA: 'L1 SLA',
  L1_NS: 'L1 Neg. Space',
};

function ScoreBar({ score, band }: { score: number; band: string }) {
  const color = BAND_COLORS[band] ?? '#94a3b8';
  return (
    <div className="score-bar-wrap" style={{ minWidth: 100 }}>
      <div className="score-bar-track">
        <div
          className="score-bar-fill"
          style={{ width: `${score}%`, background: color }}
        />
      </div>
      <div style={{ fontSize: 11, color, fontWeight: 700, marginTop: 4 }}>
        {score.toFixed(1)} / 100
      </div>
    </div>
  );
}

function BandBadge({ band, onClick, active }: { band: string, onClick?: () => void, active?: boolean }) {
  const style = active !== false ? {} : { opacity: 0.4 };
  return (
    <span 
      className={`band-badge band-${band}`} 
      onClick={onClick}
      style={{ ...style, cursor: onClick ? 'pointer' : 'default' }}
    >
      {band}
    </span>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [entities, setEntities] = useState<Entity[]>([]);
  const [flagSummary, setFlagSummary] = useState<FlagSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [sector, setSector] = useState('');
  const [error, setError] = useState<string | null>(null);
  
  // Interactive filters
  const [activeBandFilter, setActiveBandFilter] = useState<string | null>(null);

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

  const byBand = useMemo(() => {
    return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].reduce<Record<string, number>>(
      (acc, b) => ({ ...acc, [b]: entities.filter(e => e.band === b).length }),
      {}
    );
  }, [entities]);

  const sectors = useMemo(() => [...new Set(entities.map(e => e.sector))].sort(), [entities]);

  const filteredEntities = useMemo(() => {
    if (!activeBandFilter) return entities;
    return entities.filter(e => e.band === activeBandFilter);
  }, [entities, activeBandFilter]);

  const pieData = useMemo(() => {
    return Object.entries(byBand)
      .filter(([_, count]) => count > 0)
      .map(([name, value]) => ({ name, value }));
  }, [byBand]);

  if (loading) return (
    <div className="flex items-center justify-center h-full text-muted animate-fade-in">
      <Activity className="animate-spin" style={{ marginRight: 8 }} /> Loading Intelligence...
    </div>
  );
  if (error) return <div className="p-6 text-critical">Error: {error}</div>;

  return (
    <div className="p-6 flex-col gap-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Risk Intelligence Overview</h1>
          <p className="text-muted">Cycle: <strong className="text-accent">{CYCLE}</strong> | Real-time metric gaming and SLA distortion monitoring</p>
        </div>
        <select
          className="select-input"
          value={sector}
          onChange={e => setSector(e.target.value)}
        >
          <option value="">All Sectors</option>
          {sectors.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {/* KPI Strip */}
      <div className="flex gap-4">
        <div className="card flex-1 flex-col gap-2">
          <div className="flex items-center gap-2 text-muted text-sm font-semibold">
            <Users size={16} className="text-accent" /> Total Entities
          </div>
          <div className="text-xl font-bold">{entities.length}</div>
        </div>
        <div className="card flex-1 flex-col gap-2">
          <div className="flex items-center gap-2 text-muted text-sm font-semibold">
            <AlertTriangle size={16} className="text-critical" /> Critical & High Risk
          </div>
          <div className="text-xl font-bold">{byBand.CRITICAL + byBand.HIGH}</div>
        </div>
        <div className="card flex-1 flex-col gap-2">
          <div className="flex items-center gap-2 text-muted text-sm font-semibold">
            <TrendingUp size={16} className="text-medium" /> Total Flags Generated
          </div>
          <div className="text-xl font-bold">
            {flagSummary.reduce((sum, d) => sum + d.flagged_count, 0)}
          </div>
        </div>
        <div className="card flex-1 flex-col gap-2">
          <div className="flex items-center gap-2 text-muted text-sm font-semibold">
            <Zap size={16} className="text-low" /> Average Risk Score
          </div>
          <div className="text-xl font-bold">
            {(entities.reduce((sum, e) => sum + (e.score || 0), 0) / (entities.length || 1)).toFixed(1)}
          </div>
        </div>
      </div>

      <div className="flex gap-6" style={{ height: 320 }}>
        {/* Flag Bar Chart */}
        <div className="card flex-col gap-4" style={{ flex: 2 }}>
          <h3 className="font-semibold text-sm text-muted">DETECTOR FLAGS (TOP OFFENDERS)</h3>
          <div style={{ flex: 1, minHeight: 0 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={flagSummary} layout="vertical" margin={{ left: 40, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="var(--border)" />
                <XAxis type="number" tick={{ fill: 'var(--text-muted)' }} />
                <YAxis dataKey="name" type="category" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} width={120} />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, boxShadow: 'var(--shadow-md)' }}
                  cursor={{ fill: 'var(--bg-hover)' }}
                />
                <Bar dataKey="flagged_count" fill="var(--accent)" radius={[0, 4, 4, 0]} animationDuration={1500} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Distribution Pie Chart */}
        <div className="card flex-col gap-4" style={{ flex: 1 }}>
          <h3 className="font-semibold text-sm text-muted">RISK DISTRIBUTION</h3>
          <div style={{ flex: 1, minHeight: 0, position: 'relative' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={5}
                  dataKey="value"
                  animationDuration={1500}
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={BAND_COLORS[entry.name] || '#ccc'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, boxShadow: 'var(--shadow-sm)' }} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center' }}>
              <Shield size={24} className="text-muted" style={{ opacity: 0.5 }} />
            </div>
          </div>
          
          {/* Quick Filters */}
          <div className="flex justify-center gap-2 flex-wrap">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(b => (
              <BandBadge 
                key={b} 
                band={b} 
                onClick={() => setActiveBandFilter(activeBandFilter === b ? null : b)}
                active={activeBandFilter === null || activeBandFilter === b}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Entities Table */}
      <div className="card flex-col gap-4">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-sm text-muted">ENTITY REVIEW QUEUE</h3>
          {activeBandFilter && (
            <span className="text-xs text-muted">
              Filtering by: <strong className="text-accent">{activeBandFilter}</strong> 
              <button className="btn btn-outline ml-2 text-xs" style={{ padding: '2px 8px' }} onClick={() => setActiveBandFilter(null)}>Clear</button>
            </span>
          )}
        </div>
        <div style={{ overflowX: 'auto', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Entity / Sector</th>
                <th>Asset Class</th>
                <th>Size</th>
                <th>Risk Score</th>
                <th>Band</th>
                <th style={{ width: 40 }}></th>
              </tr>
            </thead>
            <tbody>
              {filteredEntities.map((ent) => (
                <tr
                  key={ent.entity_id}
                  onClick={() => navigate(`/entity/${ent.entity_id}`)}
                  style={{ cursor: 'pointer' }}
                >
                  <td>
                    <div className="font-semibold text-accent">{ent.name}</div>
                    <div className="text-muted" style={{ fontSize: 11 }}>{ent.entity_id} • {ent.sector}</div>
                  </td>
                  <td>
                    <span style={{ 
                      background: 'var(--bg-hover)', padding: '2px 8px', borderRadius: '4px', fontSize: 11, fontWeight: 500 
                    }}>
                      {ent.asset_class}
                    </span>
                  </td>
                  <td style={{ textTransform: 'capitalize', fontSize: 12 }}>{ent.size_band}</td>
                  <td>
                    {ent.score !== null ? (
                      <ScoreBar score={ent.score} band={ent.band || 'LOW'} />
                    ) : <span className="text-muted">N/A</span>}
                  </td>
                  <td>{ent.band ? <BandBadge band={ent.band} /> : <span className="text-muted">-</span>}</td>
                  <td style={{ textAlign: 'right', paddingRight: 20 }}>
                    <ChevronRight size={16} className="text-muted" />
                  </td>
                </tr>
              ))}
              {filteredEntities.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                    No entities found matching the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

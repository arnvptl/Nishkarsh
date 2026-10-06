import { useState, useEffect } from 'react';
import { CheckCircle, AlertTriangle, RefreshCw } from 'lucide-react';

const API = '/api';

type AuditEntry = {
  id: number;
  ts: string;
  event_type: string;
  actor: string;
  details: string;
  entry_hash: string;
};

const EVENT_COLORS: Record<string, string> = {
  QUERY: 'var(--accent)',
  DETECTOR_RUN: 'var(--medium)',
  EXPORT: 'var(--low)',
  TEST: 'var(--text-muted)',
};

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [chainMsg, setChainMsg] = useState('');
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);

  const load = () => {
    setLoading(true);
    fetch(`${API}/audit/recent?limit=100`)
      .then(r => r.json())
      .then(data => { setEntries(data.entries ?? []); setLoading(false); })
      .catch(() => setLoading(false));
  };

  const verify = () => {
    setVerifying(true);
    fetch(`${API}/audit/verify`)
      .then(r => r.json())
      .then(data => { setChainValid(data.valid); setChainMsg(data.message); setVerifying(false); })
      .catch(() => setVerifying(false));
  };

  useEffect(() => { load(); verify(); }, []);

  return (
    <div>
      {/* ── Chain status ── */}
      <div className="card" style={{ marginBottom: 20, display: 'flex', alignItems: 'center', gap: 16 }}>
        {chainValid === null ? (
          <div className="spinner" />
        ) : chainValid ? (
          <CheckCircle size={20} color="var(--low)" />
        ) : (
          <AlertTriangle size={20} color="var(--critical)" />
        )}
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: chainValid ? 'var(--low)' : 'var(--critical)' }}>
            Hash Chain: {chainValid === null ? 'Verifying…' : chainValid ? 'VALID' : 'INTEGRITY FAILURE'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{chainMsg}</div>
        </div>
        <button className="btn btn-ghost" onClick={() => { load(); verify(); }} disabled={verifying}>
          <RefreshCw size={13} className={verifying ? 'spin' : ''} />
          Refresh
        </button>
      </div>

      {/* ── Audit table ── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="section-header" style={{ padding: '16px 20px 12px' }}>
          <div className="section-title">Recent Audit Entries</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{entries.length} entries</div>
        </div>

        {loading ? (
          <div className="loading-state" style={{ padding: '30px 0' }}>
            <div className="spinner" /><span>Loading…</span>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Event</th>
                <th>Actor</th>
                <th>Details</th>
                <th>Hash</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id}>
                  <td className="text-muted font-mono">{e.id}</td>
                  <td className="font-mono" style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {new Date(e.ts).toLocaleString()}
                  </td>
                  <td>
                    <span style={{
                      color: EVENT_COLORS[e.event_type] ?? 'var(--text-muted)',
                      fontSize: 11,
                      fontWeight: 700,
                      letterSpacing: '0.04em',
                    }}>{e.event_type}</span>
                  </td>
                  <td style={{ fontSize: 12, color: 'var(--text)' }}>{e.actor}</td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)', maxWidth: 400 }} className="truncate">
                    {e.details}
                  </td>
                  <td className="font-mono" style={{ color: 'var(--text-dim)', fontSize: 10 }}>
                    {e.entry_hash}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

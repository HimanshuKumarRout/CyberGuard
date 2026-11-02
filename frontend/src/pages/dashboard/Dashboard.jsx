import React from 'react';
import { RefreshCw } from 'lucide-react';
import KpiCard from '../../components/common/KpiCard';
import AttackTimeline from '../../components/timeline/AttackTimeline';
import { useSocData } from '../../context/SocDataContext';

export default function Dashboard(props) {
  const socData = useSocData();
  const stats = props.stats || socData.stats;
  const events = props.events || socData.events;
  const timelineData = props.timelineData || socData.timeline;
  const onRefresh = props.onRefresh || socData.refreshData;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top KPI Ribbon */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <KpiCard
          title="Total Events Ingested"
          value={stats.total_events}
          delta={stats.total_events > 0 ? "Live telemetry stream" : "Awaiting user input"}
          accentColor="#38bdf8"
        />
        <KpiCard
          title="Threats Detected"
          value={stats.threats_detected}
          subtext="Active malicious detections"
          accentColor="#f59e0b"
        />
        <KpiCard
          title="Critical Incidents"
          value={stats.critical_incidents}
          subtext="P1 Containment Active"
          accentColor="#ef4444"
          isAlert={stats.critical_incidents > 0}
        />
        <KpiCard
          title="Open Incidents"
          value={stats.open_incidents}
          subtext="Awaiting analyst triage"
          accentColor="#0ea5e9"
        />
      </div>

      {/* Attack Timeline Visualizer */}
      <AttackTimeline timelineData={timelineData} />

      {/* Live Ingested Security Events Feed */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1.15rem' }}>Live Threat Telemetry Feed</h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Normalized events processed by detection orchestrator</p>
          </div>
          <button className="btn btn-secondary" onClick={onRefresh} style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
            <RefreshCw size={14} /> Refresh Feed
          </button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '12px 10px' }}>EVENT ID</th>
                <th style={{ padding: '12px 10px' }}>MODALITY</th>
                <th style={{ padding: '12px 10px' }}>DETECTOR</th>
                <th style={{ padding: '12px 10px' }}>CATEGORY</th>
                <th style={{ padding: '12px 10px' }}>CONFIDENCE</th>
                <th style={{ padding: '12px 10px' }}>RISK SCORE</th>
                <th style={{ padding: '12px 10px' }}>SEVERITY</th>
              </tr>
            </thead>
            <tbody>
              {events && events.length > 0 ? (
                events.map(ev => (
                  <tr key={ev.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                    <td style={{ padding: '12px 10px', fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>
                      {ev.id.substring(0, 16)}...
                    </td>
                    <td style={{ padding: '12px 10px', textTransform: 'uppercase', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {ev.input_type}
                    </td>
                    <td style={{ padding: '12px 10px' }}>{ev.detector}</td>
                    <td style={{ padding: '12px 10px', fontWeight: 500 }}>{ev.threat_category}</td>
                    <td style={{ padding: '12px 10px', fontFamily: 'var(--font-mono)' }}>
                      {(ev.confidence * 100).toFixed(0)}%
                    </td>
                    <td style={{ padding: '12px 10px', fontWeight: 700 }}>
                      {ev.risk_score} / 100
                    </td>
                    <td style={{ padding: '12px 10px' }}>
                      <span className={`badge badge-${ev.risk_level?.toLowerCase()}`}>
                        {ev.risk_level}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No events loaded yet. Run a threat analysis in the Threat Studio to ingest new telemetry.
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

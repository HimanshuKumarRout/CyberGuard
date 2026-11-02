import React from 'react';

export default function AttackTimeline({ timelineData }) {
  const data = timelineData || [];
  const maxTotal = data.length > 0 ? Math.max(...data.map(d => (d.safe || 0) + (d.medium || 0) + (d.critical || 0)), 1) : 1;

  return (
    <div className="glass-panel" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div>
          <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1.1rem' }}>Attack Ingestion Timeline</h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Segmented distribution across Safe, Suspicious, and Critical attacks</p>
        </div>
        <div style={{ display: 'flex', gap: '14px', fontSize: '0.75rem' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '10px', height: '10px', background: '#10b981', borderRadius: '2px' }}></span> Safe
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '10px', height: '10px', background: '#f59e0b', borderRadius: '2px' }}></span> Medium
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '10px', height: '10px', background: '#ef4444', borderRadius: '2px' }}></span> Critical
          </span>
        </div>
      </div>

      {data.length === 0 ? (
        <div style={{
          padding: '36px 20px',
          textAlign: 'center',
          color: 'var(--text-muted)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '6px'
        }}>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            No attack telemetry recorded yet.
          </p>
          <span style={{ fontSize: '0.75rem' }}>
            Submit an email, URL, or authentication event in the Threat Studio to populate live timeline bars.
          </span>
        </div>
      ) : (
        /* Visual Timeline Bar Chart */
        <div style={{
          display: 'flex',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          height: '160px',
          paddingTop: '20px',
          borderBottom: '1px solid var(--border-subtle)',
          gap: '12px'
        }}>
          {data.map((item, idx) => {
            const safe = item.safe || 0;
            const med = item.medium || 0;
            const crit = item.critical || 0;
            const safeH = (safe / maxTotal) * 100;
            const medH = (med / maxTotal) * 100;
            const critH = (crit / maxTotal) * 100;

            return (
              <div key={idx} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', height: '100%', justifyContent: 'flex-end' }}>
                <div style={{ width: '100%', maxWidth: '36px', display: 'flex', flexDirection: 'column', borderRadius: '4px 4px 0 0', overflow: 'hidden' }}>
                  <div style={{ height: `${critH}%`, background: '#ef4444', transition: 'height 0.4s' }} title={`Critical: ${crit}`} />
                  <div style={{ height: `${medH}%`, background: '#f59e0b', transition: 'height 0.4s' }} title={`Medium: ${med}`} />
                  <div style={{ height: `${safeH}%`, background: '#10b981', transition: 'height 0.4s' }} title={`Safe: ${safe}`} />
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '8px', fontFamily: 'var(--font-mono)' }}>
                  {item.time}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

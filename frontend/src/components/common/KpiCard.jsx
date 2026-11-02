import React from 'react';

export default function KpiCard({ title, value, delta, subtext, accentColor, isAlert }) {
  return (
    <div
      className="glass-panel"
      style={{
        padding: '20px',
        borderLeft: accentColor ? `3px solid ${accentColor}` : undefined,
        boxShadow: isAlert ? '0 0 15px rgba(239, 68, 68, 0.2)' : undefined
      }}
    >
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {title}
      </div>
      <div style={{
        fontSize: '1.85rem',
        fontWeight: 700,
        fontFamily: 'var(--font-display)',
        marginTop: '8px',
        color: accentColor || 'var(--text-primary)'
      }}>
        {value}
      </div>
      {(delta || subtext) && (
        <div style={{
          fontSize: '0.75rem',
          color: delta && delta.startsWith('+') ? '#10b981' : (isAlert ? '#ef4444' : 'var(--text-muted)'),
          marginTop: '4px'
        }}>
          {delta || subtext}
        </div>
      )}
    </div>
  );
}

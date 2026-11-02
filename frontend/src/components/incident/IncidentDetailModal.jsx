import React, { useEffect } from 'react';
import { createPortal } from 'react-dom';
import { X, Clock, User, CheckCircle2, ShieldAlert } from 'lucide-react';
import { SEVERITY_COLORS } from '../../constants/theme';

export default function IncidentDetailModal({ incident, onClose, onUpdateStatus }) {
  // Close on Escape key & freeze background scrolling
  useEffect(() => {
    if (!incident) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = originalOverflow;
    };
  }, [incident, onClose]);

  if (!incident) return null;

  const accentColor = SEVERITY_COLORS[incident.risk_level] || '#38bdf8';

  const modalContent = (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(3, 7, 18, 0.82)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 99999,
        padding: '20px'
      }}
    >
      <div
        className="glass-panel"
        onClick={e => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '580px',
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: '28px',
          background: '#0f172a',
          border: `1px solid ${accentColor}`,
          borderRadius: '16px',
          boxShadow: `0 25px 50px -12px rgba(0, 0, 0, 0.8), 0 0 35px ${accentColor}40`,
          display: 'flex',
          flexDirection: 'column',
          gap: '20px',
          position: 'relative'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <span className={`badge badge-${incident.risk_level?.toLowerCase()}`} style={{ fontSize: '0.75rem', padding: '4px 10px' }}>
                <ShieldAlert size={12} style={{ marginRight: '4px', verticalAlign: 'middle' }} />
                {incident.priority} • {incident.risk_level}
              </span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {incident.id}
              </span>
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'white', lineHeight: '1.35' }}>
              {incident.title}
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close modal"
            style={{
              background: 'rgba(255, 255, 255, 0.06)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              transition: 'all 0.15s ease'
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Details Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '14px',
          background: 'rgba(255, 255, 255, 0.03)',
          border: '1px solid var(--border-subtle)',
          padding: '16px',
          borderRadius: 'var(--radius-sm)'
        }}>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>THREAT MODALITY</div>
            <div style={{ fontSize: '0.9rem', fontWeight: 600, marginTop: '3px', color: 'white' }}>{incident.threat_category}</div>
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>CALIBRATED RISK SCORE</div>
            <div style={{ fontSize: '1rem', fontWeight: 800, color: accentColor, marginTop: '3px', fontFamily: 'var(--font-mono)' }}>
              {incident.risk_score} / 100
            </div>
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>ASSIGNED ANALYST</div>
            <div style={{ fontSize: '0.9rem', marginTop: '3px', display: 'flex', alignItems: 'center', gap: '6px', color: '#f1f5f9' }}>
              <User size={14} color="#38bdf8" /> {incident.assigned_to || 'Unassigned'}
            </div>
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>CREATED TIMESTAMP</div>
            <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', marginTop: '3px', display: 'flex', alignItems: 'center', gap: '6px', color: '#cbd5e1' }}>
              <Clock size={14} color="var(--text-muted)" /> {incident.created_at?.substring(0, 19).replace('T', ' ')}
            </div>
          </div>
        </div>

        {/* Lifecycle Transitions & Actions */}
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '10px', textTransform: 'uppercase' }}>
            Current Status:{' '}
            <strong style={{ color: incident.status === 'Open' ? '#ef4444' : '#10b981', fontWeight: 700 }}>
              {incident.status}
            </strong>
          </div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            {['In Investigation', 'Contained', 'Resolved'].map(st => (
              <button
                key={st}
                type="button"
                className={`btn ${incident.status === st ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => {
                  onUpdateStatus(incident.id, st);
                  onClose();
                }}
                style={{ flex: 1, minWidth: '130px', fontSize: '0.8rem', padding: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
              >
                <CheckCircle2 size={15} /> {st}
              </button>
            ))}
          </div>
        </div>

        {/* Bottom Dismiss Button */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', borderTop: '1px solid var(--border-subtle)', paddingTop: '14px' }}>
          <button
            type="button"
            onClick={onClose}
            className="btn btn-secondary"
            style={{ fontSize: '0.8rem', padding: '8px 18px' }}
          >
            Close Drawer
          </button>
        </div>
      </div>
    </div>
  );

  return createPortal(modalContent, document.body);
}

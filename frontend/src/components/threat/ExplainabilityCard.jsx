import React from 'react';
import { Eye, Shield, AlertCircle } from 'lucide-react';
import RiskGauge from '../common/RiskGauge';

export default function ExplainabilityCard({ result, onSimulateAction }) {
  if (!result) {
    return (
      <div className="glass-panel" style={{
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'var(--text-muted)',
        textAlign: 'center',
        minHeight: '360px'
      }}>
        <Shield size={48} style={{ opacity: 0.25, marginBottom: '16px' }} />
        <h3 style={{ fontSize: '1rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
          Explainability & Decision Inspector
        </h3>
        <p style={{ fontSize: '0.85rem', maxWidth: '320px', lineHeight: '1.5' }}>
          Select a threat scenario and run pipeline analysis to inspect live risk assessment and transparent XAI rationale.
        </p>
      </div>
    );
  }

  const { risk_score, risk_level, threat_category, detector, explanation, recommended_actions } = result;

  return (
    <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Eye size={18} color="#38bdf8" /> Explainability & Decision Inspector
        </h3>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          ID: {result.event_id?.substring(0, 14)}...
        </span>
      </div>

      {/* Visual Risk Gauge Banner */}
      <RiskGauge
        score={risk_score}
        level={risk_level}
        category={threat_category}
        detector={detector}
      />

      {/* Executive Summary */}
      <div>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#38bdf8', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Executive Summary
        </div>
        <div style={{ fontSize: '0.875rem', lineHeight: '1.5', color: '#e2e8f0', background: 'rgba(255, 255, 255, 0.03)', padding: '10px 14px', borderRadius: 'var(--radius-sm)' }}>
          {explanation.summary}
        </div>
      </div>

      {/* Concrete Evidence Points */}
      <div>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#38bdf8', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Quantified Evidence Points ({explanation.evidence.length})
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {explanation.evidence.map((ev, i) => (
            <div
              key={i}
              style={{
                background: 'rgba(255, 255, 255, 0.04)',
                padding: '8px 12px',
                borderRadius: '4px',
                fontSize: '0.8rem',
                borderLeft: '3px solid #38bdf8',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              <AlertCircle size={14} color="#38bdf8" />
              <span>{ev}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Contextual Reasoning */}
      <div>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#38bdf8', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Contextual Reasoning Narrative
        </div>
        <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: '1.6', fontStyle: 'italic', background: 'rgba(15, 23, 42, 0.5)', padding: '10px 14px', borderRadius: 'var(--radius-sm)' }}>
          "{explanation.reasoning}"
        </div>
      </div>

      {/* Simulated Containment Playbooks */}
      <div>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#38bdf8', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Simulated Containment Playbooks
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          {recommended_actions && recommended_actions.map((act, i) => (
            <button
              key={i}
              className="btn btn-secondary"
              onClick={() => onSimulateAction(act.action_type, act.target)}
              style={{ fontSize: '0.75rem', padding: '6px 12px' }}
            >
              <Shield size={14} color="#38bdf8" /> Simulate {act.action_type}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

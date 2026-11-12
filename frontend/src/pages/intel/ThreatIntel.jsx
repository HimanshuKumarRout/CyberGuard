import React, { useState } from 'react';
import { Layers, ExternalLink, Network, ShieldAlert } from 'lucide-react';
import { MITRE_TACTICS } from '../../constants/theme';
import AttackGraph from '../../components/graph/AttackGraph';

export default function ThreatIntel() {
  const [activeTab, setActiveTab] = useState('graph'); // 'graph' or 'matrix'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Header Card */}
      <div className="glass-panel" style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          <div>
            <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.35rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldAlert size={22} color="#38bdf8" /> Threat Intelligence & Attack Correlation
            </h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
              Multi-dimensional analysis linking MITRE ATT&CK techniques with real-time entity correlation graphs
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ display: 'flex', background: 'rgba(15, 23, 42, 0.8)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: '3px' }}>
              <button
                onClick={() => setActiveTab('graph')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '6px 14px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  borderRadius: 'var(--radius-sm)',
                  border: 'none',
                  cursor: 'pointer',
                  background: activeTab === 'graph' ? '#38bdf8' : 'transparent',
                  color: activeTab === 'graph' ? '#0a0e17' : 'var(--text-muted)',
                  transition: 'all 0.2s ease'
                }}
              >
                <Network size={14} /> Attack Correlation Graph
              </button>
              <button
                onClick={() => setActiveTab('matrix')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '6px 14px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  borderRadius: 'var(--radius-sm)',
                  border: 'none',
                  cursor: 'pointer',
                  background: activeTab === 'matrix' ? '#38bdf8' : 'transparent',
                  color: activeTab === 'matrix' ? '#0a0e17' : 'var(--text-muted)',
                  transition: 'all 0.2s ease'
                }}
              >
                <Layers size={14} /> MITRE ATT&CK Matrix
              </button>
            </div>

            <a
              href="https://attack.mitre.org/"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ fontSize: '0.75rem', padding: '6px 12px' }}
            >
              <ExternalLink size={14} /> MITRE Reference
            </a>
          </div>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === 'graph' ? (
        <div className="glass-panel" style={{ padding: '20px' }}>
          <AttackGraph />
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
            {MITRE_TACTICS.map(tactic => (
              <div
                key={tactic.id}
                style={{
                  background: 'rgba(15, 23, 42, 0.8)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '18px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '14px'
                }}
              >
                <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{tactic.id}</div>
                  <div style={{ fontSize: '1.05rem', fontWeight: 700, color: tactic.color, marginTop: '2px' }}>
                    {tactic.name}
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {tactic.techniques.map(tech => (
                    <div
                      key={tech.id}
                      style={{
                        background: 'rgba(255, 255, 255, 0.03)',
                        border: '1px solid rgba(255, 255, 255, 0.06)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '10px 12px'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>
                          {tech.id}
                        </span>
                        <span style={{ fontSize: '0.7rem', color: '#10b981', background: 'rgba(16, 185, 129, 0.1)', padding: '2px 6px', borderRadius: '4px' }}>
                          Covered
                        </span>
                      </div>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'white' }}>
                        {tech.name}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                        {tech.desc}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

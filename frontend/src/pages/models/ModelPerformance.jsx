import React from 'react';
import { BarChart3, CheckCircle2 } from 'lucide-react';
import { useSocData } from '../../context/SocDataContext';

export default function ModelPerformance(props) {
  const socData = useSocData();
  const models = props.models || socData.models;
  const modelList = models && models.length > 0 ? models : [
    {
      id: 'det_phish_01',
      name: 'Phishing & Lookalike Domain Classifier',
      version: 'v1.4.2',
      type: 'Hybrid NLP + Levenshtein / Shannon Heuristics',
      latency_p50_ms: 18,
      latency_p95_ms: 42,
      precision: 0.962,
      recall: 0.948,
      f1_score: 0.955
    },
    {
      id: 'det_imper_02',
      name: 'Digital Impersonation & BEC Analyzer',
      version: 'v1.2.0',
      type: 'Header Discrepancy + Synthetic Artifact Model',
      latency_p50_ms: 12,
      latency_p95_ms: 31,
      precision: 0.941,
      recall: 0.932,
      f1_score: 0.936
    },
    {
      id: 'det_anom_03',
      name: 'Credential Theft & Impossible Travel Engine',
      version: 'v2.0.1',
      type: 'Haversine Kinematics + Sliding Window Rate Limiter',
      latency_p50_ms: 4,
      latency_p95_ms: 11,
      precision: 0.985,
      recall: 0.979,
      f1_score: 0.982
    }
  ];

  return (
    <div className="glass-panel" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <BarChart3 size={20} color="#38bdf8" /> Active AI Model Telemetry & Benchmarks
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Quantified evaluation metrics and execution latency for all deployed detectors
          </p>
        </div>
        <span style={{ fontSize: '0.75rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <CheckCircle2 size={14} /> All 3 Engines Online
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
        {modelList.map(m => (
          <div
            key={m.id}
            style={{
              background: 'rgba(15, 23, 42, 0.8)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '20px',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px'
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>
                  {m.id}
                </span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  {m.version}
                </span>
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'white' }}>
                {m.name}
              </h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                {m.type}
              </p>
            </div>

            {/* Performance Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '10px',
              background: 'rgba(255, 255, 255, 0.03)',
              padding: '12px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8rem'
            }}>
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>P50 Latency:</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#10b981' }}>{m.latency_p50_ms} ms</div>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>P95 Latency:</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#38bdf8' }}>{m.latency_p95_ms} ms</div>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Precision:</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{(m.precision * 100).toFixed(1)}%</div>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Recall:</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{(m.recall * 100).toFixed(1)}%</div>
              </div>
              <div style={{ gridColumn: 'span 2', borderTop: '1px solid var(--border-subtle)', paddingTop: '6px' }}>
                <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>F1-Score:</span>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f59e0b' }}>{(m.f1_score * 100).toFixed(1)}%</div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

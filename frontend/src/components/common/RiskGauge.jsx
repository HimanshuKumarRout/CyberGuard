import { SEVERITY_COLORS } from '../../constants/theme';

export default function RiskGauge({ score, level, category, detector }) {
  const accentColor = SEVERITY_COLORS[level] || '#38bdf8';

  return (
    <div style={{
      background: 'rgba(15, 23, 42, 0.8)',
      border: `1px solid ${accentColor}`,
      borderRadius: 'var(--radius-sm)',
      padding: '16px 20px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      boxShadow: `0 0 15px ${accentColor}25`
    }}>
      <div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Verdict Classification
        </div>
        <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'white', marginTop: '2px' }}>
          {category}
        </div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
          Detector: <span style={{ fontFamily: 'var(--font-mono)' }}>{detector}</span>
        </div>
      </div>

      <div style={{ textAlign: 'right' }}>
        <div style={{
          fontSize: '2rem',
          fontWeight: 800,
          fontFamily: 'var(--font-display)',
          color: accentColor,
          lineHeight: '1.1'
        }}>
          {score} <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>/ 100</span>
        </div>
        <span className={`badge badge-${level.toLowerCase()}`} style={{ marginTop: '4px' }}>
          {level}
        </span>
      </div>
    </div>
  );
}

import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, LogOut } from 'lucide-react';

export default function Header({ currentUser, onLogout }) {
  const name = currentUser?.name || 'Himanshu Rout';
  const role = currentUser?.role || 'Tier-1 SOC Lead';
  const initials = name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase() || 'HR';
  return (
    <header style={{
      background: 'rgba(8, 11, 17, 0.95)',
      borderBottom: '1px solid var(--border-subtle)',
      padding: '12px 24px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      backdropFilter: 'blur(10px)'
    }}>
      <Link to="/dashboard" style={{ display: 'flex', alignItems: 'center', gap: '14px', textDecoration: 'none', color: 'inherit' }}>
        <div style={{
          background: 'linear-gradient(135deg, #0284c7, #0f172a)',
          border: '1px solid #38bdf8',
          borderRadius: '10px',
          padding: '8px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 15px rgba(56, 189, 248, 0.3)'
        }}>
          <Shield size={24} color="#38bdf8" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontFamily: 'var(--font-display)', fontWeight: 800, fontSize: '1.25rem', letterSpacing: '0.05em' }}>
              CYBERGUARD
            </span>
            <span style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.75rem',
              color: '#10b981',
              background: 'rgba(16, 185, 129, 0.12)',
              padding: '2px 8px',
              borderRadius: '12px',
              border: '1px solid rgba(16, 185, 129, 0.25)'
            }}>
              <span className="status-pulse-green"></span> ENGINES ONLINE
            </span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            AI-Powered Cyber Threat, Phishing & Impersonation Defense
          </div>
        </div>
      </Link>

      {/* Global Telemetry Ribbon */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        <div style={{ display: 'flex', gap: '16px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          <div><span style={{ color: 'var(--text-muted)' }}>THROUGHPUT:</span> <span style={{ fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>1,420 evt/m</span></div>
          <div><span style={{ color: 'var(--text-muted)' }}>P95 LATENCY:</span> <span style={{ fontFamily: 'var(--font-mono)', color: '#10b981' }}>18 ms</span></div>
          <div><span style={{ color: 'var(--text-muted)' }}>SANDBOX:</span> <span style={{ fontFamily: 'var(--font-mono)', color: '#f59e0b' }}>SIMULATED</span></div>
        </div>
        <div style={{ borderLeft: '1px solid var(--border-subtle)', paddingLeft: '16px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '50%',
            background: '#1e293b',
            border: '1px solid #38bdf8',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.8rem',
            fontWeight: 600,
            color: '#38bdf8'
          }}>
            {initials}
          </div>
          <div style={{ fontSize: '0.75rem' }}>
            <div style={{ fontWeight: 600 }}>{name}</div>
            <div style={{ color: 'var(--text-muted)' }}>{role}</div>
          </div>
          {onLogout && (
            <button
              onClick={onLogout}
              title="Sign out of SOC session"
              style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.25)',
                borderRadius: 'var(--radius-sm)',
                color: '#f87171',
                cursor: 'pointer',
                padding: '6px 8px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginLeft: '6px',
                transition: 'all 0.15s ease'
              }}
            >
              <LogOut size={14} />
            </button>
          )}
        </div>
      </div>
    </header>
  );
}

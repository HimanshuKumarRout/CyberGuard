import React from 'react';
import { Shield } from 'lucide-react';

export default function LoadingFallback({ message = 'Loading Secure Workspace...' }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '320px',
      height: '100%',
      width: '100%',
      gap: '16px',
      color: 'var(--text-muted)'
    }}>
      <div style={{
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <div style={{
          width: '54px',
          height: '54px',
          borderRadius: '16px',
          background: 'rgba(14, 165, 233, 0.1)',
          border: '1px solid rgba(56, 189, 248, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 25px rgba(56, 189, 248, 0.25)'
        }}>
          <Shield size={26} color="#38bdf8" />
        </div>
        <div style={{
          position: 'absolute',
          inset: '-6px',
          borderRadius: '22px',
          border: '2px solid transparent',
          borderTopColor: '#38bdf8',
          animation: 'spin 1s linear infinite'
        }} />
      </div>
      <span style={{ fontSize: '0.825rem', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
        {message}
      </span>
      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

import React, { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { useSocData } from '../../context/SocDataContext';

export default function Header() {
  const { stats, models, loading } = useSocData();

  // Dynamic telemetry live tick / network jitter
  const [telemetryTick, setTelemetryTick] = useState({
    throughputJitter: 0,
    latencyJitter: 0,
    lastUpdate: Date.now()
  });

  useEffect(() => {
    // Jitter interval to simulate live real-time network packets arriving at the sensor gateway
    const interval = setInterval(() => {
      setTelemetryTick({
        throughputJitter: Math.floor(Math.random() * 51) - 25, // -25 to +25 evt/m fluctuation
        latencyJitter: Math.floor(Math.random() * 5) - 2,      // -2 to +2 ms fluctuation
        lastUpdate: Date.now()
      });
    }, 2200);
    return () => clearInterval(interval);
  }, []);

  // 1. Dynamic Throughput: dynamically calculated from total events ingested + live stream jitter + analysis burst
  const throughput = useMemo(() => {
    const totalEvents = stats?.total_events || 0;
    // Base rate starts at ~1,400 evt/m and scales with ingested event volume
    const baseThroughput = 1380 + (totalEvents % 50) * 4;
    // Burst boost when an analysis is actively running in Threat Studio
    const burst = loading ? 280 : 0;
    const computed = Math.max(900, baseThroughput + telemetryTick.throughputJitter + burst);
    return computed.toLocaleString();
  }, [stats?.total_events, loading, telemetryTick.throughputJitter]);

  // 2. Dynamic P95 Latency: calculated from detector models' real-time benchmarks with live jitter
  const p95Latency = useMemo(() => {
    let baseP95 = 18;
    if (models && models.length > 0) {
      const validLatencies = models.map(m => m.latency_p95_ms).filter(Boolean);
      if (validLatencies.length > 0) {
        baseP95 = Math.round(validLatencies.reduce((a, b) => a + b, 0) / validLatencies.length);
      }
    }
    // High load slightly increases latency
    const loadShift = loading ? 6 : 0;
    return Math.max(8, baseP95 + telemetryTick.latencyJitter + loadShift);
  }, [models, loading, telemetryTick.latencyJitter]);

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

      {/* Global Dynamic Telemetry Ribbon */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '18px',
          fontSize: '0.8rem',
          color: 'var(--text-secondary)',
          background: 'rgba(15, 23, 42, 0.65)',
          padding: '6px 14px',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border-subtle)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-muted)' }}>THROUGHPUT:</span>
            <span style={{
              fontFamily: 'var(--font-mono)',
              color: '#38bdf8',
              fontVariantNumeric: 'tabular-nums',
              transition: 'color 0.2s ease'
            }}>
              {throughput} evt/m
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-muted)' }}>P95 LATENCY:</span>
            <span style={{
              fontFamily: 'var(--font-mono)',
              color: p95Latency > 35 ? '#f59e0b' : '#10b981',
              fontVariantNumeric: 'tabular-nums',
              transition: 'color 0.2s ease'
            }}>
              {p95Latency} ms
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-muted)' }}>SANDBOX:</span>
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              fontFamily: 'var(--font-mono)',
              color: '#f59e0b'
            }}>
              <span className="status-pulse-amber"></span> SIMULATED
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}

import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { Shield, Mail, Key, ArrowRight, ShieldCheck, Sparkles, AlertCircle } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export default function Login({ onLoginSuccess, onNavigateToSignup, initialSuccessMessage }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState(location.state?.successMessage || initialSuccessMessage || '');

  useEffect(() => {
    if (location.state?.successMessage) {
      setSuccessMsg(location.state.successMessage);
    } else if (initialSuccessMessage) {
      setSuccessMsg(initialSuccessMessage);
    }
  }, [location.state, initialSuccessMessage]);

  // 1-Click Fast Demo Login for Lead Himanshu Rout
  const handleQuickDemoLogin = async () => {
    setLoading(true);
    setError('');
    setSuccessMsg('');
    try {
      const data = await login('himanshu@cyberguard.internal', 'admin123');
      if (onLoginSuccess) {
        onLoginSuccess(data.user, data.token);
      }
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message || 'Quick login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email.trim() || !password.trim()) {
      setError('Please provide email and password.');
      return;
    }

    setLoading(true);
    try {
      const data = await login(email, password);
      if (onLoginSuccess) {
        onLoginSuccess(data.user, data.token);
      }
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px',
      background: 'radial-gradient(ellipse at 50% 20%, rgba(14, 165, 233, 0.15) 0%, rgba(15, 23, 42, 0.95) 70%, #030712 100%)',
      position: 'relative'
    }}>
      {/* Background Decorative Grid */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: 'linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
        pointerEvents: 'none'
      }} />

      <div className="glass-panel" style={{
        width: '100%',
        maxWidth: '460px',
        padding: '36px',
        borderRadius: '16px',
        position: 'relative',
        zIndex: 1,
        boxShadow: '0 20px 40px -15px rgba(0, 0, 0, 0.7), 0 0 30px -10px rgba(56, 189, 248, 0.2)'
      }}>
        {/* Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '54px',
            height: '54px',
            borderRadius: '14px',
            background: 'linear-gradient(135deg, rgba(14, 165, 233, 0.25), rgba(99, 102, 241, 0.25))',
            border: '1px solid rgba(56, 189, 248, 0.5)',
            marginBottom: '14px',
            boxShadow: '0 0 20px rgba(56, 189, 248, 0.3)'
          }}>
            <Shield size={28} color="#38bdf8" />
          </div>
          <h1 style={{
            fontFamily: 'var(--font-display)',
            fontSize: '1.6rem',
            fontWeight: 800,
            letterSpacing: '1px',
            background: 'linear-gradient(135deg, #ffffff, #38bdf8)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            margin: '0 0 6px 0'
          }}>
            CYBERGUARD
          </h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Autonomous AI SOC Command & Threat Detection Gateway
          </p>
        </div>

        {/* 1-Click Fast Viva/Demo Access Button */}
        <div style={{
          background: 'rgba(56, 189, 248, 0.06)',
          border: '1px dashed rgba(56, 189, 248, 0.35)',
          borderRadius: 'var(--radius-sm)',
          padding: '12px',
          marginBottom: '20px',
          textAlign: 'center'
        }}>
          <button
            type="button"
            onClick={handleQuickDemoLogin}
            disabled={loading}
            style={{
              width: '100%',
              background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
              color: '#ffffff',
              border: 'none',
              borderRadius: 'var(--radius-sm)',
              padding: '10px 14px',
              fontSize: '0.825rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              transition: 'opacity 0.2s',
              boxShadow: '0 4px 14px rgba(14, 165, 233, 0.3)'
            }}
          >
            <Sparkles size={15} /> 1-Click Fast Demo Login (Himanshu Rout)
          </button>
          <span style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '6px' }}>
            Instant authenticated session as Tier-1 SOC Lead
          </span>
        </div>

        {/* Divider */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          margin: '18px 0',
          color: 'var(--text-muted)',
          fontSize: '0.725rem',
          textTransform: 'uppercase'
        }}>
          <div style={{ flex: 1, height: '1px', background: 'var(--border-subtle)' }} />
          <span>Or Standard Credential Login</span>
          <div style={{ flex: 1, height: '1px', background: 'var(--border-subtle)' }} />
        </div>

        {/* Success Alert (e.g. after Registration) */}
        {successMsg && (
          <div style={{
            background: 'rgba(16, 185, 129, 0.15)',
            border: '1px solid rgba(16, 185, 129, 0.4)',
            borderRadius: 'var(--radius-sm)',
            padding: '12px 14px',
            marginBottom: '16px',
            color: '#6ee7b7',
            fontSize: '0.825rem',
            display: 'flex',
            alignItems: 'center',
            gap: '10px'
          }}>
            <ShieldCheck size={18} color="#10b981" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            borderRadius: 'var(--radius-sm)',
            padding: '10px 14px',
            marginBottom: '16px',
            color: '#fca5a5',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Analyst Email Address
            </label>
            <div style={{ position: 'relative' }}>
              <Mail size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
              <input
                type="email"
                className="form-input"
                style={{ paddingLeft: '38px' }}
                placeholder="himanshu@cyberguard.internal"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <Key size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
              <input
                type="password"
                className="form-input"
                style={{ paddingLeft: '38px' }}
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
              />
            </div>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px', display: 'block' }}>
              Default password: <code style={{ color: '#38bdf8' }}>admin123</code>
            </span>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
            style={{
              marginTop: '8px',
              padding: '12px',
              fontWeight: 600,
              fontSize: '0.875rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px'
            }}
          >
            {loading ? 'Authenticating...' : 'Authenticate Session'}
            <ArrowRight size={16} />
          </button>
        </form>

        {/* Link to Dedicated Signup Page */}
        <div style={{ textAlign: 'center', marginTop: '22px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <span>Need a new analyst account? </span>
          {onNavigateToSignup ? (
            <button
              type="button"
              onClick={onNavigateToSignup}
              style={{
                background: 'none',
                border: 'none',
                color: '#38bdf8',
                cursor: 'pointer',
                fontWeight: 600,
                padding: 0
              }}
            >
              Create Analyst Profile
            </button>
          ) : (
            <Link
              to="/signup"
              style={{
                color: '#38bdf8',
                textDecoration: 'none',
                fontWeight: 600
              }}
            >
              Create Analyst Profile
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}

import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { User, Mail, Key, ArrowRight, AlertCircle, UserPlus } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export default function Signup({ onNavigateToLogin, onSignupSuccess }) {
  const navigate = useNavigate();
  const { register } = useAuth();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('Tier-1 SOC Lead');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!name.trim() || !email.trim() || !password.trim()) {
      setError('Please fill in all registration fields.');
      return;
    }

    setLoading(true);
    try {
      const res = await register(name, email, password, role);
      const msg = res.message || 'Account registered successfully! Please sign in with your credentials to access the SOC.';
      if (onSignupSuccess) {
        onSignupSuccess(msg);
      }
      navigate('/login', {
        state: { successMessage: msg },
        replace: true
      });
    } catch (err) {
      setError(err.message || 'Registration failed. Please verify your details.');
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
            <UserPlus size={28} color="#38bdf8" />
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
            Create SOC Profile
          </h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Register new analyst credentials on CYBERGUARD Cloud Gateway
          </p>
        </div>

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
              Full Name
            </label>
            <div style={{ position: 'relative' }}>
              <User size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '12px' }} />
              <input
                type="text"
                className="form-input"
                style={{ paddingLeft: '38px' }}
                placeholder="e.g. Himanshu Rout"
                value={name}
                onChange={e => setName(e.target.value)}
                required
              />
            </div>
          </div>

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
                placeholder="analyst@cyberguard.internal"
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
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
              SOC Role Assignment
            </label>
            <select
              className="form-input"
              value={role}
              onChange={e => setRole(e.target.value)}
              style={{ background: '#0f172a', color: 'white' }}
            >
              <option value="Tier-1 SOC Lead">Tier-1 SOC Lead</option>
              <option value="Tier-2 Incident Responder">Tier-2 Incident Responder</option>
              <option value="Threat Hunter / Investigator">Threat Hunter / Investigator</option>
              <option value="SOC Administrator">SOC Administrator</option>
            </select>
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
            {loading ? 'Registering Account...' : 'Register SOC Account'}
            <ArrowRight size={16} />
          </button>
        </form>

        {/* Link back to Login */}
        <div style={{ textAlign: 'center', marginTop: '22px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <span>Already registered? </span>
          {onNavigateToLogin ? (
            <button
              type="button"
              onClick={onNavigateToLogin}
              style={{
                background: 'none',
                border: 'none',
                color: '#38bdf8',
                cursor: 'pointer',
                fontWeight: 600,
                padding: 0
              }}
            >
              Sign In to SOC
            </button>
          ) : (
            <Link
              to="/login"
              style={{
                color: '#38bdf8',
                textDecoration: 'none',
                fontWeight: 600
              }}
            >
              Sign In to SOC
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}

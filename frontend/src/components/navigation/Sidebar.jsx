import React from 'react';
import { NavLink } from 'react-router-dom';
import { Activity, Terminal, AlertTriangle, Layers, BarChart3 } from 'lucide-react';

const NAV_ITEMS = [
  { path: '/dashboard', label: 'Command Center', icon: Activity },
  { path: '/studio', label: 'Threat Studio', icon: Terminal },
  { path: '/incidents', label: 'Incident Triage', icon: AlertTriangle },
  { path: '/intel', label: 'MITRE Matrix', icon: Layers },
  { path: '/models', label: 'Model Telemetry', icon: BarChart3 },
];

export default function Sidebar() {
  return (
    <nav style={{
      width: '240px',
      background: 'rgba(15, 23, 42, 0.6)',
      borderRight: '1px solid var(--border-subtle)',
      padding: '20px 12px',
      display: 'flex',
      flexDirection: 'column',
      gap: '8px'
    }}>
      {NAV_ITEMS.map(tab => {
        const Icon = tab.icon;
        return (
          <NavLink
            key={tab.path}
            to={tab.path}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              padding: '10px 14px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid',
              borderColor: isActive ? 'rgba(56, 189, 248, 0.4)' : 'transparent',
              background: isActive ? 'rgba(14, 165, 233, 0.15)' : 'transparent',
              color: isActive ? '#38bdf8' : 'var(--text-secondary)',
              cursor: 'pointer',
              fontSize: '0.875rem',
              fontWeight: 500,
              textAlign: 'left',
              textDecoration: 'none',
              transition: 'all 0.15s ease'
            })}
          >
            <Icon size={18} />
            {tab.label}
          </NavLink>
        );
      })}
    </nav>
  );
}

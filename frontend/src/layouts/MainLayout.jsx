import React from 'react';
import { Outlet } from 'react-router-dom';
import Header from '../components/navigation/Header';
import Sidebar from '../components/navigation/Sidebar';
import LoadingFallback from '../components/common/LoadingFallback';
import { useAuth } from '../context/AuthContext';
import { useSocData } from '../context/SocDataContext';

export default function MainLayout() {
  const { currentUser, logout } = useAuth();
  const { notification, setNotification } = useSocData();

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Persistent SOC Command Header */}
      <Header currentUser={currentUser} onLogout={logout} />

      {/* Main Content Workspace */}
      <div style={{ display: 'flex', flex: 1 }}>
        {/* Navigation Sidebar */}
        <Sidebar />

        {/* Routed Page Container */}
        <main style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>
          {/* Notification Toast */}
          {notification && (
            <div style={{
              background: notification.type === 'error' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
              border: `1px solid ${notification.type === 'error' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
              borderRadius: 'var(--radius-sm)',
              padding: '12px 16px',
              color: notification.type === 'error' ? '#fca5a5' : '#34d399',
              fontSize: '0.875rem',
              marginBottom: '20px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <span>{notification.message}</span>
              <button
                onClick={() => setNotification(null)}
                style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '1rem' }}
              >
                ✕
              </button>
            </div>
          )}

          {/* Render Active Route with Optimized Fallback */}
          <React.Suspense fallback={<LoadingFallback message="Loading Cyber Workspace..." />}>
            <Outlet />
          </React.Suspense>
        </main>
      </div>
    </div>
  );
}

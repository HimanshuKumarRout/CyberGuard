import React, { createContext, useContext, useMemo } from 'react';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // User login removed: pure open workspace with persistent operational session
  const value = useMemo(() => ({
    currentUser: null,
    authToken: 'active_soc_session',
    isAuthenticated: true,
    login: async () => ({ status: 'authenticated' }),
    logout: () => {},
    register: async () => ({})
  }), []);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

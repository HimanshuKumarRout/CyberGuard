import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';
import { api } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(() => {
    try {
      const saved = localStorage.getItem('cyberguard_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [authToken, setAuthToken] = useState(() => {
    return localStorage.getItem('cyberguard_token') || null;
  });

  const login = useCallback(async (email, password) => {
    const data = await api.login(email, password);
    setCurrentUser(data.user);
    setAuthToken(data.token);
    localStorage.setItem('cyberguard_user', JSON.stringify(data.user));
    localStorage.setItem('cyberguard_token', data.token);
    return data;
  }, []);

  const logout = useCallback(() => {
    setCurrentUser(null);
    setAuthToken(null);
    localStorage.removeItem('cyberguard_user');
    localStorage.removeItem('cyberguard_token');
  }, []);

  const register = useCallback(async (name, email, password, role) => {
    return await api.register(name, email, password, role);
  }, []);

  const value = useMemo(() => ({
    currentUser,
    authToken,
    isAuthenticated: Boolean(currentUser && authToken),
    login,
    logout,
    register
  }), [currentUser, authToken, login, logout, register]);

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

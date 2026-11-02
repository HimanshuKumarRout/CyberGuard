import React from 'react';
import { Route, Navigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

const Login = React.lazy(() => import('../../pages/auth/Login'));
const Signup = React.lazy(() => import('../../pages/auth/Signup'));

export function PublicOnlyRoute({ children }) {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }
  return children;
}

export const authRoutes = (
  <React.Fragment key="auth-routes">
    <Route
      path="/login"
      element={
        <PublicOnlyRoute>
          <Login />
        </PublicOnlyRoute>
      }
    />
    <Route
      path="/signin"
      element={<Navigate to="/login" replace />}
    />
    <Route
      path="/signup"
      element={
        <PublicOnlyRoute>
          <Signup />
        </PublicOnlyRoute>
      }
    />
    <Route
      path="/register"
      element={<Navigate to="/signup" replace />}
    />
  </React.Fragment>
);

import React from 'react';
import { Route, Navigate } from 'react-router-dom';

/**
 * Auth Routes: User login has been removed from CYBERGUARD.
 * Any legacy auth URLs immediately redirect directly to the SOC Command Center.
 */
export const authRoutes = (
  <React.Fragment key="auth-routes">
    <Route path="/login" element={<Navigate to="/dashboard" replace />} />
    <Route path="/signin" element={<Navigate to="/dashboard" replace />} />
    <Route path="/signup" element={<Navigate to="/dashboard" replace />} />
    <Route path="/register" element={<Navigate to="/dashboard" replace />} />
  </React.Fragment>
);

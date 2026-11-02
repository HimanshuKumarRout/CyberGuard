import React, { Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import ProtectedRoute from './guards/ProtectedRoute';
import MainLayout from '../layouts/MainLayout';
import LoadingFallback from '../components/common/LoadingFallback';
import { authRoutes } from './modules/authRoutes';
import { dashboardRoutes } from './modules/dashboardRoutes';
import { threatStudioRoutes } from './modules/threatStudioRoutes';
import { incidentRoutes } from './modules/incidentRoutes';
import { threatIntelRoutes } from './modules/threatIntelRoutes';
import { modelRoutes } from './modules/modelRoutes';

export default function AppRoutes() {
  return (
    <Suspense fallback={<LoadingFallback message="Initializing Cyber SOC Engine..." />}>
      <Routes>
        {/* 1. Public Authentication Routes (Login / Signup) */}
        {authRoutes}

        {/* 2. Protected SOC Operations Workspace Routes */}
        <Route
          element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }
        >
          {dashboardRoutes}
          {threatStudioRoutes}
          {incidentRoutes}
          {threatIntelRoutes}
          {modelRoutes}
        </Route>

        {/* 3. Global Fallback 404 Route */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Suspense>
  );
}

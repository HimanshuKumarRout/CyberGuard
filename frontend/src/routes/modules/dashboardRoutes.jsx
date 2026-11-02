import React from 'react';
import { Route, Navigate } from 'react-router-dom';

const Dashboard = React.lazy(() => import('../../pages/dashboard/Dashboard'));

export const dashboardRoutes = (
  <React.Fragment key="dashboard-routes">
    <Route index element={<Dashboard />} />
    <Route path="/dashboard" element={<Dashboard />} />
    <Route path="/command-center" element={<Navigate to="/dashboard" replace />} />
  </React.Fragment>
);

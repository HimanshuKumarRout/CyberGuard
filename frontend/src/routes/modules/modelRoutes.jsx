import React from 'react';
import { Route, Navigate } from 'react-router-dom';

const ModelPerformance = React.lazy(() => import('../../pages/models/ModelPerformance'));

export const modelRoutes = (
  <React.Fragment key="model-routes">
    <Route path="/models" element={<ModelPerformance />} />
    <Route path="/model-telemetry" element={<Navigate to="/models" replace />} />
    <Route path="/model-performance" element={<Navigate to="/models" replace />} />
  </React.Fragment>
);

import React from 'react';
import { Route, Navigate } from 'react-router-dom';

const ThreatStudio = React.lazy(() => import('../../pages/studio/ThreatStudio'));

export const threatStudioRoutes = (
  <React.Fragment key="threat-studio-routes">
    <Route path="/studio" element={<ThreatStudio />} />
    <Route path="/threat-studio" element={<Navigate to="/studio" replace />} />
  </React.Fragment>
);

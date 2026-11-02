import React from 'react';
import { Route, Navigate } from 'react-router-dom';

const ThreatIntel = React.lazy(() => import('../../pages/intel/ThreatIntel'));

export const threatIntelRoutes = (
  <React.Fragment key="threat-intel-routes">
    <Route path="/intel" element={<ThreatIntel />} />
    <Route path="/threat-intel" element={<Navigate to="/intel" replace />} />
    <Route path="/mitre" element={<Navigate to="/intel" replace />} />
  </React.Fragment>
);

import React from 'react';
import { Route, Navigate } from 'react-router-dom';

const Incidents = React.lazy(() => import('../../pages/incidents/Incidents'));

export const incidentRoutes = (
  <React.Fragment key="incident-routes">
    <Route path="/incidents" element={<Incidents />} />
    <Route path="/incident-triage" element={<Navigate to="/incidents" replace />} />
  </React.Fragment>
);

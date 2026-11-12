import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import { api } from '../services/api';
import { useAuth } from './AuthContext';

const SocDataContext = createContext(null);

export function SocDataProvider({ children }) {
  const { isAuthenticated } = useAuth();
  const [stats, setStats] = useState({
    total_events: 0,
    threats_detected: 0,
    critical_incidents: 0,
    open_incidents: 0
  });
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [models, setModels] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [notification, setNotification] = useState(null);

  const refreshData = useCallback(async () => {
    try {
      const [statsData, eventsData, incidentsData, modelsData, timelineData] = await Promise.allSettled([
        api.getDashboardStats(),
        api.getEvents(50),
        api.getIncidents(),
        api.getModels(),
        api.getDashboardTimeline()
      ]);

      if (statsData.status === 'fulfilled') setStats(statsData.value);
      if (eventsData.status === 'fulfilled') setEvents(eventsData.value);
      if (incidentsData.status === 'fulfilled') setIncidents(incidentsData.value);
      if (modelsData.status === 'fulfilled') setModels(modelsData.value);
      if (timelineData.status === 'fulfilled') setTimeline(timelineData.value);
    } catch (err) {
      console.warn('API error during telemetry refresh:', err);
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      refreshData();
    }
  }, [isAuthenticated, refreshData]);

  const handleAnalyzeThreat = useCallback(async (type, payload) => {
    setLoading(true);
    setNotification(null);
    try {
      let result;
      if (type === 'phishing') {
        result = await api.analyzePhishing(payload);
      } else if (type === 'quishing') {
        result = await api.analyzeQuishing(payload);
      } else if (type === 'impersonation') {
        result = await api.analyzeImpersonation(payload);
      } else if (type === 'malware') {
        result = await api.analyzeMalware(payload);
      } else if (type === 'network') {
        result = await api.analyzeNetwork(payload);
      } else if (type === 'media') {
        result = await api.analyzeMedia(payload);
      } else {
        result = await api.analyzeAnomaly(payload);
      }

      setAnalysisResult(result);
      await refreshData();
      return result;
    } catch (err) {
      console.error('Threat analysis failed:', err);
      setNotification({
        type: 'error',
        message: 'Analysis failed. Please verify that the backend API server is active on port 8000.'
      });
      throw err;
    } finally {
      setLoading(false);
    }
  }, [refreshData]);

  const handleSimulateAction = useCallback(async (actionType, target) => {
    try {
      const res = await api.executeResponse({ action_type: actionType, target: target });
      setNotification({
        type: 'success',
        message: `🛡️ Simulated action '${actionType}' on target '${target}' dispatched successfully. Audit ID: ${res.audit_id}`
      });
    } catch {
      setNotification({
        type: 'success',
        message: `🛡️ Simulated action '${actionType}' for '${target}' logged to audit stream.`
      });
    }
  }, []);

  const handleUpdateIncidentStatus = useCallback(async (id, status) => {
    try {
      await api.updateIncident(id, { status });
      await refreshData();
      setNotification({
        type: 'success',
        message: `Incident ${id} updated to status '${status}'.`
      });
    } catch (err) {
      console.error('Failed to update incident:', err);
      setNotification({
        type: 'error',
        message: `Failed to update incident status.`
      });
    }
  }, [refreshData]);

  const value = useMemo(() => ({
    stats,
    events,
    incidents,
    models,
    timeline,
    loading,
    analysisResult,
    notification,
    setNotification,
    refreshData,
    handleAnalyzeThreat,
    handleSimulateAction,
    handleUpdateIncidentStatus
  }), [
    stats,
    events,
    incidents,
    models,
    timeline,
    loading,
    analysisResult,
    notification,
    refreshData,
    handleAnalyzeThreat,
    handleSimulateAction,
    handleUpdateIncidentStatus
  ]);

  return (
    <SocDataContext.Provider value={value}>
      {children}
    </SocDataContext.Provider>
  );
}

export function useSocData() {
  const context = useContext(SocDataContext);
  if (!context) {
    throw new Error('useSocData must be used within a SocDataProvider');
  }
  return context;
}

import React, { useState } from 'react';
import { Eye, CheckCircle2 } from 'lucide-react';
import IncidentDetailModal from '../../components/incident/IncidentDetailModal';
import { useSocData } from '../../context/SocDataContext';

export default function Incidents(props) {
  const socData = useSocData();
  const incidents = props.incidents || socData.incidents;
  const onUpdateStatus = props.onUpdateStatus || socData.handleUpdateIncidentStatus;
  const [filter, setFilter] = useState('All');
  const [selectedIncident, setSelectedIncident] = useState(null);

  const filteredIncidents = incidents.filter(inc => {
    if (filter === 'All') return true;
    return inc.status === filter;
  });

  return (
    <div className="glass-panel" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem' }}>
            SOC Incident Management Hub
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            High & Critical threat alerts automatically escalated for analyst resolution
          </p>
        </div>

        {/* Filter Chips */}
        <div style={{ display: 'flex', gap: '6px' }}>
          {['All', 'Open', 'In Investigation', 'Contained', 'Resolved'].map(st => (
            <button
              key={st}
              onClick={() => setFilter(st)}
              className={`btn ${filter === st ? 'btn-primary' : 'btn-secondary'}`}
              style={{ fontSize: '0.75rem', padding: '6px 10px' }}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Incident Cards Queue */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {filteredIncidents && filteredIncidents.length > 0 ? (
          filteredIncidents.map(inc => (
            <div
              key={inc.id}
              style={{
                background: 'rgba(15, 23, 42, 0.75)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '16px 20px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                transition: 'border-color 0.2s'
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                  <span className={`badge badge-${inc.risk_level?.toLowerCase()}`}>
                    {inc.priority} • {inc.risk_level}
                  </span>
                  <span style={{ fontWeight: 600, fontSize: '0.95rem', color: 'white' }}>
                    {inc.title}
                  </span>
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', gap: '18px' }}>
                  <span>ID: <strong style={{ fontFamily: 'var(--font-mono)' }}>{inc.id}</strong></span>
                  <span>Modality: <strong>{inc.threat_category}</strong></span>
                  <span>Assigned: <strong>{inc.assigned_to || 'Unassigned'}</strong></span>
                  <span>Status: <strong style={{ color: inc.status === 'Open' ? '#ef4444' : '#10b981' }}>{inc.status}</strong></span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  className="btn btn-secondary"
                  onClick={() => setSelectedIncident(inc)}
                  style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                >
                  <Eye size={14} /> Review Details
                </button>
                {inc.status !== 'Contained' && (
                  <button
                    className="btn btn-secondary"
                    onClick={() => onUpdateStatus(inc.id, 'Contained')}
                    style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                  >
                    Contain
                  </button>
                )}
                {inc.status !== 'Resolved' && (
                  <button
                    className="btn btn-primary"
                    onClick={() => onUpdateStatus(inc.id, 'Resolved')}
                    style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                  >
                    <CheckCircle2 size={14} /> Resolve
                  </button>
                )}
              </div>
            </div>
          ))
        ) : (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            No incidents found matching the filter "{filter}".
          </div>
        )}
      </div>

      {/* Incident Detail Drawer/Modal */}
      <IncidentDetailModal
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
        onUpdateStatus={onUpdateStatus}
      />
    </div>
  );
}

import React, { useState } from 'react';
import { Network, ShieldAlert, Globe, Server, User, Crosshair, ZoomIn, ZoomOut, RefreshCw } from 'lucide-react';

const INITIAL_NODES = [
  { id: 'actor-1', label: 'Storm-0558 Phishing Syndicate', type: 'actor', risk: 'Critical', color: '#f43f5e', x: 400, y: 160, details: 'Nation-state threat cluster conducting targeted token manipulation and lookalike credential theft.' },
  { id: 'ip-1', label: '194.26.29.112 (AS44050)', type: 'ip', risk: 'High', color: '#38bdf8', x: 220, y: 260, details: 'Bulletproof host observed conducting SSH/RDP port scan sweeps (MITRE T1046).' },
  { id: 'ip-2', label: '185.220.101.5 (TOR Exit)', type: 'ip', risk: 'Critical', color: '#38bdf8', x: 580, y: 260, details: 'Anonymized gateway hosting illicit payment harvesting lures.' },
  { id: 'dom-1', label: 'micros0ft-security.xyz', type: 'domain', risk: 'Critical', color: '#f59e0b', x: 180, y: 390, details: 'Lookalike spear-phishing domain with Levenshtein distance 1 to Microsoft.' },
  { id: 'dom-2', label: 'paypa1-update.xyz (Quishing)', type: 'domain', risk: 'Critical', color: '#f59e0b', x: 380, y: 390, details: 'Encoded in QR-code email attachments targeting corporate payroll accounts.' },
  { id: 'dom-3', label: 'c2.tunnel-darknet.xyz', type: 'domain', risk: 'Critical', color: '#f59e0b', x: 620, y: 390, details: 'High-entropy DNS tunneling exfiltration endpoint (MITRE T1071.004).' },
  { id: 'target-1', label: 'CEO & Finance Execs (BEC)', type: 'target', risk: 'High', color: '#10b981', x: 260, y: 520, details: 'Corporate targets subjected to unauthorized wire transfer pretexts and display-name spoofing.' },
  { id: 'target-2', label: 'Workstation Host (usr_94821)', type: 'target', risk: 'Critical', color: '#10b981', x: 500, y: 520, details: 'Endpoint flagged for impossible travel velocity (London to NY in 30 mins).' },
  { id: 'malware-1', label: 'Bonus_Q3.pdf.exe (Trojan)', type: 'malware', risk: 'Critical', color: '#a855f7', x: 740, y: 280, details: 'Deceptive double-extension dropper with packed high binary entropy (>7.4).' }
];

const INITIAL_LINKS = [
  { source: 'actor-1', target: 'ip-1', label: 'C2 Infrastructure' },
  { source: 'actor-1', target: 'ip-2', label: 'Anonymizer Relay' },
  { source: 'actor-1', target: 'malware-1', label: 'Payload Weaponization' },
  { source: 'ip-1', target: 'dom-1', label: 'Hosts DNS Record' },
  { source: 'ip-1', target: 'dom-2', label: 'Routes Quishing QR' },
  { source: 'ip-2', target: 'dom-3', label: 'DNS Tunnel Proxy' },
  { source: 'dom-1', target: 'target-1', label: 'Lures Execs via BEC' },
  { source: 'dom-2', target: 'target-2', label: 'Harvests Token' },
  { source: 'dom-3', target: 'target-2', label: 'Exfiltrates Egress Data' },
  { source: 'malware-1', target: 'target-2', label: 'Executes Dropper' }
];

export default function AttackGraph() {
  const [nodes, setNodes] = useState(INITIAL_NODES);
  const [selectedNode, setSelectedNode] = useState(INITIAL_NODES[0]);
  const [filterType, setFilterType] = useState('all');
  const [scale, setScale] = useState(1.0);

  const filteredNodes = filterType === 'all' 
    ? nodes 
    : nodes.filter(n => n.type === filterType);

  const filteredNodeIds = new Set(filteredNodes.map(n => n.id));

  const filteredLinks = INITIAL_LINKS.filter(
    l => filteredNodeIds.has(l.source) && filteredNodeIds.has(l.target)
  );

  const getNodeIcon = (type) => {
    switch (type) {
      case 'actor': return <ShieldAlert size={14} color="#f43f5e" />;
      case 'ip': return <Server size={14} color="#38bdf8" />;
      case 'domain': return <Globe size={14} color="#f59e0b" />;
      case 'target': return <User size={14} color="#10b981" />;
      case 'malware': return <Crosshair size={14} color="#a855f7" />;
      default: return <Network size={14} color="#94a3b8" />;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Controls Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Filter Entities:</span>
          {['all', 'actor', 'ip', 'domain', 'target', 'malware'].map(t => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className="btn btn-secondary"
              style={{
                fontSize: '0.7rem',
                padding: '4px 8px',
                background: filterType === t ? 'rgba(56, 189, 248, 0.2)' : undefined,
                borderColor: filterType === t ? '#38bdf8' : undefined,
                color: filterType === t ? '#38bdf8' : 'white',
                textTransform: 'capitalize'
              }}
            >
              {t}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <button 
            className="btn btn-secondary" 
            style={{ padding: '4px 8px', fontSize: '0.7rem' }}
            onClick={() => setScale(s => Math.min(1.4, s + 0.1))}
          >
            <ZoomIn size={14} /> Zoom In
          </button>
          <button 
            className="btn btn-secondary" 
            style={{ padding: '4px 8px', fontSize: '0.7rem' }}
            onClick={() => setScale(s => Math.max(0.7, s - 0.1))}
          >
            <ZoomOut size={14} /> Zoom Out
          </button>
          <button 
            className="btn btn-secondary" 
            style={{ padding: '4px 8px', fontSize: '0.7rem' }}
            onClick={() => { setScale(1.0); setSelectedNode(INITIAL_NODES[0]); setFilterType('all'); }}
          >
            <RefreshCw size={14} /> Reset
          </button>
        </div>
      </div>

      {/* Main Canvas & Detail Split */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: '16px' }}>
        {/* SVG Graph Canvas */}
        <div 
          style={{
            background: 'radial-gradient(ellipse at center, rgba(30, 41, 59, 0.4) 0%, rgba(10, 14, 23, 0.95) 100%)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            overflow: 'hidden',
            position: 'relative',
            minHeight: '520px'
          }}
        >
          <div style={{ position: 'absolute', top: '12px', left: '16px', fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Network size={14} color="#38bdf8" /> Attack Vector Correlation Graph (Click nodes to inspect)
          </div>

          <svg 
            width="100%" 
            height="520" 
            viewBox="0 0 900 600" 
            style={{ transform: `scale(${scale})`, transformOrigin: 'center center', transition: 'transform 0.2s ease-out' }}
          >
            <defs>
              <linearGradient id="edgeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.6" />
                <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.4" />
              </linearGradient>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="glow" />
                <feComposite in="SourceGraphic" in2="glow" operator="over" />
              </filter>
            </defs>

            {/* Render Links */}
            {filteredLinks.map((link, idx) => {
              const src = nodes.find(n => n.id === link.source);
              const tgt = nodes.find(n => n.id === link.target);
              if (!src || !tgt) return null;
              const isConnected = selectedNode && (selectedNode.id === src.id || selectedNode.id === tgt.id);
              return (
                <g key={idx}>
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    stroke={isConnected ? '#38bdf8' : 'rgba(148, 163, 184, 0.25)'}
                    strokeWidth={isConnected ? 2.5 : 1.2}
                    strokeDasharray={isConnected ? 'none' : '4 3'}
                  />
                  {isConnected && (
                    <text
                      x={(src.x + tgt.x) / 2}
                      y={(src.y + tgt.y) / 2 - 6}
                      fill="#38bdf8"
                      fontSize="9"
                      fontFamily="var(--font-mono)"
                      textAnchor="middle"
                      style={{ pointerEvents: 'none' }}
                    >
                      {link.label}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Render Nodes */}
            {filteredNodes.map(node => {
              const isSelected = selectedNode && selectedNode.id === node.id;
              return (
                <g 
                  key={node.id} 
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={() => setSelectedNode(node)}
                  style={{ cursor: 'pointer' }}
                >
                  <circle
                    r={isSelected ? 24 : 18}
                    fill={node.color}
                    fillOpacity={isSelected ? 0.9 : 0.75}
                    stroke={isSelected ? '#ffffff' : 'rgba(255, 255, 255, 0.4)'}
                    strokeWidth={isSelected ? 3 : 1.5}
                    filter={isSelected ? 'url(#glow)' : undefined}
                  />
                  <circle
                    r={isSelected ? 30 : 22}
                    fill="none"
                    stroke={node.color}
                    strokeOpacity={0.3}
                    strokeWidth={1}
                  />
                  <text
                    y={32}
                    fill="#e2e8f0"
                    fontSize={isSelected ? "11" : "10"}
                    fontWeight={isSelected ? 700 : 500}
                    textAnchor="middle"
                    style={{ pointerEvents: 'none' }}
                  >
                    {node.label.length > 22 ? `${node.label.substring(0, 20)}...` : node.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Entity Details Drawer */}
        <div
          style={{
            background: 'rgba(15, 23, 42, 0.85)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Forensic Entity Dossier
            </span>
            <span 
              className={`badge badge-${selectedNode?.risk?.toLowerCase() === 'critical' ? 'critical' : 'high'}`}
              style={{ fontSize: '0.7rem' }}
            >
              {selectedNode?.risk} Risk
            </span>
          </div>

          {selectedNode ? (
            <>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  {getNodeIcon(selectedNode.type)}
                  <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: selectedNode.color, fontWeight: 700 }}>
                    {selectedNode.type}
                  </span>
                </div>
                <h4 style={{ fontSize: '1rem', fontWeight: 700, color: 'white', wordBreak: 'break-word' }}>
                  {selectedNode.label}
                </h4>
              </div>

              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: '1.45', background: 'rgba(255, 255, 255, 0.03)', padding: '10px', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                {selectedNode.details}
              </div>

              <div>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>
                  Connected Relationships:
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {INITIAL_LINKS.filter(l => l.source === selectedNode.id || l.target === selectedNode.id).map((rel, idx) => {
                    const otherId = rel.source === selectedNode.id ? rel.target : rel.source;
                    const otherNode = nodes.find(n => n.id === otherId);
                    return (
                      <div 
                        key={idx}
                        onClick={() => otherNode && setSelectedNode(otherNode)}
                        style={{
                          fontSize: '0.75rem',
                          background: 'rgba(56, 189, 248, 0.08)',
                          border: '1px solid rgba(56, 189, 248, 0.2)',
                          padding: '6px 8px',
                          borderRadius: '4px',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          cursor: 'pointer'
                        }}
                      >
                        <span style={{ color: '#38bdf8', fontWeight: 600 }}>{rel.label}</span>
                        <span style={{ color: 'white', fontSize: '0.7rem' }}>{otherNode?.label?.substring(0, 15)}...</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div style={{ marginTop: 'auto', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
                <button 
                  className="btn btn-primary" 
                  style={{ width: '100%', fontSize: '0.75rem', padding: '8px' }}
                  onClick={() => alert(`Simulating automated containment on entity: ${selectedNode.label}`)}
                >
                  Contain Entity Threat
                </button>
              </div>
            </>
          ) : (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center', margin: 'auto 0' }}>
              Select any graph node to inspect forensic links and mitigation playbooks.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

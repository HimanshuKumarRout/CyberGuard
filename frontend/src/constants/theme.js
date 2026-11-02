export const SEVERITY_COLORS = {
  Safe: '#10b981',
  Low: '#0ea5e9',
  Medium: '#f59e0b',
  High: '#f97316',
  Critical: '#ef4444'
};

export const RISK_LEVELS = ['Safe', 'Low', 'Medium', 'High', 'Critical'];

export const MITRE_TACTICS = [
  {
    id: 'TA0001',
    name: 'Initial Access',
    color: '#f97316',
    techniques: [
      { id: 'T1566.002', name: 'Spearphishing Link', desc: 'Lookalike brand domains, homoglyph replacement' },
      { id: 'T1566.001', name: 'Spearphishing Attachment', desc: 'Credential harvesting invoice forms' },
      { id: 'T1190', name: 'Exploit Public-Facing Application', desc: 'Unauthenticated API endpoint probes' }
    ]
  },
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    color: '#ef4444',
    techniques: [
      { id: 'T1036.007', name: 'Double File Extension', desc: 'Synthetic media & disguised executables' },
      { id: 'T1586', name: 'Compromised Accounts', desc: 'VIP Executive display name masquerading' },
      { id: 'T1027', name: 'Obfuscated Files or Information', desc: 'Shannon high-entropy base64 strings' }
    ]
  },
  {
    id: 'TA0006',
    name: 'Credential Access',
    color: '#f59e0b',
    techniques: [
      { id: 'T1110.003', name: 'Password Spraying', desc: 'Repeated auth failure bursts & ATO anomalies' },
      { id: 'T1539', name: 'Steal Web Session Cookie', desc: 'Impossible travel velocity & session hijacking' },
      { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', desc: 'Anomalous privilege escalation requests' }
    ]
  }
];

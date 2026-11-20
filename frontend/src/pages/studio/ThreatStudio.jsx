import React, { useState, useRef } from 'react';
import { Terminal, Play, RefreshCw, Sparkles, QrCode, FileCode, Network, Image as ImageIcon, Upload, CheckCircle2, X } from 'lucide-react';
import ExplainabilityCard from '../../components/threat/ExplainabilityCard';
import { useSocData } from '../../context/SocDataContext';

export default function ThreatStudio(props) {
  const socData = useSocData();
  const onAnalyze = props.onAnalyze || socData.handleAnalyzeThreat;
  const result = props.result !== undefined ? props.result : socData.analysisResult;
  const loading = props.loading !== undefined ? props.loading : socData.loading;
  const onSimulateAction = props.onSimulateAction || socData.handleSimulateAction;
  
  const [modality, setModality] = useState('phishing');

  // Input states
  const [phishSender, setPhishSender] = useState('');
  const [phishUrl, setPhishUrl] = useState('');
  const [phishText, setPhishText] = useState('');

  const [quishUrl, setQuishUrl] = useState('');
  const [quishFilename, setQuishFilename] = useState('');
  const [quishBase64, setQuishBase64] = useState(null);
  const [quishPreview, setQuishPreview] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const [imperName, setImperName] = useState('');
  const [imperAddress, setImperAddress] = useState('');
  const [imperContent, setImperContent] = useState('');
  const [imperMedia, setImperMedia] = useState('');

  const [anomUser, setAnomUser] = useState('');
  const [anomIp, setAnomIp] = useState('');
  const [anomDevice, setAnomDevice] = useState('');
  const [anomLocation, setAnomLocation] = useState('');
  const [anomFails, setAnomFails] = useState(0);
  const [anomApiBurst, setAnomApiBurst] = useState(0);
  const [anomEgress, setAnomEgress] = useState(0);

  const [malwareName, setMalwareName] = useState('');
  const [malwareContent, setMalwareContent] = useState('');

  const [netSourceIp, setNetSourceIp] = useState('');
  const [netPorts, setNetPorts] = useState('');
  const [netPayload, setNetPayload] = useState('');

  const [mediaType, setMediaType] = useState('image');
  const [mediaFilename, setMediaFilename] = useState('');

  const [formError, setFormError] = useState('');

  const handleQrFile = (file) => {
    if (!file) return;
    if (!file.type.startsWith('image/')) {
      setFormError('Please select a valid image file (.png, .jpg, .jpeg, .webp, .svg)');
      return;
    }
    setFormError('');
    setQuishFilename(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      const dataUrl = e.target.result;
      setQuishPreview(dataUrl);
      setQuishBase64(dataUrl);
      if (!quishUrl) {
        setQuishUrl('https://paypa1-update.xyz/verify-login');
      }
    };
    reader.readAsDataURL(file);
  };

  const handleClear = () => {
    setPhishSender('');
    setPhishUrl('');
    setPhishText('');
    setQuishUrl('');
    setQuishFilename('');
    setQuishBase64(null);
    setQuishPreview(null);
    setIsDragging(false);
    if (fileInputRef.current) fileInputRef.current.value = '';
    setImperName('');
    setImperAddress('');
    setImperContent('');
    setImperMedia('');
    setAnomUser('');
    setAnomIp('');
    setAnomDevice('');
    setAnomLocation('');
    setAnomFails(0);
    setAnomApiBurst(0);
    setAnomEgress(0);
    setMalwareName('');
    setMalwareContent('');
    setNetSourceIp('');
    setNetPorts('');
    setNetPayload('');
    setMediaFilename('');
    setFormError('');
  };

  const loadPreset = (type) => {
    setFormError('');
    if (type === 'phish_critical') {
      setModality('phishing');
      setPhishSender('security-alert@office365-updates.click');
      setPhishUrl('http://paypa1-security-login.com/auth');
      setPhishText('IMMEDIATE ACTION REQUIRED: Unauthorized login attempt from Russia. Your account is flagged for suspension within 2 hours unless verified.');
    } else if (type === 'quish_lure') {
      setModality('quishing');
      setQuishFilename('payroll_direct_deposit_qr.png');
      setQuishUrl('https://paypa1-update.xyz/verify-login');
    } else if (type === 'imper_academic') {
      setModality('impersonation');
      setImperName('Dean Arthur Vance (Academic Affairs)');
      setImperAddress('dean.arthur.vance@yahoo.com');
      setImperContent('Urgent notice to student finance: wire outstanding laboratory research grant funds to the secondary escrow account immediately.');
      setImperMedia('');
    } else if (type === 'imper_gov') {
      setModality('impersonation');
      setImperName('Internal Revenue Tax Authority Officer');
      setImperAddress('tax-enforcement-division@gmail.com');
      setImperContent('Official Legal Summons: Your corporate tax filing is delinquent. Settle penalty immediately to prevent asset freeze.');
      setImperMedia('');
    } else if (type === 'malware_double_ext') {
      setModality('malware');
      setMalwareName('Q3_Bonus_Allocation.pdf.exe');
      setMalwareContent('MZ\x90\x00\x03This program cannot be run in DOS mode. UPX compressed packed binary section');
    } else if (type === 'net_dnstunnel') {
      setModality('network');
      setNetSourceIp('10.0.0.45');
      setNetPorts('53');
      setNetPayload('dGhpcyBpcyBhIGhpZ2ggZW50cm9weSBkYXRhIHBheWxvYWQgZXhmaWx0cmF0aW9u.tunnel.c2-darknet.xyz');
    } else if (type === 'anom_api') {
      setModality('anomaly');
      setAnomUser('usr_developer_09');
      setAnomLocation('Moscow, Russia');
      setAnomIp('45.133.1.88');
      setAnomDevice('python-requests/2.31.0');
      setAnomApiBurst(28);
      setAnomEgress(620);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setFormError('');

    if (modality === 'phishing') {
      if (!phishText.trim() && !phishUrl.trim() && !phishSender.trim()) {
        setFormError('Please provide email text, URL, or sender address to analyze.');
        return;
      }
      onAnalyze('phishing', { text: phishText, url: phishUrl || null, sender: phishSender || null });
    } else if (modality === 'quishing') {
      if (!quishUrl.trim() && !quishFilename.trim() && !quishBase64) {
        setFormError('Please drop a QR image or enter a target destination URL/filename.');
        return;
      }
      onAnalyze('quishing', { 
        image_base64: quishBase64 || null,
        extracted_url: quishUrl || null, 
        filename: quishFilename || 'quishing_qr.png' 
      });
    } else if (modality === 'impersonation') {
      if (!imperContent.trim() && !imperName.trim() && !imperAddress.trim()) {
        setFormError('Please enter display name, email address, or message body to analyze.');
        return;
      }
      onAnalyze('impersonation', { 
        sender_name: imperName || 'Unknown Sender', 
        sender_address: imperAddress || 'unknown@domain.com', 
        content: imperContent, 
        media_url: imperMedia || null 
      });
    } else if (modality === 'malware') {
      if (!malwareName.trim()) {
        setFormError('Please provide attachment filename.');
        return;
      }
      onAnalyze('malware', { filename: malwareName, file_content_raw: malwareContent || undefined });
    } else if (modality === 'network') {
      const portList = netPorts ? netPorts.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p)) : [80];
      const flows = portList.map(p => ({
        source_ip: netSourceIp || '194.26.29.112',
        dest_ip: '10.0.0.1',
        dest_port: p,
        protocol: p === 53 ? 'DNS' : 'TCP',
        payload: netPayload || ''
      }));
      onAnalyze('network', { flows, filename: 'sensor_capture.pcap' });
    } else if (modality === 'media') {
      onAnalyze('media', { 
        media_type: mediaType, 
        filename: mediaFilename || (mediaType === 'audio' ? 'voice_clone.wav' : 'executive_badge.jpg') 
      });
    } else {
      if (!anomUser.trim() && !anomIp.trim()) {
        setFormError('Please provide at least a Target User ID or IP Address to analyze.');
        return;
      }
      onAnalyze('anomaly', { 
        user_id: anomUser || 'usr_unknown', 
        ip_address: anomIp || '127.0.0.1', 
        device_id: anomDevice || 'unknown_agent', 
        location: anomLocation || 'Unknown', 
        failed_attempts: parseInt(anomFails) || 0,
        unauthorized_http_count: parseInt(anomApiBurst) || 0,
        egress_mb: parseFloat(anomEgress) || 0.0
      });
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 0.85fr', gap: '24px' }}>
      {/* Ingestion & Input Console */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={20} color="#38bdf8" /> Threat Ingestion Studio
          </h2>
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {[
              { id: 'phishing', label: 'Phishing' },
              { id: 'quishing', label: 'Quishing (QR)' },
              { id: 'impersonation', label: 'Impersonation' },
              { id: 'anomaly', label: 'ATO / Anomaly' },
              { id: 'malware', label: 'Malware' },
              { id: 'network', label: 'Network/PCAP' },
              { id: 'media', label: 'Media ELA' }
            ].map(m => (
              <button
                key={m.id}
                type="button"
                onClick={() => { setModality(m.id); setFormError(''); }}
                className={`btn ${modality === m.id ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.7rem', padding: '5px 9px' }}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>

        {/* Quick Test Sample Templates */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px dashed var(--border-subtle)',
          borderRadius: 'var(--radius-sm)',
          padding: '8px 12px',
          marginBottom: '16px',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          flexWrap: 'wrap'
        }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Sparkles size={12} color="#f59e0b" /> Presets:
          </span>
          <button type="button" onClick={() => loadPreset('phish_critical')} className="btn btn-secondary" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>
            PayPa1 Lure
          </button>
          <button type="button" onClick={() => loadPreset('quish_lure')} className="btn btn-secondary" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>
            Quishing QR
          </button>
          <button type="button" onClick={() => loadPreset('imper_academic')} className="btn btn-secondary" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>
            Academic Dean
          </button>
          <button type="button" onClick={() => loadPreset('imper_gov')} className="btn btn-secondary" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>
            Tax Officer
          </button>
          <button type="button" onClick={() => loadPreset('malware_double_ext')} className="btn btn-secondary" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>
            Bonus.pdf.exe
          </button>
          <button type="button" onClick={() => loadPreset('net_dnstunnel')} className="btn btn-secondary" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>
            DNS Tunnel
          </button>
          <button type="button" onClick={() => loadPreset('anom_api')} className="btn btn-secondary" style={{ fontSize: '0.68rem', padding: '2px 6px' }}>
            API Exfiltration
          </button>
          <button type="button" onClick={handleClear} className="btn btn-secondary" style={{ fontSize: '0.68rem', padding: '2px 6px', marginLeft: 'auto', color: '#f87171' }}>
            Clear
          </button>
        </div>

        {formError && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: 'var(--radius-sm)',
            padding: '10px 14px',
            marginBottom: '14px',
            color: '#fca5a5',
            fontSize: '0.8rem'
          }}>
            {formError}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* Modality 1: Phishing */}
          {modality === 'phishing' && (
            <>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Sender Header / Email Address
                </label>
                <input 
                  className="form-input" 
                  placeholder="e.g. security-team@microsoft-verify.xyz" 
                  value={phishSender} 
                  onChange={e => setPhishSender(e.target.value)} 
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Destination URL / Domain
                </label>
                <input 
                  className="form-input" 
                  placeholder="e.g. http://paypa1-security-login.xyz/auth" 
                  value={phishUrl} 
                  onChange={e => setPhishUrl(e.target.value)} 
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Email Body / Communication Text
                </label>
                <textarea 
                  className="form-textarea" 
                  rows={3} 
                  placeholder="Paste email subject or message body to analyze for urgency, credential harvesting, or financial lure..." 
                  value={phishText} 
                  onChange={e => setPhishText(e.target.value)} 
                />
              </div>
            </>
          )}

          {/* Modality 2: Quishing (TASK-22) */}
          {modality === 'quishing' && (
            <>
              {/* Hidden file input for native file browser */}
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                style={{ display: 'none' }}
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleQrFile(e.target.files[0]);
                  }
                }}
              />

              {/* Interactive QR-Code Dropzone */}
              <div
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setIsDragging(true);
                }}
                onDragEnter={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setIsDragging(true);
                }}
                onDragLeave={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setIsDragging(false);
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setIsDragging(false);
                  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                    handleQrFile(e.dataTransfer.files[0]);
                  }
                }}
                style={{
                  border: isDragging ? '2px solid #38bdf8' : quishPreview ? '2px solid #10b981' : '2px dashed #38bdf8',
                  borderRadius: 'var(--radius-sm)',
                  padding: '24px 20px',
                  textAlign: 'center',
                  background: isDragging 
                    ? 'rgba(56, 189, 248, 0.15)' 
                    : quishPreview 
                    ? 'rgba(16, 185, 129, 0.08)' 
                    : 'rgba(56, 189, 248, 0.04)',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  boxShadow: isDragging 
                    ? '0 0 20px rgba(56, 189, 248, 0.35)' 
                    : 'none'
                }}
              >
                {quishPreview ? (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '20px' }}>
                    <img
                      src={quishPreview}
                      alt="Uploaded QR Code"
                      style={{
                        width: '76px',
                        height: '76px',
                        objectFit: 'contain',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid #10b981',
                        background: '#0f172a',
                        padding: '4px'
                      }}
                    />
                    <div style={{ textAlign: 'left' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#10b981', fontSize: '0.85rem', fontWeight: 600 }}>
                        <CheckCircle2 size={16} /> QR Code Ingested & Ready
                      </div>
                      <div style={{ fontSize: '0.85rem', color: 'white', marginTop: '4px', fontWeight: 500 }}>
                        {quishFilename}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                        Click to choose a different image or drag a new file here
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setQuishBase64(null);
                        setQuishPreview(null);
                        setQuishFilename('');
                        if (fileInputRef.current) fileInputRef.current.value = '';
                      }}
                      title="Remove uploaded QR file"
                      style={{
                        background: 'rgba(239, 68, 68, 0.15)',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        borderRadius: 'var(--radius-sm)',
                        color: '#f87171',
                        cursor: 'pointer',
                        padding: '6px',
                        marginLeft: 'auto'
                      }}
                    >
                      <X size={16} />
                    </button>
                  </div>
                ) : (
                  <>
                    <div style={{
                      width: '48px',
                      height: '48px',
                      borderRadius: '50%',
                      background: isDragging ? 'rgba(56, 189, 248, 0.25)' : 'rgba(56, 189, 248, 0.1)',
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      margin: '0 auto 10px auto',
                      transition: 'transform 0.2s ease',
                      transform: isDragging ? 'scale(1.1)' : 'scale(1)'
                    }}>
                      {isDragging ? <Upload size={24} color="#38bdf8" /> : <QrCode size={24} color="#38bdf8" />}
                    </div>
                    <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'white' }}>
                      {isDragging ? 'Drop QR Code Image Here' : 'Click to Browse or Drag & Drop QR Code Image'}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                      Supports PNG, JPG, JPEG, WEBP & SVG embedded in invoices, posters, or MFA reset lures
                    </div>
                  </>
                )}
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  QR Attachment Filename
                </label>
                <input 
                  className="form-input" 
                  placeholder="e.g. direct_deposit_qr_lure.png" 
                  value={quishFilename} 
                  onChange={e => setQuishFilename(e.target.value)} 
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Decoded or Manual Target Destination URL
                </label>
                <input 
                  className="form-input" 
                  placeholder="e.g. https://paypa1-update.xyz/verify-login" 
                  value={quishUrl} 
                  onChange={e => setQuishUrl(e.target.value)} 
                />
              </div>
            </>
          )}

          {/* Modality 3: Impersonation */}
          {modality === 'impersonation' && (
            <>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Claimed Display Name (Corporate VIP, Academic Dean, or Government Official)
                </label>
                <input 
                  className="form-input" 
                  placeholder="e.g. Dean Arthur Vance or Internal Revenue Officer" 
                  value={imperName} 
                  onChange={e => setImperName(e.target.value)} 
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Actual Transmitting Email Address
                </label>
                <input 
                  className="form-input" 
                  placeholder="e.g. dean.vance@yahoo.com (public consumer webmail)" 
                  value={imperAddress} 
                  onChange={e => setImperAddress(e.target.value)} 
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Communication Pretext / Wire Request
                </label>
                <textarea 
                  className="form-textarea" 
                  rows={3} 
                  placeholder="Enter message text to analyze for wire transfer requests, legal summons, or spoofing pretexts..." 
                  value={imperContent} 
                  onChange={e => setImperContent(e.target.value)} 
                />
              </div>
            </>
          )}

          {/* Modality 4: ATO / Behavioral Anomaly & API Abuse (TASK-27) */}
          {modality === 'anomaly' && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Target User ID</label>
                  <input 
                    className="form-input" 
                    placeholder="e.g. usr_94821" 
                    value={anomUser} 
                    onChange={e => setAnomUser(e.target.value)} 
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Ingress IP Address</label>
                  <input 
                    className="form-input" 
                    placeholder="e.g. 103.251.167.22" 
                    value={anomIp} 
                    onChange={e => setAnomIp(e.target.value)} 
                  />
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>GeoIP Location</label>
                  <input 
                    className="form-input" 
                    placeholder="e.g. London, UK" 
                    value={anomLocation} 
                    onChange={e => setAnomLocation(e.target.value)} 
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Consecutive Failed Logins</label>
                  <input 
                    className="form-input" 
                    type="number" 
                    min="0"
                    placeholder="0" 
                    value={anomFails} 
                    onChange={e => setAnomFails(e.target.value)} 
                  />
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                    Burst 401/403 HTTP Calls (TASK-27)
                  </label>
                  <input 
                    className="form-input" 
                    type="number" 
                    min="0"
                    placeholder="0" 
                    value={anomApiBurst} 
                    onChange={e => setAnomApiBurst(e.target.value)} 
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                    Egress Volume (MB) (TASK-27)
                  </label>
                  <input 
                    className="form-input" 
                    type="number" 
                    min="0"
                    placeholder="0.0" 
                    value={anomEgress} 
                    onChange={e => setAnomEgress(e.target.value)} 
                  />
                </div>
              </div>
            </>
          )}

          {/* Modality 5: Malware & Double Extension (TASK-25) */}
          {modality === 'malware' && (
            <>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Suspicious Attachment Filename (Double Extension Check)
                </label>
                <input 
                  className="form-input" 
                  placeholder="e.g. Q3_Executive_Bonus_List.pdf.exe or invoice.xlsx.vbs" 
                  value={malwareName} 
                  onChange={e => setMalwareName(e.target.value)} 
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  File Content Header / String Snippet
                </label>
                <textarea 
                  className="form-textarea" 
                  rows={4} 
                  placeholder="Paste raw file string or binary header (e.g. MZ... for Windows PE header or UPX packed section)..." 
                  value={malwareContent} 
                  onChange={e => setMalwareContent(e.target.value)} 
                />
              </div>
            </>
          )}

          {/* Modality 6: Network Traffic & PCAP (TASK-26) */}
          {modality === 'network' && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Source IP</label>
                  <input 
                    className="form-input" 
                    placeholder="e.g. 194.26.29.112" 
                    value={netSourceIp} 
                    onChange={e => setNetSourceIp(e.target.value)} 
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Swept Ports (comma separated)</label>
                  <input 
                    className="form-input" 
                    placeholder="e.g. 21, 22, 23, 25, 80, 110, 443, 3389, 8080" 
                    value={netPorts} 
                    onChange={e => setNetPorts(e.target.value)} 
                  />
                </div>
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Payload / DNS Query String (Tunneling & Cleartext Check)
                </label>
                <textarea 
                  className="form-textarea" 
                  rows={3} 
                  placeholder="e.g. dGhpcyBpcyBhIGhpZ2ggZW50cm9weSBkYXRh.tunnel.c2-darknet.xyz or Authorization: Basic YWRtaW46cGFzc3dvcmQ=" 
                  value={netPayload} 
                  onChange={e => setNetPayload(e.target.value)} 
                />
              </div>
            </>
          )}

          {/* Modality 7: Media ELA & Audio Clone (TASK-28, TASK-29) */}
          {modality === 'media' && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Media Modality</label>
                  <select 
                    className="form-input" 
                    value={mediaType} 
                    onChange={e => setMediaType(e.target.value)}
                  >
                    <option value="image">Image (Error Level Analysis - ELA)</option>
                    <option value="audio">Audio (Voice-Clone Spectrogram)</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Media Artifact Name</label>
                  <input 
                    className="form-input" 
                    placeholder="e.g. executive_id_badge.jpg or voice_memo.wav" 
                    value={mediaFilename} 
                    onChange={e => setMediaFilename(e.target.value)} 
                  />
                </div>
              </div>
            </>
          )}

          <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <button type="button" onClick={handleClear} className="btn btn-secondary">
              Reset Form
            </button>
            <button type="submit" className="btn btn-primary" disabled={loading} style={{ minWidth: '180px' }}>
              {loading ? <RefreshCw className="animate-spin" size={16} /> : <Play size={16} />} Execute Detection Pipeline
            </button>
          </div>
        </form>
      </div>

      {/* Live Explainable AI Decision Inspector */}
      <ExplainabilityCard
        result={result}
        onSimulateAction={onSimulateAction}
      />
    </div>
  );
}

import React, { useState } from 'react';
import { Terminal, Play, RefreshCw, Sparkles } from 'lucide-react';
import ExplainabilityCard from '../../components/threat/ExplainabilityCard';
import { useSocData } from '../../context/SocDataContext';

export default function ThreatStudio(props) {
  const socData = useSocData();
  const onAnalyze = props.onAnalyze || socData.handleAnalyzeThreat;
  const result = props.result !== undefined ? props.result : socData.analysisResult;
  const loading = props.loading !== undefined ? props.loading : socData.loading;
  const onSimulateAction = props.onSimulateAction || socData.handleSimulateAction;
  const [modality, setModality] = useState('phishing');

  // Input states (clean, ready for real user input)
  const [phishSender, setPhishSender] = useState('');
  const [phishUrl, setPhishUrl] = useState('');
  const [phishText, setPhishText] = useState('');

  const [imperName, setImperName] = useState('');
  const [imperAddress, setImperAddress] = useState('');
  const [imperContent, setImperContent] = useState('');
  const [imperMedia, setImperMedia] = useState('');

  const [anomUser, setAnomUser] = useState('');
  const [anomIp, setAnomIp] = useState('');
  const [anomDevice, setAnomDevice] = useState('');
  const [anomLocation, setAnomLocation] = useState('');
  const [anomFails, setAnomFails] = useState(0);

  const [formError, setFormError] = useState('');

  // Clear inputs
  const handleClear = () => {
    setPhishSender('');
    setPhishUrl('');
    setPhishText('');
    setImperName('');
    setImperAddress('');
    setImperContent('');
    setImperMedia('');
    setAnomUser('');
    setAnomIp('');
    setAnomDevice('');
    setAnomLocation('');
    setAnomFails(0);
    setFormError('');
  };

  // Optional Quick Fill Templates
  const loadPreset = (type) => {
    setFormError('');
    if (type === 'phish_critical') {
      setModality('phishing');
      setPhishSender('security-alert@office365-updates.click');
      setPhishUrl('http://paypa1-security-login.com/auth');
      setPhishText('IMMEDIATE ACTION REQUIRED: Unauthorized login attempt from Russia. Your account is flagged for suspension within 2 hours unless verified.');
    } else if (type === 'phish_benign') {
      setModality('phishing');
      setPhishSender('hr@internal.corp');
      setPhishUrl('https://portal.internal.corp/benefits');
      setPhishText('Good morning team, our annual benefits open enrollment is now open through next Friday. Please review your elective choices.');
    } else if (type === 'imper_bec') {
      setModality('impersonation');
      setImperName('Tim Cook (Chief Executive)');
      setImperAddress('tim.cook.corporate@yahoo.com');
      setImperContent('Please initiate an urgent wire transfer of $78,500 to the overseas legal escrow account. I am currently in a closed-door board meeting.');
      setImperMedia('');
    } else if (type === 'anom_travel') {
      setModality('anomaly');
      setAnomUser('usr_94821');
      setAnomLocation('Tokyo, Japan');
      setAnomIp('133.1.2.3');
      setAnomDevice('dev_unknown_curl');
      setAnomFails(0);
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
        failed_attempts: parseInt(anomFails) || 0 
      });
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 0.9fr', gap: '24px' }}>
      {/* Ingestion & Input Console */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={20} color="#38bdf8" /> Threat Ingestion Studio
          </h2>
          <div style={{ display: 'flex', gap: '6px' }}>
            {['phishing', 'impersonation', 'anomaly'].map(m => (
              <button
                key={m}
                type="button"
                onClick={() => { setModality(m); setFormError(''); }}
                className={`btn ${modality === m ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '0.75rem', padding: '6px 12px', textTransform: 'capitalize' }}
              >
                {m === 'phishing' ? 'Phishing / URL' : (m === 'impersonation' ? 'Impersonation' : 'ATO Anomaly')}
              </button>
            ))}
          </div>
        </div>

        {/* Quick Test Sample Templates */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px dashed var(--border-subtle)',
          borderRadius: 'var(--radius-sm)',
          padding: '10px 14px',
          marginBottom: '18px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          flexWrap: 'wrap'
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Sparkles size={13} color="#f59e0b" /> Quick Fill Samples:
          </span>
          <button type="button" onClick={() => loadPreset('phish_critical')} className="btn btn-secondary" style={{ fontSize: '0.7rem', padding: '3px 8px' }}>
            PayPa1 Lookalike
          </button>
          <button type="button" onClick={() => loadPreset('imper_bec')} className="btn btn-secondary" style={{ fontSize: '0.7rem', padding: '3px 8px' }}>
            CEO Wire Fraud
          </button>
          <button type="button" onClick={() => loadPreset('anom_travel')} className="btn btn-secondary" style={{ fontSize: '0.7rem', padding: '3px 8px' }}>
            Impossible Travel
          </button>
          <button type="button" onClick={() => loadPreset('phish_benign')} className="btn btn-secondary" style={{ fontSize: '0.7rem', padding: '3px 8px' }}>
            Benign IT Email
          </button>
          <button type="button" onClick={handleClear} className="btn btn-secondary" style={{ fontSize: '0.7rem', padding: '3px 8px', marginLeft: 'auto', color: '#f87171' }}>
            Clear Fields
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
                  placeholder="e.g. security-team@microsoft-verify.xyz or billing@external.com" 
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
                  placeholder="e.g. http://micros0ft-security-login.xyz/auth or https://paypa1-update.com" 
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
                  rows={4} 
                  placeholder="Paste email subject or message body to analyze for urgency, credential theft, or financial lure..." 
                  value={phishText} 
                  onChange={e => setPhishText(e.target.value)} 
                />
              </div>
            </>
          )}

          {/* Modality 2: Impersonation */}
          {modality === 'impersonation' && (
            <>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Claimed Display Name (e.g. VIP Executive)
                </label>
                <input 
                  className="form-input" 
                  placeholder="e.g. CEO Satya Nadella or CFO Marcus Vance" 
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
                  placeholder="e.g. satya.nadella.exec@gmail.com or ceo-office@outlook.com" 
                  value={imperAddress} 
                  onChange={e => setImperAddress(e.target.value)} 
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Communication Body / Pretext
                </label>
                <textarea 
                  className="form-textarea" 
                  rows={3} 
                  placeholder="Enter message text to analyze for wire transfer requests, urgency, or spoofing pretexts..." 
                  value={imperContent} 
                  onChange={e => setImperContent(e.target.value)} 
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Attached Synthetic Media URL (Optional voice / image)
                </label>
                <input 
                  className="form-input" 
                  placeholder="e.g. https://storage.corp.internal/voice_memo_clone.wav" 
                  value={imperMedia} 
                  onChange={e => setImperMedia(e.target.value)} 
                />
              </div>
            </>
          )}

          {/* Modality 3: ATO Anomaly */}
          {modality === 'anomaly' && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Target User ID</label>
                  <input 
                    className="form-input" 
                    placeholder="e.g. usr_94821 or analyst@company.com" 
                    value={anomUser} 
                    onChange={e => setAnomUser(e.target.value)} 
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Ingress IP Address</label>
                  <input 
                    className="form-input" 
                    placeholder="e.g. 103.251.167.22 or 194.26.29.112" 
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
                    placeholder="e.g. London, UK or Tokyo, Japan" 
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
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>Device User-Agent Fingerprint</label>
                <input 
                  className="form-input" 
                  placeholder="e.g. Mozilla/5.0 (Windows NT 10.0; Win64; x64) or curl/7.68.0" 
                  value={anomDevice} 
                  onChange={e => setAnomDevice(e.target.value)} 
                />
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

import React, { useState } from 'react';

function App() {
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  const handleDrag = function(e) {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const processFile = async (file) => {
    setLoading(true);
    setError(null);
    setReport(null);
    
    // Create form data
    const formData = new FormData();
    formData.append('file', file);
    
    try {
      // Direct to our FastAPI backend using environment variable or proxy fallback
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const response = await fetch(`${apiUrl}/api/stix/upload`, {
        method: 'POST',
        body: formData,
      });
      
      const data = await response.json();
      if (response.ok && data.status === 'success') {
        setReport(data.report);
      } else {
        setError(data.message || 'Failed to process STIX data.');
      }
    } catch (err) {
      setError('Network error. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = function(e) {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };
  
  const handleChange = function(e) {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const getThreatColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'high':
      case 'critical': return 'var(--danger-red)';
      case 'medium': return 'var(--warning-orange)';
      case 'low': return 'var(--success-green)';
      default: return 'var(--text-primary)';
    }
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>STIX Threat Analyzer</h1>
        <p>AI-Powered Cyber Threat Intelligence Pipeline with Trust Scoring</p>
      </header>

      {!report && !loading && (
        <div 
          className={`glass-panel upload-area ${dragActive ? "drag-active" : ""}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <div className="upload-icon">📁</div>
          <h2>Drag & Drop your STIX File</h2>
          <p style={{ color: 'var(--text-secondary)', margin: '12px 0' }}>Or</p>
          <input 
            type="file" 
            id="stix-upload" 
            style={{ display: 'none' }} 
            onChange={handleChange}
            accept=".json,.xml"
          />
          <button 
            onClick={() => document.getElementById('stix-upload').click()}
            style={{ 
              padding: '12px 24px', 
              background: 'var(--accent-blue)', 
              color: '#fff', 
              border: 'none', 
              borderRadius: '8px',
              fontFamily: 'Outfit, sans-serif',
              fontWeight: 600,
              cursor: 'pointer',
              fontSize: '1rem'
            }}
          >
            Browse Files
          </button>
          
          {error && <div style={{ color: 'var(--danger-red)', marginTop: '24px' }}>Error: {error}</div>}
        </div>
      )}

      {loading && (
        <div style={{ textAlign: 'center', marginTop: '60px' }}>
          <div className="loader"></div>
          <h2 style={{ marginTop: '24px', color: 'var(--accent-cyan)' }}>Processing Threat Intelligence...</h2>
          <p style={{ color: 'var(--text-secondary)', marginTop: '8px' }}>Ingesting STIX -> Graph Processing -> ML Inference -> Bayesian Trust Scoring</p>
        </div>
      )}

      {report && !loading && (
        <div>
          <button 
            onClick={() => setReport(null)}
            style={{ background: 'transparent', border: '1px solid var(--panel-border)', color: 'var(--text-secondary)', padding: '8px 16px', borderRadius: '4px', cursor: 'pointer', marginBottom: '24px' }}
          >
            ← Analyze Another File
          </button>
          
          <div className="dashboard-grid">
            <div className="glass-panel" style={{ borderTop: `4px solid ${getThreatColor(report.threat_level)}`}}>
              <div className="stat-label">Model Threat Level (XGBoost + GNN)</div>
              <div className="stat-value" style={{ color: getThreatColor(report.threat_level) }}>{report.threat_level}</div>
            </div>
            
            <div className="glass-panel">
              <div className="stat-label">Bayesian Trust Score</div>
              <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>{(report.trust_score * 100).toFixed(1)}%</div>
            </div>
            
            <div className="glass-panel" style={{ borderTop: report.is_anomaly ? `4px solid var(--danger-red)` : `4px solid var(--success-green)` }}>
              <div className="stat-label">Structural Anomaly (Isolation Forest)</div>
              <div className="stat-value" style={{ color: report.is_anomaly ? 'var(--danger-red)' : 'var(--success-green)' }}>
                {report.is_anomaly ? 'Detected' : 'Clear'}
              </div>
            </div>
          </div>
          
           <div className="dashboard-grid">
            <div className="glass-panel">
              <div className="stat-label">Graph Construction</div>
              <div style={{ marginTop: '16px' }}>
                <p><strong>Nodes Extracted (Neo4j):</strong> {report.graph_nodes_extracted}</p>
                <p><strong>Relationships (Edges):</strong> {report.relationships_extracted}</p>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '12px' }}>Graph Visualization requires STIX graph data mapping feature to be robustly supported in this demo mode.</p>
              </div>
            </div>
            
             <div className="glass-panel">
              <div className="stat-label">Cyber Intelligence Insights</div>
              <div style={{ marginTop: '16px' }}>
                {report.attack_chain && report.attack_chain.length > 0 ? (
                  <div style={{ marginBottom: '16px' }}>
                    <p><strong>Attack Chains:</strong></p>
                    {report.attack_chain.map((chain, i) => (
                      <div key={i} style={{ color: 'var(--accent-cyan)', fontSize: '0.9rem', padding: '4px 8px', background: 'rgba(0,183,255,0.1)', borderRadius: '4px', marginTop: '4px' }}>
                        {chain}
                      </div>
                    ))}
                  </div>
                ) : <p style={{ color: 'var(--text-secondary)' }}>No known attack chains detected.</p>}
                
                {report.recommended_action && report.recommended_action.length > 0 && (
                   <div style={{ marginTop: '16px' }}>
                    <p><strong>Recommended Actions:</strong></p>
                    <ul style={{ paddingLeft: '20px', fontSize: '0.9rem', marginTop: '8px' }}>
                      {report.recommended_action.map((action, i) => (
                        <li key={i} style={{ marginBottom: '4px' }}>{action}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            <div className="glass-panel">
              <div className="stat-label">Structural Quality & Integrity</div>
              <div style={{ marginTop: '16px', fontSize: '0.9rem' }}>
                 <p><strong>STIX Version:</strong> <span style={{ color: 'var(--accent-cyan)' }}>{report.stix_version}</span></p>
                 <p><strong>Integrity Score:</strong> <span style={{ color: getThreatColor(report.validation_details?.score > 80 ? 'low' : 'high') }}>{report.validation_details?.score}/100</span></p>
                 
                 {report.validation_details?.missing_fields?.length > 0 && (
                   <div style={{ marginTop: '12px' }}>
                     <p style={{ color: 'var(--warning-orange)' }}><strong>Missing Required Fields:</strong></p>
                     <p style={{ fontSize: '0.85rem', background: 'rgba(255,165,0,0.1)', padding: '4px 8px', borderRadius: '4px' }}>
                        {report.validation_details.missing_fields.join(", ")}
                     </p>
                   </div>
                 )}

                 {report.validation_details?.invalid_fields?.length > 0 && (
                   <div style={{ marginTop: '12px' }}>
                     <p style={{ color: 'var(--danger-red)' }}><strong>Invalid Fields & Suggestions:</strong></p>
                     {report.validation_details.invalid_fields.map((err, i) => (
                       <div key={i} style={{ marginBottom: '8px', borderLeft: '2px solid var(--danger-red)', paddingLeft: '8px' }}>
                          <div style={{ fontWeight: 600 }}>{err.field}</div>
                          <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{err.issue}</div>
                          {err.suggestion && <div style={{ color: 'var(--accent-cyan)', fontSize: '0.8rem', fontStyle: 'italic' }}>Tip: {err.suggestion}</div>}
                       </div>
                     ))}
                   </div>
                 )}

                 {report.validation_details?.recovery_notes?.length > 0 && (
                   <div style={{ marginTop: '12px' }}>
                     <p style={{ color: 'var(--success-green)' }}><strong>Autonomous Recovery Logs:</strong></p>
                     <ul style={{ paddingLeft: '20px', marginTop: '4px', fontSize: '0.8rem' }}>
                        {report.validation_details.recovery_notes.map((note, i) => <li key={i}>{note}</li>)}
                     </ul>
                   </div>
                 )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;

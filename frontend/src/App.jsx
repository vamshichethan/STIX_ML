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
              <div className="stat-label">Raw Parsing Summary</div>
              <div style={{ marginTop: '16px' }}>
                <p><strong>Status:</strong> {report.summary}</p>
                <p><strong>Bundle Ref:</strong> {report.raw_data_refs}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;

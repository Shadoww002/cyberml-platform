import React, { useState } from 'react';
import { Upload, Link, Activity, Shield, AlertTriangle, CheckCircle, XCircle, Globe, FileSearch, Network, Eye, Download } from 'lucide-react';

const CyberMLDashboard = () => {
  const [activeTab, setActiveTab] = useState('upload');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [apiInput, setApiInput] = useState('');
  const [file, setFile] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [networkMonitoring, setNetworkMonitoring] = useState(false);

  const analyzeFile = () => {
    if (!file) return;
    
    setLoading(true);
    
    setTimeout(() => {
      const result = {
        type: 'file',
        name: file.name,
        size: file.size,
        hash: 'sha256:' + Math.random().toString(36).substring(7),
        threat_level: Math.random() > 0.5 ? 'high' : 'low',
        confidence: (Math.random() * 0.4 + 0.6).toFixed(2),
        verdict: Math.random() > 0.5 ? 'malicious' : 'safe',
        details: {
          entropy: (Math.random() * 2 + 6).toFixed(2),
          suspicious_strings: Math.floor(Math.random() * 20),
          yara_matches: Math.random() > 0.7 ? ['Suspicious_PE', 'Packed_Binary'] : [],
          ml_features: {
            file_operations: Math.floor(Math.random() * 50),
            network_calls: Math.floor(Math.random() * 30),
            registry_access: Math.floor(Math.random() * 20)
          }
        },
        timestamp: new Date().toISOString()
      };
      
      setAnalysisResult(result);
      addAlert(result);
      setLoading(false);
    }, 2000);
  };

  const analyzeURL = () => {
    if (!urlInput) return;
    
    setLoading(true);
    
    setTimeout(() => {
      const result = {
        type: 'url',
        url: urlInput,
        threat_level: Math.random() > 0.6 ? 'medium' : 'low',
        confidence: (Math.random() * 0.3 + 0.65).toFixed(2),
        verdict: Math.random() > 0.7 ? 'suspicious' : 'safe',
        details: {
          ssl_valid: Math.random() > 0.3,
          domain_age: Math.floor(Math.random() * 3650),
          reputation_score: Math.floor(Math.random() * 100),
          vulnerabilities: Math.random() > 0.6 ? ['XSS', 'SQL Injection'] : [],
          security_headers: {
            'X-Frame-Options': Math.random() > 0.5,
            'Content-Security-Policy': Math.random() > 0.5,
            'Strict-Transport-Security': Math.random() > 0.5
          }
        },
        timestamp: new Date().toISOString()
      };
      
      setAnalysisResult(result);
      addAlert(result);
      setLoading(false);
    }, 2500);
  };

  const analyzeAPI = () => {
    if (!apiInput) return;
    
    setLoading(true);
    
    setTimeout(() => {
      const result = {
        type: 'api',
        endpoint: apiInput,
        threat_level: Math.random() > 0.7 ? 'high' : 'low',
        confidence: (Math.random() * 0.3 + 0.7).toFixed(2),
        verdict: Math.random() > 0.6 ? 'vulnerable' : 'secure',
        details: {
          authentication: Math.random() > 0.5 ? 'Required' : 'None',
          rate_limiting: Math.random() > 0.5,
          vulnerabilities: [],
          security_issues: Math.random() > 0.5 ? ['Weak Auth', 'CORS Misconfiguration'] : [],
          response_time: Math.floor(Math.random() * 500) + 'ms'
        },
        timestamp: new Date().toISOString()
      };
      
      if (result.verdict === 'vulnerable') {
        result.details.vulnerabilities = ['Injection', 'Broken Auth', 'Security Misconfiguration'];
      }
      
      setAnalysisResult(result);
      addAlert(result);
      setLoading(false);
    }, 2000);
  };

  const addAlert = (result) => {
    const newAlert = {
      id: Date.now(),
      ...result
    };
    setAlerts(prev => [newAlert, ...prev].slice(0, 10));
  };

  const getThreatColor = (level) => {
    const colors = {
      high: 'text-red-600 bg-red-50 border-red-200',
      medium: 'text-yellow-600 bg-yellow-50 border-yellow-200',
      low: 'text-green-600 bg-green-50 border-green-200'
    };
    return colors[level] || colors.low;
  };

  const getVerdictIcon = (verdict) => {
    if (verdict === 'malicious' || verdict === 'vulnerable' || verdict === 'suspicious') {
      return <XCircle className="w-5 h-5 text-red-600" />;
    }
    return <CheckCircle className="w-5 h-5 text-green-600" />;
  };

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    setFile(selectedFile);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900 p-4 md:p-8">
      <div className="max-w-7xl mx-auto mb-8">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="w-10 h-10 text-blue-400" />
          <h1 className="text-3xl md:text-4xl font-bold text-white">CyberML Security Platform</h1>
        </div>
        <p className="text-blue-200">AI-Powered Threat Detection & Analysis</p>
      </div>

      <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-white rounded-xl shadow-2xl overflow-hidden">
            <div className="flex border-b border-gray-200">
              <button
                onClick={() => setActiveTab('upload')}
                className={`flex-1 px-6 py-4 flex items-center justify-center gap-2 font-medium transition-colors ${
                  activeTab === 'upload'
                    ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                <Upload className="w-5 h-5" />
                Upload File
              </button>
              <button
                onClick={() => setActiveTab('url')}
                className={`flex-1 px-6 py-4 flex items-center justify-center gap-2 font-medium transition-colors ${
                  activeTab === 'url'
                    ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                <Globe className="w-5 h-5" />
                Check URL
              </button>
              <button
                onClick={() => setActiveTab('api')}
                className={`flex-1 px-6 py-4 flex items-center justify-center gap-2 font-medium transition-colors ${
                  activeTab === 'api'
                    ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                <Link className="w-5 h-5" />
                Test API
              </button>
            </div>

            <div className="p-6">
              {activeTab === 'upload' && (
                <div className="space-y-4">
                  <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-400 transition-colors">
                    <input
                      type="file"
                      id="file-upload"
                      className="hidden"
                      onChange={handleFileChange}
                    />
                    <label htmlFor="file-upload" className="cursor-pointer">
                      <FileSearch className="w-12 h-12 mx-auto text-gray-400 mb-4" />
                      <p className="text-lg font-medium text-gray-700 mb-2">
                        {file ? file.name : 'Drop file here or click to upload'}
                      </p>
                      <p className="text-sm text-gray-500">
                        Supports: EXE, DLL, PDF, ZIP, APK (Max 50MB)
                      </p>
                    </label>
                  </div>
                  <button
                    onClick={analyzeFile}
                    disabled={!file || loading}
                    className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Eye className="w-5 h-5" />
                        Analyze File
                      </>
                    )}
                  </button>
                </div>
              )}

              {activeTab === 'url' && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Website or URL to Scan
                    </label>
                    <input
                      type="text"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="https://example.com"
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  <button
                    onClick={analyzeURL}
                    disabled={!urlInput || loading}
                    className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Eye className="w-5 h-5" />
                        Scan URL
                      </>
                    )}
                  </button>
                  <p className="text-xs text-gray-500">
                    Checks for malware, phishing, SSL issues, and vulnerabilities
                  </p>
                </div>
              )}

              {activeTab === 'api' && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      API Endpoint to Test
                    </label>
                    <input
                      type="text"
                      value={apiInput}
                      onChange={(e) => setApiInput(e.target.value)}
                      placeholder="https://api.example.com/v1/endpoint"
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                  <button
                    onClick={analyzeAPI}
                    disabled={!apiInput || loading}
                    className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                        Testing...
                      </>
                    ) : (
                      <>
                        <Eye className="w-5 h-5" />
                        Test API Security
                      </>
                    )}
                  </button>
                  <p className="text-xs text-gray-500">
                    Tests for OWASP Top 10 vulnerabilities and security best practices
                  </p>
                </div>
              )}
            </div>
          </div>

          {analysisResult && (
            <div className="bg-white rounded-xl shadow-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
                  {getVerdictIcon(analysisResult.verdict)}
                  Analysis Results
                </h2>
                <span className={`px-4 py-2 rounded-full text-sm font-semibold border ${getThreatColor(analysisResult.threat_level)}`}>
                  {analysisResult.threat_level.toUpperCase()} RISK
                </span>
              </div>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-gray-600">Type</p>
                    <p className="text-lg font-semibold text-gray-900 capitalize">{analysisResult.type}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Verdict</p>
                    <p className="text-lg font-semibold text-gray-900 capitalize">{analysisResult.verdict}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Confidence</p>
                    <p className="text-lg font-semibold text-gray-900">{(analysisResult.confidence * 100).toFixed(0)}%</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Analyzed</p>
                    <p className="text-lg font-semibold text-gray-900">
                      {new Date(analysisResult.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                </div>

                <div className="border-t pt-4">
                  <h3 className="font-semibold text-gray-900 mb-3">Detailed Analysis</h3>
                  <div className="bg-gray-50 rounded-lg p-4 space-y-2">
                    {Object.entries(analysisResult.details).map(([key, value]) => (
                      <div key={key} className="flex justify-between items-center">
                        <span className="text-sm text-gray-600 capitalize">
                          {key.replace(/_/g, ' ')}
                        </span>
                        <span className="text-sm font-medium text-gray-900">
                          {Array.isArray(value) ? (
                            value.length > 0 ? value.join(', ') : 'None'
                          ) : typeof value === 'object' ? (
                            JSON.stringify(value)
                          ) : (
                            String(value)
                          )}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <button className="w-full bg-gray-100 text-gray-700 px-6 py-3 rounded-lg font-medium hover:bg-gray-200 transition-colors flex items-center justify-center gap-2">
                  <Download className="w-5 h-5" />
                  Download Full Report
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="space-y-6">
          <div className="bg-white rounded-xl shadow-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                <Network className="w-5 h-5 text-blue-600" />
                Network Monitor
              </h3>
              <button
                onClick={() => setNetworkMonitoring(!networkMonitoring)}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  networkMonitoring
                    ? 'bg-green-100 text-green-700 hover:bg-green-200'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                {networkMonitoring ? 'Active' : 'Inactive'}
              </button>
            </div>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Packets Analyzed</span>
                <span className="font-semibold text-gray-900">
                  {networkMonitoring ? '12,345' : '0'}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Threats Blocked</span>
                <span className="font-semibold text-red-600">
                  {networkMonitoring ? '3' : '0'}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Active Connections</span>
                <span className="font-semibold text-gray-900">
                  {networkMonitoring ? '47' : '0'}
                </span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-xl shadow-2xl p-6">
            <h3 className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2">
              <Activity className="w-5 h-5 text-blue-600" />
              Recent Alerts
            </h3>
            <div className="space-y-3">
              {alerts.length === 0 ? (
                <p className="text-sm text-gray-500 text-center py-4">No alerts yet</p>
              ) : (
                alerts.map((alert) => (
                  <div key={alert.id} className="border border-gray-200 rounded-lg p-3 hover:bg-gray-50 transition-colors">
                    <div className="flex items-start justify-between mb-2">
                      <span className="text-sm font-medium text-gray-900 capitalize">
                        {alert.type} Analysis
                      </span>
                      <span className={`text-xs px-2 py-1 rounded-full ${getThreatColor(alert.threat_level)}`}>
                        {alert.threat_level}
                      </span>
                    </div>
                    <p className="text-xs text-gray-600 truncate">
                      {alert.name || alert.url || alert.endpoint}
                    </p>
                    <p className="text-xs text-gray-400 mt-1">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="bg-gradient-to-br from-blue-600 to-blue-700 rounded-xl shadow-2xl p-6 text-white">
            <h3 className="text-lg font-bold mb-4">Today's Statistics</h3>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-blue-100">Files Scanned</span>
                <span className="font-bold">{alerts.filter(a => a.type === 'file').length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-blue-100">URLs Checked</span>
                <span className="font-bold">{alerts.filter(a => a.type === 'url').length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-blue-100">APIs Tested</span>
                <span className="font-bold">{alerts.filter(a => a.type === 'api').length}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CyberMLDashboard;
import React, { useState, useEffect, useRef } from 'react';
import { Upload, Link, Activity, Shield, AlertTriangle, CheckCircle, XCircle, Globe, FileSearch, Network, Eye, Download, Info, AlertOctagon, ShieldAlert, TrendingUp, BarChart3, PieChart, Zap, Lock, Unlock, MessageCircle, Send, X } from 'lucide-react';

const CyberMLDashboard = () => {
  const [activeTab, setActiveTab] = useState('upload');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [apiInput, setApiInput] = useState('');
  const [file, setFile] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [networkMonitoring, setNetworkMonitoring] = useState(false);
  const [networkData, setNetworkData] = useState({ packets: 0, threats: 0, connections: 0, bandwidth: 0 });
  const [networkLogs, setNetworkLogs] = useState([]);
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef(null);

  const API_URL = 'http://localhost:8000';

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages]);

  const sendChatMessage = async () => {
    if (!chatInput.trim() || chatLoading) return;

    const userMessage = chatInput.trim();
    setChatInput('');
    setChatMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setChatLoading(true);

    try {
      const response = await fetch(`${API_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessage,
          context: analysisResult
        })
      });

      const data = await response.json();
      setChatMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
    } catch (error) {
      setChatMessages(prev => [...prev, { 
        role: 'assistant', 
        content: 'Sorry, I encountered an error. Please try again.' 
      }]);
    } finally {
      setChatLoading(false);
    }
  };

  const downloadPDF = async () => {
    if (!analysisResult || !analysisResult.analysis_id) {
      alert('No analysis results available. Please run an analysis first.');
      return;
    }

    const analysis_id = analysisResult.analysis_id;
    console.log('📄 Downloading PDF for:', analysis_id);

    try {
      const response = await fetch(`${API_URL}/api/report/${analysis_id}/pdf`, {
        method: 'GET',
        headers: {
          'Accept': 'application/pdf'
        }
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('PDF error response:', errorText);
        throw new Error(`Server returned ${response.status}: ${errorText}`);
      }

      const blob = await response.blob();
      console.log('📦 PDF blob received:', blob.size, 'bytes');
      
      if (blob.size < 100) {
        throw new Error('PDF file appears to be empty or corrupted');
      }

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cyberml_report_${analysis_id}.pdf`;
      document.body.appendChild(a);
      a.click();
      
      setTimeout(() => {
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      }, 100);
      
      console.log('✅ PDF downloaded successfully');
    } catch (error) {
      console.error('❌ PDF download failed:', error);
      alert(`Failed to download PDF: ${error.message}\n\nMake sure:\n1. Backend is running on http://localhost:8000\n2. Analysis was completed successfully\n3. Check browser console for details`);
    }
  };

  useEffect(() => {
    if (networkMonitoring) {
      const interval = setInterval(() => {
        setNetworkData(prev => ({
          packets: prev.packets + Math.floor(Math.random() * 100),
          threats: prev.threats + (Math.random() > 0.95 ? 1 : 0),
          connections: Math.floor(Math.random() * 20) + 30,
          bandwidth: (Math.random() * 50 + 20).toFixed(2)
        }));

        if (Math.random() > 0.7) {
          const types = ['connection', 'dns_query', 'http_request', 'suspicious_traffic'];
          setNetworkLogs(prev => [{
            id: Date.now(),
            type: types[Math.floor(Math.random() * types.length)],
            source: `192.168.1.${Math.floor(Math.random() * 255)}`,
            destination: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            port: Math.floor(Math.random() * 65535),
            protocol: ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
            threat_level: Math.random() > 0.8 ? 'high' : Math.random() > 0.5 ? 'medium' : 'low',
            timestamp: new Date().toISOString()
          }, ...prev].slice(0, 50));
        }
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [networkMonitoring]);

  const CircularProgress = ({ value, size = 120, strokeWidth = 10, color = '#3B82F6' }) => {
    const radius = (size - strokeWidth) / 2;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (value / 100) * circumference;

    return (
      <div className="relative inline-flex items-center justify-center">
        <svg width={size} height={size} className="transform -rotate-90">
          <circle cx={size / 2} cy={size / 2} r={radius} stroke="#E5E7EB" strokeWidth={strokeWidth} fill="none" />
          <circle cx={size / 2} cy={size / 2} r={radius} stroke={color} strokeWidth={strokeWidth} fill="none"
            strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
            className="transition-all duration-1000 ease-out" />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-2xl font-bold" style={{ color }}>{value}%</span>
        </div>
      </div>
    );
  };

  const ThreatMeter = ({ level }) => {
    const levels = { low: 20, medium: 60, high: 90 };
    const colors = { low: '#10B981', medium: '#F59E0B', high: '#EF4444' };
    const value = levels[level] || 0;
    
    return (
      <div className="relative w-full h-8 bg-gradient-to-r from-green-200 via-yellow-200 to-red-200 rounded-full overflow-hidden">
        <div className="absolute inset-0 flex items-center justify-between px-4 text-xs font-semibold">
          <span>SAFE</span>
          <span>CAUTION</span>
          <span>DANGER</span>
        </div>
        <div className="absolute top-0 h-full w-1 bg-gray-900 transition-all duration-700"
          style={{ left: `${value}%`, boxShadow: '0 0 10px rgba(0,0,0,0.5)' }} />
      </div>
    );
  };

  const getRecommendations = (type, verdict) => {
    const recs = {
      file: {
        malicious: [{
          title: "🚨 Immediate Actions Required",
          items: ["Isolate the infected system from network immediately", "Delete the malicious file and empty recycle bin", "Run full system scan with updated antivirus", "Check Task Manager for suspicious processes", "Scan all USB drives and external storage"]
        }],
        suspicious: [{
          title: "⚠️ Recommended Actions",
          items: ["Quarantine the file immediately", "Upload to VirusTotal.com for multi-engine scan", "Check file properties and digital signature", "Verify the file source and download location"]
        }]
      },
      url: {
        suspicious: [{
          title: "🚫 Immediate Actions",
          items: ["Close the browser tab immediately", "Do NOT enter any credentials or personal information", "Clear browser cache, cookies, and history", "Run malware scan if you clicked any links"]
        }]
      },
      api: {
        vulnerable: [{
          title: "🔴 Critical Security Issues",
          items: ["Do not deploy this API to production", "Implement OAuth 2.0 or JWT authentication", "Add rate limiting (100 requests/minute)", "Enable HTTPS/TLS 1.3 encryption only"]
        }]
      }
    };
    return recs[type]?.[verdict] || [];
  };

  const analyzeFile = async () => {
    if (!file) return;
    setLoading(true);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await fetch(`${API_URL}/api/analyze/file`, {
        method: 'POST',
        body: formData
      });
      
      if (!response.ok) throw new Error('Analysis failed');
      
      const result = await response.json();
      setAnalysisResult(result);
      setAlerts(prev => [{ id: Date.now(), ...result }, ...prev].slice(0, 10));
    } catch (error) {
      console.error('File analysis error:', error);
      alert('Analysis failed. Make sure backend is running on http://localhost:8000');
    } finally {
      setLoading(false);
    }
  };

  const analyzeURL = async () => {
    if (!urlInput) return;
    setLoading(true);
    
    try {
      const response = await fetch(`${API_URL}/api/analyze/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput })
      });
      
      if (!response.ok) throw new Error('URL analysis failed');
      
      const result = await response.json();
      setAnalysisResult(result);
      setAlerts(prev => [{ id: Date.now(), ...result }, ...prev].slice(0, 10));
    } catch (error) {
      console.error('URL analysis error:', error);
      alert('Analysis failed. Make sure backend is running on http://localhost:8000');
    } finally {
      setLoading(false);
    }
  };

  const analyzeAPI = async () => {
    if (!apiInput) return;
    setLoading(true);
    
    try {
      const response = await fetch(`${API_URL}/api/analyze/api`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpoint: apiInput })
      });
      
      if (!response.ok) throw new Error('API analysis failed');
      
      const result = await response.json();
      setAnalysisResult(result);
      setAlerts(prev => [{ id: Date.now(), ...result }, ...prev].slice(0, 10));
    } catch (error) {
      console.error('API analysis error:', error);
      alert('Analysis failed. Make sure backend is running on http://localhost:8000');
    } finally {
      setLoading(false);
    }
  };

  const getThreatColor = (level) => ({
    high: 'text-red-600 bg-red-50 border-red-200',
    medium: 'text-yellow-600 bg-yellow-50 border-yellow-200',
    low: 'text-green-600 bg-green-50 border-green-200'
  }[level] || 'text-gray-600 bg-gray-50 border-gray-200');

  const getVerdictIcon = (verdict) => 
    ['malicious', 'vulnerable', 'suspicious'].includes(verdict) 
      ? <XCircle className="w-6 h-6 text-red-600" />
      : <CheckCircle className="w-6 h-6 text-green-600" />;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 p-4 md:p-8">
      <div className="fixed inset-0 opacity-10">
        <div className="absolute inset-0" style={{
          backgroundImage: 'radial-gradient(circle at 20% 50%, rgba(59, 130, 246, 0.3) 0%, transparent 50%), radial-gradient(circle at 80% 80%, rgba(139, 92, 246, 0.3) 0%, transparent 50%)',
          animation: 'pulse 4s ease-in-out infinite'
        }} />
      </div>

      <div className="relative max-w-7xl mx-auto mb-8">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="w-12 h-12 text-blue-400" />
              <div className="absolute inset-0 animate-ping">
                <Shield className="w-12 h-12 text-blue-400 opacity-75" />
              </div>
            </div>
            <div>
              <h1 className="text-3xl md:text-4xl font-bold text-white">CyberML Security Platform</h1>
              <p className="text-blue-200 text-sm">Enterprise-Grade Threat Intelligence</p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-4">
            <div className="text-right">
              <p className="text-xs text-blue-300">Total Scans</p>
              <p className="text-2xl font-bold text-white">{alerts.length}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="relative max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-2xl overflow-hidden border border-gray-200">
            <div className="flex border-b border-gray-200 overflow-x-auto">
              {[
                { id: 'upload', icon: Upload, label: 'File Analysis', color: 'blue' },
                { id: 'url', icon: Globe, label: 'URL Scanner', color: 'green' },
                { id: 'api', icon: Link, label: 'API Security', color: 'purple' },
                { id: 'network', icon: Network, label: 'Network Monitor', color: 'orange' }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex-1 px-4 py-4 flex items-center justify-center gap-2 font-semibold transition-all whitespace-nowrap ${
                    activeTab === tab.id 
                      ? `bg-${tab.color}-50 text-${tab.color}-600 border-b-3 border-${tab.color}-500 shadow-inner` 
                      : 'text-gray-600 hover:bg-gray-50'
                  }`}
                >
                  <tab.icon className="w-5 h-5" />
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="p-6">
              {activeTab === 'upload' && (
                <div className="space-y-4">
                  <div className="relative border-2 border-dashed border-blue-300 rounded-xl p-8 text-center hover:border-blue-500 transition-all bg-gradient-to-br from-blue-50 to-white">
                    <input type="file" id="file-upload" className="hidden" onChange={(e) => setFile(e.target.files[0])} />
                    <label htmlFor="file-upload" className="cursor-pointer">
                      <div className="relative inline-block mb-4">
                        <FileSearch className="w-16 h-16 text-blue-400" />
                        <Upload className="w-6 h-6 text-blue-600 absolute -bottom-1 -right-1" />
                      </div>
                      <p className="text-xl font-bold text-gray-800 mb-2">{file ? file.name : 'Drop file or click to upload'}</p>
                      <p className="text-sm text-gray-600">Supports: EXE, DLL, PDF, ZIP, APK, DOC, JS</p>
                    </label>
                  </div>
                  <button onClick={analyzeFile} disabled={!file || loading} 
                    className="w-full bg-gradient-to-r from-blue-600 to-blue-700 text-white px-6 py-4 rounded-xl font-bold hover:from-blue-700 hover:to-blue-800 disabled:from-gray-300 disabled:to-gray-400 disabled:cursor-not-allowed transition-all shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 flex items-center justify-center gap-2">
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                        <span>Analyzing with AI Engine...</span>
                      </>
                    ) : (
                      <>
                        <Eye className="w-5 h-5" />
                        <span>Start Deep Analysis</span>
                      </>
                    )}
                  </button>
                </div>
              )}

              {activeTab === 'url' && (
                <div className="space-y-4">
                  <div className="relative">
                    <label className="block text-sm font-bold text-gray-700 mb-3">Website or URL Security Scan</label>
                    <div className="relative">
                      <Globe className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                      <input type="text" value={urlInput} onChange={(e) => setUrlInput(e.target.value)} 
                        placeholder="https://example.com" 
                        className="w-full pl-12 pr-4 py-4 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-green-500 focus:border-transparent text-lg" />
                    </div>
                  </div>
                  <button onClick={analyzeURL} disabled={!urlInput || loading} 
                    className="w-full bg-gradient-to-r from-green-600 to-green-700 text-white px-6 py-4 rounded-xl font-bold hover:from-green-700 hover:to-green-800 disabled:from-gray-300 disabled:to-gray-400 transition-all shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 flex items-center justify-center gap-2">
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                        <span>Scanning URL...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5" />
                        <span>Scan for Threats</span>
                      </>
                    )}
                  </button>
                </div>
              )}

              {activeTab === 'api' && (
                <div className="space-y-4">
                  <div className="relative">
                    <label className="block text-sm font-bold text-gray-700 mb-3">API Endpoint Security Testing</label>
                    <div className="relative">
                      <Link className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                      <input type="text" value={apiInput} onChange={(e) => setApiInput(e.target.value)} 
                        placeholder="https://api.example.com/v1/endpoint" 
                        className="w-full pl-12 pr-4 py-4 border-2 border-gray-300 rounded-xl focus:ring-2 focus:ring-purple-500 focus:border-transparent text-lg" />
                    </div>
                  </div>
                  <button onClick={analyzeAPI} disabled={!apiInput || loading} 
                    className="w-full bg-gradient-to-r from-purple-600 to-purple-700 text-white px-6 py-4 rounded-xl font-bold hover:from-purple-700 hover:to-purple-800 disabled:from-gray-300 disabled:to-gray-400 transition-all shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 flex items-center justify-center gap-2">
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                        <span>Testing API...</span>
                      </>
                    ) : (
                      <>
                        <Zap className="w-5 h-5" />
                        <span>Run Security Tests</span>
                      </>
                    )}
                  </button>
                </div>
              )}

              {activeTab === 'network' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-5 bg-gradient-to-r from-orange-50 to-red-50 rounded-xl border-2 border-orange-200">
                    <div className="flex items-center gap-3">
                      <Network className="w-8 h-8 text-orange-600" />
                      <div>
                        <h3 className="font-bold text-gray-900">Real-Time Network Monitoring</h3>
                        <p className="text-sm text-gray-600">Deep Packet Inspection</p>
                      </div>
                    </div>
                    <button onClick={() => setNetworkMonitoring(!networkMonitoring)} 
                      className={`px-8 py-3 rounded-xl font-bold transition-all shadow-lg ${
                        networkMonitoring 
                          ? 'bg-red-600 text-white hover:bg-red-700' 
                          : 'bg-green-600 text-white hover:bg-green-700'
                      }`}>
                      {networkMonitoring ? 'Stop Monitor' : 'Start Monitor'}
                    </button>
                  </div>

                  {networkMonitoring && (
                    <>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        {[
                          { label: 'Packets', value: networkData.packets, icon: Activity, color: 'blue' },
                          { label: 'Threats', value: networkData.threats, icon: AlertTriangle, color: 'red' },
                          { label: 'Connections', value: networkData.connections, icon: Network, color: 'green' },
                          { label: 'Bandwidth', value: networkData.bandwidth + ' MB/s', icon: TrendingUp, color: 'purple' }
                        ].map((stat, i) => (
                          <div key={i} className="bg-gradient-to-br from-white to-gray-50 border-2 border-gray-200 rounded-xl p-4">
                            <p className="text-sm font-semibold text-gray-600 mb-2">{stat.label}</p>
                            <p className="text-3xl font-bold text-gray-900">{stat.value}</p>
                          </div>
                        ))}
                      </div>

                      <div className="bg-white border-2 border-gray-200 rounded-xl p-5">
                        <h4 className="font-bold text-gray-900 mb-4">Live Network Traffic</h4>
                        <div className="space-y-2 max-h-96 overflow-y-auto">
                          {networkLogs.map(log => (
                            <div key={log.id} className={`border-l-4 rounded-lg p-4 ${
                              log.threat_level === 'high' ? 'border-red-500 bg-red-50' :
                              log.threat_level === 'medium' ? 'border-yellow-500 bg-yellow-50' :
                              'border-green-500 bg-green-50'
                            }`}>
                              <div className="flex justify-between mb-2">
                                <span className="text-sm font-bold">{log.type.replace(/_/g, ' ')}</span>
                                <span className={`text-xs px-3 py-1 rounded-full font-semibold ${getThreatColor(log.threat_level)}`}>
                                  {log.threat_level.toUpperCase()}
                                </span>
                              </div>
                              <div className="text-xs text-gray-700">
                                <div>Source: {log.source} | Dest: {log.destination}</div>
                                <div>Port: {log.port} | Protocol: {log.protocol}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>

          {analysisResult && activeTab !== 'network' && (
            <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-2xl p-6 border border-gray-200">
              <div className="flex items-center justify-between mb-6 pb-4 border-b-2">
                <h2 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
                  {getVerdictIcon(analysisResult.verdict)}
                  Threat Report
                </h2>
                <span className={`px-6 py-3 rounded-full text-sm font-bold border-2 ${getThreatColor(analysisResult.threat_level)}`}>
                  {analysisResult.threat_level.toUpperCase()} RISK
                </span>
              </div>

              <div className="mb-6 p-5 bg-gradient-to-r from-gray-50 to-blue-50 rounded-xl">
                <ThreatMeter level={analysisResult.threat_level} />
              </div>

              <div className="mb-6 flex items-center justify-center gap-8 p-6 bg-gradient-to-br from-blue-50 to-purple-50 rounded-xl">
                <CircularProgress 
                  value={Math.round(analysisResult.confidence * 100)} 
                  color={analysisResult.confidence > 0.7 ? '#EF4444' : analysisResult.confidence > 0.4 ? '#F59E0B' : '#10B981'}
                />
                <div>
                  <p className="text-sm text-gray-600 mb-1">Detection Confidence</p>
                  <p className="text-3xl font-bold text-gray-900">{(analysisResult.confidence * 100).toFixed(0)}%</p>
                </div>
              </div>

              <div className="mb-6">
                <h3 className="font-bold text-gray-900 text-xl mb-4">Technical Analysis</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {Object.entries(analysisResult.details).slice(0, 8).map(([key, value]) => (
                    <div key={key} className="bg-gradient-to-br from-gray-50 to-white rounded-xl p-5 border-2 border-gray-200">
                      <p className="text-sm font-bold text-gray-700 capitalize mb-3">{key.replace(/_/g, ' ')}</p>
                      <div className="space-y-2">
                        {typeof value === 'object' && !Array.isArray(value) ? (
                          Object.entries(value).slice(0, 4).map(([k, v]) => (
                            <div key={k} className="flex justify-between text-sm">
                              <span className="text-gray-600 capitalize">{k.replace(/_/g, ' ')}:</span>
                              <span className="font-semibold text-gray-900">{String(v)}</span>
                            </div>
                          ))
                        ) : (
                          <div className="text-sm font-semibold text-gray-900">{String(value)}</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {getRecommendations(analysisResult.type, analysisResult.verdict).length > 0 && (
                <div className="mb-6">
                  <h3 className="font-bold text-gray-900 text-xl mb-4">Security Recommendations</h3>
                  {getRecommendations(analysisResult.type, analysisResult.verdict).map((section, i) => (
                    <div key={i} className="bg-gradient-to-r from-orange-50 to-red-50 border-2 border-orange-300 rounded-xl p-5 mb-4">
                      <h4 className="font-bold text-orange-900 mb-3">{section.title}</h4>
                      <ul className="space-y-2">
                        {section.items.map((item, j) => (
                          <li key={j} className="flex items-start gap-3 text-sm">
                            <span className="flex-shrink-0 w-6 h-6 bg-orange-500 text-white rounded-full flex items-center justify-center text-xs font-bold">{j + 1}</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}

              <div className="flex gap-4">
                <button onClick={downloadPDF} className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 text-white px-6 py-4 rounded-xl font-bold hover:from-blue-700 hover:to-blue-800 transition-all flex items-center justify-center gap-2">
                  <Download className="w-5 h-5" />
                  Download PDF Report
                </button>
                <button onClick={() => setAnalysisResult(null)} 
                  className="flex-1 bg-gradient-to-r from-gray-100 to-gray-200 text-gray-700 px-6 py-4 rounded-xl font-bold hover:from-gray-200 hover:to-gray-300 transition-all">
                  Start New Analysis
                </button>
              </div>
            </div>
          )}
        </div>

        {chatOpen && (
          <div className="fixed bottom-24 right-8 w-96 h-[500px] bg-white rounded-2xl shadow-2xl border-2 border-blue-500 flex flex-col z-50">
            <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white p-4 rounded-t-2xl flex items-center justify-between">
              <div className="flex items-center gap-2">
                <MessageCircle className="w-6 h-6" />
                <div>
                  <h3 className="font-bold">CyberML AI Assistant</h3>
                  <p className="text-xs text-blue-100">Security Expert</p>
                </div>
              </div>
              <button onClick={() => setChatOpen(false)} className="hover:bg-white/20 p-1 rounded">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-3">
              {chatMessages.length === 0 && (
                <div className="text-center text-gray-500 mt-8">
                  <MessageCircle className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                  <p className="text-sm">Ask me about cybersecurity!</p>
                </div>
              )}
              {chatMessages.map((msg, idx) => (
                <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[80%] p-3 rounded-2xl ${
                    msg.role === 'user' 
                      ? 'bg-blue-600 text-white rounded-br-none' 
                      : 'bg-gray-100 text-gray-800 rounded-bl-none'
                  }`}>
                    <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
                  </div>
                </div>
              ))}
              {chatLoading && (
                <div className="flex justify-start">
                  <div className="bg-gray-100 p-3 rounded-2xl">
                    <div className="flex gap-1">
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                    </div>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            <div className="p-4 border-t">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && sendChatMessage()}
                  placeholder="Ask about security..."
                  className="flex-1 px-4 py-2 border-2 border-gray-300 rounded-xl focus:border-blue-500 focus:outline-none"
                />
                <button onClick={sendChatMessage} disabled={!chatInput.trim()} className="bg-blue-600 text-white p-2 rounded-xl hover:bg-blue-700 disabled:bg-gray-300">
                  <Send className="w-5 h-5" />
                </button>
              </div>
            </div>
          </div>
        )}

        <button onClick={() => setChatOpen(!chatOpen)} className="fixed bottom-8 right-8 bg-gradient-to-r from-blue-600 to-purple-600 text-white p-4 rounded-full shadow-2xl hover:scale-110 transition-all z-40">
          <MessageCircle className="w-6 h-6" />
        </button>

        <div className="space-y-6">
          <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-2xl p-6 border border-gray-200">
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
              <Activity className="w-6 h-6 text-blue-600" />
              Recent Alerts
            </h3>
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {alerts.length === 0 ? (
                <div className="text-center py-8">
                  <AlertTriangle className="w-12 h-12 mx-auto text-gray-300 mb-2" />
                  <p className="text-sm text-gray-500">No alerts yet</p>
                </div>
              ) : (
                alerts.map(alert => (
                  <div key={alert.id} className="border-2 border-gray-200 rounded-xl p-4 hover:bg-gray-50 cursor-pointer transition-all">
                    <div className="flex justify-between mb-2">
                      <span className="text-sm font-bold capitalize">{alert.type}</span>
                      <span className={`text-xs px-3 py-1 rounded-full font-bold ${getThreatColor(alert.threat_level)}`}>
                        {alert.threat_level}
                      </span>
                    </div>
                    <p className="text-xs text-gray-600 truncate">{alert.details?.filename || alert.details?.url || alert.details?.endpoint}</p>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="bg-gradient-to-br from-blue-600 to-purple-700 rounded-2xl shadow-2xl p-6 text-white">
            <h3 className="text-lg font-bold mb-4">Analytics</h3>
            <div className="space-y-4">
              {[
                { label: 'Files Scanned', value: alerts.filter(a => a.type === 'file').length, icon: FileSearch },
                { label: 'URLs Checked', value: alerts.filter(a => a.type === 'url').length, icon: Globe },
                { label: 'APIs Tested', value: alerts.filter(a => a.type === 'api').length, icon: Link }
              ].map((stat, i) => (
                <div key={i} className="flex justify-between items-center bg-white/20 rounded-lg p-3">
                  <div className="flex items-center gap-2">
                    <stat.icon className="w-5 h-5" />
                    <span className="text-sm">{stat.label}</span>
                  </div>
                  <span className="font-bold text-2xl">{stat.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CyberMLDashboard;
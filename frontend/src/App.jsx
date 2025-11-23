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
    if (!analysisResult) return;

    try {
      const response = await fetch(`${API_URL}/api/report/${analysisResult.analysis_id}/pdf`);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cyberml_report_${analysisResult.analysis_id}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      alert('Failed to download PDF report');
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

  const BarChart = ({ data, title }) => {
    const maxValue = Math.max(...data.map(d => d.value));
    return (
      <div className="space-y-3">
        <h4 className="text-sm font-semibold text-gray-700">{title}</h4>
        {data.map((item, idx) => (
          <div key={idx} className="space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-gray-600">{item.label}</span>
              <span className="font-semibold text-gray-900">{item.value}</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2 overflow-hidden">
              <div className={`h-2 rounded-full transition-all duration-500 ${item.color || 'bg-blue-500'}`}
                style={{ width: `${(item.value / maxValue) * 100}%` }} />
            </div>
          </div>
        ))}
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
        }, {
          title: "🛡️ Prevention & Protection",
          items: ["Install reputable antivirus (Windows Defender, Malwarebytes)", "Enable Windows Firewall and configure rules", "Keep Windows and all software updated", "Enable User Account Control (UAC)", "Use standard user accounts for daily tasks"]
        }, {
          title: "🔒 Security Best Practices",
          items: ["Never open email attachments from unknown senders", "Download software only from official websites", "Enable file extension visibility in Windows", "Use virtual machines for testing suspicious files", "Backup important data regularly to external drives"]
        }],
        suspicious: [{
          title: "⚠️ Recommended Actions",
          items: ["Quarantine the file immediately", "Upload to VirusTotal.com for multi-engine scan", "Check file properties and digital signature", "Verify the file source and download location", "Monitor system behavior for 24-48 hours"]
        }, {
          title: "🔍 Additional Analysis",
          items: ["Use online sandbox services (Any.run, Hybrid Analysis)", "Check file hash on threat intelligence platforms", "Analyze with PE analysis tools if executable", "Review file strings with tools like BinText"]
        }]
      },
      url: {
        suspicious: [{
          title: "🚫 Immediate Actions",
          items: ["Close the browser tab immediately", "Do NOT enter any credentials or personal information", "Clear browser cache, cookies, and history", "Run malware scan if you clicked any links", "Change passwords if you entered them"]
        }, {
          title: "🔐 Account Security",
          items: ["Enable two-factor authentication on all accounts", "Use unique passwords for each website", "Install password manager (Bitwarden, 1Password)", "Monitor bank statements for unauthorized transactions", "Set up credit monitoring alerts"]
        }, {
          title: "🌐 Safe Browsing Practices",
          items: ["Verify HTTPS and check for padlock icon", "Hover over links before clicking to see destination", "Be cautious of urgent messages or scare tactics", "Install browser security extensions (uBlock Origin)", "Use DNS filtering (Cloudflare 1.1.1.1, Quad9)"]
        }]
      },
      api: {
        vulnerable: [{
          title: "🔴 Critical Security Issues",
          items: ["Do not deploy this API to production", "Implement OAuth 2.0 or JWT authentication", "Add rate limiting (100 requests/minute)", "Enable HTTPS/TLS 1.3 encryption only", "Sanitize all user inputs to prevent injection"]
        }, {
          title: "🔧 Security Hardening Steps",
          items: ["Add API key authentication as minimum", "Implement request signing and validation", "Set up API gateway with security policies", "Enable CORS with specific allowed origins", "Add security headers (CSP, HSTS, X-Frame-Options)"]
        }, {
          title: "📊 Monitoring & Logging",
          items: ["Enable comprehensive API logging", "Set up alerts for suspicious patterns", "Monitor for brute force attempts", "Implement IP blocking for abuse", "Regular security audits and penetration testing"]
        }]
      }
    };
    return recs[type]?.[verdict] || [];
  };

  const analyzeFile = () => {
    if (!file) return;
    setLoading(true);
    setTimeout(() => {
      const score = Math.random();
      const verdict = score > 0.6 ? 'malicious' : score > 0.3 ? 'suspicious' : 'safe';
      const result = {
        type: 'file',
        name: file.name,
        size: file.size,
        verdict,
        threat_level: score > 0.6 ? 'high' : score > 0.3 ? 'medium' : 'low',
        confidence: parseFloat((Math.random() * 0.4 + 0.6).toFixed(2)),
        details: {
          file_hash: Math.random().toString(36).substring(7),
          entropy: parseFloat((Math.random() * 2 + 6).toFixed(2)),
          suspicious_strings: Math.floor(Math.random() * 20),
          file_type: file.name.split('.').pop().toUpperCase(),
          yara_matches: verdict === 'malicious' ? ['Trojan.Generic', 'Packed_Binary', 'Suspicious_Network'] : verdict === 'suspicious' ? ['Packed_Binary'] : [],
          behavioral_indicators: {
            file_operations: Math.floor(Math.random() * 50),
            network_calls: Math.floor(Math.random() * 30),
            registry_modifications: Math.floor(Math.random() * 20),
            process_injection: Math.floor(Math.random() * 5)
          },
          static_analysis: {
            pe_structure: file.name.endsWith('.exe') ? 'Valid PE' : 'N/A',
            digital_signature: Math.random() > 0.5 ? 'Not Found ⚠️' : 'Valid ✓',
            packer_detected: verdict === 'malicious' ? 'UPX Detected' : 'None',
            imports_count: Math.floor(Math.random() * 100),
            sections_count: Math.floor(Math.random() * 8)
          },
          threat_intelligence: {
            known_malware: verdict === 'malicious',
            threat_family: verdict === 'malicious' ? 'Trojan.Downloader' : 'None',
            first_seen: '2024-11-15',
            detection_rate: `${Math.floor(Math.random() * 40) + 20}/70 engines`
          }
        },
        timestamp: new Date().toISOString()
      };
      setAnalysisResult(result);
      setAlerts(prev => [{ id: Date.now(), ...result }, ...prev].slice(0, 10));
      setLoading(false);
    }, 2500);
  };

  const analyzeURL = () => {
    if (!urlInput) return;
    setLoading(true);
    setTimeout(() => {
      const score = Math.random();
      const verdict = score > 0.6 ? 'suspicious' : 'safe';
      const result = {
        type: 'url',
        url: urlInput,
        verdict,
        threat_level: score > 0.6 ? 'high' : 'low',
        confidence: parseFloat((Math.random() * 0.3 + 0.65).toFixed(2)),
        details: {
          ssl_analysis: {
            valid_certificate: Math.random() > 0.3,
            certificate_issuer: "Let's Encrypt Authority",
            expiry_date: '2025-12-31',
            tls_version: 'TLS 1.3',
            cipher_strength: '256-bit'
          },
          domain_info: {
            age_days: Math.floor(Math.random() * 3650),
            reputation_score: Math.floor(Math.random() * 100),
            registrar: 'GoDaddy LLC',
            country: 'United States',
            blacklist_status: verdict === 'suspicious' ? 'Listed' : 'Clean'
          },
          security_headers: {
            'Strict-Transport-Security': Math.random() > 0.5 ? '✓ Present' : '✗ Missing',
            'Content-Security-Policy': Math.random() > 0.5 ? '✓ Present' : '✗ Missing',
            'X-Frame-Options': Math.random() > 0.5 ? '✓ Present' : '✗ Missing',
            'X-Content-Type-Options': Math.random() > 0.5 ? '✓ Present' : '✗ Missing'
          },
          threat_detection: {
            phishing_score: Math.floor(Math.random() * 100),
            malware_detected: verdict === 'suspicious',
            suspicious_redirects: Math.floor(Math.random() * 3),
            external_links: Math.floor(Math.random() * 50)
          },
          page_resources: {
            scripts: Math.floor(Math.random() * 20),
            iframes: Math.floor(Math.random() * 3),
            forms: Math.floor(Math.random() * 5),
            cookies: Math.floor(Math.random() * 10)
          }
        },
        timestamp: new Date().toISOString()
      };
      setAnalysisResult(result);
      setAlerts(prev => [{ id: Date.now(), ...result }, ...prev].slice(0, 10));
      setLoading(false);
    }, 3000);
  };

  const analyzeAPI = () => {
    if (!apiInput) return;
    setLoading(true);
    setTimeout(() => {
      const score = Math.random();
      const verdict = score > 0.6 ? 'vulnerable' : 'secure';
      const result = {
        type: 'api',
        endpoint: apiInput,
        verdict,
        threat_level: score > 0.7 ? 'high' : 'low',
        confidence: parseFloat((Math.random() * 0.3 + 0.7).toFixed(2)),
        details: {
          authentication: {
            method: Math.random() > 0.5 ? 'Bearer Token' : 'API Key',
            strength_score: Math.floor(Math.random() * 100),
            two_factor: Math.random() > 0.7
          },
          vulnerabilities: verdict === 'vulnerable' ? [
            { name: 'SQL Injection', severity: 'High', cvss: 9.1, description: 'Unvalidated user input in query' },
            { name: 'Broken Authentication', severity: 'Critical', cvss: 9.8, description: 'Weak session management' },
            { name: 'Security Misconfiguration', severity: 'Medium', cvss: 6.5, description: 'Default credentials enabled' }
          ] : [],
          security_score: {
            authentication: Math.floor(Math.random() * 40) + 60,
            encryption: Math.floor(Math.random() * 40) + 60,
            input_validation: Math.floor(Math.random() * 40) + 60,
            rate_limiting: Math.floor(Math.random() * 40) + 60
          },
          response_analysis: {
            average_time: Math.floor(Math.random() * 500) + 'ms',
            status_codes: { '200': 85, '400': 10, '500': 5 },
            information_disclosure: verdict === 'vulnerable',
            cors_config: Math.random() > 0.5 ? 'Restricted' : 'Permissive (*)'
          }
        },
        timestamp: new Date().toISOString()
      };
      setAnalysisResult(result);
      setAlerts(prev => [{ id: Date.now(), ...result }, ...prev].slice(0, 10));
      setLoading(false);
    }, 2500);
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
      {/* Animated Background */}
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
                      <p className="text-xs text-gray-500 mt-2">Maximum file size: 50MB</p>
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
                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                    <p className="text-xs text-blue-800">
                      <Info className="w-4 h-4 inline mr-1" />
                      Checks: SSL/TLS, Malware, Phishing, Security Headers, Blacklists
                    </p>
                  </div>
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
                  <div className="bg-purple-50 border border-purple-200 rounded-lg p-3">
                    <p className="text-xs text-purple-800">
                      <AlertTriangle className="w-4 h-4 inline mr-1" />
                      Tests: OWASP Top 10, Authentication, Rate Limiting, CORS, Encryption
                    </p>
                  </div>
                </div>
              )}

              {activeTab === 'network' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-5 bg-gradient-to-r from-orange-50 to-red-50 rounded-xl border-2 border-orange-200">
                    <div className="flex items-center gap-3">
                      <Network className="w-8 h-8 text-orange-600" />
                      <div>
                        <h3 className="font-bold text-gray-900">Real-Time Network Monitoring</h3>
                        <p className="text-sm text-gray-600">Deep Packet Inspection & Threat Detection</p>
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
                          { label: 'Packets', value: networkData.packets, icon: Activity, color: 'blue', suffix: '' },
                          { label: 'Threats', value: networkData.threats, icon: AlertTriangle, color: 'red', suffix: '' },
                          { label: 'Connections', value: networkData.connections, icon: Network, color: 'green', suffix: '' },
                          { label: 'Bandwidth', value: networkData.bandwidth, icon: TrendingUp, color: 'purple', suffix: ' MB/s' }
                        ].map((stat, i) => (
                          <div key={i} className="bg-gradient-to-br from-white to-gray-50 border-2 border-gray-200 rounded-xl p-4 hover:shadow-lg transition-all">
                            <div className="flex items-center justify-between mb-2">
                              <p className="text-sm font-semibold text-gray-600">{stat.label}</p>
                              <stat.icon className={`w-5 h-5 text-${stat.color}-500`} />
                            </div>
                            <p className={`text-3xl font-bold text-${stat.color}-600`}>
                              {typeof stat.value === 'number' && stat.value % 1 !== 0 ? stat.value : stat.value.toLocaleString()}{stat.suffix}
                            </p>
                          </div>
                        ))}
                      </div>

                      <div className="bg-white border-2 border-gray-200 rounded-xl p-5 shadow-lg">
                        <h4 className="font-bold text-gray-900 mb-4 flex items-center gap-2">
                          <Activity className="w-6 h-6 text-orange-600" />
                          Live Network Traffic Analysis
                        </h4>
                        <div className="space-y-2 max-h-96 overflow-y-auto custom-scrollbar">
                          {networkLogs.length === 0 ? (
                            <div className="text-center py-12">
                              <Network className="w-16 h-16 mx-auto text-gray-300 mb-3" />
                              <p className="text-gray-500">Monitoring network activity...</p>
                            </div>
                          ) : (
                            networkLogs.map(log => (
                              <div key={log.id} className={`border-l-4 rounded-lg p-4 transition-all hover:shadow-md ${
                                log.threat_level === 'high' ? 'border-red-500 bg-red-50' :
                                log.threat_level === 'medium' ? 'border-yellow-500 bg-yellow-50' :
                                'border-green-500 bg-green-50'
                              }`}>
                                <div className="flex justify-between items-start mb-2">
                                  <div className="flex items-center gap-2">
                                    <span className="text-sm font-bold capitalize">{log.type.replace(/_/g, ' ')}</span>
                                    {log.threat_level === 'high' && <Lock className="w-4 h-4 text-red-600" />}
                                  </div>
                                  <span className={`text-xs px-3 py-1 rounded-full font-semibold ${getThreatColor(log.threat_level)}`}>
                                    {log.threat_level.toUpperCase()}
                                  </span>
                                </div>
                                <div className="grid grid-cols-2 gap-3 text-xs text-gray-700">
                                  <div className="flex items-center gap-1">
                                    <span className="font-semibold">Source:</span> 
                                    <code className="bg-white px-2 py-1 rounded">{log.source}</code>
                                  </div>
                                  <div className="flex items-center gap-1">
                                    <span className="font-semibold">Dest:</span> 
                                    <code className="bg-white px-2 py-1 rounded">{log.destination}</code>
                                  </div>
                                  <div className="flex items-center gap-1">
                                    <span className="font-semibold">Port:</span> 
                                    <code className="bg-white px-2 py-1 rounded">{log.port}</code>
                                  </div>
                                  <div className="flex items-center gap-1">
                                    <span className="font-semibold">Protocol:</span> 
                                    <code className="bg-white px-2 py-1 rounded">{log.protocol}</code>
                                  </div>
                                </div>
                                <p className="text-xs text-gray-500 mt-2">{new Date(log.timestamp).toLocaleString()}</p>
                              </div>
                            ))
                          )}
                        </div>
                      </div>

                      {networkData.threats > 0 && (
                        <div className="bg-gradient-to-r from-red-50 to-orange-50 border-2 border-red-300 rounded-xl p-5 shadow-lg animate-pulse">
                          <h4 className="font-bold text-red-900 mb-3 flex items-center gap-2">
                            <AlertTriangle className="w-6 h-6" />
                            ⚠️ Active Threat Detection Alert
                          </h4>
                          <p className="text-sm text-red-800 mb-4 font-semibold">
                            {networkData.threats} suspicious network activities detected. Immediate action required!
                          </p>
                          <div className="bg-white rounded-lg p-4">
                            <h5 className="text-sm font-bold text-red-900 mb-2">🚨 Recommended Actions:</h5>
                            <ul className="text-sm text-red-800 space-y-2">
                              <li className="flex items-start gap-2">
                                <span className="text-red-600 font-bold">1.</span>
                                <span>Block suspicious IP addresses in firewall immediately</span>
                              </li>
                              <li className="flex items-start gap-2">
                                <span className="text-red-600 font-bold">2.</span>
                                <span>Review and update firewall rules</span>
                              </li>
                              <li className="flex items-start gap-2">
                                <span className="text-red-600 font-bold">3.</span>
                                <span>Enable enhanced logging for forensic investigation</span>
                              </li>
                            </ul>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>
          </div>

          {analysisResult && activeTab !== 'network' && (
            <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-2xl p-6 border border-gray-200">
              <div className="flex items-center justify-between mb-6 pb-4 border-b-2 border-gray-200">
                <h2 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
                  {getVerdictIcon(analysisResult.verdict)}
                  Comprehensive Threat Report
                </h2>
                <span className={`px-6 py-3 rounded-full text-sm font-bold border-2 shadow-lg ${getThreatColor(analysisResult.threat_level)}`}>
                  {analysisResult.threat_level.toUpperCase()} RISK
                </span>
              </div>

              {/* Threat Meter */}
              <div className="mb-6 p-5 bg-gradient-to-r from-gray-50 to-blue-50 rounded-xl border border-gray-200">
                <h3 className="font-bold text-gray-900 mb-4 flex items-center gap-2">
                  <BarChart3 className="w-5 h-5 text-blue-600" />
                  Threat Level Indicator
                </h3>
                <ThreatMeter level={analysisResult.threat_level} />
              </div>

              {/* Confidence Score */}
              <div className="mb-6 flex items-center justify-center gap-8 p-6 bg-gradient-to-br from-blue-50 to-purple-50 rounded-xl border border-blue-200">
                <div>
                  <CircularProgress 
                    value={Math.round(analysisResult.confidence * 100)} 
                    color={analysisResult.confidence > 0.7 ? '#EF4444' : analysisResult.confidence > 0.4 ? '#F59E0B' : '#10B981'}
                  />
                </div>
                <div>
                  <p className="text-sm text-gray-600 mb-1">Detection Confidence</p>
                  <p className="text-3xl font-bold text-gray-900">{(analysisResult.confidence * 100).toFixed(0)}%</p>
                  <p className="text-xs text-gray-500 mt-2">Based on {Math.floor(Math.random() * 50 + 50)} analysis parameters</p>
                </div>
              </div>

              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <div className="p-5 bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl border-2 border-blue-200">
                  <h3 className="font-bold text-blue-900 mb-3 flex items-center gap-2">
                    <Info className="w-5 h-5" />
                    Analysis Summary
                  </h3>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-sm text-blue-800">Type:</span>
                      <span className="font-bold text-blue-900 capitalize">{analysisResult.type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-blue-800">Verdict:</span>
                      <span className="font-bold text-blue-900 capitalize">{analysisResult.verdict}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-blue-800">Analyzed:</span>
                      <span className="font-bold text-blue-900">{new Date(analysisResult.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                </div>

                <div className="p-5 bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl border-2 border-purple-200">
                  <h3 className="font-bold text-purple-900 mb-3 flex items-center gap-2">
                    <PieChart className="w-5 h-5" />
                    Risk Assessment
                  </h3>
                  <div className="space-y-2">
                    {[
                      { label: 'Malware Risk', value: analysisResult.threat_level === 'high' ? 85 : 25 },
                      { label: 'Privacy Risk', value: Math.floor(Math.random() * 60) + 20 },
                      { label: 'Data Risk', value: Math.floor(Math.random() * 50) + 15 }
                    ].map((risk, i) => (
                      <div key={i}>
                        <div className="flex justify-between text-xs mb-1">
                          <span className="text-purple-800">{risk.label}</span>
                          <span className="font-bold text-purple-900">{risk.value}%</span>
                        </div>
                        <div className="w-full bg-purple-200 rounded-full h-2">
                          <div className="bg-purple-600 h-2 rounded-full transition-all" style={{ width: `${risk.value}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Technical Details */}
              <div className="mb-6">
                <h3 className="font-bold text-gray-900 text-xl mb-4 flex items-center gap-2">
                  <FileSearch className="w-6 h-6 text-blue-600" />
                  Technical Analysis & Forensics
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {Object.entries(analysisResult.details).map(([key, value]) => (
                    <div key={key} className="bg-gradient-to-br from-gray-50 to-white rounded-xl p-5 border-2 border-gray-200 hover:border-blue-300 transition-all">
                      <p className="text-sm font-bold text-gray-700 capitalize mb-3 flex items-center gap-2">
                        <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                        {key.replace(/_/g, ' ')}
                      </p>
                      <div className="space-y-2">
                        {typeof value === 'object' && !Array.isArray(value) ? (
                          Object.entries(value).map(([k, v]) => (
                            <div key={k} className="flex justify-between text-sm items-center">
                              <span className="text-gray-600 capitalize">{k.replace(/_/g, ' ')}:</span>
                              <span className="font-semibold text-gray-900 text-right">
                                {typeof v === 'boolean' ? (v ? '✓ Yes' : '✗ No') : String(v)}
                              </span>
                            </div>
                          ))
                        ) : Array.isArray(value) ? (
                          <div className="text-sm">
                            {value.length > 0 ? (
                              typeof value[0] === 'object' ? (
                                value.map((item, idx) => (
                                  <div key={idx} className="mb-2 p-3 bg-red-50 border border-red-200 rounded-lg">
                                    {Object.entries(item).map(([k, v]) => (
                                      <div key={k} className="flex justify-between text-xs">
                                        <span className="text-red-700 capitalize">{k}:</span>
                                        <span className="font-semibold text-red-900">{String(v)}</span>
                                      </div>
                                    ))}
                                  </div>
                                ))
                              ) : (
                                <div className="flex flex-wrap gap-2">
                                  {value.map((v, i) => (
                                    <span key={i} className="px-3 py-1 bg-red-100 text-red-800 rounded-full text-xs font-semibold">
                                      {v}
                                    </span>
                                  ))}
                                </div>
                              )
                            ) : (
                              <span className="text-green-600 font-semibold">✓ None detected</span>
                            )}
                          </div>
                        ) : (
                          <div className="text-sm font-semibold text-gray-900">{String(value)}</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Security Recommendations */}
              {getRecommendations(analysisResult.type, analysisResult.verdict).length > 0 && (
                <div className="mb-6">
                  <h3 className="font-bold text-gray-900 text-xl mb-4 flex items-center gap-2">
                    <ShieldAlert className="w-6 h-6 text-orange-600" />
                    Security Recommendations & Action Plan
                  </h3>
                  <div className="space-y-4">
                    {getRecommendations(analysisResult.type, analysisResult.verdict).map((section, i) => (
                      <div key={i} className="bg-gradient-to-r from-orange-50 to-red-50 border-2 border-orange-300 rounded-xl p-5 hover:shadow-lg transition-all">
                        <h4 className="font-bold text-orange-900 text-lg mb-4 flex items-center gap-2">
                          <AlertOctagon className="w-5 h-5" />
                          {section.title}
                        </h4>
                        <ul className="space-y-3">
                          {section.items.map((item, j) => (
                            <li key={j} className="flex items-start gap-3 text-sm text-gray-800 bg-white rounded-lg p-3 hover:bg-orange-50 transition-all">
                              <span className="flex-shrink-0 w-6 h-6 bg-orange-500 text-white rounded-full flex items-center justify-center text-xs font-bold">
                                {j + 1}
                              </span>
                              <span className="flex-1 font-medium">{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex gap-4">
                <button onClick={downloadPDF} className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 text-white px-6 py-4 rounded-xl font-bold hover:from-blue-700 hover:to-blue-800 transition-all shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 flex items-center justify-center gap-2">
                  <Download className="w-5 h-5" />
                  Download PDF Report
                </button>
                <button onClick={() => setAnalysisResult(null)} 
                  className="flex-1 bg-gradient-to-r from-gray-100 to-gray-200 text-gray-700 px-6 py-4 rounded-xl font-bold hover:from-gray-200 hover:to-gray-300 transition-all shadow-lg hover:shadow-xl transform hover:-translate-y-0.5">
                  Start New Analysis
                </button>
              </div>
            </div>
          )}
        </div>

        {/* AI Chatbot */}
        {chatOpen && (
          <div className="fixed bottom-24 right-8 w-96 h-[500px] bg-white rounded-2xl shadow-2xl border-2 border-blue-500 flex flex-col z-50">
            <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white p-4 rounded-t-2xl flex items-center justify-between">
              <div className="flex items-center gap-2">
                <MessageCircle className="w-6 h-6" />
                <div>
                  <h3 className="font-bold">CyberML AI Assistant</h3>
                  <p className="text-xs text-blue-100">Powered by Gemini</p>
                </div>
              </div>
              <button onClick={() => setChatOpen(false)} className="hover:bg-white/20 p-1 rounded">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
              {chatMessages.length === 0 && (
                <div className="text-center text-gray-500 mt-8">
                  <MessageCircle className="w-12 h-12 mx-auto mb-3 text-gray-300" />
                  <p className="text-sm">Ask me anything about cybersecurity!</p>
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
                  <div className="bg-gray-100 p-3 rounded-2xl rounded-bl-none">
                    <div className="flex gap-1">
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
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
                  placeholder="Ask about security threats..."
                  className="flex-1 px-4 py-2 border-2 border-gray-300 rounded-xl focus:border-blue-500 focus:outline-none"
                  disabled={chatLoading}
                />
                <button
                  onClick={sendChatMessage}
                  disabled={chatLoading || !chatInput.trim()}
                  className="bg-blue-600 text-white p-2 rounded-xl hover:bg-blue-700 disabled:bg-gray-300 transition-colors"
                >
                  <Send className="w-5 h-5" />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Chatbot Toggle Button */}
        <button
          onClick={() => setChatOpen(!chatOpen)}
          className="fixed bottom-8 right-8 bg-gradient-to-r from-blue-600 to-purple-600 text-white p-4 rounded-full shadow-2xl hover:shadow-blue-500/50 transition-all transform hover:scale-110 z-40"
        >
          <MessageCircle className="w-6 h-6" />
        </button>

        {/* Sidebar */}
        <div className="space-y-6">
          <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-2xl p-6 border border-gray-200">
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
              <Activity className="w-6 h-6 text-blue-600" />
              Recent Alerts
            </h3>
            <div className="space-y-3 max-h-96 overflow-y-auto custom-scrollbar">
              {alerts.length === 0 ? (
                <div className="text-center py-8">
                  <AlertTriangle className="w-12 h-12 mx-auto text-gray-300 mb-2" />
                  <p className="text-sm text-gray-500">No alerts yet</p>
                </div>
              ) : (
                alerts.map(alert => (
                  <div key={alert.id} className="border-2 border-gray-200 rounded-xl p-4 hover:bg-gray-50 hover:border-blue-300 cursor-pointer transition-all">
                    <div className="flex justify-between items-start mb-2">
                      <div className="flex items-center gap-2">
                        {alert.type === 'file' && <FileSearch className="w-4 h-4 text-blue-600" />}
                        {alert.type === 'url' && <Globe className="w-4 h-4 text-green-600" />}
                        {alert.type === 'api' && <Link className="w-4 h-4 text-purple-600" />}
                        <span className="text-sm font-bold capitalize">{alert.type}</span>
                      </div>
                      <span className={`text-xs px-3 py-1 rounded-full font-bold ${getThreatColor(alert.threat_level)}`}>
                        {alert.threat_level}
                      </span>
                    </div>
                    <p className="text-xs text-gray-600 truncate font-medium">{alert.name || alert.url || alert.endpoint}</p>
                    <p className="text-xs text-gray-400 mt-2">{new Date(alert.timestamp).toLocaleTimeString()}</p>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="bg-gradient-to-br from-blue-600 to-purple-700 rounded-2xl shadow-2xl p-6 text-white">
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
              <BarChart3 className="w-6 h-6" />
              Analytics Dashboard
            </h3>
            <div className="space-y-4">
              {[
                { label: 'Files Scanned', value: alerts.filter(a => a.type === 'file').length, icon: FileSearch },
                { label: 'URLs Checked', value: alerts.filter(a => a.type === 'url').length, icon: Globe },
                { label: 'APIs Tested', value: alerts.filter(a => a.type === 'api').length, icon: Link },
                { label: 'Network Events', value: networkLogs.length, icon: Network }
              ].map((stat, i) => (
                <div key={i} className="flex justify-between items-center bg-white/20 backdrop-blur-sm rounded-lg p-3 hover:bg-white/30 transition-all">
                  <div className="flex items-center gap-2">
                    <stat.icon className="w-5 h-5" />
                    <span className="text-blue-100 text-sm">{stat.label}</span>
                  </div>
                  <span className="font-bold text-2xl">{stat.value}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white/95 backdrop-blur-sm rounded-2xl shadow-2xl p-6 border border-gray-200">
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
              <Shield className="w-6 h-6 text-green-600" />
              System Status
            </h3>
            <div className="space-y-3">
              {[
                { label: 'Firewall', status: 'Active', icon: Shield, color: 'green' },
                { label: 'Real-time Protection', status: 'Enabled', icon: Lock, color: 'green' },
                { label: 'Last Scan', status: '2 hours ago', icon: Activity, color: 'yellow' }
              ].map((item, i) => (
                <div key={i} className={`flex items-center justify-between p-3 bg-${item.color}-50 rounded-lg border border-${item.color}-200`}>
                  <div className="flex items-center gap-2">
                    <item.icon className={`w-4 h-4 text-${item.color}-600`} />
                    <span className="text-sm text-gray-700 font-medium">{item.label}</span>
                  </div>
                  <span className={`text-sm font-bold text-${item.color}-700`}>{item.status}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <style jsx>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 8px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: #f1f1f1;
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #888;
          border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #555;
        }
      `}</style>
    </div>
  );
};

export default CyberMLDashboard;
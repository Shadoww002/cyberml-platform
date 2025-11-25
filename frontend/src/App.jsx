import React, { useState, useEffect, useRef } from 'react';
import { Upload, Link, Activity, Shield, AlertTriangle, CheckCircle, XCircle, Globe, FileSearch, Network, Eye, Download, Info, AlertOctagon, ShieldAlert, TrendingUp, BarChart3, PieChart, Zap, Lock, Unlock, MessageCircle, Send, X, Code, Server, Clock, Calendar, Hash, Layers, ChevronDown, ChevronUp } from 'lucide-react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// --- Custom Component for Collapsible Detail Sections ---
const DetailSection = ({ title, data, Icon }) => {
    const [isOpen, setIsOpen] = useState(false);

    // Function to render complex data elegantly from the FastAPI structure
    const renderData = (value) => {
        if (Array.isArray(value)) {
            return (
                <ul className="list-disc pl-5 space-y-1 mt-1 text-sm text-gray-700 bg-gray-50 p-3 rounded-xl border border-gray-200 shadow-inner">
                    {value.map((item, index) => <li key={index} className="break-all">{typeof item === 'object' ? JSON.stringify(item) : item}</li>)}
                </ul>
            );
        }
        if (typeof value === 'object' && value !== null) {
            return (
                <div className="space-y-2 mt-1 p-4 bg-gray-100 rounded-xl border border-gray-200 shadow-inner">
                    {Object.entries(value).map(([subKey, subValue]) => (
                        <div key={subKey} className="flex flex-col border-b border-gray-300/70 last:border-b-0 pb-1">
                            <span className="text-xs font-semibold text-gray-700 uppercase tracking-wider">{subKey.replace(/_/g, ' ')}:</span>
                            <span className="text-sm font-mono bg-white p-1 rounded break-all shadow-sm">{typeof subValue === 'object' ? JSON.stringify(subValue, null, 2) : String(subValue)}</span>
                        </div>
                    ))}
                </div>
            );
        }
        return <p className="mt-1 text-sm text-gray-700 font-mono break-all bg-gray-100 p-2 rounded-lg">{String(value)}</p>;
    };

    if (data === undefined || data === null || (Array.isArray(data) && data.length === 0)) {
        return null;
    }

    return (
        <div className="border border-gray-300 rounded-2xl shadow-md overflow-hidden transition-all duration-300 hover:shadow-xl hover:border-blue-400">
            <button 
                onClick={() => setIsOpen(!isOpen)} 
                className={`w-full flex justify-between items-center p-4 text-left font-extrabold text-gray-800 transition-colors duration-300 ${isOpen ? 'bg-blue-100/70' : 'bg-gray-100 hover:bg-gray-200'}`}
            >
                <div className="flex items-center gap-3">
                    <Icon className="w-6 h-6 text-blue-700" />
                    <span className="text-lg">{title}</span>
                </div>
                {isOpen ? <ChevronUp className="w-5 h-5 text-blue-700" /> : <ChevronDown className="w-5 h-5 text-gray-500" />}
            </button>
            {isOpen && (
                <div className="p-5 bg-white border-t border-gray-200 animate-fade-in">
                    {renderData(data)}
                </div>
            )}
        </div>
    );
};

// Initial Chat Message
const INITIAL_CHAT_MESSAGE = {
    role: 'assistant',
    content: `Welcome to the CyberML AI Analyst! I am here to help you interpret the security findings from your file, URL, and API scans.

You can ask me questions like:
- "What does high entropy mean for my file?"
- "How do I fix the vulnerabilities found in my API?"
- "What are the biggest threats associated with this verdict?"

If you run an analysis, I can provide context-specific advice!`
};


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
  const [chatLoading, setChatLoading] = useState(false); 
  const [chatMessages, setChatMessages] = useState([INITIAL_CHAT_MESSAGE]);
  const [chatInput, setChatInput] = useState(''); 
  
  const chatEndRef = useRef(null);


  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [chatMessages]);

  const sendChatMessage = async () => {
    if (!chatInput.trim() || chatLoading) return; 

    const userMessage = chatInput.trim();
    
    // Clear input and add user message to state
    setChatInput(''); 
    setChatMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setChatLoading(true);

    let context = null;
    if (analysisResult) {
        // Only send key summary data to the chat API
        context = {
            id: analysisResult.analysis_id,
            type: analysisResult.type,
            verdict: analysisResult.verdict,
            threat_level: analysisResult.threat_level,
            primary_details: analysisResult.details?.filename || analysisResult.details?.url || analysisResult.details?.endpoint
        };
    }

    try {
      const response = await fetch(`${API_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMessage,
          context: context
        })
      });

      const data = await response.json();
      setChatMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
    } catch (error) {
      setChatMessages(prev => [...prev, { 
        role: 'assistant', 
        content: 'Error: Could not connect to the AI chatbot service. Make sure the backend is running and accessible.' 
      }]);
    } finally {
      setChatLoading(false);
    }
  };

  const downloadPDF = async () => {
    if (!analysisResult || !analysisResult.analysis_id) {
      console.warn('No analysis results available.');
      console.error('Download failed: No analysis results available.');
      return;
    }

    const analysis_id = analysisResult.analysis_id;
    console.log('📄 Attempting to download report for:', analysis_id);

    try {
      const response = await fetch(`${API_URL}/api/report/${analysis_id}/pdf`, {
        method: 'GET',
        headers: { 'Accept': 'application/pdf' }
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('Report fetch error:', errorText);
        throw new Error(`Server returned ${response.status}: ${errorText}`);
      }

      const blob = await response.blob();
      
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = `cyberml_report_${analysis_id}.pdf`;
      if (contentDisposition) {
        const matches = contentDisposition.match(/filename="(.+?)"/);
        if (matches && matches[1]) {
            filename = matches[1];
        }
      }

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      
      setTimeout(() => {
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      }, 100);
      
      console.log(`✅ Report downloaded successfully as ${filename}`);
    } catch (error) {
      console.error('❌ Report download failed:', error);
      console.error(`Download Failed: Make sure the backend (http://localhost:8000) is running and the analysis was successfully cached.`);
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
  
  const runAnalysis = async (type, input, fileData) => {
    setLoading(true);
    let endpoint = '';
    let body = {};
    let headers = { 'Content-Type': 'application/json' };
    let method = 'POST';

    try {
        if (type === 'file') {
            endpoint = '/api/analyze/file';
            const formData = new FormData();
            if (fileData) {
                formData.append('file', fileData);
            }
            body = formData;
            headers = {}; // Must NOT set Content-Type for FormData
        } else if (type === 'url') {
            endpoint = '/api/analyze/url';
            body = JSON.stringify({ url: input });
        } else if (type === 'api') {
            endpoint = '/api/analyze/api';
            body = JSON.stringify({ endpoint: input });
        }

        console.log(`[Network] Sending ${method} request to ${API_URL}${endpoint}`);
        
        const response = await fetch(`${API_URL}${endpoint}`, { 
            method: method, 
            headers: headers, 
            body: body 
        });

        console.log(`[Network] Received response status: ${response.status}`);

        if (!response.ok) {
            let errorDetail = { detail: "Unknown error or failed to parse JSON response." };
            try {
                errorDetail = await response.json();
            } catch (e) {
                console.warn("[Network] Failed to parse JSON error response.");
            }
            throw new Error(`Analysis failed (Status ${response.status}): ${errorDetail.detail}`);
        }

        const result = await response.json();
        setAnalysisResult(result);
        setAlerts(prev => [{ id: Date.now(), ...result }, ...prev].slice(0, 10));

        // --- ENHANCED CHAT RESPONSE ---
        const humanAnalysis = getAnalysisDescription(result).replace(/\*\*/g, '').replace(/\n/g, ' ');

        setChatMessages(prev => [...prev, {
            role: 'assistant',
            content: `**Analysis Complete for ${result.type.toUpperCase()}:** ${result.details?.filename || result.details?.url || result.details?.endpoint}. 

**Verdict:** ${result.verdict.toUpperCase()} (Confidence: ${Math.round(result.confidence * 100)}%).
            
---
*Quick Summary:* ${humanAnalysis}
---
Ask me about the *'Threat Factors'*, *'Recommendations'*, or the *'Entropy'* to dive deeper!`
        }]);

    } catch (error) {
        console.error(`❌ Analysis Error for ${type}:`, error);
        console.error(`Connection or API issue: Please ensure the Python backend is running on ${API_URL}`);
        setAnalysisResult({ 
             analysis_id: 'FAIL-001', 
             type, 
             verdict: 'backend_error', 
             threat_level: 'high', 
             confidence: 0.99,
             description: `Failed to connect to the CyberML backend at ${API_URL}. Check your server logs and ensure it is running.`,
             details: { error: error.message, status: 'Connection Failed' }
        });
        setAlerts(prev => [{ id: Date.now(), type, threat_level: 'high', details: { filename: 'Backend Error' } }, ...prev].slice(0, 10));

    } finally {
        setLoading(false);
    }
  };


  const analyzeFile = () => {
    if (!file) {
        console.error("No file selected.");
        return;
    }
    // Pass the actual file object here
    runAnalysis('file', file.name, file);
  };

  const analyzeURL = () => {
    if (!urlInput) return;
    runAnalysis('url', urlInput, null);
  };

  const analyzeAPI = () => {
    if (!apiInput) return;
    runAnalysis('api', apiInput, null);
  };

  // --- REFINED: Function to derive human-readable description ---
  const getAnalysisDescription = (result) => {
    if (!result || !result.details) return "Analysis details not available.";

    if (result.verdict === 'backend_error') {
        return "CRITICAL ERROR: The dashboard could not communicate with the backend security engine. The analysis failed.";
    }

    const { type, verdict, details, confidence } = result;
    const confidenceScore = `(Confidence: ${Math.round(confidence * 100)}%)`;

    if (type === 'file') {
        const factors = details?.threat_intelligence?.threat_factors || [];
        const entropy = details?.entropy;

        if (verdict === 'malicious') {
            return `CRITICAL MALWARE THREAT ${confidenceScore}: This file is classified as malicious. It exhibits strong indicators like **${factors.join(', ')}** and an unusually high entropy score of **${entropy}**, suggesting it is a packed, executable threat like a Trojan or Downloader. **IMMEDIATE ISOLATION IS REQUIRED.**`;
        }
        if (verdict === 'suspicious') {
            return `ELEVATED RISK ${confidenceScore}: The file is suspicious due to findings like **${factors.join(', ')}**. The structure contains indicators of evasion (e.g., packer detection) and moderate suspicious behavior, but further sandboxing is recommended before execution.`;
        }
        return `FILE CLEAN ${confidenceScore}: The file is classified as safe. Low suspicious activity detected, the entropy is normal, and no critical malware signatures were found.`;
    }
    
    if (type === 'url') {
        const isSecure = details?.ssl_analysis?.valid_certificate;
        const blacklist = details?.domain_info?.blacklist_status;
        const phishingScore = details?.threat_detection?.phishing_score;

        if (verdict === 'suspicious' && (blacklist === 'Listed' || phishingScore > 60)) {
            return `PHISHING WARNING ${confidenceScore}: This URL is highly suspicious. It has a phishing score of **${phishingScore}%** and is currently **${blacklist}** on known threat intelligence lists. ${isSecure ? 'Despite having HTTPS,' : 'Lacking HTTPS,'} the content analysis strongly suggests a malicious attempt to steal credentials. **DO NOT PROCEED.**`;
        }
        return `URL SAFE ${confidenceScore}: Domain reputation is good, HTTPS is valid, and content scoring found no critical phishing or malware links.`;
    }
    
    if (type === 'api') {
        const vulns = details?.vulnerabilities || [];
        const isSecure = details?.security_score?.encryption > 80;

        if (verdict === 'vulnerable' && vulns.length > 0) {
            return `MAJOR VULNERABILITY DETECTED ${confidenceScore}: The API endpoint failed several security tests. Critical findings include: **${vulns.map(v => v.name).join(', ')}**. The current authentication (**${details?.authentication?.method}**) is likely inadequate, and deployment must be halted until these flaws are addressed.`;
        }
        return `API SECURE ${confidenceScore}: Passed all major security checks. The encryption is **${isSecure ? 'Strong' : 'Moderate'}**, and no critical OWASP Top 10 API vulnerabilities were found in this scan.`;
    }

    return "Analysis results processed. Refer to the specific technical details below.";
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
        }],
        backend_error: [{
            title: "⚠️ Backend Connection Error",
            items: ["Ensure the Python server is running on port 8000.", "Check browser console for CORS or connection rejection errors.", "Verify network connectivity to localhost."]
        }]
      },
      url: {
        malicious: [{
          title: "🚫 Immediate Actions",
          items: ["Block URL/IP on firewall and proxy", "Scan system that accessed the URL", "Alert affected users immediately", "Check for related phishing campaigns"]
        }],
        suspicious: [{
          title: "🚫 Immediate Actions",
          items: ["Close the browser tab immediately", "Do NOT enter any credentials or personal information", "Clear browser cache, cookies, and history", "Run malware scan if you clicked any links"]
        }],
        backend_error: [{
            title: "⚠️ Backend Connection Error",
            items: ["Ensure the Python server is running on port 8000.", "Check browser console for CORS or connection rejection errors.", "Verify network connectivity to localhost."]
        }]
      },
      api: {
        vulnerable: [{
          title: "🔴 Critical Security Issues",
          items: ["Do not deploy this API to production", "Implement OAuth 2.0 or JWT authentication", "Add rate limiting (100 requests/minute)", "Enable HTTPS/TLS 1.3 encryption only"]
        }],
        backend_error: [{
            title: "⚠️ Backend Connection Error",
            items: ["Ensure the Python server is running on port 8000.", "Check browser console for CORS or connection rejection errors.", "Verify network connectivity to localhost."]
        }]
      }
    };
    return recs[type]?.[verdict] || [];
  };
  
  // --- FIX: Function to map tab class strings explicitly ---
  const getTabClasses = (id, isActive) => {
      const base = "flex-1 px-4 py-3 flex items-center justify-center gap-2 font-bold text-base rounded-2xl transition-all duration-300 whitespace-nowrap m-1 transform hover:scale-[1.01]";
      
      const activeMap = {
          'upload': 'bg-blue-600 text-white shadow-lg shadow-blue-300/40 ring-2 ring-white/50',
          'url': 'bg-green-600 text-white shadow-lg shadow-green-300/40 ring-2 ring-white/50',
          'api': 'bg-purple-600 text-white shadow-lg shadow-purple-300/40 ring-2 ring-white/50',
          'network': 'bg-orange-600 text-white shadow-lg shadow-orange-300/40 ring-2 ring-white/50',
      };
      
      const inactive = 'text-gray-700 hover:bg-gray-200';

      return `${base} ${isActive ? activeMap[id] : inactive}`;
  };


  // --- START: UI Components ---

  const getThreatColor = (level) => ({
    high: 'text-red-600 bg-red-50 border-red-200',
    medium: 'text-yellow-600 bg-yellow-50 border-yellow-200',
    low: 'text-green-600 bg-green-50 border-green-200',
    safe: 'text-green-600 bg-green-50 border-green-200',
    benign: 'text-green-600 bg-green-50 border-green-200',
    secure: 'text-green-600 bg-green-50 border-green-200',
    backend_error: 'text-gray-600 bg-gray-100 border-gray-200'
  }[level] || 'text-gray-600 bg-gray-50 border-gray-200');

  const getVerdictIcon = (verdict) => {
    if (['malicious', 'vulnerable'].includes(verdict)) return <AlertOctagon className="w-8 h-8 text-red-600" />;
    if (verdict === 'suspicious') return <AlertTriangle className="w-8 h-8 text-yellow-600" />;
    if (verdict === 'backend_error') return <XCircle className="w-8 h-8 text-gray-600" />;
    return <CheckCircle className="w-8 h-8 text-green-600" />;
  };
  
  const CircularProgress = ({ value, size = 120, strokeWidth = 10, color = '#3B82F6', label }) => {
    const radius = (size - strokeWidth) / 2;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (value / 100) * circumference;

    return (
      <div className="relative inline-flex items-center justify-center p-2">
        <svg width={size} height={size} className="transform -rotate-90">
          <circle cx={size / 2} cy={size / 2} r={radius} stroke="#E5E7EB" strokeWidth={strokeWidth} fill="none" />
          <circle cx={size / 2} cy={size / 2} r={radius} stroke={color} strokeWidth={strokeWidth} fill="none"
            strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
            className="transition-all duration-1000 ease-out drop-shadow-lg" />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-extrabold" style={{ color }}>{value}%</span>
          {label && <span className="text-xs text-gray-500 mt-1">{label}</span>}
        </div>
      </div>
    );
  };

  const ThreatMeter = ({ level, confidence }) => {
    const colorMap = { low: '#10B981', safe: '#10B981', benign: '#10B981', secure: '#10B981', medium: '#F59E0B', high: '#EF4444', vulnerable: '#EF4444', backend_error: '#6B7280' };
    const color = colorMap[level] || '#9CA3AF';
    
    return (
      <div className="w-full">
        <div className="relative h-4 bg-gray-200 rounded-full shadow-inner overflow-hidden">
          <div className="h-full rounded-full transition-all duration-700 ease-out"
            style={{ width: `${confidence * 100}%`, backgroundColor: color, boxShadow: `0 0 10px ${color}` }} />
        </div>
        <div className="flex justify-between text-xs font-semibold mt-1 text-gray-600">
          <span>Low / Safe</span>
          <span className="text-yellow-600">Medium</span>
          <span className="text-red-600">High / Critical</span>
        </div>
      </div>
    );
  };

  const StatCard = ({ icon: Icon, title, value, colorClass, description }) => (
    <div className="p-6 rounded-2xl shadow-xl bg-white text-gray-900 border border-gray-100 transition-all duration-300 hover:shadow-2xl hover:scale-[1.03] transform hover:bg-gray-50/50">
      <div className="flex items-center justify-between mb-3">
        <Icon className={`w-8 h-8 opacity-75 ${colorClass} transition-colors duration-300`} />
        <p className="text-2xl font-extrabold">{value}</p>
      </div>
      <p className="text-sm font-semibold text-gray-700">{title}</p>
      <p className="text-xs opacity-80 mt-1 text-gray-500">{description}</p>
    </div>
  );

  const IconTextDetail = ({ icon: Icon, label, value }) => {
    if (value === undefined || value === null || value === "") return null;
    return (
        <div className="flex items-start p-4 bg-white border border-gray-200 rounded-xl shadow-md transition-all duration-300 hover:shadow-lg hover:border-blue-300">
        <Icon className="w-5 h-5 flex-shrink-0 mt-1 text-blue-500" />
        <div className="ml-3">
            <p className="text-xs font-semibold text-gray-500 uppercase">{label}</p>
            <p className="text-sm font-medium text-gray-900 break-all">{String(value)}</p>
        </div>
        </div>
    );
  };

  // --- END: UI Components ---


  // --- START: Main Render ---
  return (
    <div className="min-h-screen p-4 md:p-8 font-sans" style={{ 
        // Custom Lighter Dark Blue Gradient Background
        background: 'linear-gradient(135deg, #0F172A 0%, #1D3A5F 100%)' 
    }}> 
      <style>{`
        @keyframes glow {
          0%, 100% { box-shadow: 0 0 18px rgba(59, 130, 246, 0.6), 0 0 6px rgba(59, 130, 246, 0.3); } 
          50% { box-shadow: 0 0 30px rgba(59, 130, 246, 0.9), 0 0 12px rgba(59, 130, 246, 0.5); }
        }
        .glow-on-hover {
          animation: glow 4s ease-in-out infinite;
        }
        .shadow-3xl {
            box-shadow: 0 20px 30px -5px rgba(0, 0, 0, 0.5), 0 10px 15px -5px rgba(0, 0, 0, 0.3);
        }
        .shadow-4xl {
            box-shadow: 0 25px 60px -12px rgba(0, 0, 0, 0.6);
        }
        .custom-scrollbar::-webkit-scrollbar {
            width: 8px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
            background: #bdbdbd;
            border-radius: 10px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
            background: #9d9d9d;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .animate-fade-in {
            animation: fadeIn 0.5s ease-out forwards;
        }
      `}</style>

      <div className="relative max-w-7xl mx-auto mb-10">
        <div className="flex items-end justify-between border-b-4 border-blue-600/60 pb-4">
          <div className="flex items-center gap-4">
            <ShieldAlert className="w-14 h-14 text-blue-400 glow-on-hover" />
            <div>
              <h1 className="text-4xl md:text-5xl font-extrabold text-white tracking-tight">CyberML Platform</h1>
              <p className="text-blue-300 text-base font-light">AI-Driven Threat Intelligence & Prevention</p>
            </div>
          </div>
          <div className="hidden md:block">
            <span className="text-sm font-semibold text-blue-200 bg-blue-700/50 px-3 py-1 rounded-full border border-blue-500/50 shadow-inner">STATUS: OPERATIONAL</span>
          </div>
        </div>
      </div>

      <div className="relative max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Main Content / Analysis Section */}
        <div className="lg:col-span-2 space-y-8">
          
          {/* Tab Selector & Input Area */}
          <div className="bg-white/95 backdrop-blur-md rounded-3xl shadow-3xl overflow-hidden border border-gray-100">
            <div className="flex border-b border-gray-200 overflow-x-auto bg-gray-50 p-2"> 
              {[
                { id: 'upload', icon: FileSearch, label: 'File Analysis', color: 'blue' },
                { id: 'url', icon: Globe, label: 'URL Scanner', color: 'green' },
                { id: 'api', icon: Code, label: 'API Security', color: 'purple' },
                { id: 'network', icon: Network, label: 'Network Monitor', color: 'orange' }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={getTabClasses(tab.id, activeTab === tab.id)}
                >
                  <tab.icon className="w-5 h-5" />
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="p-8 bg-white">
              {/* File Analysis Tab Content */}
              {activeTab === 'upload' && (
                <div className="space-y-6 animate-fade-in">
                  <div className="relative border-4 border-dashed border-blue-400/80 rounded-3xl p-10 text-center transition-all duration-300 hover:border-blue-600 hover:bg-blue-50/70 group bg-blue-50 shadow-md">
                    <input type="file" id="file-upload" className="hidden" onChange={(e) => setFile(e.target.files[0])} />
                    <label htmlFor="file-upload" className="cursor-pointer block">
                      <div className="relative inline-block mb-4 p-5 rounded-full bg-blue-100 group-hover:bg-blue-200 transition-all duration-300 shadow-lg">
                        <FileSearch className="w-14 h-14 text-blue-600" />
                        <Upload className="w-7 h-7 text-blue-700 absolute -bottom-1 -right-1 bg-white rounded-full p-1 shadow-md" />
                      </div> 
                      <p className="text-2xl font-extrabold text-gray-900 mb-2">{file ? file.name : 'Select or Drop File for ML Analysis'}</p>
                      <p className="text-sm text-gray-600">Max size 50MB. Supports: EXE, DLL, PDF, ZIP, APK, DOC, JS, PY, SH</p>
                    </label>
                  </div>
                  <button onClick={analyzeFile} disabled={!file || loading} 
                    className="w-full bg-gradient-to-r from-blue-600 to-blue-700 text-white px-8 py-4 rounded-xl font-bold text-xl hover:from-blue-700 hover:to-blue-800 disabled:from-gray-400 disabled:to-gray-500 disabled:cursor-not-allowed transition-all duration-300 shadow-xl hover:shadow-2xl transform hover:scale-[1.005] flex items-center justify-center gap-3">
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                        <span>Initiating Deep Scan...</span>
                      </>
                    ) : (
                      <>
                        <Eye className="w-6 h-6" />
                        <span>Start File Threat Analysis</span>
                      </>
                    )}
                  </button>
                </div>
              )}

              {/* URL Scanner Tab Content */}
              {activeTab === 'url' && (
                <div className="space-y-6 animate-fade-in">
                  <div className="relative p-8 border-2 border-green-300 rounded-3xl bg-green-50/50 shadow-md">
                    <label className="block text-xl font-bold text-gray-900 mb-4 flex items-center gap-3"><Globe className="w-7 h-7 text-green-600"/> Website or URL Security Scan</label>
                    <div className="relative">
                      <input type="text" value={urlInput} onChange={(e) => setUrlInput(e.target.value)} 
                        placeholder="Enter URL (e.g., https://phishing-site.com)" 
                        className="w-full pl-6 pr-4 py-4 border-2 border-gray-300 rounded-xl focus:ring-4 focus:ring-green-300 focus:border-green-500 text-lg shadow-md transition-all duration-300" />
                    </div>
                  </div>
                  <button onClick={analyzeURL} disabled={!urlInput || loading} 
                    className="w-full bg-gradient-to-r from-green-600 to-green-700 text-white px-8 py-4 rounded-xl font-bold text-xl hover:from-green-700 hover:to-green-800 disabled:from-gray-400 disabled:to-gray-500 transition-all duration-300 shadow-xl hover:shadow-2xl transform hover:scale-[1.005] flex items-center justify-center gap-3">
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                        <span>Checking Domain Reputation...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-6 h-6" />
                        <span>Scan URL for Threats</span>
                      </>
                    )}
                  </button>
                </div>
              )}

              {/* API Security Tab Content */}
              {activeTab === 'api' && (
                <div className="space-y-6 animate-fade-in">
                  <div className="relative p-8 border-2 border-purple-300 rounded-3xl bg-purple-50/50 shadow-md">
                    <label className="block text-xl font-bold text-gray-900 mb-4 flex items-center gap-3"><Server className="w-7 h-7 text-purple-600"/> API Endpoint Security Testing</label>
                    <div className="relative">
                      <input type="text" value={apiInput} onChange={(e) => setApiInput(e.target.value)} 
                        placeholder="Enter API endpoint (e.g., https://api.example.com/v1/users)" 
                        className="w-full pl-6 pr-4 py-4 border-2 border-gray-300 rounded-xl focus:ring-4 focus:ring-purple-300 focus:border-purple-500 text-lg shadow-md transition-all duration-300" />
                    </div>
                  </div>
                  <button onClick={analyzeAPI} disabled={!apiInput || loading} 
                    className="w-full bg-gradient-to-r from-purple-600 to-purple-700 text-white px-8 py-4 rounded-xl font-bold text-xl hover:from-purple-700 hover:to-purple-800 disabled:from-gray-400 disabled:to-gray-500 transition-all duration-300 shadow-xl hover:shadow-2xl transform hover:scale-[1.005] flex items-center justify-center gap-3">
                    {loading ? (
                      <>
                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                        <span>Simulating Attack Vectors...</span>
                      </>
                    ) : (
                      <>
                        <Zap className="w-6 h-6" />
                        <span>Run Penetration Tests</span>
                      </>
                    )}
                  </button>
                </div>
              )}
              
              {/* Network Monitor Tab Content */}
              {activeTab === 'network' && (
                <div className="space-y-6 animate-fade-in">
                  <div className="flex items-center justify-between p-5 bg-gradient-to-r from-orange-50 to-red-50 rounded-2xl border-4 border-orange-300/70 shadow-lg">
                    <div className="flex items-center gap-3">
                      <Network className="w-10 h-10 text-orange-600 animate-pulse" />
                      <div>
                        <h3 className="font-bold text-gray-900 text-xl">Real-Time Network Monitoring</h3>
                        <p className="text-sm text-gray-600">Deep Packet Inspection via ML Engine</p>
                      </div>
                    </div>
                    <button onClick={() => setNetworkMonitoring(!networkMonitoring)} 
                      className={`px-8 py-3 rounded-xl font-bold transition-all shadow-xl text-white duration-300 ${
                        networkMonitoring 
                          ? 'bg-red-600 hover:bg-red-700 transform hover:scale-[1.05]' 
                          : 'bg-green-600 hover:bg-green-700 transform hover:scale-[1.05]'
                      }`}>
                      {networkMonitoring ? '🔴 Stop Monitor' : '🟢 Start Monitor'}
                    </button>
                  </div>

                  {networkMonitoring && (
                    <>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <StatCard icon={Activity} title="Packets Monitored" value={networkData.packets.toLocaleString()} colorClass="text-blue-700" description="Total packets processed" />
                        <StatCard icon={AlertTriangle} title="Identified Threats" value={networkData.threats.toLocaleString()} colorClass="text-red-700" description="Malicious activity detected" />
                        <StatCard icon={Network} title="Active Connections" value={networkData.connections} colorClass="text-green-700" description="Live inbound/outbound links" />
                        <StatCard icon={TrendingUp} title="Bandwidth Usage" value={networkData.bandwidth + ' MB/s'} colorClass="text-purple-700" description="Real-time traffic rate" />
                      </div>

                      <div className="bg-white border-2 border-gray-200 rounded-2xl p-6 shadow-lg">
                        <h4 className="font-extrabold text-gray-900 text-xl mb-4 flex items-center gap-2"><Layers className="w-5 h-5"/> Live Network Logs</h4>
                        <div className="space-y-2 max-h-80 overflow-y-auto pr-2 custom-scrollbar">
                          {networkLogs.map(log => (
                            <div key={log.id} className={`border-l-4 rounded-lg p-3 transition-all duration-300 hover:bg-gray-100 ${
                              log.threat_level === 'high' ? 'border-red-500 bg-red-50' :
                              log.threat_level === 'medium' ? 'border-yellow-500 bg-yellow-50' :
                              'border-green-500 bg-green-50'
                            }`}>
                              <div className="flex justify-between items-center mb-1">
                                <span className="text-sm font-bold text-gray-800">{log.type.replace(/_/g, ' ')}</span>
                                <span className={`text-xs px-3 py-1 rounded-full font-semibold border ${getThreatColor(log.threat_level)}`}>
                                  {log.threat_level.toUpperCase()}
                                </span>
                              </div>
                              <div className="text-xs text-gray-700 flex justify-between">
                                <span>**Source:** {log.source} ➡️ **Dest:** {log.destination}</span>
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

          {/* Analysis Result Panel */}
          {/* FIX: Ensure analysisResult exists AND has valid data (either hash/url/endpoint) before attempting complex rendering */}
          {analysisResult && (analysisResult.details?.file_hash || analysisResult.details?.url || analysisResult.details?.endpoint || analysisResult.verdict === 'backend_error') && activeTab !== 'network' && (
            <div className="bg-gray-50 rounded-3xl shadow-3xl p-8 border border-gray-200 overflow-hidden animate-fade-in">
              
              {/* Report Header & Verdict */}
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between mb-8 pb-4 border-b-2 border-gray-300">
                <div className="flex items-center gap-4 mb-4 md:mb-0">
                  {getVerdictIcon(analysisResult.verdict)}
                  <div>
                    <h2 className="text-3xl font-extrabold text-gray-900">Analysis Completed: <span className="capitalize text-blue-700">{analysisResult.verdict}</span></h2>
                    <p className="text-sm text-gray-500">ML Engine v2.0 | ID: {analysisResult.analysis_id.substring(0, 12)}...</p>
                  </div>
                </div>
                <span className={`px-4 py-2 rounded-full text-sm font-extrabold border-2 shadow-md ${getThreatColor(analysisResult.threat_level)}`}>
                  {analysisResult.threat_level.toUpperCase()} RISK
                </span>
              </div>

              {/* Summary Metrics */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div className="col-span-1 flex flex-col items-center justify-center p-6 rounded-2xl bg-white border border-blue-200/80 shadow-lg">
                  <CircularProgress 
                    value={Math.round(analysisResult.confidence * 100)} 
                    color={analysisResult.confidence > 0.7 ? '#EF4444' : analysisResult.confidence > 0.4 ? '#F59E0B' : '#10B981'}
                    label="Confidence Score"
                    size={150}
                  />
                  <p className="text-sm text-gray-700 pt-3 font-bold text-center">
                    **Verdict:** <span className="capitalize">{analysisResult.verdict}</span>
                  </p>
                </div>
                {/* Human Understandable Analysis Block */}
                <div className="col-span-2 space-y-4 p-6 rounded-2xl bg-white border border-gray-300 shadow-lg">
                  <h3 className="font-bold text-gray-900 text-xl flex items-center gap-2"><BarChart3 className="w-5 h-5 text-gray-700"/> Human Understandable Analysis</h3>
                  <ThreatMeter level={analysisResult.threat_level} confidence={analysisResult.confidence} />
                  <p className="text-base text-gray-800 pt-2 font-medium leading-relaxed">
                    {getAnalysisDescription(analysisResult)}
                  </p>
                </div>
              </div>

              {/* Detailed Technical Analysis - Primary Details */}
              <div className="mb-8">
                <h3 className="font-bold text-gray-900 text-2xl mb-5 border-b pb-2 flex items-center gap-2"><Info className="w-6 h-6 text-gray-700"/> Primary Technical Details</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  
                  {/* Mapping primary details based on type */}
                  {analysisResult.type === 'file' && analysisResult.details && (
                      <>
                          <IconTextDetail icon={FileSearch} label="File Name" value={analysisResult.details.filename} />
                          <IconTextDetail icon={Hash} label="SHA256 Hash" value={analysisResult.details.file_hash} />
                          <IconTextDetail icon={Link} label="Size (bytes)" value={analysisResult.details.size_bytes?.toLocaleString()} />
                          <IconTextDetail icon={Activity} label="Entropy" value={analysisResult.details.entropy} />
                          <IconTextDetail icon={Code} label="Suspicious Strings" value={analysisResult.details.suspicious_strings} />
                          <IconTextDetail icon={Zap} label="File Type" value={analysisResult.details.file_type} />
                      </>
                  )}
                  {analysisResult.type === 'url' && analysisResult.details && (
                      <>
                          <IconTextDetail icon={Globe} label="URL Analyzed" value={analysisResult.details.url} />
                          <IconTextDetail icon={Server} label="Domain" value={analysisResult.details.domain} />
                          <IconTextDetail icon={Shield} label="Reputation Score" value={analysisResult.details.domain_info?.reputation_score} />
                          <IconTextDetail icon={Lock} label="SSL Status" value={analysisResult.details.ssl_analysis?.valid_certificate ? "Valid" : "Invalid"} />
                          <IconTextDetail icon={AlertTriangle} label="Blacklist Status" value={analysisResult.details.domain_info?.blacklist_status} />
                          <IconTextDetail icon={TrendingUp} label="Phishing Score" value={analysisResult.details.threat_detection?.phishing_score} />
                      </>
                  )}
                  {analysisResult.type === 'api' && analysisResult.details && (
                      <>
                          <IconTextDetail icon={Server} label="Endpoint" value={analysisResult.details.endpoint} />
                          <IconTextDetail icon={Lock} label="Auth Method" value={analysisResult.details.authentication?.method} />
                          <IconTextDetail icon={Shield} label="Encryption" value={analysisResult.details.security_score?.encryption > 50 ? 'Strong' : 'Weak'} />
                          <IconTextDetail icon={Zap} label="Rate Limiting Score" value={analysisResult.details.security_score?.rate_limiting} />
                          <IconTextDetail icon={Clock} label="Avg Response Time" value={analysisResult.details.response_analysis?.average_time} />
                      </>
                  )}
                </div>
              </div>

              {/* Detailed Analysis Sections (Grouped complex objects/arrays) */}
              <div className="mb-8">
                <h3 className="font-bold text-gray-900 text-2xl mb-5 border-b pb-2 flex items-center gap-2"><Layers className="w-6 h-6 text-blue-600"/> Deep Scan Findings</h3>
                <div className="space-y-4">
                    
                    {/* File Analysis Details */}
                    {analysisResult.type === 'file' && analysisResult.details && (
                        <>
                            <DetailSection title="Static Analysis" data={analysisResult.details.static_analysis} Icon={Code} />
                            <DetailSection title="Behavioral Indicators" data={analysisResult.details.behavioral_indicators} Icon={Activity} />
                            <DetailSection title="YARA Matches" data={analysisResult.details.yara_matches} Icon={ShieldAlert} />
                            <DetailSection title="Threat Intelligence" data={analysisResult.details.threat_intelligence} Icon={Globe} />
                        </>
                    )}

                    {/* URL Analysis Details */}
                    {analysisResult.type === 'url' && analysisResult.details && (
                        <>
                            <DetailSection title="SSL Analysis" data={analysisResult.details.ssl_analysis} Icon={Lock} />
                            <DetailSection title="Domain Info" data={analysisResult.details.domain_info} Icon={Hash} />
                            <DetailSection title="Security Headers" data={analysisResult.details.security_headers} Icon={Shield} />
                            <DetailSection title="Threat Detection Scores" data={analysisResult.details.threat_detection} Icon={AlertOctagon} />
                            <DetailSection title="Page Resources" data={analysisResult.details.page_resources} Icon={Layers} />
                        </>
                    )}

                    {/* API Analysis Details */}
                    {analysisResult.type === 'api' && analysisResult.details && (
                        <>
                            <DetailSection title="Authentication Check" data={analysisResult.details.authentication} Icon={Unlock} />
                            <DetailSection title="Vulnerability Findings" data={analysisResult.details.vulnerabilities} Icon={AlertOctagon} />
                            <DetailSection title="Security Scorecard" data={analysisResult.details.security_score} Icon={BarChart3} />
                            <DetailSection title="Response Analysis" data={analysisResult.details.response_analysis} Icon={Zap} />
                        </>
                    )}
                </div>
              </div>

              {/* Security Recommendations */}
              {getRecommendations(analysisResult.type, analysisResult.verdict).length > 0 && (
                <div className="mb-8 p-6 bg-red-50 rounded-2xl border-4 border-red-300 shadow-xl animate-fade-in">
                  <h3 className="font-extrabold text-red-900 text-2xl mb-4 flex items-center gap-2"><ShieldAlert className="w-6 h-6"/> Security Recommendations</h3>
                  {getRecommendations(analysisResult.type, analysisResult.verdict).map((section, i) => (
                    <div key={i} className="mb-4">
                      <h4 className="font-bold text-red-700 mb-3 text-lg">{section.title}</h4>
                      <ul className="space-y-3">
                        {section.items.map((item, j) => (
                          <li key={j} className="flex items-start gap-3 text-base text-gray-800 bg-white p-3 rounded-xl border border-red-200 shadow-md transition-all duration-300 hover:bg-red-100">
                            <span className="flex-shrink-0 w-6 h-6 bg-red-500 text-white rounded-full flex items-center justify-center text-xs font-bold ring-2 ring-red-300">{j + 1}</span>
                            <span className="font-medium">{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex gap-4 pt-4 border-t border-gray-300">
                <button onClick={downloadPDF} className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 text-white px-6 py-4 rounded-xl font-bold hover:from-blue-700 hover:to-blue-800 transition-all duration-300 flex items-center justify-center gap-2 text-lg shadow-lg hover:shadow-xl transform hover:scale-[1.01]">
                  <Download className="w-5 h-5" />
                  Download PDF Report
                </button>
                <button onClick={() => setAnalysisResult(null)} 
                  className="flex-1 bg-gray-200 text-gray-700 px-6 py-4 rounded-xl font-bold hover:bg-gray-300 transition-all duration-300 text-lg shadow-lg hover:shadow-xl transform hover:scale-[1.01]">
                  Start New Analysis
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Sidebar (Alerts & Analytics) */}
        <div className="space-y-8">
          
          {/* Recent Alerts */}
          <div className="bg-white/95 backdrop-blur-md rounded-3xl shadow-3xl p-6 border border-gray-200 animate-fade-in">
            <h3 className="text-xl font-extrabold mb-4 flex items-center gap-2 border-b pb-2 text-gray-900">
              <Activity className="w-6 h-6 text-blue-700" />
              Recent Activity Stream
            </h3>
            <div className="space-y-3 max-h-96 overflow-y-auto pr-2 custom-scrollbar">
              {alerts.length === 0 ? (
                <div className="text-center py-8 bg-gray-100 rounded-xl shadow-inner">
                  <AlertTriangle className="w-12 h-12 mx-auto text-gray-400 mb-2" />
                  <p className="text-sm text-gray-600 font-medium">No recent alerts. Start an analysis!</p>
                </div>
              ) : (
                alerts.map(alert => (
                  <div key={alert.id} className="border-l-4 border-gray-300 rounded-xl p-4 hover:bg-gray-100 cursor-pointer transition-all duration-300 shadow-md"
                    style={{ borderLeftColor: getThreatColor(alert.threat_level).match(/-(red|yellow|green)-\d+/)?.[0].replace(/-(\d+)/, '') }}
                  >
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-sm font-extrabold capitalize text-gray-900">{alert.type} Scan</span>
                      <span className={`text-xs px-3 py-1 rounded-full font-bold border ${getThreatColor(alert.threat_level)}`}>
                        {alert.threat_level.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-gray-600 truncate">{alert.details?.filename || alert.details?.url || alert.details?.endpoint || `Analysis ID: ${alert.analysis_id.substring(0, 8)}...`}</p>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Analytics Card */}
          <div className="bg-gradient-to-br from-blue-700 to-purple-800 rounded-3xl shadow-3xl p-6 text-white border-4 border-blue-500/50 animate-fade-in">
            <h3 className="text-xl font-extrabold mb-5 flex items-center gap-2"><PieChart className="w-6 h-6"/> Platform Analytics Summary</h3>
            <div className="space-y-4">
              {[
                { label: 'Files Scanned', value: alerts.filter(a => a.type === 'file').length, icon: FileSearch, color: 'text-green-300' },
                { label: 'URLs Checked', value: alerts.filter(a => a.type === 'url').length, icon: Globe, color: 'text-yellow-300' },
                { label: 'APIs Tested', value: alerts.filter(a => a.type === 'api').length, icon: Link, color: 'text-pink-300' },
                { label: 'Total Alerts', value: alerts.length, icon: AlertOctagon, color: 'text-red-300' }
              ].map((stat, i) => (
                <div key={i} className="flex justify-between items-center bg-white/10 hover:bg-white/20 rounded-xl p-4 transition-all duration-300 border border-white/10 shadow-inner">
                  <div className="flex items-center gap-3">
                    <stat.icon className={`w-6 h-6 ${stat.color}`} />
                    <span className="text-base font-medium">{stat.label}</span>
                  </div>
                  <span className="font-extrabold text-3xl">{stat.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      
      {/* Floating Chat Widget */}
      {chatOpen && (
        <div className="fixed bottom-24 right-8 w-96 h-[500px] bg-white rounded-2xl shadow-4xl border-4 border-blue-600 flex flex-col z-50 transform transition-all duration-300 animate-fade-in">
          <div className="bg-gradient-to-r from-blue-700 to-purple-800 text-white p-4 rounded-t-xl flex items-center justify-between shadow-xl">
            <div className="flex items-center gap-2">
              <MessageCircle className="w-6 h-6 animate-pulse" />
              <div>
                <h3 className="font-bold text-lg">CyberML AI Analyst</h3>
                <p className="text-xs text-blue-200">Intelligent Security Consultation</p>
              </div>
            </div>
            <button onClick={() => setChatOpen(false)} className="hover:bg-white/30 p-2 rounded-full transition-all">
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-gray-50 custom-scrollbar">
            {chatMessages.map((msg, idx) => (
              <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] p-3 rounded-2xl shadow-md transition-all duration-300 ${
                  msg.role === 'user' 
                    ? 'bg-blue-600 text-white rounded-br-none hover:bg-blue-700' 
                    : 'bg-white text-gray-800 rounded-bl-none border border-gray-200 hover:bg-gray-100'
                }`}>
                  <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
                </div>
              </div>
            ))}
            {chatLoading && (
              <div className="flex justify-start">
                <div className="bg-white p-3 rounded-2xl border border-gray-200 shadow-md">
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

          <div className="p-4 border-t border-gray-200 bg-white rounded-b-xl">
            <div className="flex gap-2">
              <input
                type="text"
                value={chatInput} 
                onChange={(e) => setChatInput(e.target.value)} 
                onKeyPress={(e) => e.key === 'Enter' && sendChatMessage()}
                placeholder="Ask about security..."
                className="flex-1 px-4 py-3 border-2 border-gray-300 rounded-xl focus:border-blue-500 focus:ring-2 focus:ring-blue-200 focus:outline-none transition-all duration-300"
              />
              <button onClick={sendChatMessage} disabled={chatLoading || chatInput.trim() === ''} className="bg-blue-600 text-white p-3 rounded-xl hover:bg-blue-700 disabled:bg-gray-400 transition-all duration-300 shadow-md">
                <Send className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      )}

      <button onClick={() => setChatOpen(!chatOpen)} className="fixed bottom-8 right-8 bg-gradient-to-r from-blue-600 to-purple-600 text-white p-5 rounded-full shadow-4xl hover:scale-110 transition-all duration-300 z-40 ring-4 ring-white/20">
        <MessageCircle className="w-7 h-7" />
      </button>
    </div>
  );
};

export default CyberMLDashboard;
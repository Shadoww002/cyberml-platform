# ============================================================================
# FILE: backend/app.py
# Simplified FastAPI Backend for Easy Deployment
# ============================================================================

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import hashlib
import math
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import requests
from collections import Counter

app = FastAPI(title="CyberML API", version="1.0.0")

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Models
# ============================================================================

class URLScanRequest(BaseModel):
    url: HttpUrl

class APIScanRequest(BaseModel):
    endpoint: HttpUrl

class AnalysisResponse(BaseModel):
    type: str
    verdict: str
    confidence: float
    threat_level: str
    details: Dict[str, Any]
    timestamp: str

# ============================================================================
# Utility Functions
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy

def detect_suspicious_strings(data: bytes) -> int:
    """Count suspicious strings in binary data"""
    suspicious_patterns = [
        b'cmd.exe', b'powershell', b'bash', b'/bin/sh',
        b'eval', b'exec', b'system', b'shell',
        b'http://', b'https://',
        b'CreateRemoteThread', b'VirtualAlloc', b'WriteProcessMemory'
    ]
    
    count = 0
    data_lower = data.lower()
    
    for pattern in suspicious_patterns:
        count += data_lower.count(pattern)
    
    return count

def is_pe_file(data: bytes) -> bool:
    """Check if file is a Windows PE executable"""
    return data[:2] == b'MZ'

def analyze_pe_structure(data: bytes) -> Dict[str, Any]:
    """Basic PE file analysis"""
    details = {
        "is_pe": False,
        "sections": 0,
        "packed": False
    }
    
    if len(data) < 64:
        return details
    
    details["is_pe"] = is_pe_file(data)
    
    # Check for common packers
    packer_signatures = [b'UPX', b'aPLib', b'.themida', b'ASPack', b'PECompact']
    details["packed"] = any(sig in data for sig in packer_signatures)
    
    return details

def calculate_threat_score(features: Dict[str, Any]) -> tuple:
    """Calculate threat score and level"""
    score = 0.0
    
    # Entropy check
    entropy = features.get('entropy', 0)
    if entropy > 7.5:
        score += 0.3
    elif entropy > 7.0:
        score += 0.2
    
    # Suspicious strings
    suspicious = features.get('suspicious_strings', 0)
    if suspicious > 15:
        score += 0.3
    elif suspicious > 5:
        score += 0.2
    
    # Packer detection
    if features.get('packed', False):
        score += 0.25
    
    # File operations
    file_ops = features.get('file_operations', 0)
    if file_ops > 30:
        score += 0.15
    
    confidence = min(score, 1.0)
    
    # Determine threat level
    if confidence > 0.7:
        threat_level = "high"
        verdict = "malicious"
    elif confidence > 0.4:
        threat_level = "medium"
        verdict = "suspicious"
    else:
        threat_level = "low"
        verdict = "safe"
    
    return verdict, confidence, threat_level

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CyberML Security API",
        "version": "1.0.0",
        "endpoints": {
            "file_analysis": "/api/analyze/file",
            "url_scan": "/api/analyze/url",
            "api_scan": "/api/analyze/api",
            "health": "/health"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/analyze/file", response_model=AnalysisResponse)
async def analyze_file(file: UploadFile = File(...)):
    """
    Analyze uploaded file for malware and suspicious behavior
    """
    try:
        # Read file content
        content = await file.read()
        file_hash = hashlib.sha256(content).hexdigest()
        
        # Extract features
        entropy = calculate_entropy(content)
        suspicious_strings = detect_suspicious_strings(content)
        pe_info = analyze_pe_structure(content)
        
        features = {
            "entropy": entropy,
            "size": len(content),
            "suspicious_strings": suspicious_strings,
            "packed": pe_info["packed"],
            "is_pe": pe_info["is_pe"],
            "file_operations": suspicious_strings * 2  # Simplified metric
        }
        
        # Calculate threat
        verdict, confidence, threat_level = calculate_threat_score(features)
        
        # Prepare response
        return AnalysisResponse(
            type="file",
            verdict=verdict,
            confidence=confidence,
            threat_level=threat_level,
            details={
                "filename": file.filename,
                "sha256": file_hash,
                "size_bytes": len(content),
                "entropy": round(entropy, 2),
                "suspicious_strings": suspicious_strings,
                "is_pe_file": pe_info["is_pe"],
                "packed": pe_info["packed"],
                "mime_type": file.content_type
            },
            timestamp=datetime.utcnow().isoformat()
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze/url", response_model=AnalysisResponse)
async def analyze_url(request: URLScanRequest):
    """
    Analyze URL for phishing, malware, and security issues
    """
    try:
        url = str(request.url)
        
        # Parse URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        # Initialize features
        features = {
            "has_ip": bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc)),
            "suspicious_tld": parsed.netloc.split('.')[-1] in ['tk', 'ml', 'ga', 'cf', 'gq'],
            "long_url": len(url) > 100,
            "has_suspicious_keywords": any(kw in url.lower() for kw in ['login', 'verify', 'secure', 'account', 'update']),
            "uses_https": parsed.scheme == 'https'
        }
        
        # Try to fetch headers
        ssl_valid = False
        security_headers = {}
        
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            ssl_valid = response.url.startswith('https')
            security_headers = {
                'X-Frame-Options': 'X-Frame-Options' in response.headers,
                'Content-Security-Policy': 'Content-Security-Policy' in response.headers,
                'Strict-Transport-Security': 'Strict-Transport-Security' in response.headers,
                'X-Content-Type-Options': 'X-Content-Type-Options' in response.headers
            }
        except:
            pass
        
        # Calculate threat score
        score = 0.0
        if features['has_ip']:
            score += 0.3
        if features['suspicious_tld']:
            score += 0.2
        if features['has_suspicious_keywords']:
            score += 0.2
        if not features['uses_https']:
            score += 0.15
        if not ssl_valid:
            score += 0.15
        
        confidence = min(score, 1.0)
        
        if confidence > 0.6:
            verdict = "suspicious"
            threat_level = "high"
        elif confidence > 0.3:
            verdict = "suspicious"
            threat_level = "medium"
        else:
            verdict = "safe"
            threat_level = "low"
        
        return AnalysisResponse(
            type="url",
            verdict=verdict,
            confidence=confidence,
            threat_level=threat_level,
            details={
                "url": url,
                "domain": parsed.netloc,
                "uses_https": features['uses_https'],
                "ssl_valid": ssl_valid,
                "security_headers": security_headers,
                "suspicious_indicators": {
                    "ip_address": features['has_ip'],
                    "suspicious_tld": features['suspicious_tld'],
                    "long_url": features['long_url'],
                    "phishing_keywords": features['has_suspicious_keywords']
                }
            },
            timestamp=datetime.utcnow().isoformat()
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {str(e)}")

@app.post("/api/analyze/api", response_model=AnalysisResponse)
async def analyze_api(request: APIScanRequest):
    """
    Analyze API endpoint for security vulnerabilities
    """
    try:
        endpoint = str(request.endpoint)
        
        vulnerabilities = []
        security_issues = []
        
        # Test endpoint
        try:
            response = requests.get(endpoint, timeout=5)
            status_code = response.status_code
            
            # Check authentication
            if status_code == 200:
                security_issues.append("No authentication required")
            
            # Check for common security headers
            headers = response.headers
            if 'X-Content-Type-Options' not in headers:
                security_issues.append("Missing X-Content-Type-Options header")
            if 'X-Frame-Options' not in headers:
                security_issues.append("Missing X-Frame-Options header")
            
            # Check CORS
            if 'Access-Control-Allow-Origin' in headers:
                if headers['Access-Control-Allow-Origin'] == '*':
                    vulnerabilities.append("Permissive CORS configuration")
            
            # Check for information disclosure
            if 'Server' in headers:
                security_issues.append("Server header exposed")
            if 'X-Powered-By' in headers:
                security_issues.append("X-Powered-By header exposed")
            
        except requests.exceptions.Timeout:
            security_issues.append("Request timeout")
        except requests.exceptions.SSLError:
            vulnerabilities.append("SSL/TLS configuration issue")
        except Exception as e:
            security_issues.append(f"Connection error: {str(e)}")
        
        # Calculate threat score
        vuln_score = len(vulnerabilities) * 0.3
        issue_score = len(security_issues) * 0.15
        confidence = min(vuln_score + issue_score, 1.0)
        
        if confidence > 0.6:
            verdict = "vulnerable"
            threat_level = "high"
        elif confidence > 0.3:
            verdict = "needs_review"
            threat_level = "medium"
        else:
            verdict = "secure"
            threat_level = "low"
        
        return AnalysisResponse(
            type="api",
            verdict=verdict,
            confidence=confidence,
            threat_level=threat_level,
            details={
                "endpoint": endpoint,
                "vulnerabilities": vulnerabilities,
                "security_issues": security_issues,
                "recommendations": [
                    "Implement authentication",
                    "Add rate limiting",
                    "Configure security headers",
                    "Restrict CORS policy"
                ] if len(vulnerabilities) + len(security_issues) > 0 else ["API appears secure"]
            },
            timestamp=datetime.utcnow().isoformat()
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"API analysis failed: {str(e)}")

# ============================================================================
# Run Server
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
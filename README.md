# Secure Scan – Nmap-Based Website Security Scanner

A Python-based automated security scanning tool that performs multi-layer website analysis using Nmap and web security techniques.

---

## Features

### Network Scanning (Nmap)
- Detects open ports and running services
- Service and version detection (-sV)
- Vulnerability scanning using Nmap scripts

### 🔒 SSL/TLS Analysis
- Certificate validation
- Expiry detection
- Weak configuration identification

### 🛡️ Security Headers Check
- Detects missing security headers:
  - Content Security Policy (CSP)
  - HSTS
  - X-Frame-Options

### 🍪 Cookie Security Analysis
- Checks Secure flag
- HttpOnly flag validation
- SameSite attribute analysis

### 🌐 DNS & WHOIS Lookup
- Domain information extraction
- Name server and registrar details

### 📂 Sensitive File Detection
- Detects exposed files like:
  - .env
  - .git
  - config files

### ⚡ Performance Optimization
- Uses multithreading (Concurrent Futures)
- Parallel execution of scan modules

---

## Risk Scoring System

The tool calculates an overall security risk level:

- 🟢 LOW
- 🟡 MEDIUM
- 🔴 HIGH

Based on:
- Open ports
- SSL status
- Missing headers
- Cookie security
- Exposed files

---

## Tech Stack

- Python
- Nmap (python-nmap)
- Requests
- DNS Resolver
- WHOIS Library
- Socket & SSL
- Multithreading (Concurrent Futures)

---

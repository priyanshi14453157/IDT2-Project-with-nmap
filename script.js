async function analyzeURL() {
    const urlInput = document.getElementById("urlInput");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const url = urlInput.value.trim();
    
    if (!url) {
        showError("Please enter a URL to analyze");
        return;
    }
    
    // Show loading state
    analyzeBtn.classList.add('loading');
    analyzeBtn.disabled = true;
    
    try {
        // Call the backend API
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayResults(data);
        } else {
            showError(data.error || 'Failed to analyze URL');
        }
    } catch (error) {
        console.error('Error:', error);
        showError('Failed to connect to the server');
    } finally {
        // Remove loading state
        analyzeBtn.classList.remove('loading');
        analyzeBtn.disabled = false;
    }
}

function displayResults(data) {
    const resultSection = document.getElementById("resultSection");
    resultSection.style.display = "block";
    
    // Display URL Analysis
    displayURLAnalysis(data.url_analysis);
    
    // Display Website Security Scan Results
    displayWebsiteScan(data.website_scan);
    
    // Display Summary - make sure we're using the summary from the response
    displaySummary(data.summary);
    
    // Also update the URL risk meter to match URL analysis
    updateURLRiskMeter(data.url_analysis);
    
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Add this new function to update URL risk meter separately
function updateURLRiskMeter(urlAnalysis) {
    const riskPercentage = urlAnalysis.risk_percentage || 0;
    const riskLevel = urlAnalysis.risk_level || 'Safe';
    
    // Update URL risk meter
    document.getElementById("riskPercentage").innerText = riskPercentage + "%";
    
    const riskBar = document.getElementById("riskBar");
    riskBar.style.width = riskPercentage + "%";
    
    // Set color based on risk level
    if (riskLevel === 'Safe') {
        riskBar.style.backgroundColor = '#10b981';
    } else if (riskLevel === 'Suspicious') {
        riskBar.style.backgroundColor = '#f59e0b';
    } else {
        riskBar.style.backgroundColor = '#ef4444';
    }
}

function displayURLAnalysis(analysis) {
    const urlAnalysisDiv = document.getElementById("urlAnalysis");
    
    // Update risk level
    const riskLevel = document.getElementById("riskLevel");
    const riskBadge = document.getElementById("riskBadge");
    riskLevel.innerText = analysis.risk_level;
    
    let riskClass = "";
    if (analysis.risk_level === "Safe") riskClass = "safe";
    else if (analysis.risk_level === "Suspicious") riskClass = "suspicious";
    else riskClass = "highrisk";
    
    riskBadge.className = `risk-badge ${riskClass}`;
    
    // Update risk badge icon
    const badgeIcon = riskBadge.querySelector('i');
    if (riskClass === 'safe') {
        badgeIcon.className = 'fas fa-shield-alt';
    } else if (riskClass === 'suspicious') {
        badgeIcon.className = 'fas fa-exclamation-triangle';
    } else {
        badgeIcon.className = 'fas fa-skull-crosswalk';
    }
    
    // Update risk score
    document.getElementById("riskScore").innerHTML = `
        <span class="score-value">${analysis.risk_score}/7</span>
        <span class="score-label">URL Risk Score</span>
    `;
    
    // Update risk percentage
    document.getElementById("riskPercentage").innerText = analysis.risk_percentage + "%";
    
    // Update risk bar
    const riskBar = document.getElementById("riskBar");
    riskBar.style.width = analysis.risk_percentage + "%";
    
    // Update warning list
    const warningList = document.getElementById("warningList");
    const warningCount = document.getElementById("warningCount");
    
    warningList.innerHTML = "";
    
    if (analysis.warnings.length === 0) {
        warningCount.innerText = "0";
        warningList.innerHTML = `
            <li class="empty-state">
                <i class="fas fa-check-circle"></i>
                <span>No risk factors detected. URL appears safe.</span>
            </li>
        `;
    } else {
        warningCount.innerText = analysis.warnings.length;
        analysis.warnings.forEach(function(warning) {
            let li = document.createElement("li");
            li.innerHTML = `<i class="fas fa-times-circle"></i>${warning}`;
            warningList.appendChild(li);
        });
    }
}

function displayNmapResults(nmapData) {
    const nmapSection = document.getElementById("nmapResults");
    
    if (nmapData.error) {
        nmapSection.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-circle"></i>
                Nmap scan failed: ${nmapData.error}
            </div>
        `;
        return;
    }
    
    const riskLevel = nmapData.risk_assessment.level;
    const riskClass = riskLevel.toLowerCase();
    
    nmapSection.innerHTML = `
        <h3><i class="fas fa-network-wired"></i> Network Security Scan (Nmap)</h3>
        
        <div class="nmap-summary">
            <div class="nmap-header">
                <div class="nmap-info">
                    <p><strong>Domain:</strong> ${nmapData.domain}</p>
                    <p><strong>IP Address:</strong> ${nmapData.ip_address}</p>
                    <p><strong>Host Status:</strong> <span class="status-${nmapData.host_status}">${nmapData.host_status}</span></p>
                </div>
                <div class="nmap-risk-badge ${riskClass}">
                    <span>Network Risk: ${riskLevel}</span>
                    <span class="risk-score">${nmapData.risk_assessment.score}</span>
                </div>
            </div>
            
            <div class="nmap-stats">
                <div class="stat-card">
                    <i class="fas fa-door-open"></i>
                    <span class="stat-value">${nmapData.open_ports.length}</span>
                    <span class="stat-label">Open Ports</span>
                </div>
                <div class="stat-card">
                    <i class="fas fa-cogs"></i>
                    <span class="stat-value">${nmapData.services.length}</span>
                    <span class="stat-label">Services</span>
                </div>
                <div class="stat-card">
                    <i class="fas fa-bug"></i>
                    <span class="stat-value">${nmapData.vulnerabilities.length}</span>
                    <span class="stat-label">Vulnerabilities</span>
                </div>
            </div>
            
            ${nmapData.open_ports.length > 0 ? `
                <div class="open-ports">
                    <h4>Open Ports & Services</h4>
                    <div class="ports-grid">
                        ${nmapData.services.map(service => `
                            <div class="port-card ${getPortRiskClass(service.port)}">
                                <span class="port-number">Port ${service.port}</span>
                                <span class="port-service">${service.service}</span>
                                ${service.version ? `<span class="port-version">${service.version}</span>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            ` : ''}
            
            ${nmapData.vulnerabilities.length > 0 ? `
                <div class="vulnerabilities">
                    <h4>Detected Vulnerabilities</h4>
                    <ul class="vuln-list">
                        ${nmapData.vulnerabilities.map(vuln => `
                            <li class="vuln-item">
                                <i class="fas fa-exclamation-triangle"></i>
                                <div class="vuln-details">
                                    <strong>${vuln.type.replace('_', ' ').toUpperCase()}</strong>
                                    <p>${vuln.description}</p>
                                    ${vuln.port ? `<small>Port: ${vuln.port}</small>` : ''}
                                </div>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${nmapData.risk_assessment.factors.length > 0 ? `
                <div class="risk-factors">
                    <h4>Risk Factors</h4>
                    <ul>
                        ${nmapData.risk_assessment.factors.map(factor => `
                            <li><i class="fas fa-circle"></i> ${factor}</li>
                        `).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;
}

function displayOverallRisk(overall) {
    const overallDiv = document.getElementById("overallRisk");
    const riskClass = overall.level.toLowerCase();
    
    overallDiv.innerHTML = `
        <h3><i class="fas fa-chart-line"></i> Overall Risk Assessment</h3>
        <div class="overall-risk-meter">
            <div class="overall-score ${riskClass}">
                <span class="score-value">${overall.score}%</span>
                <span class="score-label">Overall Risk Score</span>
            </div>
            <div class="overall-level ${riskClass}">
                <span>${overall.level} Risk</span>
            </div>
        </div>
        <div class="recommendation">
            ${getRecommendation(overall.level)}
        </div>
    `;
}

function getPortRiskClass(port) {
    const riskyPorts = [21, 23, 25, 445, 3389, 5900, 5432];
    if (riskyPorts.includes(port)) {
        return 'high-risk';
    }
    return 'normal';
}

function getRecommendation(riskLevel) {
    switch(riskLevel.toLowerCase()) {
        case 'low':
            return '<i class="fas fa-check-circle"></i> The URL appears safe. Normal browsing precautions recommended.';
        case 'medium':
            return '<i class="fas fa-exclamation-circle"></i> Exercise caution. Consider using a VPN or avoid entering sensitive information.';
        case 'high':
            return '<i class="fas fa-skull-crosswalk"></i> WARNING: High risk detected. Do not proceed unless absolutely necessary and use extreme caution.';
        default:
            return '';
    }
}

function showError(message) {
    const resultSection = document.getElementById("resultSection");
    resultSection.style.display = "block";
    
    resultSection.innerHTML = `
        <div class="error-container">
            <i class="fas fa-exclamation-triangle"></i>
            <h3>Error</h3>
            <p>${message}</p>
        </div>
    `;
}

function handleKeyPress(event) {
    if (event.key === "Enter") {
        analyzeURL();
    }
}

function setExample(url) {
    document.getElementById("urlInput").value = url;
    analyzeURL();
}
function displayResults(data) {
    const resultSection = document.getElementById("resultSection");
    resultSection.style.display = "block";
    
    // Display URL Analysis
    displayURLAnalysis(data.url_analysis);
    
    // Display Website Security Scan Results
    displayWebsiteScan(data.website_scan);
    
    // Display Summary
    displaySummary(data.summary);
    
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function displayWebsiteScan(scan) {
    const scanDiv = document.getElementById("nmapResults");
    
    // Get the correct risk score - use scan.risk_score if available, otherwise 0
    const riskScore = scan.risk_score || 0;
    const riskLevel = scan.risk_level || 'UNKNOWN';
    
    let html = `
        <h3><i class="fas fa-shield-alt"></i> Comprehensive Website Security Scan</h3>
        
        <div class="risk-meter" style="margin-bottom: 20px;">
            <div class="meter-header">
                <span>Overall Security Risk</span>
                <span>${riskScore}%</span>
            </div>
            <div class="risk-bar-container">
                <div class="risk-bar" style="width: ${riskScore}%; background: ${getRiskColor(riskLevel)};"></div>
            </div>
            <div class="meter-labels">
                <span>Low Risk</span>
                <span>Medium</span>
                <span>High Risk</span>
            </div>
        </div>
    `;
    
    // Rest of the function remains the same
    // Risk Factors
    if (scan.risk_factors && scan.risk_factors.length > 0) {
        html += `
            <div class="warnings-section">
                <div class="warnings-header">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>Risk Factors Found</h3>
                    <span class="warning-count">${scan.risk_factors.length}</span>
                </div>
                <ul class="warning-list">
                    ${scan.risk_factors.map(factor => 
                        `<li><i class="fas fa-times-circle"></i>${factor}</li>`
                    ).join('')}
                </ul>
            </div>
        `;
    }
    
    // Network Scan Results
    if (scan.network_scan) {
        html += `
            <div class="scan-section">
                <h4><i class="fas fa-network-wired"></i> Network Security</h4>
                <p>IP Address: ${scan.network_scan.ip_address || 'N/A'}</p>
                <p>Open Ports: ${scan.network_scan.open_ports?.length || 0}</p>
                <div class="ports-grid">
                    ${(scan.network_scan.services || []).map(service => `
                        <div class="port-card ${service.port < 1024 ? 'high-risk' : ''}">
                            <span class="port-number">Port ${service.port}</span>
                            <span class="port-service">${service.service}</span>
                            ${service.version ? `<small>${service.version}</small>` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    // SSL/TLS Results
    if (scan.ssl_tls && !scan.ssl_tls.error) {
        const ssl = scan.ssl_tls;
        html += `
            <div class="scan-section">
                <h4><i class="fas fa-lock"></i> SSL/TLS Security</h4>
                <p>Issuer: ${ssl.issuer || 'N/A'}</p>
                <p>Expires in: ${ssl.expires_in_days || 0} days ${ssl.is_expiring_soon ? '<span class="warning">(Expiring soon!)</span>' : ''}</p>
                <p>SSL Version: ${ssl.ssl_version || 'N/A'}</p>
                <p>Cipher: ${ssl.cipher || 'N/A'}</p>
            </div>
        `;
    }
    
    // Security Headers
    if (scan.security_headers && !scan.security_headers.error) {
        html += `
            <div class="scan-section">
                <h4><i class="fas fa-heading"></i> Security Headers</h4>
                <div class="headers-grid">
                    ${(scan.security_headers.found || []).map(header => `
                        <div class="header-item good">
                            <strong>✅ ${header.header}</strong>
                            <small>${header.description}</small>
                        </div>
                    `).join('')}
                    ${(scan.security_headers.missing || []).map(header => `
                        <div class="header-item bad">
                            <strong>❌ ${header.header}</strong>
                            <small>${header.description}</small>
                            <span class="severity ${header.severity.toLowerCase()}">${header.severity}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    // Sensitive Files
    if (scan.sensitive_files && scan.sensitive_files.length > 0) {
        html += `
            <div class="scan-section">
                <h4><i class="fas fa-file-exclamation"></i> Exposed Sensitive Files</h4>
                <div class="sensitive-files">
                    ${scan.sensitive_files.map(file => `
                        <div class="file-item ${file.risk.toLowerCase()}">
                            <strong>${file.path}</strong>
                            <span class="risk-badge ${file.risk.toLowerCase()}">${file.risk}</span>
                            ${file.status === 200 ? '<span class="accessible">Accessible!</span>' : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    // Technologies
    if (scan.technologies && !scan.technologies.error) {
        html += `
            <div class="scan-section">
                <h4><i class="fas fa-code"></i> Technologies Detected</h4>
                <p>Server: ${scan.technologies.server || 'Unknown'}</p>
                ${scan.technologies.cms ? `<p>CMS: ${scan.technologies.cms}</p>` : ''}
                ${scan.technologies.libraries?.length ? `<p>Libraries: ${scan.technologies.libraries.join(', ')}</p>` : ''}
                ${scan.technologies.os ? `<p>OS: ${scan.technologies.os}</p>` : ''}
            </div>
        `;
    }
    
    scanDiv.innerHTML = html;
}

function displaySummary(summary) {
    const summaryDiv = document.getElementById("overallRisk");
    
    // Get risk score and level
    const riskScore = summary.risk_score || 0;
    const riskLevel = summary.risk_level || 'UNKNOWN';
    
    summaryDiv.innerHTML = `
        <h3><i class="fas fa-chart-pie"></i> Security Summary</h3>
        <div class="summary-stats">
            <div class="stat-card">
                <i class="fas fa-door-open"></i>
                <span class="stat-value">${summary.open_ports || 0}</span>
                <span class="stat-label">Open Ports</span>
            </div>
            <div class="stat-card">
                <i class="fas fa-bug"></i>
                <span class="stat-value">${summary.vulnerabilities || 0}</span>
                <span class="stat-label">Vulnerabilities</span>
            </div>
            <div class="stat-card">
                <i class="fas fa-heading"></i>
                <span class="stat-value">${summary.missing_headers || 0}</span>
                <span class="stat-label">Missing Headers</span>
            </div>
            <div class="stat-card">
                <i class="fas fa-file-exclamation"></i>
                <span class="stat-value">${summary.sensitive_files || 0}</span>
                <span class="stat-label">Exposed Files</span>
            </div>
        </div>
        <div class="overall-risk-meter">
            <div class="overall-score ${riskLevel.toLowerCase()}">
                <span class="score-value">${riskScore}%</span>
                <span class="score-label">Risk Score</span>
            </div>
            <div class="overall-level ${riskLevel.toLowerCase()}">
                <span>${riskLevel} Risk</span>
            </div>
        </div>
    `;
}

function getRiskColor(level) {
    switch(level?.toLowerCase()) {
        case 'high':
            return '#ef4444';
        case 'medium':
            return '#f59e0b';
        case 'low':
            return '#10b981';
        default:
            return '#6b7280'; // gray for unknown
    }
}
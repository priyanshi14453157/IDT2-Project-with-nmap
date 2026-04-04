#!/usr/bin/env python3
import nmap
import sys
import json
import socket
import requests
import ssl
import whois
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse
import concurrent.futures

class WebsiteSecurityScanner:
    def __init__(self, domain):
        self.domain = domain.lower()
        self.results = {
            'domain': domain,
            'scan_timestamp': datetime.now().isoformat(),
            'network_scan': {},
            'ssl_tls': {},
            'security_headers': {},
            'cookies': [],
            'technologies': {},
            'dns_info': {},
            'whois_info': {},
            'sensitive_files': [],
            'vulnerabilities': [],
            'risk_score': 0,
            'risk_level': 'LOW'
        }
        
        # Extract base domain for HTTP checks
        if not self.domain.startswith('http'):
            self.base_url = f'https://{self.domain}'
        else:
            self.base_url = self.domain
            parsed = urlparse(self.domain)
            self.domain = parsed.netloc

    def scan_all(self):
        """Run all security scans"""
        print(f"\n[+] Starting comprehensive scan of {self.domain}", file=sys.stderr)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self.network_scan): 'network',
                executor.submit(self.ssl_scan): 'ssl',
                executor.submit(self.check_security_headers): 'headers',
                executor.submit(self.analyze_cookies): 'cookies',
                executor.submit(self.fingerprint_technologies): 'tech',
                executor.submit(self.dns_scan): 'dns',
                executor.submit(self.whois_lookup): 'whois',
                executor.submit(self.check_sensitive_files): 'files'
            }
            
            for future in concurrent.futures.as_completed(futures):
                scan_type = futures[future]
                try:
                    result = future.result()
                    if scan_type == 'network':
                        self.results['network_scan'] = result
                    elif scan_type == 'ssl':
                        self.results['ssl_tls'] = result
                    elif scan_type == 'headers':
                        self.results['security_headers'] = result
                    elif scan_type == 'cookies':
                        self.results['cookies'] = result
                    elif scan_type == 'tech':
                        self.results['technologies'] = result
                    elif scan_type == 'dns':
                        self.results['dns_info'] = result
                    elif scan_type == 'whois':
                        self.results['whois_info'] = result
                    elif scan_type == 'files':
                        self.results['sensitive_files'] = result
                except Exception as e:
                    print(f"[-] Error in {scan_type} scan: {e}", file=sys.stderr)
        
        # Calculate overall risk
        self.calculate_risk_score()
        return self.results

    def network_scan(self):
        """Enhanced Nmap scan with vulnerability detection"""
        try:
            nm = nmap.PortScanner()
            
            # Resolve domain to IP
            try:
                ip_address = socket.gethostbyname(self.domain)
            except:
                ip_address = self.domain
            
            print(f"[*] Network scan: {self.domain} ({ip_address})", file=sys.stderr)
            
            # Comprehensive scan with version detection and vuln scripts
            nm.scan(ip_address, arguments='-sV -sC --script vuln --script-args=mincvss=7.0 -T4 --host-timeout 120s')
            
            scan_results = {
                'ip_address': ip_address,
                'host_status': 'up' if nm.all_hosts() else 'down',
                'open_ports': [],
                'services': [],
                'vulnerabilities': []
            }
            
            for host in nm.all_hosts():
                if 'tcp' in nm[host]:
                    for port, port_data in nm[host]['tcp'].items():
                        if port_data['state'] == 'open':
                            service_info = {
                                'port': port,
                                'service': port_data['name'],
                                'product': port_data.get('product', ''),
                                'version': port_data.get('version', ''),
                                'cpe': port_data.get('cpe', '')
                            }
                            scan_results['open_ports'].append(port)
                            scan_results['services'].append(service_info)
                            
                            # Check for script results (vulnerabilities)
                            if 'script' in port_data:
                                for script_name, script_output in port_data['script'].items():
                                    if any(keyword in script_output.lower() for keyword in ['vuln', 'cve', 'exploit', 'vulnerable']):
                                        scan_results['vulnerabilities'].append({
                                            'port': port,
                                            'script': script_name,
                                            'output': script_output[:200]  # Truncate long output
                                        })
            
            return scan_results
        except Exception as e:
            return {'error': str(e)}

    def ssl_scan(self):
        """Check SSL/TLS configuration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Get certificate details
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    # Parse expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.now()).days
                    
                    # Check SSL version
                    ssl_version = ssock.version()
                    
                    # Check cipher
                    cipher = ssock.cipher()
                    
                    return {
                        'issuer': issuer.get('organizationName', 'Unknown'),
                        'expires_in_days': days_left,
                        'is_valid': days_left > 0,
                        'is_expiring_soon': days_left < 30,
                        'subject': subject.get('commonName', ''),
                        'alternative_names': [name[1] for name in cert.get('subjectAltName', [])],
                        'ssl_version': ssl_version,
                        'cipher': cipher[0] if cipher else 'Unknown',
                        'cipher_strength': cipher[2] if cipher else 0
                    }
        except Exception as e:
            return {'error': str(e)}

    def check_security_headers(self):
        """Check for essential security headers"""
        headers_to_check = {
            'Content-Security-Policy': {
                'description': 'Prevents XSS and data injection attacks',
                'severity': 'HIGH'
            },
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'severity': 'HIGH'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'severity': 'MEDIUM'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'severity': 'MEDIUM'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information leakage',
                'severity': 'LOW'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features access',
                'severity': 'LOW'
            },
            'X-XSS-Protection': {
                'description': 'Enables browser XSS filtering',
                'severity': 'MEDIUM'
            }
        }
        
        try:
            response = requests.get(self.base_url, timeout=10, verify=False)
            headers = response.headers
            
            result = {
                'found': [],
                'missing': [],
                'score': 0
            }
            
            for header, info in headers_to_check.items():
                if header in headers:
                    result['found'].append({
                        'header': header,
                        'value': headers[header],
                        'description': info['description']
                    })
                    result['score'] += 10
                else:
                    result['missing'].append({
                        'header': header,
                        'description': info['description'],
                        'severity': info['severity']
                    })
            
            return result
        except Exception as e:
            return {'error': str(e)}

    def analyze_cookies(self):
        """Analyze cookie security"""
        try:
            response = requests.get(self.base_url, timeout=10, verify=False)
            cookie_analysis = []
            
            for cookie in response.cookies:
                analysis = {
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': cookie.get_nonstandard_attr('SameSite', 'none'),
                    'domain': cookie.domain,
                    'path': cookie.path
                }
                
                # Risk assessment
                risks = []
                if not cookie.secure:
                    risks.append("Not marked Secure - can be intercepted")
                    analysis['risk_score'] = 10
                if not cookie.httponly:
                    risks.append("Not HttpOnly - accessible to JavaScript")
                    analysis['risk_score'] = analysis.get('risk_score', 0) + 8
                if analysis['samesite'] == 'none':
                    risks.append("No SameSite - potentially vulnerable to CSRF")
                    analysis['risk_score'] = analysis.get('risk_score', 0) + 5
                
                analysis['risks'] = risks
                cookie_analysis.append(analysis)
            
            return cookie_analysis
        except Exception as e:
            return {'error': str(e)}

    def fingerprint_technologies(self):
        """Detect technologies used by the website"""
        try:
            response = requests.get(self.base_url, timeout=10, verify=False)
            html = response.text.lower()
            headers = response.headers
            
            technologies = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown'),
                'cms': None,
                'frameworks': [],
                'libraries': [],
                'os': None
            }
            
            # Detect CMS
            cms_patterns = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', 'com_content'],
                'Drupal': ['drupal', 'sites/all'],
                'Magento': ['magento', 'skin/frontend'],
                'Shopify': ['shopify', 'myshopify']
            }
            
            for cms, patterns in cms_patterns.items():
                if any(pattern in html for pattern in patterns):
                    technologies['cms'] = cms
                    break
            
            # Detect JavaScript frameworks
            js_patterns = {
                'jQuery': ['jquery'],
                'React': ['react', 'reactdom'],
                'Vue.js': ['vue.js', 'vuejs'],
                'Angular': ['angular', 'ng-'],
                'Bootstrap': ['bootstrap', 'bootstrapcdn']
            }
            
            for framework, patterns in js_patterns.items():
                if any(pattern in html for pattern in patterns):
                    technologies['libraries'].append(framework)
            
            # Detect server OS from headers
            server_header = headers.get('Server', '').lower()
            if 'ubuntu' in server_header:
                technologies['os'] = 'Ubuntu'
            elif 'centos' in server_header:
                technologies['os'] = 'CentOS'
            elif 'debian' in server_header:
                technologies['os'] = 'Debian'
            elif 'windows' in server_header:
                technologies['os'] = 'Windows'
            
            return technologies
        except Exception as e:
            return {'error': str(e)}

    def dns_scan(self):
        """Check DNS configuration"""
        try:
            dns_info = {
                'a_records': [],
                'mx_records': [],
                'txt_records': [],
                'ns_records': []
            }
            
            # A records
            try:
                answers = dns.resolver.resolve(self.domain, 'A')
                dns_info['a_records'] = [str(r) for r in answers]
            except:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                dns_info['mx_records'] = [str(r.exchange) for r in answers]
            except:
                pass
            
            # TXT records
            try:
                answers = dns.resolver.resolve(self.domain, 'TXT')
                dns_info['txt_records'] = [str(r) for r in answers]
            except:
                pass
            
            # NS records
            try:
                answers = dns.resolver.resolve(self.domain, 'NS')
                dns_info['ns_records'] = [str(r) for r in answers]
            except:
                pass
            
            return dns_info
        except Exception as e:
            return {'error': str(e)}

    def whois_lookup(self):
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(self.domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
                'org': w.org,
                'country': w.country
            }
        except Exception as e:
            return {'error': str(e)}

    def check_sensitive_files(self):
        """Check for exposed sensitive files"""
        sensitive_paths = [
            '/.git/config', '/.env', '/backup.zip', '/wp-config.php',
            '/config.php', '/.aws/credentials', '/.ssh/id_rsa',
            '/database.sql', '/phpinfo.php', '/info.php',
            '/.htaccess', '/.htpasswd', '/web.config',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/.well-known/security.txt', '/robots.txt',
            '/sitemap.xml', '/.DS_Store', '/.gitignore'
        ]
        
        found_files = []
        
        for path in sensitive_paths:
            try:
                url = f"{self.base_url}{path}"
                response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    # Check if it's actually a file (not a directory listing)
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type or len(response.content) < 1000:
                        found_files.append({
                            'path': path,
                            'url': url,
                            'status': 200,
                            'size': len(response.content),
                            'risk': 'HIGH'
                        })
                elif response.status_code == 403:
                    found_files.append({
                        'path': path,
                        'url': url,
                        'status': 403,
                        'risk': 'MEDIUM'
                    })
            except:
                pass
        
        return found_files

    def calculate_risk_score(self):
        """Calculate overall risk score based on all findings"""
        score = 0
        factors = []
        
        # Network risks
        network = self.results.get('network_scan', {})
        if network.get('open_ports'):
            port_count = len(network['open_ports'])
            score += min(port_count * 2, 20)
            if port_count > 5:
                factors.append(f"Multiple open ports ({port_count})")
        
        # SSL/TLS risks
        ssl = self.results.get('ssl_tls', {})
        if ssl.get('is_expiring_soon'):
            score += 10
            factors.append("SSL certificate expiring soon")
        if not ssl.get('is_valid'):
            score += 30
            factors.append("Invalid SSL certificate")
        
        # Missing security headers
        headers = self.results.get('security_headers', {})
        if isinstance(headers, dict):
            missing_count = len(headers.get('missing', []))
            score += missing_count * 5
            if missing_count > 0:
                factors.append(f"Missing {missing_count} security headers")
        
        # Cookie risks
        cookies = self.results.get('cookies', [])
        for cookie in cookies:
            if isinstance(cookie, dict):
                score += cookie.get('risk_score', 0)
        
        # Sensitive files found
        sensitive = self.results.get('sensitive_files', [])
        score += len(sensitive) * 15
        if sensitive:
            factors.append(f"Found {len(sensitive)} exposed sensitive files")
        
        # Set risk level
        self.results['risk_score'] = min(score, 100)
        if score >= 60:
            self.results['risk_level'] = 'HIGH'
        elif score >= 30:
            self.results['risk_level'] = 'MEDIUM'
        else:
            self.results['risk_level'] = 'LOW'
        
        self.results['risk_factors'] = factors

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No domain provided'}))
        sys.exit(1)
    
    domain = sys.argv[1]
    scanner = WebsiteSecurityScanner(domain)
    results = scanner.scan_all()
    print(json.dumps(results, indent=2, default=str))
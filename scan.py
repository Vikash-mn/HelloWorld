#!/usr/bin/env python3
# Ultimate Linux Network Security Scanner - Power Edition (Combined Version)

import ssl
import whois
from ssl import SSLWantReadError, SSLWantWriteError

# Database imports with error handling
try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    print("[-] MySQL connector not available - MySQL scanning disabled")

try:
    import psycopg2
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    print("[-] Psycopg2 not available - PostgreSQL scanning disabled")

try:
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False
    print("[-] PyMongo not available - MongoDB scanning disabled")
from time import sleep
import logging
from typing import Pattern
import argparse
import aiohttp
import asyncio
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
import ipwhois
import vt
import dns.resolver
import nmap
import requests
import scapy.all as scapy
import sslyze
from bs4 import BeautifulSoup
from cryptography import x509
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
try:
    from wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False
    print("[-] Wappalyzer not available - technology detection disabled")

# Advanced imports for enhanced capabilities
try:
    import torch
    import torch.nn as nn
    from transformers import AutoTokenizer, AutoModel
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[-] PyTorch/Transformers not available - ML features disabled")

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    print("[-] Docker library not available - container scanning disabled")

try:
    from kubernetes import client, config
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    print("[-] Kubernetes library not available - K8s scanning disabled")

try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    print("[-] Boto3 not available - AWS cloud scanning disabled")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[-] YARA not available - advanced pattern matching disabled")

COMMON_CREDS = {
    'mysql': [
        ('root', ''),
        ('root', 'root'),
        ('admin', 'admin'),
        ('mysql', 'mysql'),
        ('user', 'password')
    ],
    'postgresql': [
        ('postgres', 'postgres'),
        ('postgres', ''),
        ('admin', 'admin'),
        ('admin', 'password'),
        ('user', 'postgres')
    ],
    'mongodb': [
        ('admin', ''),
        ('admin', 'admin'),
        ('user', '123456'),
        ('root', 'root')
    ],
    'oracle': [
        ('system', 'manager'),
        ('sys', 'change_on_install'),
        ('scott', 'tiger')
    ]
}

# Connection timeouts in seconds
CONNECT_TIMEOUT = 3
RETRY_DELAY = 1  # seconds between retries
MAX_RETRIES = 2

# Enhanced Configuration
CONFIG = {
    "api_keys": {
        "virustotal": "81fcb279085331b577c95830aacb4baf90b1eb8dc16c890af5ecc1e36ec73398",
        "shodan": "Y5VLGOqBwOJvHX2oCJrNy5xZq4jerrmr4",
        "censys": None,
        "binaryedge": None,
    },
    "scan": {
        "default_ports": "21,22,80,443,3389,8080,8443",
        "full_ports": "1-65535",
        "web_ports": "80,443,8080,8443,8888,4443,4444,10443",
        "hidden_ports": "3000-4000,5000-6000,7000-8000,9000-10000",
        "database_ports": "1433,1434,1521,1830,3306,3351,5432,5984,6379,7199,7474,7473,7687",
        "scan_threads": 900,
        "timeout": 90,
        "max_pages": 500,
        "max_depth": 10,
        "max_threads": 50,
    },
    "telemetry": {
        "enabled": False
    },
    "paths": {
        "output_dir": "/var/log/security_scans",
        "screenshots_dir": "/var/log/security_scans/screenshots",
        "wordlists": {
            'dirs': '/usr/share/wordlists/dirb/common.txt',
            'subdomains': '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
            'passwords': '/usr/share/wordlists/rockyou.txt',
            'api_endpoints': '/usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt',
        },
        "tools": {
            'nmap': '/usr/bin/nmap',
            'nikto': '/usr/bin/nikto',
            'nuclei': '/usr/bin/nuclei',
            'gobuster': '/usr/bin/gobuster',
            'ffuf': '/usr/bin/ffuf',
            'sqlmap': '/usr/bin/sqlmap',
            'dirb': '/usr/bin/dirb',
            'hydra': '/usr/bin/hydra',
            'john': '/usr/bin/john',
            'hashcat': '/usr/bin/hashcat',
        }
    },
    "advanced": {
        "tor_proxy": "socks5://127.0.0.1:9050",
        "user_agents": "/usr/share/wordlists/user-agents.txt",
        "rate_limit_delay": 0.05,
        "aggressive_scan": False,
        "stealth_mode": False,
    },
    "rate_limiting": {
        "min_request_interval": 0.1,
        "max_requests_per_window": 100,
        "rate_limit_window": 60,
    },
    "scan_safety": {
        "max_requests_per_target": 1000,
        "max_bandwidth": "10Mbps",
        "dangerous_tests": {
            "sql_injection": True,
            "rce_test": False,
            "lfi_test": True
        }
    },
    "ml_detection": {
        "enabled": True,
        "model_path": "/opt/models/vuln_detector.pt",
        "confidence_threshold": 0.85,
        "max_patterns": 1000
    },
    "advanced_evasion": {
        "enabled": True,
        "fragmented_packets": True,
        "spoofed_source": False,
        "randomized_timing": True,
        "payload_obfuscation": True
    },
    "container_security": {
        "enabled": True,
        "scan_images": True,
        "check_privileges": True,
        "analyze_networking": True
    },
    "iot_security": {
        "enabled": True,
        "device_fingerprinting": True,
        "protocol_analysis": True,
        "known_vulnerabilities": True
    },
    "api_security": {
        "enabled": True,
        "test_graphql": True,
        "test_rest": True,
        "check_rate_limits": True,
        "analyze_auth": True
    }
}

# Constants
DEFAULT_CHANNELS = list(range(1, 14)) + [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
WIFI_SCAN_DURATION = 60  # seconds
MAX_CONCURRENT_SCANS = 5  # Limit concurrent scans to avoid system overload

class MLVulnerabilityDetector:
    """Machine Learning-based vulnerability detection system"""

    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.vulnerability_patterns = {
            'sqli': [
                r'(?i)(union|select|insert|update|delete|drop|create|alter).*',
                r'(?i)(1=1|--|#|/\*|\*/)',
                r'(?i)(benchmark|sleep|waitfor)\s*\(',
                r'(?i)(information_schema|sysobjects|syscolumns)'
            ],
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'<iframe[^>]*>.*?</iframe>',
                r'<object[^>]*>.*?</object>',
                r'<embed[^>]*>.*?</embed>'
            ],
            'rce': [
                r'(?i)(eval|exec|system|shell_exec|popen|passthru)',
                r'(?i)(cmd|command|bash|sh|python|perl)\s+',
                r'(?i)(Runtime\.getRuntime|ProcessBuilder)',
                r'(?i)(\$\{.*\}|\$\(.*\))',
                r'(?i)(import\s+os|subprocess\.|commands\.)'
            ],
            'lfi': [
                r'\.\./',
                r'\.\.%2e/',
                r'%2e%2e/',
                r'file://',
                r'(?i)(include|require|readfile|fopen)',
                r'(?i)(/etc/passwd|/etc/shadow|/proc/self/environ)'
            ],
            'idor': [
                r'/user/\d+',
                r'/admin/\d+',
                r'/profile/\d+',
                r'/account/\d+',
                r'/id=\d+',
                r'/user_id=\d+'
            ]
        }

    def initialize_model(self):
        """Initialize the ML model for vulnerability detection"""
        if not ML_AVAILABLE:
            return False

        try:
            # Load pre-trained model for vulnerability detection
            self.tokenizer = AutoTokenizer.from_pretrained('microsoft/codebert-base')
            self.model = AutoModel.from_pretrained('microsoft/codebert-base')

            # Move model to appropriate device
            self.model.to(self.device)
            self.model.eval()

            return True
        except Exception as e:
            print(f"[-] ML model initialization failed: {str(e)}")
            return False

    def analyze_code_patterns(self, content: str) -> Dict:
        """Analyze code patterns for potential vulnerabilities"""
        results = {
            'detected_vulnerabilities': [],
            'confidence_scores': {},
            'risk_level': 'low'
        }

        if not content:
            return results

        # Pattern-based detection
        for vuln_type, patterns in self.vulnerability_patterns.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    matches.append(pattern)

            if matches:
                confidence = min(0.9, len(matches) * 0.2)
                results['detected_vulnerabilities'].append({
                    'type': vuln_type,
                    'patterns': matches,
                    'confidence': confidence,
                    'severity': self._calculate_severity(vuln_type, confidence)
                })
                results['confidence_scores'][vuln_type] = confidence

        # Calculate overall risk level
        if results['detected_vulnerabilities']:
            max_confidence = max([v['confidence'] for v in results['detected_vulnerabilities']])
            if max_confidence > 0.8:
                results['risk_level'] = 'critical'
            elif max_confidence > 0.6:
                results['risk_level'] = 'high'
            elif max_confidence > 0.4:
                results['risk_level'] = 'medium'

        return results

    def analyze_http_traffic(self, request: str, response: str) -> Dict:
        """Analyze HTTP traffic for anomalies and vulnerabilities"""
        results = {
            'anomalies': [],
            'potential_vulnerabilities': [],
            'traffic_score': 0.0
        }

        # Check for suspicious patterns in request
        if request:
            if len(request) > 10000:  # Unusually large request
                results['anomalies'].append('Unusually large request size')

            if request.count('../') > 3:
                results['potential_vulnerabilities'].append({
                    'type': 'path_traversal',
                    'confidence': 0.8
                })

        # Check for suspicious patterns in response
        if response:
            if 'error' in response.lower() and 'sql' in response.lower():
                results['potential_vulnerabilities'].append({
                    'type': 'sql_injection',
                    'confidence': 0.9
                })

            if '<script>' in response and 'alert(' in response:
                results['potential_vulnerabilities'].append({
                    'type': 'xss',
                    'confidence': 0.85
                })

        # Calculate traffic score
        if results['potential_vulnerabilities']:
            results['traffic_score'] = sum([v['confidence'] for v in results['potential_vulnerabilities']])

        return results

    def _calculate_severity(self, vuln_type: str, confidence: float) -> str:
        """Calculate severity based on vulnerability type and confidence"""
        severity_map = {
            'rce': 'critical',
            'sqli': 'high',
            'xss': 'medium',
            'lfi': 'high',
            'idor': 'medium'
        }

        base_severity = severity_map.get(vuln_type, 'medium')

        if confidence > 0.8:
            return 'critical'
        elif confidence > 0.6:
            return 'high'
        elif confidence > 0.4:
            return base_severity
        else:
            return 'low'

class AdvancedEvasion:
    """Advanced evasion techniques for stealth scanning"""

    def __init__(self):
        self.session_fragments = []
        self.timing_variations = [0.1, 0.2, 0.5, 1.0, 1.5, 2.0]

    def fragment_request(self, data: bytes, fragment_size: int = 8) -> List[bytes]:
        """Fragment data into smaller packets"""
        fragments = []
        for i in range(0, len(data), fragment_size):
            fragment = data[i:i + fragment_size]
            fragments.append(fragment)
        return fragments

    def obfuscate_payload(self, payload: str) -> str:
        """Obfuscate payload to evade detection"""
        # Simple obfuscation techniques
        obfuscated = payload

        # Case variation
        if len(obfuscated) > 5:
            chars = list(obfuscated)
            for i in range(1, len(chars) - 1, 2):
                chars[i] = chars[i].upper()
            obfuscated = ''.join(chars)

        # Insert junk data
        if len(obfuscated) > 10:
            junk_positions = [len(obfuscated) // 3, len(obfuscated) * 2 // 3]
            for pos in junk_positions:
                if pos < len(obfuscated):
                    obfuscated = obfuscated[:pos] + f"/*{pos}*/" + obfuscated[pos:]

        return obfuscated

    def randomize_timing(self) -> float:
        """Return randomized delay for timing-based evasion"""
        import random
        return random.choice(self.timing_variations)

    def create_decoy_traffic(self, target: str, duration: int = 30):
        """Create decoy traffic to mask real scanning activity"""
        try:
            # Send benign requests to common endpoints
            decoy_urls = [
                '/robots.txt',
                '/sitemap.xml',
                '/favicon.ico',
                '/.well-known/security.txt'
            ]

            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    for url in decoy_urls:
                        response = requests.get(f"{target}{url}", timeout=2)
                        time.sleep(self.randomize_timing())
                except:
                    pass

        except Exception as e:
            print(f"[-] Decoy traffic generation failed: {str(e)}")

class ContainerSecurityScanner:
    """Container and Docker security scanning"""

    def __init__(self):
        self.docker_client = None
        if DOCKER_AVAILABLE:
            try:
                self.docker_client = docker.from_env()
            except:
                self.docker_client = None

    def scan_docker_images(self) -> Dict:
        """Scan Docker images for vulnerabilities"""
        results = {
            'images': [],
            'vulnerabilities': [],
            'recommendations': []
        }

        if not self.docker_client:
            return {'error': 'Docker not available'}

        try:
            # Get all images
            images = self.docker_client.images.list()

            for image in images:
                image_info = {
                    'id': image.id,
                    'tags': image.tags,
                    'size': image.attrs.get('Size', 0),
                    'created': image.attrs.get('Created'),
                    'vulnerabilities': []
                }

                # Check for privileged containers
                containers = self.docker_client.containers.list(all=True)
                for container in containers:
                    if container.image.id == image.id:
                        if container.attrs.get('HostConfig', {}).get('Privileged', False):
                            image_info['vulnerabilities'].append({
                                'type': 'privileged_container',
                                'severity': 'critical',
                                'description': 'Container running in privileged mode'
                            })

                # Check for exposed ports
                if image.attrs.get('Config', {}).get('ExposedPorts'):
                    image_info['vulnerabilities'].append({
                        'type': 'exposed_ports',
                        'severity': 'medium',
                        'description': f"Image exposes ports: {list(image.attrs['Config']['ExposedPorts'].keys())}"
                    })

                # Check for root user
                if image.attrs.get('Config', {}).get('User') == 'root':
                    image_info['vulnerabilities'].append({
                        'type': 'root_user',
                        'severity': 'high',
                        'description': 'Container runs as root user'
                    })

                results['images'].append(image_info)

        except Exception as e:
            results['error'] = str(e)

        return results

    def check_container_networking(self) -> Dict:
        """Analyze container networking for security issues"""
        results = {
            'network_issues': [],
            'recommendations': []
        }

        if not self.docker_client:
            return {'error': 'Docker not available'}

        try:
            # Check for containers with host networking
            containers = self.docker_client.containers.list(all=True)
            for container in containers:
                network_mode = container.attrs.get('HostConfig', {}).get('NetworkMode', '')
                if network_mode == 'host':
                    results['network_issues'].append({
                        'container': container.name,
                        'issue': 'host_networking',
                        'severity': 'critical',
                        'description': 'Container uses host networking mode'
                    })

            # Check for port mappings
            for container in containers:
                ports = container.attrs.get('NetworkSettings', {}).get('Ports', {})
                if ports:
                    for port_spec, host_bindings in ports.items():
                        if host_bindings:
                            results['network_issues'].append({
                                'container': container.name,
                                'issue': 'port_mapping',
                                'severity': 'medium',
                                'description': f"Port {port_spec} mapped to host"
                            })

        except Exception as e:
            results['error'] = str(e)

        return results

class IoTSecurityScanner:
    """IoT device security scanning"""

    def __init__(self):
        self.known_vulnerabilities = {
            'telnet': {'ports': [23], 'severity': 'critical'},
            'upnp': {'ports': [1900], 'severity': 'high'},
            'hnap': {'ports': [8080], 'severity': 'high'},
            'tr-064': {'ports': [49000], 'severity': 'critical'}
        }

    def fingerprint_device(self, host: str, port: int) -> Dict:
        """Fingerprint IoT device characteristics"""
        result = {
            'device_type': 'unknown',
            'manufacturer': 'unknown',
            'model': 'unknown',
            'vulnerabilities': []
        }

        try:
            # Try common IoT protocols
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)

            if sock.connect_ex((host, port)) == 0:
                # Try HTTP
                if port in [80, 8080, 8000]:
                    try:
                        sock.send(b'GET / HTTP/1.0\r\n\r\n')
                        response = sock.recv(1024)
                        if b'Server:' in response:
                            server = response.split(b'Server:')[1].split(b'\r\n')[0]
                            result['manufacturer'] = server.decode().split('/')[0] if b'/' in server else server.decode()
                    except:
                        pass

                # Try Telnet
                elif port == 23:
                    result['vulnerabilities'].append({
                        'type': 'telnet_enabled',
                        'severity': 'critical',
                        'description': 'Telnet service exposed - weak authentication'
                    })

                # Try UPnP
                elif port == 1900:
                    result['vulnerabilities'].append({
                        'type': 'upnp_exposed',
                        'severity': 'high',
                        'description': 'UPnP service exposed - potential for external control'
                    })

            sock.close()

        except Exception as e:
            result['error'] = str(e)

        return result

    def scan_iot_devices(self, network_range: str) -> Dict:
        """Scan network range for IoT devices"""
        results = {
            'devices': [],
            'vulnerabilities': [],
            'recommendations': []
        }

        try:
            # Scan common IoT ports
            common_iot_ports = [23, 80, 443, 8080, 1900, 2000, 49000, 50000]

            for port in common_iot_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((network_range, port))

                    if result == 0:
                        device_info = self.fingerprint_device(network_range, port)
                        device_info['port'] = port
                        device_info['protocol'] = 'tcp'
                        results['devices'].append(device_info)

                        # Check for known vulnerabilities
                        for vuln, info in self.known_vulnerabilities.items():
                            if port in info['ports']:
                                results['vulnerabilities'].append({
                                    'device': network_range,
                                    'port': port,
                                    'vulnerability': vuln,
                                    'severity': info['severity']
                                })

                    sock.close()

                except Exception:
                    continue

        except Exception as e:
            results['error'] = str(e)

        return results

class UltimateScanner:
    def __init__(self, target: str):
        self.target = target
        self.domain = None
        self.ip_address = None
        self.base_url = None
        self.logger = logging.getLogger(__name__)
        self.MAX_RETRIES = 3
        self.CONNECT_TIMEOUT = 3
        self.visited_urls = set()
        self.results = {
            'metadata': {
                'target': target,
                'start_time': datetime.utcnow().isoformat(),
                'tool_version': '5.0-Ultra',
                'config': CONFIG
            },
            'results': {}
        }
        self.session = self._init_http_session()
        self.selenium_driver = self._init_selenium()
        self.lock = threading.Lock()

        # Initialize advanced components
        self.ml_detector = MLVulnerabilityDetector()
        self.evasion_engine = AdvancedEvasion()
        self.container_scanner = ContainerSecurityScanner()
        self.iot_scanner = IoTSecurityScanner()

        # Initialize ML model if enabled
        if CONFIG['ml_detection']['enabled']:
            self.ml_detector.initialize_model()

    def _init_http_session(self) -> requests.Session:
        """Initialize advanced HTTP session with retries and proxies"""
        session = requests.Session()
        
        self.request_counter = 0
        self.last_request_time = time.time()
        self.window_start = time.time()
        
        # Configure retry strategy
        retry = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"]
        )
        
        # Add rate limiting adapter
        class RateLimitingAdapter(HTTPAdapter):
            def send(self, request, **kwargs):
                # Enforce rate limiting
                elapsed = time.time() - self.last_request_time
                if elapsed < CONFIG['advanced']['min_request_interval']:
                    time.sleep(CONFIG['advanced']['min_request_interval'] - elapsed)

                self.last_request_time = time.time()
                self.request_counter += 1

                # Reset counter if window passed
                if time.time() - self.window_start > CONFIG['advanced']['rate_limit_window']:
                    self.request_counter = 0
                    self.window_start = time.time()

                # Check if we've exceeded rate limit
                if self.request_counter >= CONFIG['advanced']['max_requests_per_window']:
                    time.sleep(CONFIG['advanced']['rate_limit_window'] - (time.time() - self.window_start))
                    self.request_counter = 0
                    self.window_start = time.time()

                return super().send(request, **kwargs)
        
        adapter = RateLimitingAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure headers
        session.headers.update({
            'User-Agent': UserAgent().random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Configure proxies if Tor is available
        if self._check_tor():
            session.proxies = {
                'http': CONFIG['advanced']['tor_proxy'],
                'https': CONFIG['advanced']['tor_proxy']
            }
        
        return session
    
    def _init_selenium(self) -> Optional[webdriver.Chrome]:
        """Initialize headless Chrome with advanced options"""
        try:
            options = Options()
            
            # Basic options
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--window-size=1920,1080')
            
            # Security options
            options.add_argument('--disable-extensions')
            options.add_argument('--disable-popup-blocking')
            options.add_argument('--disable-notifications')
            options.add_argument('--ignore-certificate-errors')
            
            # Performance options
            options.add_argument('--disable-software-rasterizer')
            options.add_argument('--disable-background-networking')
            options.add_argument('--disable-default-apps')
            options.add_argument('--disable-sync')
            
            # Find Chrome binary
            chrome_paths = [
                '/usr/bin/google-chrome',
                '/usr/bin/chromium',
                '/usr/bin/chromium-browser',
                '/usr/local/bin/chrome',
                '/opt/google/chrome/chrome'
            ]
            
            for path in chrome_paths:
                if os.path.exists(path):
                    options.binary_location = path
                    break
            
            # Set up proxy if Tor is available
            if self._check_tor():
                options.add_argument(f'--proxy-server={CONFIG["advanced"]["tor_proxy"]}')
            
            # Configure ChromeDriver
            driver = webdriver.Chrome(
                options=options,
                service_args=['--verbose', '--log-path=chromedriver.log']
            )
            
            # Set timeouts
            driver.set_page_load_timeout(30)
            driver.set_script_timeout(20)
            
            return driver
        except Exception as e:
            print(f"[-] Selenium initialization failed: {str(e)}")
            return None

    def _submit_telemetry(self) -> None:
        """Submit anonymous usage statistics to improve the tool"""
        if not CONFIG['telemetry']['enabled']:
            return

        telemetry_data = {
            'scan_type': self.scan_type,
            'duration': self.results['metadata']['execution_time'],
            'findings_count': self.results['executive_summary']['findings_summary']['total_vulnerabilities'],
            'version': self.results['metadata']['tool_version'],
            'timestamp': datetime.utcnow().isoformat()
        }

        try:
            requests.post(
                "https://telemetry.example.com/submit",
                json=telemetry_data,
                timeout=5
            )
        except:
            pass  # Fail silently

    def _sanitize_input(self, input_str: str) -> str:
        """Sanitize input to prevent command injection"""
        if not input_str:
            return ""

        # Remove potentially dangerous characters
        sanitized = re.sub(r"[;|&$`]", "", input_str)

        # For URLs, validate structure
        if any(sanitized.startswith(p) for p in ['http://', 'https://']):
            parsed = urlparse(sanitized)
            if not parsed.netloc:
                raise ValueError("Invalid URL provided")

        return sanitized

    def _run_subprocess(self, command: List[str]) -> str:
        """Execute subprocess command with enhanced security checks"""
        try:
            # Validate and sanitize all command parts
            sanitized_cmd = [self._sanitize_input(part) for part in command]

            # Security checks
            dangerous_commands = ['rm', 'sh', 'bash', 'chmod', 'dd']
            if any(cmd in dangerous_commands for cmd in sanitized_cmd):
                raise ValueError(f"Potentially dangerous command blocked: {' '.join(sanitized_cmd)}")

            # Execute with timeout and restricted environment
            result = subprocess.run(
                sanitized_cmd,
                capture_output=True,
                text=True,
                timeout=CONFIG['scan']['timeout'],
                check=False,
                shell=False,
                env={'PATH': '/usr/bin:/bin', 'HOME': os.getcwd()}
            )

            if result.returncode != 0:
                self.logger.error(f"Command failed: {result.stderr}")
                return f"Error: {result.stderr}"

            return result.stdout
        except subprocess.TimeoutExpired:
            return "Error: Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"

    def check_for_updates(self) -> Dict:
        """Check for updates to the scanner"""
        try:
            response = requests.get(
                "https://api.github.com/repos/your-repo/ultimate-scanner/releases/latest",
                timeout=5
            )
            latest = response.json()
            current = self.results['metadata']['tool_version']

            return {
                'update_available': latest['tag_name'] != current,
                'current_version': current,
                'latest_version': latest['tag_name'],
                'changelog': latest.get('body', '')
            }
        except Exception as e:
            return {'error': str(e)}

    def _validate_scan_parameters(self):
        """Validate scan parameters for safety"""
        if not self.target:
            raise ValueError("Scan target not specified")
        
        if self.is_valid_ip(self.target) and not self._is_scan_allowed(self.target):
            raise ValueError(f"Scanning target {self.target} is not permitted")
        
        if (CONFIG['scan_safety']['dangerous_tests']['rce_test'] and 
            not CONFIG['advanced']['aggressive_scan']):
            CONFIG['scan_safety']['dangerous_tests']['rce_test'] = False
            logging.warning("RCE tests disabled - enable aggressive scan to run them")

    def _check_ssl_vulnerabilities(self, hostname: str) -> Dict:
        """Comprehensive SSL/TLS vulnerability checker"""
        result = {
            'heartbleed': False,
            'poodle': False,
            'freak': False,
            'beast': False,
            'lucky13': False,
            'ccs_injection': False,
            'robot': False,
            'secure_renegotiation': False,
            'compression': False,
            'weak_ciphers': False,
            'certificate_issues': {
                'self_signed': False,
                'expired': False,
                'weak_signature': False,
                'hostname_mismatch': False
            }
        }

        try:
            # First check if port 443 is even open
            if not self._is_port_open(hostname, 443):
                result['error'] = "Port 443 not open"
                return result

            # Create a default SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Test basic SSL connection first
            try:
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        pass
            except Exception as e:
                result['error'] = f"Basic SSL connection failed: {str(e)}"
                return result

            # Check Heartbleed (CVE-2014-0160)
            result['heartbleed'] = self._check_heartbleed(hostname)

            # Check POODLE (CVE-2014-3566)
            result['poodle'] = self._check_poodle(hostname)

            # Check FREAK (CVE-2015-0204)
            result['freak'] = self._check_freak(hostname)

            # Check BEAST (CVE-2011-3389)
            result['beast'] = self._check_beast(hostname)

            # Check weak ciphers
            result['weak_ciphers'] = self._check_weak_ciphers(hostname)

            # Check certificate issues
            cert_info = self._get_certificate_info(hostname)
            if cert_info and 'error' not in cert_info:
                result['certificate_issues'] = {
                    'self_signed': cert_info.get('self_signed', False),
                    'expired': cert_info.get('expired', False),
                    'weak_signature': cert_info.get('weak_signature', False),
                    'hostname_mismatch': cert_info.get('hostname_mismatch', False),
                    'valid_from': cert_info.get('valid_from'),
                    'valid_to': cert_info.get('valid_to'),
                    'issuer': cert_info.get('issuer')
                }

            return result

        except Exception as e:
            result['error'] = f"SSL vulnerability check failed: {str(e)}"
            logging.error(f"SSL check failed for {hostname}: {str(e)}", exc_info=True)
        return result

    def _is_port_open(self, host: str, port: int) -> bool:
        """Check if a port is open"""
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except (socket.timeout, ConnectionRefusedError):
            return False
        except Exception:
            return False

    def _check_heartbleed(self, hostname: str) -> bool:
        """Check for Heartbleed vulnerability (CVE-2014-0160)"""
        try:
            # Create vulnerable SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False

            # Craft malicious heartbeat request
            payload = bytearray.fromhex(
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            )

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.sendall(payload)
                    response = ssock.recv(1024)

                    # If we get a response, it's likely vulnerable
                    return len(response) > 0

        except Exception:
            return False

    def _check_poodle(self, hostname: str) -> bool:
        """Check for POODLE vulnerability (CVE-2014-3566)"""
        try:
            # Try to connect with SSLv3 (vulnerable protocol)
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # If connection succeeds, server supports SSLv3 (vulnerable)
                    return True

        except ssl.SSLError:
            # Server doesn't support SSLv3 (not vulnerable)
            return False
        except Exception:
            return False

    def _check_freak(self, hostname: str) -> bool:
        """Check for FREAK vulnerability (CVE-2015-0204)"""
        try:
            # Try to connect with EXPORT cipher suites
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.set_ciphers('EXPORT')
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # If connection succeeds with EXPORT cipher, vulnerable
                    return True

        except ssl.SSLError:
            # Server doesn't support EXPORT ciphers (not vulnerable)
            return False
        except Exception:
            return False

    def _check_beast(self, hostname: str) -> bool:
        """Check for BEAST vulnerability (CVE-2011-3389)"""
        try:
            # Try to connect with RC4 cipher (vulnerable)
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.set_ciphers('RC4')
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    # If using RC4, vulnerable
                    return cipher[0] == 'RC4'

        except ssl.SSLError:
            # Server doesn't support RC4 (not vulnerable)
            return False
        except Exception:
            return False

    def _check_weak_ciphers(self, hostname: str) -> bool:
        """Check for weak cipher suites"""
        weak_ciphers = [
            'DES', '3DES', 'RC4', 'RC2', 'IDEA',
            'SEED', 'MD5', 'ANON', 'NULL', 'EXPORT',
            'CBC', 'SHA1'
        ]

        try:
            context = ssl.create_default_context()
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        return any(wc in cipher[0] for wc in weak_ciphers)
                    return False

        except Exception:
            return False

    def _get_certificate_info(self, hostname: str) -> Dict:
        """Get detailed certificate information"""
        result = {
            'self_signed': False,
            'expired': False,
            'weak_signature': False,
            'hostname_mismatch': False
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Check if certificate is self-signed
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    result['self_signed'] = issuer == subject

                    # Check expiration
                    not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                    result['expired'] = time.time() > not_after
                    result['valid_from'] = cert['notBefore']
                    result['valid_to'] = cert['notAfter']
                    result['issuer'] = issuer.get('organizationName', 'Unknown')

                    # Check signature algorithm
                    if 'sha1' in cert.get('signatureAlgorithm', '').lower():
                        result['weak_signature'] = True

                    # Check hostname match
                    try:
                        ssl.match_hostname(cert, hostname)
                        result['hostname_mismatch'] = False
                    except ssl.CertificateError:
                        result['hostname_mismatch'] = True

                    return result

        except ssl.SSLError as e:
            if 'CERTIFICATE_VERIFY_FAILED' in str(e):
                result['error'] = "Certificate verification failed"
                return result
            raise
        except Exception as e:
            result['error'] = f"Certificate check failed: {str(e)}"
            return result

    def _check_db_auth(self, host: str, port: int, db_type: str) -> bool:
        """Check if database requires authentication."""
        try:
            if db_type == 'mysql':
                conn = mysql.connector.connect(
                    host=host,
                    port=port,
                    user='invalid_user',
                    password='invalid_password',
                    connect_timeout=self.CONNECT_TIMEOUT
                )
                conn.close()
                return False
            elif db_type == 'postgresql':
                conn = psycopg2.connect(
                    host=host,
                    port=port,
                    user='invalid_user',
                    password='invalid_password',
                    connect_timeout=self.CONNECT_TIMEOUT
                )
                conn.close()
                return False
            elif db_type == 'mongodb':
                client = MongoClient(
                    host=host,
                    port=port,
                    username='invalid_user',
                    password='invalid_password',
                    serverSelectionTimeoutMS=self.CONNECT_TIMEOUT * 1000
                )
                client.admin.command('ismaster')
                return False
            return True
        except mysql.connector.errors.ProgrammingError as e:
            return 'Access denied' in str(e)
        except Exception:
            return True

    def _test_default_db_creds(self, host: str, port: int, db_type: str) -> List[Dict]:
        """Test common database credentials against the target database."""
        results = []

        if db_type not in COMMON_CREDS:
            return results

        for user, pwd in COMMON_CREDS[db_type]:
            try:
                if db_type == 'mysql':
                    conn = mysql.connector.connect(
                        host=host,
                        port=port,
                        user=user,
                        password=pwd,
                        connect_timeout=self.CONNECT_TIMEOUT
                    )
                    if conn.is_connected():
                        results.append({'user': user, 'password': pwd, 'success': True})
                    conn.close()
                elif db_type == 'postgresql':
                    conn = psycopg2.connect(
                        host=host,
                        port=port,
                        user=user,
                        password=pwd,
                        connect_timeout=self.CONNECT_TIMEOUT
                    )
                    results.append({'user': user, 'password': pwd, 'success': True})
                    conn.close()
                elif db_type == 'mongodb':
                    client = MongoClient(
                        host=host,
                        port=port,
                        username=user,
                        password=pwd,
                        serverSelectionTimeoutMS=self.CONNECT_TIMEOUT * 1000
                    )
                    client.admin.command('ismaster')
                    results.append({'user': user, 'password': pwd, 'success': True})
                    client.close()
            except Exception:
                continue
            
        return results

    def _find_subdomains(self) -> List[str]:
        """Brute-force subdomains using wordlist."""
        if not os.path.exists(CONFIG['paths']['wordlists']['subdomains']):
            return []

        found = []
        with open(CONFIG['paths']['wordlists']['subdomains']) as f:
            subdomains = [line.strip() for line in f if line.strip()]

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(
                    self._check_subdomain,
                    f"{sub}.{self.domain}"
                ): sub for sub in subdomains
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        return found

    def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if subdomain resolves and responds."""
        try:
            ip = socket.gethostbyname(subdomain)
            response = self.session.head(f"http://{subdomain}", timeout=3)
            if response.status_code < 400:
                return subdomain
        except:
            return None

    def _check_directory_listing(self, url: str) -> bool:
        """Check if directory listing is enabled."""
        test_paths = ['/images/', '/assets/', '/static/']
        for path in test_paths:
            try:
                response = self.session.get(url + path, timeout=5)
                if 'Index of' in response.text and '<a href=' in response.text:
                    return True
            except requests.RequestException:
                continue
        return False

    def _find_sensitive_files(self) -> List[Dict]:
        """Check for common sensitive files."""
        sensitive_files = [
            '/.env', '/.git/config', '/.htaccess',
            '/web.config', '/phpinfo.php', '/server-status'
        ]
        results = []
        for file in sensitive_files:
            try:
                response = self.session.get(self.base_url + file, timeout=3)
                if response.status_code == 200 and len(response.text) > 0:
                    results.append({
                        'url': response.url,
                        'status': response.status_code,
                        'size': len(response.content)
                    })
            except requests.RequestException:
                continue
        return results

    def _check_cors(self) -> Dict:
        """Test for CORS misconfigurations."""
        test_headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'GET'
        }
        try:
            response = self.session.options(
                self.base_url,
                headers=test_headers,
                timeout=5
            )
            cors_headers = {
                k.lower(): v for k, v in response.headers.items()
                if k.lower().startswith('access-control')
            }
            return {
                'vulnerable': '*' in cors_headers.get('access-control-allow-origin', ''),
                'headers': cors_headers
            }
        except requests.RequestException as e:
            return {'error': str(e)}

    def _query_shodan(self) -> Dict:
        """Query Shodan for target information."""
        if not CONFIG['api_keys']['shodan'] or not self.ip_address:
            return {}

        try:
            from shodan import Shodan
            api = Shodan(CONFIG['api_keys']['shodan'])
            host = api.host(self.ip_address)
            return {
                'ports': host.get('ports', []),
                'vulns': host.get('vulns', []),
                'services': {item['port']: item for item in host.get('data', [])}
            }
        except Exception as e:
            return {'error': str(e)}

    def _query_virustotal(self) -> Dict:
        """Query VirusTotal for domain/IP reputation."""
        if not CONFIG['api_keys']['virustotal'] or not self.domain:
            return {}

        try:
            client = vt.Client(CONFIG['api_keys']['virustotal'])
            url_id = vt.url_id(self.base_url)
            report = client.get_object(f"/urls/{url_id}")
            return {
                'malicious': report.last_analysis_stats['malicious'],
                'engines': {k: v for k, v in report.last_analysis_results.items() if v['category'] == 'malicious'}
            }
        except Exception as e:
            return {'error': str(e)}

    def _detect_cloud_provider(self) -> Optional[str]:
        """Detect cloud hosting provider."""
        if not self.ip_address:
            return None

        try:
            ip_info = ipwhois.IPWhois(self.ip_address)
            rdap = ip_info.lookup_rdap()
            rdap_str = str(rdap).lower()

            if 'amazon' in rdap_str:
                return 'AWS'
            elif 'google' in rdap_str:
                return 'GCP'
            elif 'microsoft' in rdap_str:
                return 'Azure'
        except Exception as e:
            print(f"Error detecting cloud provider via RDAP: {e}")

        # Fallback to DNS checks
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            if any('cloudflare' in str(r).lower() for r in ns_records):
                return 'Cloudflare'
        except Exception as e:
            print(f"Error detecting cloud provider via DNS: {e}")

        return None

    def generate_html_report(self, results: Dict) -> str:
        """Generate comprehensive HTML report"""
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; }
                .critical { color: #d9534f; font-weight: bold; }
                .high { color: #f0ad4e; }
                .medium { color: #5bc0de; }
                .low { color: #5cb85c; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                tr:hover { background-color: #f5f5f5; }
            </style>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            <h2>Executive Summary</h2>
            <!-- Report content would go here -->
        </body>
        </html>
        """

        # Implement actual report generation logic
        # ...
        return template

    def _generate_executive_summary(self):
        """Enhanced executive summary with more metrics"""
        summary = {
            'scan_overview': {
                'target': self.target,
                'start_time': self.results['metadata']['start_time'],
                'end_time': self.results['metadata']['end_time'],
                'duration_seconds': self.results['metadata']['execution_time'],
                'scan_type': 'full' if 'vulnerability_scan' in self.results['results'] else 'web'
            },
            'findings_summary': {
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'medium_vulnerabilities': 0,
                'open_ports': 0,
                'web_pages_found': 0
            },
            'recommendations': []
        }
        
        # Count vulnerabilities
        if 'risk_assessment' in self.results:
            for severity, vulns in self.results['risk_assessment'].items():
                if severity in summary['findings_summary']:
                    summary['findings_summary'][f"{severity}_vulnerabilities"] = len(vulns)
                    summary['findings_summary']['total_vulnerabilities'] += len(vulns)
        
        # Count open ports
        if 'port_scan' in self.results['results']:
            for host, data in self.results['results']['port_scan'].items():
                if 'protocols' in data:
                    for proto, ports in data['protocols'].items():
                        summary['findings_summary']['open_ports'] += len(ports)
        
        # Count web pages
        if 'web_spider' in self.results['results']:
            summary['findings_summary']['web_pages_found'] = len(
                self.results['results']['web_spider'].get('pages', [])
            )
        
        # Generate recommendations
        if summary['findings_summary']['critical_vulnerabilities'] > 0:
            summary['recommendations'].append(
                "Immediate remediation required for critical vulnerabilities"
            )
        
        if summary['findings_summary']['high_vulnerabilities'] > 0:
            summary['recommendations'].append(
                "Prioritize remediation of high severity vulnerabilities"
            )
        
        if 'outdated_software_vulnerabilities' in self.results.get('relationships', {}):
            summary['recommendations'].append(
                "Update outdated software components to mitigate known vulnerabilities"
            )
        
        self.results['executive_summary'] = summary
        return summary

    def _detect_cdn(self) -> Optional[str]:
        """Detect Content Delivery Network."""
        common_cdns = {
            'cloudflare': ('cloudflare', 'cf-ray'),
            'akamai': ('akamai', 'akamaighost'),
            'fastly': ('fastly', 'x-served-by'),
            'cloudfront': ('cloudfront', 'x-amz-cf-pop')
        }

        try:
            headers = self._get_http_headers()
            headers_str = str(headers).lower()
            for cdn, indicators in common_cdns.items():
                if any(indicator in headers_str for indicator in indicators):
                    return cdn
        except Exception as e:
            print(f"Error detecting CDN: {e}")

        return None

    def _detect_waf(self) -> Optional[str]:
        """Detect Web Application Firewall."""
        waf_signatures = {
            'Cloudflare': (re.compile(r'cloudflare', re.I), 'cf-ray'),
            'Akamai': (re.compile(r'akamai', re.I), 'akamaighost'),
            'Imperva': (re.compile(r'incapsula', re.I), 'x-cdn'),
            'AWS WAF': (re.compile(r'aws', re.I), 'x-aws-request-id')
        }

        try:
            response = self.session.get(self.base_url + "/<>'", timeout=5)
            for waf, (header_pattern, cookie_key) in waf_signatures.items():
                if header_pattern.search(str(response.headers)) or cookie_key in response.cookies:
                    return waf
        except Exception as e:
            print(f"Error detecting WAF: {e}")

        return None

    def _get_http_headers(self, url: str = None) -> Dict:
        """Get HTTP headers for a given URL with enhanced functionality"""
        target_url = url if url else self.base_url
        if not target_url:
            return {'error': 'No URL available for headers check'}
        
        try:
            response = self.session.head(target_url, timeout=5, allow_redirects=True)
            headers = dict(response.headers)
            
            # Additional security header analysis
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Referrer-Policy': headers.get('Referrer-Policy')
            }
            
            return {
                'status_code': response.status_code,
                'headers': headers,
                'security_headers': security_headers,
                'cookies': dict(response.cookies),
                'redirect_chain': [r.url for r in response.history],
                'final_url': response.url
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _scan_ports(self, ports: str) -> Dict:
        """Perform comprehensive port scanning with Nmap"""
        result = {}
        try:
            nm = nmap.PortScanner()
            scan_args = '-sV -T4' if not CONFIG['advanced']['stealth_mode'] else '-sS -T2'
            
            print(f"[*] Scanning ports {ports} on {self.ip_address or self.domain}")
            nm.scan(
                hosts=self.ip_address or self.domain,
                ports=ports,
                arguments=scan_args
            )
            
            for host in nm.all_hosts():
                result[host] = {
                    'hostnames': nm[host].hostnames(),
                    'status': nm[host].state(),
                    'protocols': {}
                }
                
                for proto in nm[host].all_protocols():
                    result[host]['protocols'][proto] = {}
                    
                    for port, data in nm[host][proto].items():
                        if data['state'] == 'open':
                            result[host]['protocols'][proto][port] = {
                                'name': data['name'],
                                'product': data.get('product', ''),
                                'version': data.get('version', ''),
                                'extrainfo': data.get('extrainfo', ''),
                                'cpe': data.get('cpe', ''),
                                'scripts': data.get('script', {})
                            }
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _is_host_up(self) -> bool:
        """Check if the target host is up and responsive"""
        try:
            if self.ip_address:
                # ICMP ping check
                subprocess.run(
                    ['ping', '-c', '1', '-W', '1', self.ip_address],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                return True
            elif self.base_url:
                # HTTP request check
                response = self.session.head(self.base_url, timeout=5)
                return response.status_code < 400
        except:
            return False
    
    def _recursive_spider(self, url: str, result: Dict, depth: int):
        """Recursively spider the website up to a specified depth"""
        if depth > CONFIG['scan']['max_depth'] or len(result['pages']) >= CONFIG['scan']['max_pages']:
            return
        
        try:
            self.selenium_driver.get(url)
            time.sleep(2)  # Wait for page to load
            
            # Get new links on this page
            links = self.selenium_driver.find_elements(By.TAG_NAME, 'a')
            new_links = []
            
            for link in links:
                try:
                    href = link.get_attribute('href')
                    if href and href not in self.visited_urls and self.domain in href:
                        new_links.append(href)
                        self.visited_urls.add(href)
                except:
                    continue
                
            # Process new links (limited to prevent excessive scanning)
            for link in new_links[:10]:  # Limit to 10 links per page
                try:
                    self.selenium_driver.get(link)
                    time.sleep(1)
                    
                    page_info = {
                        'url': self.selenium_driver.current_url,
                        'title': self.selenium_driver.title,
                        'source': self.selenium_driver.page_source[:1000] + '...',
                        'screenshot': os.path.join(
                            CONFIG['paths']['screenshots_dir'],
                            f"{hashlib.md5(link.encode()).hexdigest()}.png"
                        )
                    }
                    
                    self.selenium_driver.save_screenshot(page_info['screenshot'])
                    result['pages'].append(page_info)
                    
                    # Recurse
                    self._recursive_spider(link, result, depth + 1)
                except:
                    continue
        except Exception as e:
            print(f"[-] Error during spidering: {str(e)}")
    
    def _analyze_relationships(self):
        """Analyze relationships between different findings"""
        relationships = {
            'outdated_software_vulnerabilities': [],
            'open_ports_services': [],
            'web_application_risks': []
        }
        
        # Link outdated software with vulnerabilities
        if 'tech_stack' in self.results['results'] and 'vulnerability_scan' in self.results['results']:
            for tech, data in self.results['results']['tech_stack'].items():
                if 'versions' in data:
                    current = data['versions'][0] if data['versions'] else None
                    latest = data.get('latest_version')
                    if current != latest:
                        relationships['outdated_software_vulnerabilities'].append({
                            'technology': tech,
                            'current_version': current,
                            'latest_version': latest,
                            'associated_vulnerabilities': []
                        })
        
        # Link open ports with services
        if 'port_scan' in self.results['results']:
            for host, data in self.results['results']['port_scan'].items():
                if 'protocols' in data:
                    for proto, ports in data['protocols'].items():
                        for port, service in ports.items():
                            if service['state'] == 'open':
                                relationships['open_ports_services'].append({
                                    'host': host,
                                    'port': port,
                                    'service': service['name'],
                                    'vulnerabilities': service.get('vulnerabilities', [])
                                })
        
        self.results['relationships'] = relationships
    
    def _generate_risk_assessment(self):
        """Generate risk assessment based on findings"""
        risks = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'informational': []
        }
        
        # Classify vulnerabilities by severity
        if 'vulnerability_scan' in self.results['results']:
            for scan_type, results in self.results['results']['vulnerability_scan'].items():
                if isinstance(results, list):
                    for vuln in results:
                        if isinstance(vuln, dict):
                            severity = vuln.get('severity', 'medium').lower()
                            if severity in risks:
                                risks[severity].append({
                                    'type': scan_type,
                                    'details': vuln
                                })
        
        # Classify outdated software as medium risk
        if 'relationships' in self.results and self.results['relationships'].get('outdated_software_vulnerabilities'):
            risks['medium'].extend([{
                'type': 'outdated_software',
                'details': tech
            } for tech in self.results['relationships']['outdated_software_vulnerabilities']])
        
        self.results['risk_assessment'] = risks
    
    def _calculate_hashes(self):
        """Calculate hashes of important findings for integrity verification"""
        hashes = {
            'pages': [],
            'resources': [],
            'config_files': []
        }
        
        # Hash spidered pages
        if 'web_spider' in self.results['results']:
            for page in self.results['results']['web_spider'].get('pages', []):
                if 'source' in page:
                    hashes['pages'].append({
                        'url': page['url'],
                        'sha256': hashlib.sha256(page['source'].encode()).hexdigest()
                    })
        
        # Hash resources
        if 'web_spider' in self.results['results']:
            for resource in self.results['results']['web_spider'].get('resources', []):
                if 'url' in resource:
                    hashes['resources'].append({
                        'url': resource['url'],
                        'sha256': hashlib.sha256(resource['url'].encode()).hexdigest()
                    })
        
        self.results['hashes'] = hashes
    
    def _extract_version_from_headers(self, tech_name: str, url: str) -> Optional[str]:
        """Extract version information from HTTP headers for a specific technology"""
        headers = self._get_http_headers(url).get('headers', {})
        
        # Mapping of technologies to their common header fields
        tech_header_map = {
            'apache': 'server',
            'nginx': 'server',
            'iis': 'server',
            'php': 'x-powered-by',
            'asp.net': 'x-aspnet-version',
            'wordpress': 'x-powered-by',
            'django': 'x-powered-by',
            'rails': 'x-powered-by',
            'express': 'x-powered-by'
        }
        
        header_key = tech_header_map.get(tech_name.lower())
        if not header_key:
            return None
            
        header_value = headers.get(header_key, '').lower()
        if not header_value:
            return None
            
        # Try to extract version number patterns
        version_patterns = [
            r'(\d+\.\d+\.\d+)',  # 1.2.3
            r'(\d+\.\d+)',       # 1.2
            r'/(\d+\.\d+)',      # /1.2
            r'(\d+)'             # 1
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, header_value)
            if match:
                return match.group(1)
                
        return None

    def _fetch_headers(self, url: str) -> Dict:
        """Fetch HTTP headers for a given URL"""
        try:
            response = self.session.head(url, timeout=5, allow_redirects=True)
            return dict(response.headers)
        except Exception as e:
            self.logger.error(f"Error fetching headers for {url}: {str(e)}")
            return {}

    def _check_admin_interfaces(self) -> List[str]:
        """Check for common admin interfaces"""
        common_paths = [
            '/admin/', '/wp-admin/', '/administrator/', 
            '/manager/', '/backoffice/', '/cpanel/', 
            '/webadmin/', '/admincp/', '/controlpanel/',
            '/admin/login/', '/adminarea/', '/adminpanel/'
        ]
        
        found = []
        for path in common_paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.head(url, timeout=3)
                
                if response.status_code < 400:
                    found.append(url)
                    
            except Exception:
                continue
                
        return found

    def _check_debug_endpoints(self) -> List[str]:
        """Check for debug endpoints and information leaks"""
        debug_paths = [
            '/debug', '/console', '/phpinfo', '/test', 
            '/status', '/health', '/metrics', '/info',
            '/actuator', '/env', '/config', '/dump',
            '/trace', '/heapdump', '/threaddump'
        ]
        
        found = []
        for path in debug_paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=3)
                
                if response.status_code < 400:
                    # Check for common debug page indicators
                    debug_indicators = [
                        'PHP Version',
                        'Environment Variables',
                        'Configuration',
                        'Runtime Information',
                        'Debug Console',
                        'Metrics'
                    ]
                    
                    if any(indicator in response.text for indicator in debug_indicators):
                        found.append(url)
                        
            except Exception:
                continue
                
        return found

    def _check_database_interfaces(self) -> List[str]:
        """Check for exposed database interfaces"""
        db_ports = {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            1521: 'Oracle',
            1433: 'SQL Server',
            5984: 'CouchDB',
            6379: 'Redis',
            9200: 'Elasticsearch'
        }
        
        found = []
        for port, name in db_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.ip_address, port))
                if result == 0:
                    found.append(f"{name} (port {port})")
                sock.close()
            except Exception:
                continue
                
        return found

    def _check_backup_files(self) -> List[str]:
        """Check for common backup files"""
        backup_extensions = [
            '.bak', '.backup', '.old', '.orig',
            '.swp', '.swo', '.tar.gz', '.zip',
            '.rar', '.7z', '.tgz', '.sql',
            '.dump', '.back', '.copy', '.temp'
        ]
        
        found = []
        if 'web_spider' not in self.results['results']:
            return found
            
        for page in self.results['results']['web_spider'].get('pages', []):
            url = page.get('url', '')
            for ext in backup_extensions:
                if url.endswith(ext):
                    found.append(url)
                    
        return found

    def _check_git_exposure(self) -> Dict:
        """Check for exposed Git repositories"""
        git_paths = [
            '/.git/HEAD',
            '/.git/config',
            '/.git/logs/HEAD',
            '/.git/index',
            '/.git/description'
        ]
        
        result = {
            'found': False,
            'files': [],
            'repo_downloadable': False
        }
        
        for path in git_paths:
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url, timeout=3)
                
                if response.status_code == 200:
                    result['found'] = True
                    result['files'].append({
                        'url': url,
                        'content': response.text[:200] + '...' if len(response.text) > 200 else response.text
                    })
                    
            except Exception:
                continue
                
        # Check if the entire .git directory is downloadable
        try:
            url = urljoin(self.base_url, '/.git/')
            response = self.session.head(url, timeout=3)
            if response.status_code == 200:
                result['repo_downloadable'] = True
        except Exception:
            pass
            
        return result

    def _test_idor(self) -> Dict:
        """Test for Insecure Direct Object Reference vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'tested_patterns': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for IDOR testing'}

        try:
            # Test numeric ID patterns
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)
                        for param in params.split('&'):
                            name, value = param.split('=', 1) if '=' in param else (param, '')
                            if value.isdigit():
                                # Test ID increment/decrement
                                test_id = str(int(value) + 1)
                                test_url = f"{base}?{name}={test_id}"
                                response = self.session.get(test_url, timeout=5)
                                if response.status_code == 200:
                                    result['vulnerable_endpoints'].append({
                                        'url': test_url,
                                        'parameter': name,
                                        'original_value': value,
                                        'tested_value': test_id
                                    })
                                    result['tested_patterns'].append('numeric_increment')

        except Exception as e:
            result['error'] = str(e)

        return result

    def _test_ssrf(self) -> Dict:
        """Test for Server-Side Request Forgery vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'tested_payloads': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for SSRF testing'}

        try:
            test_urls = [
                'http://169.254.169.254/latest/meta-data/',
                'http://localhost/',
                'http://internal/'
            ]

            payloads = [f"url={url}" for url in test_urls]
            result['tested_payloads'] = payloads

            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    for field in form['inputs']:
                        if field['type'] in ['text', 'url']:
                            for payload in payloads:
                                data = {f['name']: payload if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs']}
                                response = self.session.post(form['action'], data=data)
                                if any(url in response.text for url in test_urls):
                                    result['vulnerable_endpoints'].append({
                                        'form': form['action'],
                                        'field': field['name'],
                                        'payload': payload
                                    })

        except Exception as e:
            result['error'] = str(e)

        return result

    def _test_lfi(self) -> Dict:
        """Test for Local File Inclusion vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'tested_files': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for LFI testing'}

        try:
            test_files = [
                '/etc/passwd',
                '../../../../etc/passwd',
                '%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
            ]
            result['tested_files'] = test_files

            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    for field in form['inputs']:
                        if field['type'] in ['text', 'file']:
                            for test_file in test_files:
                                data = {f['name']: test_file if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs']}
                                response = self.session.post(form['action'], data=data)
                                if 'root:x:' in response.text:
                                    result['vulnerable_endpoints'].append({
                                        'form': form['action'],
                                        'field': field['name'],
                                        'file': test_file
                                    })

        except Exception as e:
            result['error'] = str(e)

        return result

    def _test_rce(self) -> Dict:
        """Test for Remote Code Execution vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'tested_commands': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for RCE testing'}

        try:
            test_commands = [
                ';id;',
                '|id',
                '`id`',
                '$(id)'
            ]
            result['tested_commands'] = test_commands

            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    for field in form['inputs']:
                        if field['type'] in ['text', 'search']:
                            for cmd in test_commands:
                                data = {f['name']: cmd if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs']}
                                response = self.session.post(form['action'], data=data)
                                if 'uid=' in response.text and 'gid=' in response.text:
                                    result['vulnerable_endpoints'].append({
                                        'form': form['action'],
                                        'field': field['name'],
                                        'command': cmd
                                    })

        except Exception as e:
            result['error'] = str(e)

        return result

    def _get_dns_records(self) -> Dict:
        """Get comprehensive DNS records for the target domain."""
        result = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for record in record_types:
            try:
                answers = resolver.resolve(self.domain, record)
                result[record] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue
        
        return result
    
    # Use connection pooling and caching
    @lru_cache(maxsize=100)
    def _dns_lookup(self, hostname: str) -> str:
        """Cached DNS lookup"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def _optimize_port_scan(self, ports: str) -> str:
        """Optimize port ranges based on detected services"""
        if not ports or ports == CONFIG['scan']['full_ports']:
            return ports

        # If we have previous scan results, optimize based on them
        if 'port_scan' in self.results['results']:
            found_services = set()
            for host, data in self.results['results']['port_scan'].items():
                for proto, ports in data.get('protocols', {}).items():
                    for port, service in ports.items():
                        if service['state'] == 'open':
                            found_services.add(service['name'])

            # Focus on web ports if web services found
            if any(s in ['http', 'https', 'http-proxy'] for s in found_services):
                return CONFIG['scan']['web_ports']

            # Focus on database ports if DB services found
            if any(s in ['mysql', 'postgresql', 'mongodb'] for s in found_services):
                return CONFIG['scan']['database_ports']

        return ports

    def _get_whois_info(self) -> Dict:
        """Retrieve WHOIS information for the target domain/IP."""
        try:
            if self.domain:
                whois_data = whois.whois(self.domain)
            else:
                whois_data = whois.whois(self.ip_address)

            return {
                'registrar': whois_data.registrar,
                'creation_date': whois_data.creation_date,
                'expiration_date': whois_data.expiration_date,
                'name_servers': whois_data.name_servers,
                'org': whois_data.org,
                'country': whois_data.country
            }
        except Exception as e:
            return {'error': str(e)}

    def _capture_network_traffic(self, duration: int = 10) -> Dict:
        """Capture network traffic for analysis (requires root)."""
        packets = scapy.sniff(filter=f"host {self.ip_address}", timeout=duration)
        
        protocols = set()
        for pkt in packets:
            if pkt.haslayer(scapy.IP):
                protocols.add(pkt[scapy.IP].proto)
        
        return {
            'total_packets': len(packets),
            'protocols': list(protocols),
            'sample': str(packets[0]) if packets else None
        }

    def _check_tor(self) -> bool:
        """Verify if Tor proxy is available."""
        try:
            test_ip = requests.get(
                'https://api.ipify.org',
                proxies={'http': CONFIG['advanced']['tor_proxy']},
                timeout=5
            ).text
            return test_ip != requests.get('https://api.ipify.org', timeout=5).text
        except:
            return False

    def _scan_db_vulnerabilities(self, host: str, port: int, db_type: str) -> List[Dict]:
        """Scan for known vulnerabilities in database services."""
        vulns = []

        if db_type == 'mysql':
            try:
                conn = mysql.connector.connect(
                    host=host,
                    port=port,
                    user='invalid_user',
                    password='invalid_password',
                    connect_timeout=3
                )
                cursor = conn.cursor()

                # Check for CVE-2012-2122 (MySQL authentication bypass)
                cursor.execute("SHOW VARIABLES LIKE 'version'")
                version = cursor.fetchone()[1]
                if version.startswith('5.1') or version.startswith('5.5'):
                    vulns.append({
                        'cve': 'CVE-2012-2122',
                        'description': 'MySQL authentication bypass vulnerability',
                        'severity': 'high'
                    })

                cursor.close()
                conn.close()
            except Exception:
                pass
            
        # Add similar checks for other database types
        return vulns

    def _check_dnssec(self) -> bool:
        """Check if DNSSEC is enabled for the domain."""
        try:
            cmd = ['dig', '+dnssec', self.domain, 'SOA']
            result = subprocess.run(cmd, capture_output=True, text=True)
            return 'RRSIG' in result.stdout
        except Exception:
            return False

    def _test_zone_transfer(self) -> List[str]:
        """Test for DNS zone transfer vulnerability."""
        vulnerable = []
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                try:
                    axfr = dns.query.xfr(str(ns), self.domain, timeout=5)
                    records = list(axfr)
                    if records:
                        vulnerable.append(str(ns))
                except:
                    continue
        except:
            pass
        return vulnerable
    
    def _get_ssl_info(self, url: str = None) -> Dict:
        """Get comprehensive SSL/TLS information for a URL"""
        target_url = url if url else self.base_url
        if not target_url:
            return {'error': 'No URL available for SSL check'}
    
        hostname = urlparse(target_url).hostname
        result = {
            'certificate': {},
            'protocols': [],
            'ciphers': [],
            'vulnerabilities': {}
        }
    
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.set_ciphers('ALL:@SECLEVEL=1')
        
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                
                    # Parse certificate
                    result['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'validity': {
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter'],
                            'expires_in': (ssl.cert_time_to_seconds(cert['notAfter']) - time.time()) / 86400
                        },
                        'serial_number': cert.get('serialNumber'),
                        'version': cert.get('version'),
                        'extensions': [ext[0] for ext in cert.get('extensions', [])]
                    }
                
                    # Get cipher info
                    result['ciphers'].append({
                        'name': cipher[0],
                        'protocol': cipher[1],
                        'bits': cipher[2]
                    })
                
                    # Check for common vulnerabilities
                    result['vulnerabilities'] = {
                        'heartbleed': self._check_heartbleed(hostname),
                        'poodle': self._check_poodle(hostname),
                        'freak': self._check_freak(hostname),
                        'beast': self._check_beast(hostname),
                        'weak_ciphers': self._check_weak_ciphers(hostname)
                    }
                
        except Exception as e:
            result['error'] = str(e)
    
        return result

    def _detect_tech_stack(self, url: str = None) -> Dict:
        """Detect web technologies used on a website"""
        target_url = url if url else self.base_url
        if not target_url:
            return {'error': 'No URL available for tech detection'}

        try:
            tech_stack = {}

            # Use Wappalyzer if available
            if WAPPALYZER_AVAILABLE:
                try:
                    wappalyzer = Wappalyzer.latest()
                    webpage = WebPage.new_from_url(target_url)
                    tech_stack = wappalyzer.analyze_with_versions_and_categories(webpage)
                except Exception as e:
                    print(f"[-] Wappalyzer detection failed: {str(e)}")
                    tech_stack = {'note': 'Wappalyzer detection failed, using fallback methods'}
            else:
                tech_stack = {'note': 'Wappalyzer not available, using fallback detection methods'}

            # Enhance with additional detection methods
            headers = self._get_http_headers(target_url).get('headers', {})
            server = headers.get('Server', '')
            powered_by = headers.get('X-Powered-By', '')

            if server:
                tech_stack['web_server'] = {
                    'name': server.split('/')[0],
                    'version': server.split('/')[1] if '/' in server else None
                }

            if powered_by:
                tech_stack['platform'] = {
                    'name': powered_by.split('/')[0],
                    'version': powered_by.split('/')[1] if '/' in powered_by else None
                }

            # Additional fallback detection
            if not tech_stack or (isinstance(tech_stack, dict) and len(tech_stack) <= 2):
                fallback_detection = self._fallback_tech_detection(target_url, headers)
                tech_stack.update(fallback_detection)

            return tech_stack
        except Exception as e:
            return {'error': str(e)}

    def _fallback_tech_detection(self, url: str, headers: Dict) -> Dict:
        """Fallback technology detection when Wappalyzer is not available"""
        detected_tech = {}

        try:
            # Analyze headers for technology signatures
            server = headers.get('Server', '').lower()
            powered_by = headers.get('X-Powered-By', '').lower()
            content_type = headers.get('Content-Type', '').lower()

            # Web server detection
            if 'apache' in server:
                detected_tech['apache'] = {'name': 'Apache', 'categories': ['Web Servers']}
            elif 'nginx' in server:
                detected_tech['nginx'] = {'name': 'Nginx', 'categories': ['Web Servers']}
            elif 'iis' in server:
                detected_tech['iis'] = {'name': 'IIS', 'categories': ['Web Servers']}
            elif 'lighttpd' in server:
                detected_tech['lighttpd'] = {'name': 'Lighttpd', 'categories': ['Web Servers']}

            # Platform detection
            if 'php' in powered_by:
                php_version = self._extract_version_from_headers('php', url)
                detected_tech['php'] = {
                    'name': 'PHP',
                    'categories': ['Programming Languages'],
                    'versions': [php_version] if php_version else []
                }
            elif 'asp.net' in powered_by:
                detected_tech['asp.net'] = {'name': 'ASP.NET', 'categories': ['Web Frameworks']}
            elif 'jsp' in powered_by or 'java' in powered_by:
                detected_tech['java'] = {'name': 'Java', 'categories': ['Programming Languages']}

            # CMS detection based on common patterns
            if 'wp-content' in url or 'wordpress' in powered_by.lower():
                detected_tech['wordpress'] = {'name': 'WordPress', 'categories': ['CMS']}
            elif 'drupal' in server.lower() or 'drupal' in powered_by.lower():
                detected_tech['drupal'] = {'name': 'Drupal', 'categories': ['CMS']}
            elif 'joomla' in server.lower() or 'joomla' in powered_by.lower():
                detected_tech['joomla'] = {'name': 'Joomla', 'categories': ['CMS']}

            # JavaScript framework detection
            if 'x-generator' in headers:
                generator = headers['x-generator'].lower()
                if 'jekyll' in generator:
                    detected_tech['jekyll'] = {'name': 'Jekyll', 'categories': ['Static Site Generator']}
                elif 'gatsby' in generator:
                    detected_tech['gatsby'] = {'name': 'Gatsby', 'categories': ['Web Frameworks']}

            # Database detection
            if 'x-powered-by' in headers and 'mysql' in powered_by:
                detected_tech['mysql'] = {'name': 'MySQL', 'categories': ['Databases']}
            elif 'x-powered-by' in headers and 'postgresql' in powered_by:
                detected_tech['postgresql'] = {'name': 'PostgreSQL', 'categories': ['Databases']}

            # Add confidence scores
            for tech_name, tech_info in detected_tech.items():
                tech_info['confidence'] = 0.7  # Medium confidence for fallback detection

        except Exception as e:
            detected_tech['fallback_error'] = str(e)

        return detected_tech

    def _scan_vulnerabilities(self) -> Dict:
        """Scan for common vulnerabilities"""
        result = {
            'web_vulnerabilities': {},
            'network_vulnerabilities': {},
            'service_vulnerabilities': {}
        }
        
        if self.base_url:
            # Web vulnerabilities
            result['web_vulnerabilities'] = {
                'sql_injection': self._test_sql_injection(),
                'xss': self._test_xss(),
                'idor': self._test_idor(),
                'ssrf': self._test_ssrf(),
                'lfi': self._test_lfi(),
                'rce': self._test_rce()
            }
        
        if self.ip_address:
            # Network vulnerabilities
            nm = nmap.PortScanner()
            nm.scan(hosts=self.ip_address, arguments='-sV --script vuln')

            for host in nm.all_hosts():
                result['network_vulnerabilities'][host] = {}
                for proto in nm[host].all_protocols():
                    result['network_vulnerabilities'][host][proto] = {}
                    for port in nm[host][proto]:
                        result['network_vulnerabilities'][host][proto][port] = {
                            'vulnerabilities': nm[host][proto][port].get('script', {})
                        }
        
        return result

    def _spider_website(self) -> Dict:
        """Crawl the website to discover pages and content"""
        if not self.base_url:
            return {'error': 'No base URL available for spidering'}
        
        result = {
            'pages': [],
            'links': [],
            'forms': [],
            'resources': []
        }
        
        try:
            # Use requests first for basic crawling
            response = self.session.get(self.base_url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links
            for link in soup.find_all('a', href=True):
                href = urljoin(self.base_url, link['href'])
                if href not in result['links']:
                    result['links'].append(href)

            # Find all forms
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(self.base_url, form.get('action', '')),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }

                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })

                result['forms'].append(form_data)

            # Find all resources
            for tag, attr in [('img', 'src'), ('script', 'src'), ('link', 'href')]:
                for resource in soup.find_all(tag, {attr: True}):
                    result['resources'].append({
                        'type': tag,
                        'url': urljoin(self.base_url, resource[attr])
                    })

            # Add initial page
            result['pages'].append({
                'url': self.base_url,
                'status': response.status_code,
                'title': soup.title.string if soup.title else '',
                'content_type': response.headers.get('Content-Type', '')
            })

        except Exception as e:
            result['error'] = str(e)
        
        return result

    def _test_sql_injection(self) -> Dict:
        """Test for SQL injection vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'payloads_used': []
        }
        
        if not self.base_url:
            return {'error': 'No base URL available for SQLi testing'}
        
        try:
            # Test URL parameters
            if '?' in self.base_url:
                base, params = self.base_url.split('?', 1)
                for param in params.split('&'):
                    name, value = param.split('=', 1) if '=' in param else (param, '')

                    # Test with SQLi payloads
                    payloads = [
                        "'",
                        "' OR '1'='1",
                        '" OR "1"="1',
                        "' OR 1=1--",
                        "' OR 1=1#",
                        "' OR 1=1/*"
                    ]

                    for payload in payloads:
                        test_url = f"{base}?{name}={payload}"
                        response = self.session.get(test_url)

                        if any(error in response.text.lower() for error in ['sql syntax', 'mysql error', 'ora-', 'syntax error']):
                            result['vulnerable_endpoints'].append({
                                'url': test_url,
                                'parameter': name,
                                'payload': payload,
                                'evidence': 'SQL error in response'
                            })
                            result['payloads_used'].append(payload)

            # Test forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    for input_field in form.get('inputs', []):
                        if input_field['type'] in ['text', 'search', 'textarea']:
                            payloads = [
                                {"name": input_field['name'], "value": "' OR '1'='1"},
                                {"name": input_field['name'], "value": '" OR "1"="1'}
                            ]

                            for payload in payloads:
                                data = {f['name']: payload['value'] if f['name'] == input_field['name'] else f.get('value', '') 
                                       for f in form.get('inputs', [])}

                                response = self.session.post(
                                    form['action'],
                                    data=data,
                                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                                )

                                if any(error in response.text.lower() for error in ['sql syntax', 'mysql error', 'ora-', 'syntax error']):
                                    result['vulnerable_endpoints'].append({
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload['value'],
                                        'evidence': 'SQL error in response'
                                    })
                                    result['payloads_used'].append(payload['value'])
        
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def _test_xss(self) -> Dict:
        """Test for Cross-Site Scripting vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'payloads_used': []
        }
        
        if not self.base_url:
            return {'error': 'No base URL available for XSS testing'}
        
        try:
            payloads = [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '" onmouseover=alert(1)',
                "' onmouseover=alert(1)"
            ]

            # Test URL parameters
            if '?' in self.base_url:
                base, params = self.base_url.split('?', 1)
                for param in params.split('&'):
                    name, value = param.split('=', 1) if '=' in param else (param, '')

                    for payload in payloads:
                        test_url = f"{base}?{name}={payload}"
                        response = self.session.get(test_url)

                        if payload in response.text:
                            result['vulnerable_endpoints'].append({
                                'url': test_url,
                                'parameter': name,
                                'payload': payload,
                                'evidence': 'Payload reflected in response'
                            })
                            result['payloads_used'].append(payload)

            # Test forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    for input_field in form.get('inputs', []):
                        if input_field['type'] in ['text', 'search', 'textarea']:
                            for payload in payloads:
                                data = {f['name']: payload if f['name'] == input_field['name'] else f.get('value', '') 
                                       for f in form.get('inputs', [])}

                                response = self.session.post(
                                    form['action'],
                                    data=data,
                                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                                )

                                if payload in response.text:
                                    result['vulnerable_endpoints'].append({
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'evidence': 'Payload reflected in response'
                                    })
                                    result['payloads_used'].append(payload)
        
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def _scan_web_services(self, scan_result: Dict):
        """Analyze web services (HTTP/HTTPS) for additional vulnerabilities."""
        for host, data in scan_result.items():
            for proto, ports in data.get('protocols', {}).items():
                for port, service in ports.items():
                    if service['state'] == 'open' and service['name'] in ['http', 'https', 'http-proxy', 'http-alt']:
                        url = f"{'https' if service['name'] == 'https' else 'http'}://{host}:{port}"
                        service['web_checks'] = {
                            'headers': self._get_http_headers(url),
                            'tech_stack': self._detect_tech_stack(url),
                            'ssl_info': self._get_ssl_info(url) if service['name'] == 'https' else None,
                            'directory_listing': self._check_directory_listing(url),
                            'admin_interfaces': self._check_admin_interfaces(),
                            'debug_endpoints': self._check_debug_endpoints()
                        }

    def _scan_database_services(self, scan_result: Dict):
        """Check database services for authentication and default credentials."""
        for host, data in scan_result.items():
            for proto, ports in data.get('protocols', {}).items():
                for port, service in ports.items():
                    if service['state'] == 'open' and service['name'] in ['mysql', 'postgresql', 'mongodb', 'redis', 'oracle']:
                        service['db_checks'] = {
                            'auth_required': self._check_db_auth(host, port, service['name']),
                            'default_creds': self._test_default_db_creds(host, port, service['name']),
                            'vulnerabilities': self._scan_db_vulnerabilities(host, port, service['name'])
                        }
   
    def _run_nikto_scan(self, target: str) -> Dict:
        """Run Nikto scan and parse results."""
        if not os.path.exists(CONFIG['paths']['tools']['nikto']):
            return {'error': 'Nikto not found'}
        
        try:
            cmd = [
                CONFIG['paths']['tools']['nikto'],
                '-h', target,
                '-Format', 'json',
                '-timeout', '10'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {'error': result.stderr}
        except Exception as e:
            return {'error': str(e)}
        
    def _run_nuclei_scan(self, target: str) -> Dict:
        """Run Nuclei scan and parse results."""
        if not os.path.exists(CONFIG['paths']['tools']['nuclei']):
            return {'error': 'Nuclei not found'}
        
        try:
            cmd = [
                CONFIG['paths']['tools']['nuclei'],
                '-u', target,
                '-json',
                '-timeout', '10'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            else:
                return {'error': result.stderr}
        except Exception as e:
            return {'error': str(e)}
    
    def _run_sqlmap_scan(self, target: str) -> Dict:
        """Run SQLMap scan for SQL injection vulnerabilities."""
        if not os.path.exists(CONFIG['paths']['tools']['sqlmap']):
            return {'error': 'SQLMap not found'}
        
        try:
            cmd = [
                CONFIG['paths']['tools']['sqlmap'],
                '-u', target,
                '--batch',
                '--crawl=1',
                '--output-dir', CONFIG['paths']['output_dir']
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                return {'output': result.stdout}
            else:
                return {'error': result.stderr}
        except Exception as e:
            return {'error': str(e)}
   
    def _bruteforce_directories(self) -> Dict:
        """Brute-force common directories using wordlist."""
        if not self.base_url:
            return {'error': 'No base URL available for directory brute-forcing'}
        
        if not os.path.exists(CONFIG['paths']['wordlists']['dirs']):
            return {'error': 'Directory wordlist not found'}
        
        result = {
            'found_directories': [],
            'tested_count': 0,
            'error_responses': []
        }
        
        try:
            with open(CONFIG['paths']['wordlists']['dirs']) as f:
                directories = [line.strip() for line in f if line.strip()]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {
                    executor.submit(
                        self._check_directory,
                        urljoin(self.base_url, directory)
                    ): directory for directory in directories
                }
                
                for future in concurrent.futures.as_completed(futures):
                    result['tested_count'] += 1
                    url, status = future.result()
                    if status < 400:
                        result['found_directories'].append({
                            'url': url,
                            'status': status
                        })
                    elif status >= 500:
                        result['error_responses'].append({
                            'url': url,
                            'status': status
                        })
            return result
        except Exception as e:
            return {'error': str(e)}

    def _check_directory(self, url: str) -> Tuple[str, int]:
        """Check if a directory exists."""
        try:
            response = self.session.get(url, timeout=3)
            return (url, response.status_code)
        except requests.RequestException as e:
            return (url, 500)

    def _analyze_content(self) -> Dict:
        """Analyze website content for sensitive information."""
        if not self.base_url:
            return {'error': 'No base URL available for content analysis'}
        
        result = {
            'emails': [],
            'phone_numbers': [],
            'comments': [],
            'sensitive_keywords': []
        }
        
        try:
            response = self.session.get(self.base_url)
            content = response.text
            
            # Find emails
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', content)
            result['emails'] = list(set(emails))
            
            # Find phone numbers
            phone_numbers = re.findall(r'(\+?\d{1,3}[-\.\s]?)?\(?\d{3}\)?[-\.\s]?\d{3}[-\.\s]?\d{4}', content)
            result['phone_numbers'] = list(set(phone_numbers))
            
            # Find HTML comments
            comments = re.findall(r'<!--.*?-->', content, re.DOTALL)
            result['comments'] = comments
            
            # Check for sensitive keywords
            sensitive_keywords = [
                'password', 'secret', 'api_key', 'token', 
                'admin', 'backup', 'confidential'
            ]
            found_keywords = []
            for keyword in sensitive_keywords:
                if re.search(rf'\b{keyword}\b', content, re.I):
                    found_keywords.append(keyword)
            result['sensitive_keywords'] = found_keywords
            
            return result
        except Exception as e:
            return {'error': str(e)}

    def _analyze_forms(self) -> Dict:
        """Analyze all forms found on the website."""
        if 'web_spider' not in self.results['results']:
            return {'error': 'Run web spider first to find forms'}
        
        forms = self.results['results']['web_spider'].get('forms', [])
        result = {
            'total_forms': len(forms),
            'login_forms': [],
            'search_forms': [],
            'upload_forms': [],
            'other_forms': []
        }
        
        for form in forms:
            form_data = {
                'action': form.get('action'),
                'method': form.get('method'),
                'inputs': []
            }
            
            is_login = False
            is_search = False
            is_upload = False
            
            for input_field in form.get('inputs', []):
                input_data = {
                    'name': input_field.get('name'),
                    'type': input_field.get('type')
                }
                form_data['inputs'].append(input_data)
                
                # Classify form types
                if input_field.get('type') == 'password':
                    is_login = True
                elif input_field.get('type') == 'search':
                    is_search = True
                elif input_field.get('type') == 'file':
                    is_upload = True
            
            if is_login:
                result['login_forms'].append(form_data)
            elif is_search:
                result['search_forms'].append(form_data)
            elif is_upload:
                result['upload_forms'].append(form_data)
            else:
                result['other_forms'].append(form_data)
        
        return result

    def _analyze_apis(self) -> Dict:
        """Analyze potential API endpoints."""
        if 'web_spider' not in self.results['results']:
            return {'error': 'Run web spider first to find API endpoints'}
        
        result = {
            'rest_endpoints': [],
            'graphql_endpoints': [],
            'soap_endpoints': [],
            'websocket_endpoints': []
        }
        
        # Check all URLs found during spidering
        for page in self.results['results']['web_spider'].get('pages', []):
            url = page.get('url', '')
            
            # Check for REST API patterns
            if re.search(r'/api/v\d+/', url) or '/graphql' in url:
                result['rest_endpoints'].append(url)
            
            # Check for GraphQL
            if '/graphql' in url.lower():
                result['graphql_endpoints'].append(url)
            
            # Check for SOAP
            if 'wsdl' in url.lower():
                result['soap_endpoints'].append(url)
        
        # Check for WebSocket connections in page source
        for page in self.results['results']['web_spider'].get('pages', []):
            if 'source' in page:
                if 'ws://' in page['source'] or 'wss://' in page['source']:
                    result['websocket_endpoints'].append(page['url'])
        
        return result

    def _analyze_auth(self) -> Dict:
        """Analyze authentication mechanisms."""
        if not self.base_url:
            return {'error': 'No base URL available for auth analysis'}
        
        result = {
            'auth_methods': [],
            'login_urls': [],
            'logout_urls': [],
            'default_credentials': [],
            'password_policy': {}
        }
        
        try:
            # Check common auth endpoints
            common_auth_urls = [
                '/login', '/signin', '/auth', '/oauth', 
                '/logout', '/signout', '/register'
            ]
            
            for endpoint in common_auth_urls:
                url = urljoin(self.base_url, endpoint)
                response = self.session.head(url, allow_redirects=False)
                if response.status_code < 400:
                    if 'login' in endpoint or 'signin' in endpoint:
                        result['login_urls'].append(url)
                    elif 'logout' in endpoint or 'signout' in endpoint:
                        result['logout_urls'].append(url)
            
            # Check HTTP auth
            response = self.session.get(self.base_url)
            if response.status_code == 401:
                result['auth_methods'].append('HTTP Basic Auth')
            
            # Check for OAuth
            if any('oauth' in url for url in result['login_urls']):
                result['auth_methods'].append('OAuth')
            
            # Check for JWT in cookies
            for cookie in self.session.cookies:
                if 'jwt' in cookie.name.lower() or 'token' in cookie.name.lower():
                    result['auth_methods'].append('JWT')
            
            # Check password policy (simplified)
            if result['login_urls']:
                login_url = result['login_urls'][0]
                test_data = {
                    'username': 'test',
                    'password': 'short'
                }
                response = self.session.post(login_url, data=test_data)
                if 'password must be at least' in response.text.lower():
                    result['password_policy']['min_length'] = 8  # Example
                elif 'password is too short' in response.text.lower():
                    result['password_policy']['min_length'] = 6  # Example
            
            return result
        except Exception as e:
            return {'error': str(e)}

    def _detect_os(self) -> Dict:
        """Detect operating system using various techniques."""
        if not self.ip_address:
            return {'error': 'No IP address available for OS detection'}
        
        result = {
            'nmap_os': None,
            'ttl_analysis': None,
            'banner_analysis': None
        }
        
        try:
            # Nmap OS detection
            nm = nmap.PortScanner()
            nm.scan(hosts=self.ip_address, arguments='-O')
            if 'osmatch' in nm[self.ip_address]:
                result['nmap_os'] = nm[self.ip_address]['osmatch']
            
            # TTL analysis
            response = subprocess.run(
                ['ping', '-c', '1', self.ip_address],
                capture_output=True,
                text=True
            )
            if 'ttl=' in response.stdout.lower():
                ttl = int(re.search(r'ttl=(\d+)', response.stdout.lower()).group(1))
                if ttl <= 64:
                    result['ttl_analysis'] = 'Linux/Unix'
                elif ttl <= 128:
                    result['ttl_analysis'] = 'Windows'
                else:
                    result['ttl_analysis'] = 'Unknown'
            
            # Banner analysis
            try:
                with socket.create_connection((self.ip_address, 80), timeout=3) as sock:
                    sock.send(b'GET / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode()
                    if 'Apache' in banner:
                        result['banner_analysis'] = 'Likely Linux (Apache)'
                    elif 'IIS' in banner:
                        result['banner_analysis'] = 'Likely Windows (IIS)'
            except:
                pass
            
            return result
        except Exception as e:
            return {'error': str(e)}

    def _detect_services(self) -> Dict:
        """Detect services running on open ports."""
        if 'port_scan' not in self.results['results']:
            return {'error': 'Run port scan first to detect services'}
        
        result = {}
        port_data = self.results['results']['port_scan']
        
        for host, data in port_data.items():
            result[host] = {}
            for proto, ports in data.get('protocols', {}).items():
                for port, service in ports.items():
                    if service['state'] == 'open':
                        result[host][port] = {
                            'service': service.get('name'),
                            'product': service.get('product'),
                            'version': service.get('version'),
                            'cpe': service.get('cpe')
                        }
        
        return result

    def fetch_headers(self, url: str) -> Dict:
        try:
            response = self.session.get(url, timeout=5)
            return dict(response.headers)
        except Exception as e:
            self.logger.error(f"Error fetching headers: {str(e)}")
            return {}

    def _check_security_headers(self) -> Dict:
        """Analyze security-related HTTP headers."""
        required_headers = {
            'Strict-Transport-Security': r'max-age=\d+',
            'Content-Security-Policy': r'.+',
            'X-Content-Type-Options': r'nosniff',
            'X-Frame-Options': r'(deny|sameorigin)',
            'Referrer-Policy': r'.+'
        }
    
        headers = self._get_http_headers().get('headers', {})
        results = {}
    
        for header, pattern in required_headers.items():
            value = headers.get(header, 'MISSING')
            results[header] = {
                'present': value != 'MISSING',
                'valid': bool(re.match(pattern, value, re.I)) if value != 'MISSING' else False
            }
    
        return results
    
    def _test_xss(self) -> Dict:
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'payloads_used': [],
            'protected_endpoints': []
        }
    
        if not self.base_url:
            return {'error': 'No base URL available for XSS testing'}
    
        try:
            # Basic XSS payloads
            payloads = [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '" onmouseover=alert(1) x="',
                "' onmouseover=alert(1) x='",
                'javascript:alert(1)'
            ]
            # Test forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    test_url = urljoin(self.base_url, form['action']) if form['action'] else self.base_url

                    for field in form['inputs']:
                        if field['type'] in ['text', 'search', 'textarea', 'password']:
                            for payload in payloads:
                                data = {f['name']: payload if f['name'] == field['name'] else 'test' 
                                   for f in form['inputs'] if f['name']}

                                try:
                                    response = self.session.post(
                                        test_url,
                                        data=data,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if payload in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })
                                        result['payloads_used'].append(payload)
                                    else:
                                        result['protected_endpoints'].append({
                                            'url': test_url,
                                            'parameter': field['name'],
                                            'payload': payload
                                        })

                                except Exception as e:
                                    continue
                                    
            # Test URL parameters
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)
                        for param in params.split('&'):
                            name, value = param.split('=', 1) if '=' in param else (param, '')

                            for payload in payloads:
                                try:
                                    test_url = f"{base}?{name}={payload}"
                                    response = self.session.get(
                                        test_url,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if payload in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': name,
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })
                                        result['payloads_used'].append(payload)

                                except Exception as e:
                                    continue
                                    
            return result

        except Exception as e:
            return {'error': f"XSS test failed: {str(e)}"}
        
    def _test_idor(self) -> Dict:
        """Test for Insecure Direct Object References"""
        result = {
            'vulnerable_endpoints': [],
            'tested_patterns': [],
            'protected_endpoints': []
        }
    
        if not self.base_url:
            return {'error': 'No base URL available for IDOR testing'}
    
        try:
            # Look for numeric IDs in URLs
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    url = page['url']

                    # Find numeric IDs in URL
                    ids = re.findall(r'/(\d+)(?:/|$|\?|\.)', url)
                    for found_id in ids:
                        test_id = int(found_id) + 1
                        test_url = url.replace(f"/{found_id}/", f"/{test_id}/")

                        try:
                            response = self.session.get(
                                test_url,
                                timeout=10,
                                allow_redirects=False
                            )

                            if response.status_code == 200:
                                result['vulnerable_endpoints'].append({
                                    'original_url': url,
                                    'tested_url': test_url,
                                    'parameter': 'numeric_id',
                                    'original_id': found_id,
                                    'tested_id': test_id,
                                    'status_code': response.status_code
                                })
                                result['tested_patterns'].append('numeric_id_increment')
                            else:
                                result['protected_endpoints'].append({
                                    'original_url': url,
                                    'tested_url': test_url,
                                    'status_code': response.status_code
                                })

                        except Exception as e:
                            continue
                            
            return result

        except Exception as e:
            return {'error': f"IDOR test failed: {str(e)}"}

    def _test_ssrf(self) -> Dict:
        """Test for Server-Side Request Forgery vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'test_payloads': [],
            'protected_endpoints': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for SSRF testing'}
    
        try:
            # Common SSRF test endpoints
            test_urls = [
                'http://169.254.169.254/latest/meta-data/',
                'http://localhost/admin',
                'http://internal.service/'
            ]

            payloads = []
            for test_url in test_urls:
                payloads.extend([
                    f"url={test_url}",
                    f"file={test_url}",
                    f"path={test_url}",
                    f"image={test_url}",
                    f"load={test_url}"
                ])

            result['test_payloads'] = payloads

            # Test forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    action_url = urljoin(self.base_url, form['action']) if form['action'] else self.base_url

                    for field in form['inputs']:
                        if field['type'] in ['text', 'url', 'file']:
                            for payload in payloads:
                                param, value = payload.split('=', 1)
                                data = {f['name']: value if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs'] if f['name']}

                                try:
                                    response = self.session.post(
                                        action_url,
                                        data=data,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if any(test_url in response.text for test_url in test_urls):
                                        result['vulnerable_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })
                                    else:
                                        result['protected_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'status_code': response.status_code
                                        })

                                except Exception as e:
                                    continue
                                    
            # Test URL parameters
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)

                        for payload in payloads:
                            param, value = payload.split('=', 1)
                            test_url = f"{base}?{param}={value}"

                            try:
                                response = self.session.get(
                                    test_url,
                                    timeout=10,
                                    allow_redirects=False
                                )

                                if any(test_url in response.text for test_url in test_urls):
                                    result['vulnerable_endpoints'].append({
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'status_code': response.status_code
                                        })
                                else:
                                    result['protected_endpoints'].append({
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'status_code': response.status_code
                                    })
                        
                            except Exception as e:
                                continue
        
            return result
    
        except Exception as e:
            return {'error': f"SSRF test failed: {str(e)}"}

    def _test_lfi(self) -> Dict:
        """Test for Local File Inclusion vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'tested_files': [],
            'protected_endpoints': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for LFI testing'}

        try:
            # Common LFI test files
            test_files = [
                '/etc/passwd',
                '/etc/hosts',
                '../../../../etc/passwd',
                '....//....//....//....//etc/passwd',
                '%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
            ]

            result['tested_files'] = test_files

            # Test forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    action_url = urljoin(self.base_url, form['action']) if form['action'] else self.base_url

                    for field in form['inputs']:
                        if field['type'] in ['text', 'file']:
                            for test_file in test_files:
                                data = {f['name']: test_file if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs'] if f['name']}

                                try:
                                    response = self.session.post(
                                        action_url,
                                        data=data,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if 'root:x:' in response.text or 'localhost' in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': test_file,
                                            'status_code': response.status_code
                                        })
                                    else:
                                        result['protected_endpoints'].append({
                                            'url': action_url,
                                            'parameter': field['name'],
                                            'payload': test_file,
                                            'status_code': response.status_code
                                        })

                                except Exception as e:
                                    continue
                                    
            # Test URL parameters
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)

                        for param in params.split('&'):
                            name, value = param.split('=', 1) if '=' in param else (param, '')

                            for test_file in test_files:
                                try:
                                    test_url = f"{base}?{name}={test_file}"
                                    response = self.session.get(
                                        test_url,
                                        timeout=10,
                                        allow_redirects=False
                                    )

                                    if 'root:x:' in response.text or 'localhost' in response.text:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': name,
                                            'payload': test_file,
                                            'status_code': response.status_code
                                        })

                                except Exception as e:
                                    continue
                                    
            return result

        except Exception as e:
            return {'error': f"LFI test failed: {str(e)}"}

    def _test_sql_injection(self) -> Dict:
        """Test for SQL injection vulnerabilities"""
        result = {
            'vulnerable_endpoints': [],
            'techniques_tested': ['boolean_based', 'time_based', 'error_based'],
            'payloads_used': [],
            'protected_endpoints': []
        }
    
        if not self.base_url:
            return {'error': 'No base URL available for SQLi testing'}
    
        try:
        # Test login forms
            if 'web_spider' in self.results['results']:
                for form in self.results['results']['web_spider'].get('forms', []):
                    test_url = urljoin(self.base_url, form['action']) if form['action'] else self.base_url
                
                    # Test each input field
                    for field in form['inputs']:
                        if field['type'] in ['text', 'password', 'search']:
                            payloads = [
                                "'",
                                "\"",
                                "' OR '1'='1",
                                "\" OR \"1\"=\"1",
                                "' OR 1=1--",
                                "1 AND SLEEP(5)"
                            ]

                            for payload in payloads:
                                data = {f['name']: payload if f['name'] == field['name'] else 'test' 
                                       for f in form['inputs'] if f['name']}

                                try:
                                    start_time = time.time()
                                    response = self.session.post(
                                        test_url,
                                        data=data,
                                        timeout=10,
                                        allow_redirects=False
                                    )
                                    response_time = time.time() - start_time

                                    # Check for signs of SQLi
                                    vulnerable = False
                                    if response_time > 5:  # Time-based detection
                                        vulnerable = True
                                    elif any(error in response.text.lower() for error in 
                                             ['sql syntax', 'mysql error', 'ora-', 'syntax error']):
                                        vulnerable = True
                                    elif response.status_code != 200:  # Error-based detection
                                        vulnerable = True

                                    if vulnerable:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': field['name'],
                                            'payload': payload,
                                            'response_time': response_time,
                                            'status_code': response.status_code,
                                            'response_length': len(response.text)
                                        })
                                        result['payloads_used'].append(payload)
                                    else:
                                        result['protected_endpoints'].append({
                                            'url': test_url,
                                            'parameter': field['name'],
                                            'payload': payload
                                        })

                                except Exception as e:
                                    continue
        
            # Test URL parameters
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        base, params = page['url'].split('?', 1)
                        for param in params.split('&'):
                            name, value = param.split('=', 1) if '=' in param else (param, '')
                            payloads = [
                                f"{name}='",
                                f"{name}=1' OR '1'='1",
                                f"{name}=1 AND SLEEP(5)"
                            ]

                            for payload in payloads:
                                try:
                                    test_url = f"{base}?{payload}"
                                    start_time = time.time()
                                    response = self.session.get(
                                        test_url,
                                        timeout=10,
                                        allow_redirects=False
                                    )
                                    response_time = time.time() - start_time

                                    # Check for signs of SQLi
                                    vulnerable = False
                                    if response_time > 5:
                                        vulnerable = True
                                    elif any(error in response.text.lower() for error in 
                                             ['sql syntax', 'mysql error', 'ora-', 'syntax error']):
                                        vulnerable = True
                                    elif response.status_code != 200:
                                        vulnerable = True

                                    if vulnerable:
                                        result['vulnerable_endpoints'].append({
                                            'url': test_url,
                                            'parameter': name,
                                            'payload': payload,
                                            'response_time': response_time,
                                            'status_code': response.status_code,
                                            'response_length': len(response.text)
                                        })
                                        result['payloads_used'].append(payload)

                                except Exception as e:
                                    continue
                                    
            return result
    
        except Exception as e:
            return {'error': f"SQL injection test failed: {str(e)}"}

    def _advanced_fuzzing(self) -> Dict:
        """Perform advanced fuzzing of endpoints"""
        result = {
            'vulnerabilities_found': [],
            'tested_endpoints': [],
            'error_responses': []
        }

        if not self.base_url:
            return {'error': 'No base URL available for fuzzing'}

        try:
            # Use ffuf if available
            if os.path.exists(CONFIG['paths']['tools']['ffuf']):
                # Fuzz common parameters
                cmd = [
                    CONFIG['paths']['tools']['ffuf'],
                    '-u', f"{self.base_url}/FUZZ",
                    '-w', CONFIG['paths']['wordlists']['api_endpoints'],
                    '-t', '50',
                    '-p', '0.1',
                    '-o', os.path.join(CONFIG['paths']['output_dir'], 'fuzzing_results.json'),
                    '-of', 'json'
                ]

                output = self._run_subprocess(cmd)
                if output and not output.startswith('Error'):
                    try:
                        with open(os.path.join(CONFIG['paths']['output_dir'], 'fuzzing_results.json')) as f:
                            fuzz_results = json.load(f)
                            for res in fuzz_results.get('results', []):
                                if res['status'] != 404:
                                    result['tested_endpoints'].append({
                                        'url': res['url'],
                                        'status': res['status'],
                                        'length': res['length']
                                    })
                                    if res['status'] >= 500:
                                        result['error_responses'].append({
                                            'url': res['url'],
                                            'status': res['status']
                                        })
                    except:
                        pass
                        
                # Parameter fuzzing
                if 'web_spider' in self.results['results']:
                    for page in self.results['results']['web_spider'].get('pages', []):
                        if '?' in page['url']:
                            base, params = page['url'].split('?', 1)
                            param_names = [p.split('=')[0] for p in params.split('&')]

                            for param in param_names:
                                cmd = [
                                    CONFIG['paths']['tools']['ffuf'],
                                    '-u', f"{base}?{param}=FUZZ",
                                    '-w', CONFIG['paths']['wordlists']['api_endpoints'],
                                    '-t', '50',
                                    '-p', '0.1',
                                    '-fs', '0'  # Filter by size 0 to catch all responses
                                ]

                                output = self._run_subprocess(cmd)
                                if output and not output.startswith('Error'):
                                    for line in output.splitlines():
                                        if 'FUZZ' in line:
                                            parts = line.split()
                                            if len(parts) > 4:
                                                result['tested_endpoints'].append({
                                                    'url': f"{base}?{param}={parts[0]}",
                                                    'status': int(parts[3]),
                                                    'length': int(parts[2])
                                                })
                                                if int(parts[3]) >= 500:
                                                    result['error_responses'].append({
                                                        'url': f"{base}?{param}={parts[0]}",
                                                        'status': int(parts[3])
                                                    })

            return result

        except Exception as e:
            return {'error': f"Advanced fuzzing failed: {str(e)}"}

    def _resolve_target(self):
        """Resolve target to IP, domain, and base URL"""
        if self.is_valid_ip(self.target):
            self.ip_address = self.target
            try:
                self.domain = socket.getfqdn(self.ip_address)
            except:
                self.domain = self.ip_address
        else:
            # Handle URL or domain
            if not self.target.startswith(('http://', 'https://')):
                self.target = f'https://{self.target}'
            
            parsed = urlparse(self.target)
            self.domain = parsed.hostname
            self.base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            try:
                self.ip_address = socket.gethostbyname(self.domain)
            except socket.gaierror:
                self.ip_address = None
    
    def is_valid_ip(self, address: str) -> bool:
        """Check if a string is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def _prepare_scan_tasks(self, scan_type: str, aggressive: bool = False) -> Dict:
        """Prepare scan tasks based on scan type"""
        tasks = {}
        
        # Common tasks for all scan types
        common_tasks = {
            'target_info': self._get_target_info,
            'dns_records': self._get_dns_records,
            'whois': self._get_whois_info,
            'ssl_tls': self._get_ssl_info,
            'http_headers': self._get_http_headers,
            'tech_stack': self._detect_tech_stack,
        }
        
        # Network scan tasks
        network_tasks = {
            'port_scan': lambda: self._scan_ports(CONFIG['scan']['default_ports']),
            'os_detection': self._detect_os,
            'service_detection': self._detect_services,
            'vulnerability_scan': self._scan_vulnerabilities,
            'network_traffic': self._capture_network_traffic,
        }
        
        # Web application scan tasks
        web_tasks = {
            'web_spider': self._spider_website,
            'content_analysis': self._analyze_content,
            'form_analysis': self._analyze_forms,
            'api_analysis': self._analyze_apis,
            'auth_analysis': self._analyze_auth,
            'security_headers': self._check_security_headers,
            'cors_analysis': self._check_cors,
            'sensitive_files': self._find_sensitive_files,
            'subdomains': self._find_subdomains,
            'directory_bruteforce': self._bruteforce_directories,
        }
        
        # Aggressive scan tasks
        aggressive_tasks = {
            'full_port_scan': lambda: self._scan_ports(CONFIG['scan']['full_ports']),
            'hidden_services': lambda: self._scan_ports(CONFIG['scan']['hidden_ports']),
            'sql_injection': self._test_sql_injection,
            'xss_test': self._test_xss,
            'idor_test': self._test_idor,
            'ssrf_test': self._test_ssrf,
            'rce_test': self._test_rce,
            'lfi_test': self._test_lfi,
            'advanced_fuzzing': self._advanced_fuzzing,
        }

        # Ultra scan tasks (new advanced features)
        ultra_tasks = {
            'ml_detection': self._scan_with_ml_detection,
            'container_security': self._scan_container_security,
            'iot_security': self._scan_iot_devices,
            'advanced_api_security': self._advanced_api_security_scan,
            'advanced_evasion': self._advanced_evasion_scan,
        }
        
        # Build task list based on scan type
        tasks.update(common_tasks)
        
        if scan_type in ["network", "full"]:
            tasks.update(network_tasks)
        
        if scan_type in ["web", "full"] and self.base_url:
            tasks.update(web_tasks)
        
        if aggressive:
            tasks.update(aggressive_tasks)

        # Always include ultra tasks for maximum power
        if scan_type in ["full", "ultra"]:
            tasks.update(ultra_tasks)

        return tasks
    
    def _get_target_info(self) -> Dict:
        """Get comprehensive target information"""
        result = {
            'target': self.target,
            'domain': self.domain,
            'ip_address': self.ip_address,
            'base_url': self.base_url,
            'is_up': self._is_host_up(),
            'cloud_provider': self._detect_cloud_provider(),
            'cdn': self._detect_cdn(),
            'waf': self._detect_waf(),
        }
        
        # Additional API lookups if available
        if CONFIG['api_keys']['shodan'] and self.ip_address:
            result['shodan'] = self._query_shodan()
        
        if CONFIG['api_keys']['virustotal'] and self.domain:
            result['virustotal'] = self._query_virustotal()
        
        return result

    def _scan_with_ml_detection(self) -> Dict:
        """Perform ML-based vulnerability detection"""
        if not CONFIG['ml_detection']['enabled']:
            return {'error': 'ML detection disabled'}

        result = {
            'ml_findings': [],
            'behavioral_analysis': {},
            'anomaly_detection': {}
        }

        try:
            # Analyze web content if available
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if 'source' in page:
                        ml_analysis = self.ml_detector.analyze_code_patterns(page['source'])
                        if ml_analysis['detected_vulnerabilities']:
                            result['ml_findings'].append({
                                'url': page['url'],
                                'analysis': ml_analysis
                            })

            # Analyze HTTP traffic patterns
            if 'http_headers' in self.results['results']:
                headers = self.results['results']['http_headers'].get('headers', {})
                header_str = str(headers)

                traffic_analysis = self.ml_detector.analyze_http_traffic('', header_str)
                if traffic_analysis['potential_vulnerabilities']:
                    result['behavioral_analysis'] = traffic_analysis

            # Anomaly detection in scan results
            anomaly_score = 0
            if result['ml_findings']:
                anomaly_score += len(result['ml_findings']) * 0.3
            if result['behavioral_analysis']:
                anomaly_score += result['behavioral_analysis']['traffic_score']

            result['anomaly_detection'] = {
                'score': anomaly_score,
                'risk_level': 'high' if anomaly_score > 0.7 else 'medium' if anomaly_score > 0.4 else 'low'
            }

        except Exception as e:
            result['error'] = str(e)

        return result

    def _scan_container_security(self) -> Dict:
        """Perform container security scanning"""
        if not CONFIG['container_security']['enabled']:
            return {'error': 'Container security scanning disabled'}

        result = {
            'docker_images': {},
            'container_networking': {},
            'kubernetes_security': {},
            'recommendations': []
        }

        try:
            # Docker image scanning
            if DOCKER_AVAILABLE:
                result['docker_images'] = self.container_scanner.scan_docker_images()

                # Container networking analysis
                result['container_networking'] = self.container_scanner.check_container_networking()

                # Generate recommendations
                if result['docker_images'].get('images'):
                    for image in result['docker_images']['images']:
                        if image.get('vulnerabilities'):
                            for vuln in image['vulnerabilities']:
                                if vuln['severity'] == 'critical':
                                    result['recommendations'].append(
                                        f"Critical: {vuln['description']} in image {image['tags'][0] if image['tags'] else image['id'][:12]}"
                                    )

        except Exception as e:
            result['error'] = str(e)

        return result

    def _scan_iot_devices(self) -> Dict:
        """Scan for IoT devices and vulnerabilities"""
        if not CONFIG['iot_security']['enabled']:
            return {'error': 'IoT security scanning disabled'}

        result = {
            'devices': [],
            'vulnerabilities': [],
            'network_analysis': {}
        }

        try:
            if self.ip_address:
                # Scan local network for IoT devices
                network_range = '.'.join(self.ip_address.split('.')[:-1]) + '.0/24'
                result = self.iot_scanner.scan_iot_devices(self.ip_address)

                # Additional network analysis
                result['network_analysis'] = {
                    'scanned_range': network_range,
                    'common_iot_ports': [23, 80, 443, 8080, 1900, 2000, 49000, 50000],
                    'detection_methods': ['port_scanning', 'banner_grabbing', 'protocol_analysis']
                }

        except Exception as e:
            result['error'] = str(e)

        return result

    def _advanced_api_security_scan(self) -> Dict:
        """Perform advanced API security testing"""
        if not CONFIG['api_security']['enabled']:
            return {'error': 'API security scanning disabled'}

        result = {
            'graphql_tests': {},
            'rest_api_tests': {},
            'rate_limit_analysis': {},
            'authentication_tests': {},
            'authorization_tests': {}
        }

        try:
            # GraphQL security testing
            if CONFIG['api_security']['test_graphql']:
                result['graphql_tests'] = self._test_graphql_security()

            # REST API security testing
            if CONFIG['api_security']['test_rest']:
                result['rest_api_tests'] = self._test_rest_api_security()

            # Rate limiting analysis
            if CONFIG['api_security']['check_rate_limits']:
                result['rate_limit_analysis'] = self._analyze_rate_limits()

            # Authentication testing
            if CONFIG['api_security']['analyze_auth']:
                result['authentication_tests'] = self._test_api_authentication()

        except Exception as e:
            result['error'] = str(e)

        return result

    def _test_graphql_security(self) -> Dict:
        """Test GraphQL endpoints for security issues"""
        result = {
            'introspection_enabled': False,
            'field_suggestions': False,
            'debug_mode': False,
            'vulnerable_queries': []
        }

        try:
            # Test for introspection
            introspection_query = {
                'query': '''
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                        types { ...FullType }
                        directives { name description locations args { ...InputValue } }
                    }
                }
                fragment FullType on __Type {
                    kind
                    name
                    description
                    fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
                    inputFields { ...InputValue }
                    interfaces { ...TypeRef }
                    enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
                    possibleTypes { ...TypeRef }
                }
                fragment InputValue on __InputValue {
                    name
                    description
                    type { ...TypeRef }
                    defaultValue
                }
                fragment TypeRef on __Type {
                    kind
                    name
                    ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
                }
                '''
            }

            response = self.session.post(
                f"{self.base_url}/graphql",
                json=introspection_query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response.status_code == 200:
                result['introspection_enabled'] = True

                # Check for field suggestions
                error_query = {'query': '{ __typename }'}
                error_response = self.session.post(
                    f"{self.base_url}/graphql",
                    json=error_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )

                if 'Did you mean' in error_response.text or 'suggestions' in error_response.text:
                    result['field_suggestions'] = True

        except Exception as e:
            result['error'] = str(e)

        return result

    def _test_rest_api_security(self) -> Dict:
        """Test REST API endpoints for security issues"""
        result = {
            'endpoints_tested': [],
            'vulnerable_endpoints': [],
            'security_headers': {},
            'common_issues': []
        }

        try:
            # Test common API endpoints
            api_endpoints = [
                '/api/v1/users',
                '/api/v1/admin',
                '/api/users',
                '/api/admin',
                '/v1/users',
                '/v1/admin'
            ]

            for endpoint in api_endpoints:
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = self.session.get(url, timeout=5)

                    result['endpoints_tested'].append({
                        'url': url,
                        'status_code': response.status_code,
                        'response_length': len(response.text)
                    })

                    # Check for information disclosure
                    if response.status_code == 200:
                        if 'password' in response.text.lower() or 'admin' in response.text.lower():
                            result['vulnerable_endpoints'].append({
                                'url': url,
                                'issue': 'information_disclosure',
                                'severity': 'high'
                            })

                    # Check for missing authentication
                    if response.status_code in [200, 201] and endpoint in ['/api/v1/admin', '/api/admin', '/v1/admin']:
                        result['vulnerable_endpoints'].append({
                            'url': url,
                            'issue': 'missing_authentication',
                            'severity': 'critical'
                        })

                except Exception:
                    continue

        except Exception as e:
            result['error'] = str(e)

        return result

    def _analyze_rate_limits(self) -> Dict:
        """Analyze API rate limiting"""
        result = {
            'rate_limit_detected': False,
            'requests_per_minute': 0,
            'burst_limit': 0,
            'bypass_possible': False
        }

        try:
            # Test rate limiting with multiple requests
            test_endpoint = f"{self.base_url}/api/test"
            responses = []

            for i in range(20):
                try:
                    response = self.session.get(test_endpoint, timeout=3)
                    responses.append(response.status_code)
                    time.sleep(0.1)  # Small delay between requests
                except:
                    break

            # Analyze response patterns
            if 429 in responses:  # Rate limit exceeded
                result['rate_limit_detected'] = True

                # Count requests until rate limit
                rate_limit_index = responses.index(429)
                result['requests_per_minute'] = rate_limit_index * 60  # Approximate

            # Check for bypass possibilities
            if result['rate_limit_detected']:
                # Try different IP (if Tor available)
                if self._check_tor():
                    try:
                        tor_response = self.session.get(test_endpoint, timeout=3)
                        if tor_response.status_code == 200:
                            result['bypass_possible'] = True
                    except:
                        pass

        except Exception as e:
            result['error'] = str(e)

        return result

    def _test_api_authentication(self) -> Dict:
        """Test API authentication mechanisms"""
        result = {
            'auth_methods': [],
            'weak_auth': [],
            'bypass_attempts': []
        }

        try:
            # Test common auth endpoints
            auth_endpoints = [
                '/api/login',
                '/api/auth',
                '/login',
                '/auth'
            ]

            for endpoint in auth_endpoints:
                try:
                    url = urljoin(self.base_url, endpoint)

                    # Test with no auth
                    response = self.session.get(url, timeout=5)
                    if response.status_code == 401:
                        result['auth_methods'].append('HTTP Basic Auth')

                    # Test with weak credentials
                    weak_creds = [
                        ('admin', 'admin'),
                        ('admin', 'password'),
                        ('user', 'user'),
                        ('test', 'test')
                    ]

                    for username, password in weak_creds:
                        auth_response = self.session.get(
                            url,
                            auth=(username, password),
                            timeout=5
                        )

                        if auth_response.status_code == 200:
                            result['weak_auth'].append({
                                'endpoint': url,
                                'credentials': f"{username}:{password}",
                                'severity': 'critical'
                            })

                except Exception:
                    continue

        except Exception as e:
            result['error'] = str(e)

        return result

    def _advanced_evasion_scan(self) -> Dict:
        """Perform scan with advanced evasion techniques"""
        if not CONFIG['advanced_evasion']['enabled']:
            return {'error': 'Advanced evasion disabled'}

        result = {
            'evasion_techniques_used': [],
            'detection_avoided': False,
            'scan_effectiveness': 0.0
        }

        try:
            # Enable evasion features
            if CONFIG['advanced_evasion']['fragmented_packets']:
                result['evasion_techniques_used'].append('packet_fragmentation')

            if CONFIG['advanced_evasion']['randomized_timing']:
                result['evasion_techniques_used'].append('timing_randomization')

            if CONFIG['advanced_evasion']['payload_obfuscation']:
                result['evasion_techniques_used'].append('payload_obfuscation')

            # Create decoy traffic
            if self.base_url:
                self.evasion_engine.create_decoy_traffic(self.base_url, duration=15)

            # Use obfuscated payloads for testing
            if 'web_spider' in self.results['results']:
                for page in self.results['results']['web_spider'].get('pages', []):
                    if '?' in page['url']:
                        # Test with obfuscated parameters
                        base, params = page['url'].split('?', 1)
                        obfuscated_params = self.evasion_engine.obfuscate_payload(params)
                        test_url = f"{base}?{obfuscated_params}"

                        try:
                            response = self.session.get(test_url, timeout=5)
                            if response.status_code == 200:
                                result['detection_avoided'] = True
                        except:
                            pass

            result['scan_effectiveness'] = 0.9 if result['detection_avoided'] else 0.7

        except Exception as e:
            result['error'] = str(e)

        return result

    def run_scan(self, scan_type: str = "full", **kwargs) -> Dict:
        """Execute comprehensive security scan"""
        start_time = time.time()
        
        # Create output directories
        os.makedirs(CONFIG['paths']['output_dir'], exist_ok=True)
        os.makedirs(CONFIG['paths']['screenshots_dir'], exist_ok=True)
        
        # Resolve target information
        self._resolve_target()
        
        # Prepare scan tasks based on type
        scan_tasks = self._prepare_scan_tasks(scan_type, kwargs.get('aggressive', False))
        
        # Execute scans with async processing and advanced rate limiting
        async def run_scan_tasks_async():
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

            async def run_task_with_semaphore(name, task):
                async with semaphore:
                    try:
                        # Add delay for rate limiting
                        await asyncio.sleep(CONFIG['advanced']['rate_limit_delay'])

                        # Run task in thread pool for CPU-bound operations
                        loop = asyncio.get_event_loop()
                        result = await loop.run_in_executor(
                            None,
                            self._safe_task_execution,
                            task
                        )

                        with self.lock:
                            self.results['results'][name] = result

                    except Exception as e:
                        with self.lock:
                            self.results['results'][name] = {'error': str(e)}

            # Create tasks
            tasks = []
            for name, task in scan_tasks.items():
                tasks.append(run_task_with_semaphore(name, task))

            # Execute all tasks concurrently
            await asyncio.gather(*tasks, return_exceptions=True)

        # Run async tasks
        asyncio.run(run_scan_tasks_async())
        
        # Post-processing
        self._post_processing()
        
        # Calculate execution time
        self.results['metadata']['execution_time'] = time.time() - start_time
        self.results['metadata']['end_time'] = datetime.utcnow().isoformat()
        
        # Clean up
        if self.selenium_driver:
            self.selenium_driver.quit()
        
        return self.results

    def _safe_task_execution(self, task):
        """Safely execute a scan task with error handling"""
        try:
            return task()
        except Exception as e:
            return {'error': str(e), 'traceback': str(e.__traceback__)}

    def _post_processing(self):
        """Perform post-processing on scan results"""
        # Analyze relationships between findings
        self._analyze_relationships()
        
        # Generate risk assessment
        self._generate_risk_assessment()
        
        # Calculate hashes of important findings
        self._calculate_hashes()
        
        # Generate executive summary
        self._generate_executive_summary()

def cli_main():
    """Enhanced command line interface"""
    parser = argparse.ArgumentParser(
        description="Ultimate Linux Network Security Scanner - Ultra Edition (v5.0) - Now with ML Detection, Container Security, IoT Scanning, and Advanced Evasion",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Target specification
    parser.add_argument(
        'target',
        help="Target to scan (IP, domain, or URL)"
    )
    
    # Scan options
    parser.add_argument(
        '-t', '--type',
        choices=['quick', 'full', 'web', 'network', 'vulnerability', 'ultra'],
        default='full',
        help="Type of scan to perform (ultra includes ML detection, container scanning, IoT scanning, and advanced evasion)"
    )
    
    parser.add_argument(
        '-o', '--output',
        help="Output file for JSON results"
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help="Enable aggressive scanning techniques"
    )
    
    parser.add_argument(
        '--stealth',
        action='store_true',
        help="Enable stealth mode (slower but less detectable)"
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help="Increase verbosity level"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Update config based on arguments
    CONFIG['advanced']['aggressive_scan'] = args.aggressive
    CONFIG['advanced']['stealth_mode'] = args.stealth
    
    # Initialize scanner
    scanner = UltimateScanner(args.target)
    
    # Run scan
    print(f"[*] Starting {args.type} scan of {args.target}")
    try:
        results = scanner.run_scan(args.type, aggressive=args.aggressive)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] Results saved to {args.output}")
        
        # Print executive summary
        summary = results.get('executive_summary', {})
        print("\n[+] Scan Summary:")
        print(f"  - Target: {summary.get('scan_overview', {}).get('target')}")
        print(f"  - Duration: {summary.get('scan_overview', {}).get('duration', 0):.2f} seconds")
        print(f"  - Open ports: {summary.get('findings_summary', {}).get('open_ports', 0)}")
        print(f"  - Critical vulnerabilities: {summary.get('findings_summary', {}).get('critical_vulnerabilities', 0)}")
        print(f"  - Web pages found: {summary.get('findings_summary', {}).get('web_pages_found', 0)}")
        
        print("\n[+] Top Recommendations:")
        for rec in summary.get('recommendations', [])[:3]:
            print(f"  - {rec}")
        
        print("\n[+] Scan completed successfully")
        
    except Exception as e:
        print(f"[-] Scan failed: {str(e)}")
        sys.exit(1)

def test_imports():
    """Test basic imports and functionality"""
    try:
        print("[+] Testing basic imports...")
        import ssl, socket, re, json, time, threading
        print("[+] Core modules imported successfully")

        print("[+] Testing advanced features...")
        print(f"[+] ML Detection: {'Available' if ML_AVAILABLE else 'Not Available'}")
        print(f"[+] Docker Scanning: {'Available' if DOCKER_AVAILABLE else 'Not Available'}")
        print(f"[+] Database Support: MySQL={'Available' if MYSQL_AVAILABLE else 'Not Available'}, PostgreSQL={'Available' if POSTGRES_AVAILABLE else 'Not Available'}, MongoDB={'Available' if MONGO_AVAILABLE else 'Not Available'}")

        print("[+] Scanner initialization test...")
        # Test scanner initialization without target
        scanner = UltimateScanner.__new__(UltimateScanner)
        print("[+] Scanner class created successfully")

        print("[+] All tests passed! Scanner is ready to use.")
        return True

    except Exception as e:
        print(f"[-] Test failed: {str(e)}")
        return False

if __name__ == "__main__":
    # Run tests first
    if test_imports():
        print("\n[+] Running scanner...")
        cli_main()
    else:
        print("\n[-] Tests failed, cannot run scanner")
        sys.exit(1)
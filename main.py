import re
import csv
import socket
import ssl
import requests
import smtplib
import sys
import argparse
import logging
import os
import time
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Any, Optional
import dns.resolver
import dns.exception

# Import configuration from config.py
from config import CONFIG, BLACKLIST_DATABASES, validate_config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

if CONFIG['VERBOSE']:
    logger.setLevel(logging.DEBUG)

class WebsiteHealthCheck:
    def __init__(self, domain: str, ssl_warning_days: int = 15):
        self.domain = domain
        self.url = f"https://{domain}"
        self.ssl_warning_days = ssl_warning_days
        self.results: Dict[str, Any] = {}

    def check_dns(self) -> Tuple[bool, str]:
        try:
            ip = socket.gethostbyname(self.domain)
            logger.info(f"OK - DNS: {domain_to_log(self.domain)} -> {ip}")
            self.results['dns'] = {'status': True, 'details': ip}
            return True, ip
        except socket.gaierror as e:
            logger.error(f"FAIL - DNS: {domain_to_log(self.domain)} - {e}")
            self.results['dns'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def check_http_and_headers(self) -> Tuple[bool, Any]:
        try:
            start_time = time.time()
            response = requests.get(self.url, timeout=10, allow_redirects=True)
            response_time = round(time.time() - start_time, 2)
            
            headers = response.headers
            security = {
                'HSTS': 'Strict-Transport-Security' in headers,
                'CSP': 'Content-Security-Policy' in headers,
                'X-Frame': 'X-Frame-Options' in headers,
                'X-Content-Type': 'X-Content-Type-Options' in headers
            }

            logger.info(f"OK - HTTP: {domain_to_log(self.domain)} ({response.status_code}) in {response_time}s")
            self.results['http'] = {
                'status': response.status_code == 200,
                'code': response.status_code,
                'time': response_time,
                'security': security
            }
            return response.status_code == 200, response.status_code
        except requests.RequestException as e:
            logger.error(f"FAIL - HTTP: {domain_to_log(self.domain)} - {e}")
            self.results['http'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def check_ssl(self) -> Tuple[bool, str]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    remaining = (expiry - datetime.now(timezone.utc)).days
                    logger.info(f"OK - SSL: {domain_to_log(self.domain)} (Expires in {remaining} days)")
                    is_valid = remaining > self.ssl_warning_days
                    self.results['ssl'] = {'status': is_valid, 'details': f"{remaining} days", 'expiry': expiry.strftime('%Y-%m-%d')}
                    return is_valid, expiry.strftime('%B %d, %Y')
        except Exception as e:
            logger.error(f"FAIL - SSL: {domain_to_log(self.domain)} - {e}")
            self.results['ssl'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def run_all(self) -> Dict[str, Any]:
        self.check_dns()
        self.check_http_and_headers()
        self.check_ssl()
        return self.results

def domain_to_log(domain: str) -> str:
    return domain

class EmailInfrastructureCheck:
    def __init__(self, domain: str, ip: str):
        self.domain, self.ip = domain, ip
        self.results: Dict[str, Any] = {}

    def check_mx(self) -> bool:
        try:
            records = dns.resolver.resolve(self.domain, 'MX')
            mx_list = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in records], key=lambda x: x[0])
            self.results['mx'] = {'status': True, 'details': str(mx_list)}
            return True
        except Exception as e:
            self.results['mx'] = {'status': False, 'details': str(e)}
            return False

    def check_spf(self) -> bool:
        try:
            records = dns.resolver.resolve(self.domain, 'TXT')
            spf = next((str(r).strip('"') for r in records if 'v=spf1' in str(r)), None)
            self.results['spf'] = {'status': bool(spf), 'details': spf or "No SPF"}
            return bool(spf)
        except Exception as e:
            self.results['spf'] = {'status': False, 'details': str(e)}
            return False

    def check_dmarc(self) -> bool:
        try:
            records = dns.resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
            dmarc = next((str(r).strip('"') for r in records if 'v=DMARC1' in str(r)), None)
            self.results['dmarc'] = {'status': bool(dmarc), 'details': dmarc or "No DMARC"}
            return bool(dmarc)
        except Exception as e:
            self.results['dmarc'] = {'status': False, 'details': str(e)}
            return False

    def check_ptr(self) -> bool:
        try:
            rev = '.'.join(reversed(self.ip.split('.'))) + '.in-addr.arpa'
            records = dns.resolver.resolve(rev, 'PTR')
            ptrs = [str(p).rstrip('.') for p in records]
            self.results['ptr'] = {'status': True, 'details': str(ptrs)}
            return True
        except Exception as e:
            self.results['ptr'] = {'status': False, 'details': str(e)}
            return False

    def run_all(self) -> Dict[str, Any]:
        self.check_mx()
        self.check_spf()
        self.check_dmarc()
        self.check_ptr()
        return self.results

class BlacklistCheck:
    def __init__(self, ip: str):
        self.ip = ip

    def _query(self, name: str, host: str) -> Tuple[str, str]:
        rev = '.'.join(reversed(self.ip.split('.')))
        try:
            dns.resolver.resolve(f"{rev}.{host}", 'A')
            return name, "LISTED" if 'dnswl' not in host.lower() else "WHITELISTED"
        except:
            return name, "CLEAN"

    def run_all(self) -> Dict[str, Any]:
        detected = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(self._query, n, h) for n, h in BLACKLIST_DATABASES.items()]
            for f in as_completed(futures):
                name, status = f.result()
                if status == "LISTED": detected.append(name)
        return {'listed': bool(detected), 'detected': detected, 'ip': self.ip}

class DomainMonitor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def _is_valid(self, domain: str) -> bool:
        return bool(re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]{0,253}[a-zA-Z0-9]\.[a-zA-Z]{2,63}$", domain))

    def _discover_ip(self, domain: str) -> Optional[str]:
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            mx_host = str(sorted(mx, key=lambda x: x.preference)[0].exchange).rstrip('.')
            return socket.gethostbyname(mx_host)
        except:
            try: return socket.gethostbyname(domain)
            except: return None

    def _process_domain(self, domain: str, check_type: str) -> Tuple[str, Dict[str, Any]]:
        logger.info(f"Processing: {domain}")
        res = {}
        if check_type in ['all', 'website']:
            res['website'] = WebsiteHealthCheck(domain, self.config['SSL_WARNING_DAYS']).run_all()
        
        ip = self.config.get('CHECK_IP') or self._discover_ip(domain)
        if ip:
            if check_type in ['all', 'email']:
                res['email'] = EmailInfrastructureCheck(domain, ip).run_all()
            if check_type in ['all', 'blacklist']:
                res['blacklist'] = BlacklistCheck(ip).run_all()
        return domain, res

    def run(self, check_type: str = 'all'):
        if not os.path.exists(self.config['DOMAIN_FILE']):
            logger.error("No domain file found.")
            return

        valid_domains = []
        try:
            with open(self.config['DOMAIN_FILE'], 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain = row.get('domain', '').strip()
                    if domain and self._is_valid(domain):
                        valid_domains.append(domain)
        except Exception as e:
            logger.error(f"Error reading domain file: {e}")
            return

        if not valid_domains:
            logger.error("No valid domains to check.")
            return

        results = {}
        with ThreadPoolExecutor(max_workers=self.config['MAX_WORKERS']) as ex:
            futures = [ex.submit(self._process_domain, d, check_type) for d in valid_domains]
            for f in as_completed(futures):
                domain, domain_res = f.result()
                results[domain] = domain_res

        self._print_summary(results)
        if self.config['ENABLE_EMAIL_ALERTS']:
            self._send_email(results)

    def _print_summary(self, results: Dict[str, Any]):
        print("\n" + "=" * 80)
        print(f"{'DOMAIN':30} | {'STATUS':7} | {'SPEED':6} | {'SSL':10} | {'IP'}")
        print("-" * 80)
        for d, data in results.items():
            web = data.get('website', {})
            status = "PASS" if web.get('dns', {}).get('status') and web.get('http', {}).get('status') else "ISSUE"
            perf = f"{web.get('http', {}).get('time', 'N/A')}s"
            ssl_days = f"{web.get('ssl', {}).get('details', 'N/A')}"
            ip = web.get('dns', {}).get('details', 'N/A')
            print(f"{d:30} | {status:7} | {perf:6} | {ssl_days:10} | {ip}")
            
            bl = data.get('blacklist', {})
            if bl.get('listed'):
                print(f"  [!] BLACKLISTED on: {', '.join(bl['detected'])} (IP: {bl['ip']})")

    def _send_email(self, results: Dict[str, Any]):
        if not self.config['APP_PASSWORD']: return
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Domain Health Report - {datetime.now().strftime('%Y-%m-%d')}"
        msg['From'], msg['To'] = self.config['EMAIL_FROM'], self.config['EMAIL_TO']
        
        html = f"""
        <html>
        <body style='font-family: sans-serif;'>
            <h2>Domain Health Monitoring Report</h2>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <table border='1' cellpadding='8' style='border-collapse: collapse; width: 100%;'>
                <tr style='background-color: #f2f2f2;'>
                    <th>Domain / Attributes</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
        """
        
        for d, data in results.items():
            web = data.get('website', {})
            mail = data.get('email', {})
            bl = data.get('blacklist', {})
            
            html += f"<tr style='background-color: #e9ecef;'><td colspan='3'><b>{d}</b></td></tr>"
            
            dns_ip = web.get('dns', {}).get('details', 'N/A')
            html += f"<tr><td>DNS IP</td><td>{'OK' if web.get('dns', {}).get('status') else 'FAIL'}</td><td>{dns_ip}</td></tr>"
            
            http = web.get('http', {})
            html += f"<tr><td>HTTP Status</td><td>{'OK' if http.get('status') else 'FAIL'}</td><td>{http.get('code', 'N/A')} (Response: {http.get('time', 'N/A')}s)</td></tr>"
            
            ssl_info = web.get('ssl', {})
            html += f"<tr><td>SSL Certificate</td><td>{'OK' if ssl_info.get('status') else 'FAIL'}</td><td>Remaining: {ssl_info.get('details', 'N/A')} (Expires: {ssl_info.get('expiry', 'N/A')})</td></tr>"
            
            sec = http.get('security', {})
            if sec:
                sec_list = [h for h, present in sec.items() if present]
                sec_missing = [h for h, present in sec.items() if not present]
                html += f"<tr><td>Security Headers</td><td>{'PASS' if not sec_missing else 'WARN'}</td><td>Found: {', '.join(sec_list) if sec_list else 'None'}<br>Missing: {', '.join(sec_missing) if sec_missing else 'None'}</td></tr>"

            if mail:
                mx = mail.get('mx', {})
                html += f"<tr><td>MX Records</td><td>{'OK' if mx.get('status') else 'FAIL'}</td><td>{mx.get('details', 'N/A')}</td></tr>"
                
                spf = mail.get('spf', {})
                html += f"<tr><td>SPF Record</td><td>{'OK' if spf.get('status') else 'FAIL'}</td><td>{spf.get('details', 'N/A')}</td></tr>"
                
                dmarc = mail.get('dmarc', {})
                html += f"<tr><td>DMARC Record</td><td>{'OK' if dmarc.get('status') else 'FAIL'}</td><td>{dmarc.get('details', 'N/A')}</td></tr>"
                
                ptr = mail.get('ptr', {})
                html += f"<tr><td>PTR (Reverse DNS)</td><td>{'OK' if ptr.get('status') else 'FAIL'}</td><td>{ptr.get('details', 'N/A')}</td></tr>"

            if bl:
                bl_details = f"IP: {bl['ip']}<br>Listed on: " + (", ".join(bl['detected']) if bl['detected'] else "None")
                html += f"<tr><td>Blacklist Status</td><td>{'FAIL' if bl.get('listed') else 'OK'}</td><td>{bl_details}</td></tr>"

        html += "</table><p style='color: grey; font-size: 0.8em;'>This is an automated report.</p></body></html>"
        msg.attach(MIMEText(html, 'html'))
        
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.config['EMAIL_FROM'], self.config['APP_PASSWORD'])
                server.send_message(msg)
            logger.info("Email report sent.")
        except Exception as e:
            logger.error(f"Email failed: {e}")

def main():
    parser = argparse.ArgumentParser(description='Advanced Domain Monitor')
    parser.add_argument('--type', choices=['all', 'website', 'email', 'blacklist'], default='all')
    args = parser.parse_args()
    
    # Validate before running
    if not validate_config():
        sys.exit(1)
        
    DomainMonitor(CONFIG).run(args.type)

if __name__ == "__main__":
    main()
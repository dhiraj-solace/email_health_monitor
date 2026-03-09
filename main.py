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
from config import CONFIG, BLACKLIST_IP, BLACKLIST_DOMAIN, BLACKLIST_EMAIL, validate_config

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
    def __init__(self, ip: str, domain: str):
        self.ip, self.domain = ip, domain

    def _query(self, target: str, host: str, is_ip: bool) -> Tuple[str, str]:
        prefix = '.'.join(reversed(target.split('.'))) if is_ip else target
        try:
            dns.resolver.resolve(f"{prefix}.{host}", 'A')
            return host, "LISTED"
        except:
            return host, "CLEAN"

    def run_category(self, target: str, databases: Dict[str, str], is_ip: bool) -> Dict[str, Any]:
        detected = []
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = [ex.submit(self._query, target, h, is_ip) for h in databases.values()]
            for f in as_completed(futures):
                host, status = f.result()
                if status == "LISTED": detected.append(host)
        return {'listed': bool(detected), 'detected': detected}

    def run_all(self) -> Dict[str, Any]:
        return {
            'ip': self.run_category(self.ip, BLACKLIST_IP, True),
            'domain': self.run_category(self.domain, BLACKLIST_DOMAIN, False),
            'email': self.run_category(self.domain, BLACKLIST_EMAIL, False)
        }

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
                res['blacklist'] = BlacklistCheck(ip, domain).run_all()
                res['blacklist']['ip_address'] = ip
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
            if bl:
                for cat in ['ip', 'domain', 'email']:
                    c = bl.get(cat, {})
                    if c.get('listed'):
                        print(f"  [!] {cat.upper()} BLACKLISTED: {', '.join(c['detected'])}")

    def _send_email(self, results: Dict[str, Any]):
        if not self.config['APP_PASSWORD']: return
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Domain Health Report - {datetime.now().strftime('%Y-%m-%d')}"
        msg['From'] = self.config['EMAIL_FROM']
        msg['To'] = ", ".join(self.config['EMAIL_TO'])
        
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
        
        def add_row(label, status, details, fail):
            color = "color: red;" if fail else ""
            return f"<tr style='{color}'><td>{label}</td><td>{status}</td><td>{details}</td></tr>"

        issue_domains, healthy_domains = [], []
        for d, data in results.items():
            has_fail = False
            for cat in ['website', 'email']:
                for check in data.get(cat, {}).values():
                    if isinstance(check, dict) and not check.get('status', True): has_fail = True
            bl = data.get('blacklist', {})
            if bl.get('ip', {}).get('listed') or bl.get('domain', {}).get('listed') or bl.get('email', {}).get('listed'):
                has_fail = True
            
            if has_fail: issue_domains.append((d, data))
            else: healthy_domains.append(d)

        html = f"""
        <html>
        <body style='font-family: sans-serif; color: #333;'>
            <div style='background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #dee2e6;'>
                <h2 style='margin-top: 0;'>Domain Health Summary</h2>
                <p>Checked: <b>{len(results)}</b> | Issues: <span style='color: {"red" if issue_domains else "green"}; font-weight: bold;'>{len(issue_domains)}</span> | Healthy: <b>{len(healthy_domains)}</b></p>
                {f"<p style='color: red;'><b>Action Required:</b> Please review the {len(issue_domains)} domains with issues below.</p>" if issue_domains else "<p style='color: green;'>All domains are healthy!</p>"}
            </div>
        """

        if issue_domains:
            html += "<h3>Domains with Issues</h3>"
            for d, data in issue_domains:
                web, mail, bl = data.get('website', {}), data.get('email', {}), data.get('blacklist', {})
                html += f"<table border='1' cellpadding='8' style='border-collapse: collapse; width: 100%; margin-bottom: 20px;'>"
                html += f"<tr style='background-color: #e9ecef;'><td colspan='3'><b>{d}</b></td></tr>"
                
                dns = web.get('dns', {})
                html += add_row("DNS IP", "YES" if dns.get('status') else "NO", dns.get('details', 'N/A'), not dns.get('status'))
                
                http = web.get('http', {})
                html += add_row("HTTP Status", "YES" if http.get('status') else "NO", f"{http.get('code', 'N/A')} (Response: {http.get('time', 'N/A')}s)", not http.get('status'))
                
                ssl = web.get('ssl', {})
                html += add_row("SSL Certificate", "YES" if ssl.get('status') else "NO", f"Remaining: {ssl.get('details', 'N/A')} (Expires: {ssl.get('expiry', 'N/A')})", not ssl.get('status'))
                
                sec = http.get('security', {})
                if sec:
                    miss = [h for h, p in sec.items() if not p]
                    html += add_row("Security Headers", "PASS" if not miss else "WARN", f"Found: {', '.join(h for h, p in sec.items() if p) or 'None'}<br>Missing: {', '.join(miss) or 'None'}", bool(miss))

                if mail:
                    for label, key in [("MX Records", "mx"), ("SPF Record", "spf"), ("DMARC Record", "dmarc"), ("PTR (Reverse DNS)", "ptr")]:
                        m = mail.get(key, {})
                        html += add_row(label, "YES" if m.get('status') else "NO", m.get('details', 'N/A'), not m.get('status'))

                if bl:
                    for label, info in [("Is IP Blacklisted", bl.get('ip', {})), ("Is Domain Blacklisted", bl.get('domain', {})), ("Is Email Blacklisted", bl.get('email', {}))]:
                        is_bl = info.get('listed')
                        details = ("Listed on: " + ", ".join(info.get('detected', []))) if is_bl else "Clean"
                        if "IP" in label: details += f" (IP: {bl.get('ip_address', 'N/A')})"
                        html += add_row(label, "YES" if is_bl else "NO", details, is_bl)
                html += "</table>"

        if healthy_domains:
            html += "<h3>Healthy Domains</h3>"
            html += f"<p style='color: green;'>{', '.join(healthy_domains)}</p>"

        html += f"<div style='margin-top: 20px; padding: 15px; background: #fff5f5; border: 1px solid #feb2b2; border-radius: 6px;'><p style='margin: 0;'><b>Need help?</b> Refer to our <a href='{self.config['TROUBLESHOOTING_URL']}'>Troubleshooting Guide</a> to resolve any issues.</p></div>"
        html += "<p style='color: grey; font-size: 0.8em; margin-top: 30px;'>Report generated on: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "</p></body></html>"
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
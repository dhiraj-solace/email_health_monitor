import re
import csv
import socket
import ssl
import requests
import smtplib
import sys
import logging
import os
import time
import functions_framework
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.utils import formatdate, make_msgid
from io import BytesIO
from xhtml2pdf import pisa
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Any, Optional
import dns.resolver
import dns.exception

# ── Hardcoded Configuration ────────────────────────────────────────────────
CONFIG = {
    "EMAIL_FROM":          "emailmonitoringalert@gmail.com",
    "EMAIL_TO":            "joey@fundmatellc.com,manny@fundmatellc.com, rihasoft2@gmail.com",
    "APP_PASSWORD":        "jrcr uvor mnyd kyrq",
    "ENABLE_EMAIL_ALERTS": True,
    "SSL_WARNING_DAYS":    15,
    "DOMAIN_FILE":         "domains.csv",
    "CHECK_IP":            None,
    "MAX_WORKERS":         10,
    "DKIM_SELECTORS":      [
        "selector1",
        "selector2",
        "google",
        "default",
        "hostingermail1",
        "hostingermail2",
        "hostingermail-a",
        "hostingermail-b",
    ],
    "VERBOSE":             True,
    # Link to your troubleshooting guide PDF on Google Drive
    "HELP_GUIDE_URL":      "https://drive.google.com/file/d/1eIGXutbVxOULDnwBBLKfUlvOhI9k0Zly/view?usp=sharing",
}

BLACKLIST_IP = {
    "Spamhaus_ZEN":     "zen.spamhaus.org",
    "Barracuda":        "b.barracudacentral.org",
    "SpamCop":          "bl.spamcop.net",
    "SORBS_SPAM":       "spam.dnsbl.sorbs.net",
    "UCEPROTECT_L1":    "dnsbl-1.uceprotect.net",
    "Invaluement":      "dnsbl.invaluement.com",
    "JustSpam":         "dnsbl.justspam.org",
    "Passive_Spam_BL":  "psbl.surriel.com",
}

BLACKLIST_DOMAIN = {
    "Spamhaus_DBL": "dbl.spamhaus.org",
    "SURBL":        "multi.surbl.org",
    "SpamCop_URL":  "bl.spamcop.net",
}

BLACKLIST_EMAIL = {
    "Spamhaus_ZEN": "zen.spamhaus.org",
    "Barracuda":    "b.barracudacentral.org",
    "SORBS":        "dnsbl.sorbs.net",
}

logging.basicConfig(
    level=logging.DEBUG if CONFIG['VERBOSE'] else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# PDF Conversion Helper
# ──────────────────────────────────────────────

def convert_html_to_pdf(html_content: str) -> Optional[bytes]:
    """Convert an HTML string to PDF bytes using xhtml2pdf."""
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html_content.encode("utf-8")), result)
    return result.getvalue() if not pdf.err else None


# ──────────────────────────────────────────────
# Health Check Classes
# ──────────────────────────────────────────────

class WebsiteHealthCheck:
    def __init__(self, domain: str, ssl_warning_days: int = 15):
        self.domain = domain
        self.url = f"https://{domain}"
        self.ssl_warning_days = ssl_warning_days
        self.results: Dict[str, Any] = {}

    def check_dns(self) -> Tuple[bool, str]:
        try:
            ip = socket.gethostbyname(self.domain)
            logger.info(f"OK - DNS: {self.domain} -> {ip}")
            self.results['dns'] = {'status': True, 'details': ip}
            return True, ip
        except socket.gaierror as e:
            logger.error(f"FAIL - DNS: {self.domain} - {e}")
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
            logger.info(f"OK - HTTP: {self.domain} ({response.status_code}) in {response_time}s")
            self.results['http'] = {
                'status': response.status_code == 200,
                'code': response.status_code,
                'time': response_time,
                'security': security
            }
            return response.status_code == 200, response.status_code
        except requests.RequestException as e:
            logger.error(f"FAIL - HTTP: {self.domain} - {e}")
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
                    logger.info(f"OK - SSL: {self.domain} (Expires in {remaining} days)")
                    is_valid = remaining > self.ssl_warning_days
                    self.results['ssl'] = {
                        'status': is_valid,
                        'details': f"{remaining} days",
                        'expiry': expiry.strftime('%Y-%m-%d')
                    }
                    return is_valid, expiry.strftime('%B %d, %Y')
        except Exception as e:
            logger.error(f"FAIL - SSL: {self.domain} - {e}")
            self.results['ssl'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def run_all(self) -> Dict[str, Any]:
        self.check_dns()
        self.check_http_and_headers()
        self.check_ssl()
        return self.results


class EmailInfrastructureCheck:
    def __init__(self, domain: str, ip: Optional[str] = None, dkim_selectors: Optional[List[str]] = None):
        self.domain, self.ip = domain, ip
        self.dkim_selectors = dkim_selectors or []
        self.results: Dict[str, Any] = {}

    def _txt_values(self, records) -> List[str]:
        values = []
        for record in records:
            if hasattr(record, 'strings'):
                values.append(''.join(part.decode('utf-8', errors='ignore') for part in record.strings))
            else:
                values.append(str(record).replace('" "', '').strip('"'))
        return values

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
            spf = next((r for r in self._txt_values(records) if r.lower().startswith('v=spf1')), None)
            self.results['spf'] = {'status': bool(spf), 'details': spf or "No SPF"}
            return bool(spf)
        except Exception as e:
            self.results['spf'] = {'status': False, 'details': str(e)}
            return False

    def check_dmarc(self) -> bool:
        try:
            records = dns.resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
            dmarc = next((r for r in self._txt_values(records) if r.lower().startswith('v=dmarc1')), None)
            self.results['dmarc'] = {'status': bool(dmarc), 'details': dmarc or "No DMARC"}
            return bool(dmarc)
        except Exception as e:
            self.results['dmarc'] = {'status': False, 'details': str(e)}
            return False
    
    def check_dkim(self) -> bool:
        if not self.dkim_selectors:
            self.results['dkim'] = {'status': False, 'details': "No DKIM selectors configured"}
            return False

        checked = []
        for selector in self.dkim_selectors:
            name = f"{selector}._domainkey.{self.domain}"
            checked.append(name)
            try:
                records = dns.resolver.resolve(name, 'TXT')
                dkim = next((r for r in self._txt_values(records) if 'p=' in r.lower()), None)
                if dkim:
                    self.results['dkim'] = {'status': True, 'details': f"{selector}: {dkim}"}
                    return True
            except Exception:
                pass

            try:
                records = dns.resolver.resolve(name, 'CNAME')
                targets = [str(r.target).rstrip('.') for r in records]
                if targets:
                    self.results['dkim'] = {'status': True, 'details': f"{selector}: CNAME -> {', '.join(targets)}"}
                    return True
            except Exception:
                pass

        self.results['dkim'] = {'status': False, 'details': "No DKIM found for: " + ", ".join(checked)}
        return False

    def check_ptr(self) -> bool:
        if not self.ip:
            self.results['ptr'] = {'status': True, 'skipped': True, 'details': "Skipped - no mail/sending IP found"}
            return True
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
        self.check_dkim()
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
                if status == "LISTED":
                    detected.append(host)
        return {'listed': bool(detected), 'detected': detected}

    def run_all(self) -> Dict[str, Any]:
        return {
            'ip': self.run_category(self.ip, BLACKLIST_IP, True),
            'domain': self.run_category(self.domain, BLACKLIST_DOMAIN, False),
            'email': self.run_category(self.domain, BLACKLIST_EMAIL, False)
        }


# ──────────────────────────────────────────────
# Domain Monitor
# ──────────────────────────────────────────────

class DomainMonitor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def _spam_risk_label(self, data: Dict[str, Any]) -> Tuple[str, str]:
        mail = data.get('email', {})
        bl = data.get('blacklist', {})
        score = 0
        reasons = []

        if bl.get('ip', {}).get('listed'):
            score += 40
            reasons.append("IP is blacklisted")
        if bl.get('domain', {}).get('listed'):
            score += 40
            reasons.append("Domain is blacklisted")

        mx = mail.get('mx', {})
        spf = mail.get('spf', {})
        dmarc = mail.get('dmarc', {})
        dkim = mail.get('dkim', {})

        if mail:
            if not mx.get('status'):
                score += 30
                reasons.append("mail server records missing")
            if not spf.get('status'):
                score += 30
                reasons.append("SPF missing")
            if not dmarc.get('status'):
                score += 30
                reasons.append("DMARC missing")
            elif "p=none" in str(dmarc.get('details', '')).lower():
                score += 15
                reasons.append("DMARC is monitoring only")
            if not dkim.get('status'):
                score += 30
                reasons.append("DKIM missing")
        else:
            score += 20
            reasons.append("email checks not available")

        if score >= 60:
            return "High", "; ".join(reasons) or "Major email reputation issue found"
        if score >= 30:
            return "Medium", "; ".join(reasons) or "Some email trust signals need review"
        return "Low", "Core email reputation checks look clean"

    def _is_valid(self, domain: str) -> bool:
        return bool(re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]{0,253}[a-zA-Z0-9]\.[a-zA-Z]{2,63}$", domain))

    def _discover_ip(self, domain: str) -> Optional[str]:
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            mx_host = str(sorted(mx, key=lambda x: x.preference)[0].exchange).rstrip('.')
            return socket.gethostbyname(mx_host)
        except:
            try:
                return socket.gethostbyname(domain)
            except:
                return None

    def _process_domain(self, domain: str, check_type: str) -> Tuple[str, Dict[str, Any]]:
        logger.info(f"Processing: {domain}")
        res = {}
        if check_type in ['all', 'website']:
            res['website'] = WebsiteHealthCheck(domain, self.config['SSL_WARNING_DAYS']).run_all()

        ip = self.config.get('CHECK_IP') or self._discover_ip(domain)
        if check_type in ['all', 'email']:
            res['email'] = EmailInfrastructureCheck(domain, ip, self.config.get('DKIM_SELECTORS', [])).run_all()
        if ip and check_type in ['all', 'blacklist']:
            res['blacklist'] = BlacklistCheck(ip, domain).run_all()
            res['blacklist']['ip_address'] = ip
        return domain, res

    def run(self, check_type: str = 'all') -> Dict[str, Any]:
        domain_file = self.config['DOMAIN_FILE']

        # Support reading from /tmp (Cloud Run writable dir) or bundled file
        if not os.path.isabs(domain_file):
            domain_file = os.path.join(os.path.dirname(__file__), domain_file)

        if not os.path.exists(domain_file):
            logger.error(f"Domain file not found: {domain_file}")
            return {}

        valid_domains = []
        try:
            with open(domain_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain = row.get('domain', '').strip()
                    if domain and self._is_valid(domain):
                        valid_domains.append(domain)
        except Exception as e:
            logger.error(f"Error reading domain file: {e}")
            return {}

        if not valid_domains:
            logger.error("No valid domains found in file.")
            return {}

        results = {}
        with ThreadPoolExecutor(max_workers=self.config['MAX_WORKERS']) as ex:
            futures = [ex.submit(self._process_domain, d, check_type) for d in valid_domains]
            for f in as_completed(futures):
                domain, domain_res = f.result()
                results[domain] = domain_res

        if self.config['ENABLE_EMAIL_ALERTS']:
            self._send_email(results)

        return results

    def _build_report_html(self, results: Dict[str, Any]) -> Tuple[str, list, list]:
        """
        Build the full detailed HTML report (used for both the PDF attachment
        and the inline email body).  Returns (html, issue_domains, healthy_domains).
        """
        help_url = self.config.get('HELP_GUIDE_URL', '')

        def add_row(label, status, details, fail):
            color = "color: red;" if fail else ""
            return (
                f"<tr style='{color}'>"
                f"<td>{label}</td><td>{status}</td><td>{details}</td>"
                f"</tr>"
            )

        issue_domains, healthy_domains = [], []
        for d, data in results.items():
            has_fail = False
            for cat in ['website', 'email']:
                for key, check in data.get(cat, {}).items():
                    if cat == 'email' and key == 'ptr':
                        continue
                    if isinstance(check, dict) and not check.get('status', True):
                        has_fail = True
            bl = data.get('blacklist', {})
            if (bl.get('ip', {}).get('listed') or
                    bl.get('domain', {}).get('listed') or
                    bl.get('email', {}).get('listed')):
                has_fail = True
            if has_fail:
                issue_domains.append((d, data))
            else:
                healthy_domains.append(d)

        html = f"""
        <html>
        <body style='font-family: sans-serif; color: #333;'>
            <div style='background: #f8f9fa; padding: 20px; border-radius: 8px;
                        margin-bottom: 20px; border: 1px solid #dee2e6;'>
                <h2 style='margin-top: 0;'>Domain Health Summary</h2>
                <p>
                    Checked: <b>{len(results)}</b> |
                    Issues: <span style='color: {"red" if issue_domains else "green"};
                                         font-weight: bold;'>{len(issue_domains)}</span> |
                    Healthy: <b>{len(healthy_domains)}</b>
                </p>
                {
                    f"<p style='color: red;'><b>Action Required:</b> "
                    f"Please review the {len(issue_domains)} domain(s) with issues below.</p>"
                    if issue_domains else
                    "<p style='color: green;'>All domains are healthy!</p>"
                }
                {
                    f"<p style='margin-top: 15px;'><b>Need help?</b> "
                    f"<a href='{help_url}' style='background: #007bff; color: white; "
                    f"padding: 10px 15px; text-decoration: none; border-radius: 4px; "
                    f"font-weight: bold; display: inline-block;'>"
                    f"View Troubleshooting Guide (PDF)</a></p>"
                    if help_url else ""
                }
            </div>
        """

        if issue_domains:
            html += "<h3>Domains with Issues</h3>"
            for d, data in issue_domains:
                web = data.get('website', {})
                mail = data.get('email', {})
                bl = data.get('blacklist', {})
                spam_risk, spam_reason = self._spam_risk_label(data)
                risk_color = {"Low": "green", "Medium": "#b36b00", "High": "red", "Not Checked": "#6c757d"}.get(spam_risk, "#333")

                html += (
                    f"<table border='1' cellpadding='8' "
                    f"style='border-collapse: collapse; width: 100%; margin-bottom: 20px;'>"
                    f"<tr style='background-color: #e9ecef;'>"
                    f"<td colspan='3'><b>{d}</b></td></tr>"
                )
                html += (
                    f"<tr><td><b>Spam Risk</b></td>"
                    f"<td><b style='color: {risk_color};'>{spam_risk}</b></td>"
                    f"<td>{spam_reason}</td></tr>"
                )

                dns_r = web.get('dns', {})
                html += add_row(
                    "DNS IP",
                    "YES" if dns_r.get('status') else "NO",
                    dns_r.get('details', 'N/A'),
                    not dns_r.get('status')
                )

                http = web.get('http', {})
                html += add_row(
                    "HTTP Status",
                    "YES" if http.get('status') else "NO",
                    f"{http.get('code', 'N/A')} (Response: {http.get('time', 'N/A')}s)",
                    not http.get('status')
                )

                ssl_r = web.get('ssl', {})
                html += add_row(
                    "SSL Certificate",
                    "YES" if ssl_r.get('status') else "NO",
                    f"Remaining: {ssl_r.get('details', 'N/A')} "
                    f"(Expires: {ssl_r.get('expiry', 'N/A')})",
                    not ssl_r.get('status')
                )

                sec = http.get('security', {})
                if sec:
                    miss = [h for h, p in sec.items() if not p]
                    html += add_row(
                        "Security Headers",
                        "PASS" if not miss else "WARN",
                        f"Found: {', '.join(h for h, p in sec.items() if p) or 'None'} | "
                        f"Missing: {', '.join(miss) or 'None'}",
                        bool(miss)
                    )

                if mail:
                    for label, key in [
                        ("MX Records", "mx"),
                        ("SPF Record", "spf"),
                        ("DMARC Record", "dmarc"),
                        ("DKIM Record", "dkim"),
                        ("PTR (Reverse DNS)", "ptr")
                    ]:
                        m = mail.get(key, {})
                        status = "SKIP" if m.get('skipped') else ("INFO" if key == "ptr" else ("YES" if m.get('status') else "NO"))
                        html += add_row(
                            label,
                            status,
                            m.get('details', 'N/A'),
                            key != "ptr" and not m.get('status') and not m.get('skipped')
                        )

                if bl:
                    for label, info in [
                        ("IP Blacklisted",     bl.get('ip', {})),
                        ("Domain Blacklisted", bl.get('domain', {})),
                        ("Email Blacklisted",  bl.get('email', {})),
                    ]:
                        is_bl = info.get('listed')
                        details = (
                            "Listed on: " + ", ".join(info.get('detected', []))
                            if is_bl else "Clean"
                        )
                        if "IP" in label:
                            details += f" (IP: {bl.get('ip_address', 'N/A')})"
                        html += add_row(label, "YES" if is_bl else "NO", details, is_bl)

                html += "</table>"

        if healthy_domains:
            html += "<h3 style='color: green;'>Healthy Domains</h3>"
            for d in healthy_domains:
                data = results[d]
                web = data.get('website', {})
                mail = data.get('email', {})
                bl = data.get('blacklist', {})
                spam_risk, spam_reason = self._spam_risk_label(data)
                risk_color = {"Low": "green", "Medium": "#b36b00", "High": "red", "Not Checked": "#6c757d"}.get(spam_risk, "#333")

                html += (
                    f"<table border='1' cellpadding='8' "
                    f"style='border-collapse: collapse; width: 100%; margin-bottom: 20px;'>"
                    f"<tr style='background-color: #d4edda;'>"
                    f"<td colspan='3'><b style='color: green;'>{d}</b></td></tr>"
                )

                html += (
                    f"<tr><td><b>Spam Risk</b></td>"
                    f"<td><b style='color: {risk_color};'>{spam_risk}</b></td>"
                    f"<td>{spam_reason}</td></tr>"
                )

                dns_r = web.get('dns', {})
                html += add_row("DNS IP", "YES" if dns_r.get('status') else "NO",
                                dns_r.get('details', 'N/A'), not dns_r.get('status'))

                http = web.get('http', {})
                html += add_row("HTTP Status", "YES" if http.get('status') else "NO",
                                f"{http.get('code', 'N/A')} (Response: {http.get('time', 'N/A')}s)",
                                not http.get('status'))

                ssl_r = web.get('ssl', {})
                html += add_row("SSL Certificate", "YES" if ssl_r.get('status') else "NO",
                                f"Remaining: {ssl_r.get('details', 'N/A')} "
                                f"(Expires: {ssl_r.get('expiry', 'N/A')})",
                                not ssl_r.get('status'))

                sec = http.get('security', {})
                if sec:
                    miss = [h for h, p in sec.items() if not p]
                    html += add_row("Security Headers", "PASS" if not miss else "WARN",
                                    f"Found: {', '.join(h for h, p in sec.items() if p) or 'None'} | "
                                    f"Missing: {', '.join(miss) or 'None'}",
                                    bool(miss))

                if mail:
                    for label, key in [("MX Records", "mx"), ("SPF Record", "spf"),
                                       ("DMARC Record", "dmarc"), ("DKIM Record", "dkim"),
                                       ("PTR (Reverse DNS)", "ptr")]:
                        m = mail.get(key, {})
                        status = "SKIP" if m.get('skipped') else ("INFO" if key == "ptr" else ("YES" if m.get('status') else "NO"))
                        html += add_row(label, status, m.get('details', 'N/A'),
                                        key != "ptr" and not m.get('status') and not m.get('skipped'))

                if bl:
                    for label, info in [("IP Blacklisted", bl.get('ip', {})),
                                        ("Domain Blacklisted", bl.get('domain', {})),
                                        ("Email Blacklisted", bl.get('email', {}))]:
                        is_bl = info.get('listed')
                        details = ("Listed on: " + ", ".join(info.get('detected', [])) if is_bl else "Clean")
                        if "IP" in label:
                            details += f" (IP: {bl.get('ip_address', 'N/A')})"
                        html += add_row(label, "YES" if is_bl else "NO", details, is_bl)

                html += "</table>"

        html += (
            f"<p style='color: grey; font-size: 0.8em; margin-top: 30px;'>"
            f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            f"</p></body></html>"
        )

        return html, issue_domains, healthy_domains

    def _send_email(self, results: Dict[str, Any]):
        if not self.config.get('APP_PASSWORD'):
            logger.warning("APP_PASSWORD not set, skipping email.")
            return

        help_url = self.config.get('HELP_GUIDE_URL', '')

        # ── Build full report HTML & derive summary counts ──────────────────
        report_html, issue_domains, healthy_domains = self._build_report_html(results)

        # ── Convert full report to PDF attachment ────────────────────────────
        pdf_data = convert_html_to_pdf(report_html)
        if not pdf_data:
            logger.warning("PDF generation failed — attaching HTML report instead.")

        # ── Compose message ──────────────────────────────────────────────────
        msg = MIMEMultipart('mixed')
        msg['Subject'] = f"Domain Health Report - {datetime.now().strftime('%Y-%m-%d')}"
        msg['From'] = f"Email Health Monitor <{self.config['EMAIL_FROM']}>"

        recipients = [r.strip() for r in str(self.config['EMAIL_TO']).split(',') if r.strip()]
        msg['To'] = ", ".join(recipients)
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = make_msgid()
        msg['MIME-Version'] = '1.0'
        msg['X-Mailer'] = 'Python-Email-Health-Monitor'

        # ── Concise plain-text fallback ──────────────────────────────────────
        plain_text = (
            f"Domain Health Monitoring Report Summary\n"
            f"Checked: {len(results)} | Issues: {len(issue_domains)} | "
            f"Healthy: {len(healthy_domains)}\n\n"
            f"Please see the attached PDF for the full report.\n"
            + (f"\nTroubleshooting Guide: {help_url}" if help_url else "")
        )

        # ── Brief HTML email body (summary + PDF note + help link) ───────────
        email_body_html = f"""
        <html>
        <body style='font-family: sans-serif; color: #333;'>
            <div style='background: #f8f9fa; padding: 20px; border-radius: 8px;
                        margin-bottom: 20px; border: 1px solid #dee2e6;'>
                <h2 style='margin-top: 0;'>Domain Health Summary</h2>
                <p>
                    Checked: <b>{len(results)}</b> |
                    Issues:
                    <span style='color: {"red" if issue_domains else "green"};
                                 font-weight: bold;'>{len(issue_domains)}</span> |
                    Healthy: <b>{len(healthy_domains)}</b>
                </p>
                {
                    f"<p style='color: red;'><b>Action Required:</b> "
                    f"{len(issue_domains)} domain(s) need attention. "
                    f"See the attached PDF for details.</p>"
                    if issue_domains else
                    "<p style='color: green;'>All domains are healthy! "
                    "Full report is attached as PDF.</p>"
                }
                <p>The detailed health report is attached as <b>Domain_Health_Report.pdf</b>.</p>
                {
                    f"<p style='margin-top: 15px;'><b>Need help?</b> "
                    f"<a href='{help_url}' style='background: #007bff; color: white; "
                    f"padding: 10px 15px; text-decoration: none; border-radius: 4px; "
                    f"font-weight: bold; display: inline-block;'>"
                    f"View Troubleshooting Guide (PDF)</a></p>"
                    if help_url else ""
                }
            </div>
            <p style='color: grey; font-size: 0.8em;'>
                Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </body>
        </html>
        """

        # Attach text/html alternative parts inside a multipart/alternative wrapper
        alt = MIMEMultipart('alternative')
        alt.attach(MIMEText(plain_text, 'plain'))
        alt.attach(MIMEText(email_body_html, 'html'))
        msg.attach(alt)

        # ── Attach PDF (or HTML fallback) ────────────────────────────────────
        if pdf_data:
            pdf_part = MIMEApplication(pdf_data, Name="Domain_Health_Report.pdf")
            pdf_part['Content-Disposition'] = 'attachment; filename="Domain_Health_Report.pdf"'
            msg.attach(pdf_part)
            logger.info("PDF report attached to email.")
        else:
            # Fallback: attach the raw HTML if xhtml2pdf failed
            html_part = MIMEApplication(
                report_html.encode('utf-8'), Name="Domain_Health_Report.html"
            )
            html_part['Content-Disposition'] = 'attachment; filename="Domain_Health_Report.html"'
            msg.attach(html_part)
            logger.info("HTML report attached to email (PDF generation failed).")

        # ── Send ─────────────────────────────────────────────────────────────
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.config['EMAIL_FROM'], self.config['APP_PASSWORD'])
                server.send_message(msg)
            logger.info("Email report sent successfully.")
        except Exception as e:
            logger.error(f"Email send failed: {e}")


# ──────────────────────────────────────────────
# Cloud Run Function Entry Points
# ──────────────────────────────────────────────

@functions_framework.http
def domain_monitor_http(request):
    """
    HTTP-triggered Cloud Run Function.
    Accepts optional query param: ?type=all|website|email|blacklist
    Example: https://<your-function-url>/?type=website
    """
    check_type = request.args.get('type', 'all')
    if check_type not in ['all', 'website', 'email', 'blacklist']:
        return {'error': f"Invalid type '{check_type}'. Use: all, website, email, blacklist"}, 400

    logger.info(f"Cloud Run triggered — check_type={check_type}")

    monitor = DomainMonitor(CONFIG)
    results = monitor.run(check_type)

    summary = {
        domain: {
            cat: {
                check: data.get('status', None)
                for check, data in checks.items()
                if isinstance(data, dict) and 'status' in data
            }
            for cat, checks in domain_data.items()
            if isinstance(checks, dict)
        }
        for domain, domain_data in results.items()
    }
    spam_risks = {
        domain: {
            'label': monitor._spam_risk_label(domain_data)[0],
            'reason': monitor._spam_risk_label(domain_data)[1],
        }
        for domain, domain_data in results.items()
    }

    total = len(results)
    issues = sum(
        1 for d in results.values()
        for cat in ['website', 'email']
        for key, chk in d.get(cat, {}).items()
        if not (cat == 'email' and key == 'ptr') and isinstance(chk, dict) and not chk.get('status', True)
    )

    return {
        'status': 'completed',
        'timestamp': datetime.now().isoformat(),
        'check_type': check_type,
        'total_domains': total,
        'domains_with_issues': issues,
        'spam_risks': spam_risks,
        'summary': summary
    }, 200


@functions_framework.cloud_event
def domain_monitor_scheduled(cloud_event):
    """
    Cloud Scheduler (Pub/Sub) triggered function.
    Deploy this for scheduled runs (e.g., daily at 8 AM).
    """
    logger.info("Scheduled Cloud Run triggered.")
    monitor = DomainMonitor(CONFIG)
    monitor.run('all')
    logger.info("Scheduled run complete.")

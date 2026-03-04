import socket
import ssl
import requests
import smtplib
import sys
import argparse
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import dns.resolver
import dns.exception

# =====================
# CONFIGURATION
# =====================

CONFIG = {
    'DOMAIN': 'solaceinfotech.co.in',
    'URL': 'https://edureka.com',
    'CHECK_EMAIL': 'broadcast@solaceinfotech.co.in',
    'CHECK_IP': '192.168.1.1',
    'EMAIL_FROM': 'dhirajrajputsolace@gmail.com',
    'EMAIL_TO': 'rihasoft2@gmail.com',
    'APP_PASSWORD': 'xblm cynl ctqj mmqn',
    'SSL_WARNING_DAYS': 15,
    'ENABLE_EMAIL_ALERTS': True,
    'VERBOSE': True,
}

# Major SMTP Blacklists
BLACKLIST_DATABASES = {
    'BARRACUDA': 'b.barracudacentral.org',
    'SPAMHAUS_ZEN': 'zen.spamhaus.org',
    'SPAMHAUS_SBL': 'sbl.spamhaus.org',
    'SPAMHAUS_CSS': 'css.spamhaus.org',
    'SPAMHAUS_PBL': 'pbl.spamhaus.org',
    'SORBS_SMTP': 'smtp.dnsbl.sorbs.net',
    'SORBS_HTTP': 'http.dnsbl.sorbs.net',
    'SORBS_MISC': 'misc.dnsbl.sorbs.net',
    'UCEPROTECT': 'dnsbl.uceprotect.net',
    'DNSWL': 'list.dnswl.org',
    'SENDERSCORE': 'bl.senderscore.net',
    'PSBL': 'psbl.surriel.com',
    'AHBL': 'ahbl.org',
    'MAILSPIKE': 'bl.mailspike.net',
    'LASHBACK': 'blacklist.lashback.com',
    'SPAMCOP': 'bl.spamcop.net',
    'CBL': 'cbl.abuseat.org',
    'PSBL': 'psbl.surriel.com',
    'MANITU': 'ix.dnsbl.manitu.net',
    'SPAMRATS': 'spam.spamrats.com',
    'SEM_FRESH': 'fresh.spameatingmonkey.net',
    'ABUSE_RO': 'dnsbl.abuse.ro',
    'BLOCKLIST_DE': 'bl.blocklist.de',
    'ZAPBL': 'dnsbl.zapbl.net',
    'UCEPROTECT_1': 'dnsbl-1.uceprotect.net'
}

class WebsiteHealthCheck:
    """Check website DNS, HTTP, and SSL status"""

    def __init__(self, domain, url, ssl_warning_days=15, verbose=True):
        self.domain = domain
        self.url = url
        self.ssl_warning_days = ssl_warning_days
        self.verbose = verbose
        self.results = {}

    def check_dns(self):
        """Check DNS resolution"""
        try:
            ip = socket.gethostbyname(self.domain)
            if self.verbose:
                print(f"✓ DNS OK: {self.domain} → {ip}")
            self.results['dns'] = {'status': True, 'details': ip}
            return True, ip
        except socket.gaierror as e:
            if self.verbose:
                print(f"✗ DNS FAILED: {e}")
            self.results['dns'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def check_http(self):
        """Check HTTP status"""
        try:
            response = requests.get(self.url, timeout=5)
            if self.verbose:
                print(f"✓ HTTP Status: {response.status_code}")
            self.results['http'] = {'status': response.status_code == 200, 'details': response.status_code}
            return response.status_code == 200, response.status_code
        except requests.RequestException as e:
            if self.verbose:
                print(f"✗ HTTP FAILED: {e}")
            self.results['http'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def check_ssl(self):
        """Check SSL certificate validity"""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry = datetime.strptime(
                        cert['notAfter'],
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)

                    now = datetime.now(timezone.utc)
                    remaining_days = (expiry - now).days

                    if self.verbose:
                        print(f"✓ SSL Certificate Valid")
                        print(f"  Expiry: {expiry.strftime('%B %d, %Y')}")
                        print(f"  Days Remaining: {remaining_days}")

                    is_valid = remaining_days > self.ssl_warning_days
                    self.results['ssl'] = {'status': is_valid, 'details': f"{remaining_days} days"}
                    return is_valid, expiry.strftime('%B %d, %Y')

        except Exception as e:
            if self.verbose:
                print(f"✗ SSL FAILED: {e}")
            self.results['ssl'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def run_all(self):
        """Run all website checks"""
        print("\n" + "=" * 70)
        print("🔧 WEBSITE HEALTH CHECKS")
        print("=" * 70)

        dns_ok, dns_detail = self.check_dns()
        http_ok, http_detail = self.check_http()
        ssl_ok, ssl_detail = self.check_ssl()

        return {
            'dns': dns_ok,
            'http': http_ok,
            'ssl': ssl_ok,
            'all_passed': dns_ok and http_ok and ssl_ok,
            'results': self.results
        }


# =====================
# 2️⃣ EMAIL INFRASTRUCTURE CHECKS
# =====================

class EmailInfrastructureCheck:
    """Check email authentication records (MX, SPF, DMARC, PTR)"""

    def __init__(self, domain, ip, verbose=True):
        self.domain = domain
        self.ip = ip
        self.verbose = verbose
        self.results = {}

    def check_mx(self):
        """Check MX records"""
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            mx_list = [(mx.preference, str(mx.exchange).rstrip('.')) for mx in mx_records]
            mx_list.sort(key=lambda x: x[0])

            if self.verbose:
                print(f"✓ MX Records Found ({len(mx_list)} servers):")
                for priority, server in mx_list:
                    print(f"  [{priority}] {server}")

            self.results['mx'] = {'status': len(mx_list) > 0, 'details': mx_list}
            return len(mx_list) > 0, mx_list
        except Exception as e:
            if self.verbose:
                print(f"✗ MX FAILED: {e}")
            self.results['mx'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def check_spf(self):
        """Check SPF record"""
        try:
            spf_records = dns.resolver.resolve(self.domain, 'TXT')
            spf_record = None
            for record in spf_records:
                if 'v=spf1' in str(record):
                    spf_record = str(record).strip('"')
                    break

            if spf_record:
                if self.verbose:
                    print(f"✓ SPF Record Found:")
                    print(f"  {spf_record}")
                self.results['spf'] = {'status': True, 'details': spf_record}
                return True, spf_record
            else:
                if self.verbose:
                    print(f"✗ SPF Record NOT Found")
                self.results['spf'] = {'status': False, 'details': 'No SPF record'}
                return False, "No SPF record found"
        except Exception as e:
            if self.verbose:
                print(f"✗ SPF FAILED: {e}")
            self.results['spf'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def check_dmarc(self):
        """Check DMARC record"""
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_record = None
            for record in dmarc_records:
                if 'v=DMARC1' in str(record):
                    dmarc_record = str(record).strip('"')
                    break

            if dmarc_record:
                policy = "reject" if "p=reject" in dmarc_record else "quarantine" if "p=quarantine" in dmarc_record else "none"
                if self.verbose:
                    print(f"✓ DMARC Record Found:")
                    print(f"  Policy: {policy.upper()}")
                    print(f"  {dmarc_record}")
                self.results['dmarc'] = {'status': True, 'details': dmarc_record}
                return True, dmarc_record
            else:
                if self.verbose:
                    print(f"✗ DMARC Record NOT Found")
                self.results['dmarc'] = {'status': False, 'details': 'No DMARC record'}
                return False, "No DMARC record found"
        except Exception as e:
            if self.verbose:
                print(f"✗ DMARC FAILED: {e}")
            self.results['dmarc'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def check_ptr(self):
        """Check PTR records (Reverse DNS)"""
        try:
            octets = self.ip.split('.')
            reversed_ip = '.'.join(reversed(octets)) + '.in-addr.arpa'
            ptr_records = dns.resolver.resolve(reversed_ip, 'PTR')

            ptr_list = [str(ptr).rstrip('.') for ptr in ptr_records]

            if self.verbose:
                print(f"✓ PTR Records Found (Reverse DNS for {self.ip}):")
                for hostname in ptr_list:
                    print(f"  {hostname}")

            self.results['ptr'] = {'status': len(ptr_list) > 0, 'details': ptr_list}
            return len(ptr_list) > 0, ptr_list
        except Exception as e:
            if self.verbose:
                print(f"⚠️  PTR Record NOT Found: {e}")
            self.results['ptr'] = {'status': False, 'details': str(e)}
            return False, str(e)

    def run_all(self):
        """Run all email infrastructure checks"""
        print("\n" + "=" * 70)
        print("📧 EMAIL INFRASTRUCTURE CHECKS")
        print("=" * 70)

        mx_ok, mx_detail = self.check_mx()
        spf_ok, spf_detail = self.check_spf()
        dmarc_ok, dmarc_detail = self.check_dmarc()
        ptr_ok, ptr_detail = self.check_ptr()

        return {
            'mx': mx_ok,
            'spf': spf_ok,
            'dmarc': dmarc_ok,
            'ptr': ptr_ok,
            'all_passed': mx_ok and spf_ok and dmarc_ok and ptr_ok,
            'results': self.results
        }


# =====================
# 3️⃣ BLACKLIST CHECKS
# =====================

class BlacklistCheck:
    """Check IP against multiple blacklist databases"""

    def __init__(self, ip, verbose=True):
        self.ip = ip
        self.verbose = verbose
        self.results = {}

    def check_blacklists(self):
        """Check IP against all blacklist databases"""
        listed = False
        blacklists_detected = []
        clean_lists = []

        octets = self.ip.split('.')
        reversed_ip = '.'.join(reversed(octets))

        for bl_name, bl_host in BLACKLIST_DATABASES.items():
            try:
                query = f"{reversed_ip}.{bl_host}"
                response = dns.resolver.resolve(query, 'A')

                if 'dnswl' in bl_host.lower():
                    if self.verbose:
                        print(f"✓ {bl_name:20} - ✓ WHITELISTED")
                    clean_lists.append(bl_name)
                else:
                    if self.verbose:
                        print(f"✗ {bl_name:20} - ⚠️  LISTED")
                    listed = True
                    blacklists_detected.append(bl_name)

            except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.exception.Timeout):
                if self.verbose:
                    print(f"✓ {bl_name:20} - ✓ CLEAN")
                clean_lists.append(bl_name)
            except Exception as e:
                if self.verbose:
                    print(f"⚠️  {bl_name:20} - Error: {str(e)[:30]}")

        self.results['blacklists_detected'] = blacklists_detected
        self.results['clean_lists'] = clean_lists

        return {
            'ip': self.ip,
            'listed': listed,
            'blacklists_detected': blacklists_detected,
            'clean_lists': clean_lists,
            'total_checked': len(BLACKLIST_DATABASES)
        }

    def check_smtp_validation(self, email):
        """Validate email via SMTP"""
        domain = email.split('@')[1]

        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            if not mx_records:
                return False, "No MX records"

            mx_host = str(mx_records[0].exchange).rstrip('.')

            try:
                smtp = smtplib.SMTP(mx_host, 25, timeout=10)
                smtp.ehlo()

                try:
                    response = smtp.verify(email)
                    smtp.quit()
                    return response[0] == 250, "Email valid" if response[0] == 250 else "Email invalid"
                except smtplib.SMTPNotSupported:
                    smtp.quit()
                    return None, "VRFY not supported"
            except Exception as e:
                return False, str(e)
        except Exception as e:
            return False, str(e)

    def run_all(self):
        """Run all blacklist checks"""
        print("\n" + "=" * 70)
        print("🔍 EMAIL BLACKLIST & REPUTATION CHECKS")
        print("=" * 70)
        print(f"Checking {len(BLACKLIST_DATABASES)} blacklist databases...\n")

        blacklist_results = self.check_blacklists()

        print(
            f"\nResults: {len(blacklist_results['blacklists_detected'])} blacklists, {len(blacklist_results['clean_lists'])} clean")

        return blacklist_results


# =====================
# EMAIL ALERTING
# =====================

class EmailAlerts:
    """Send comprehensive HTML email reports"""

    def __init__(self, email_from, email_to, app_password, verbose=True):
        self.email_from = email_from
        self.email_to = email_to
        self.app_password = app_password
        self.verbose = verbose

    def send_report(self, all_results):
        """Send comprehensive email report"""
        try:
            if "your-email@gmail.com" in self.email_from or "your-16-char" in self.app_password:
                if self.verbose:
                    print("⚠️  Email not configured. Skipping email alert.")
                return False

            # Build HTML report
            website_results = all_results.get('website', {})
            email_results = all_results.get('email', {})
            blacklist_results = all_results.get('blacklist', {})

            html_body = self._build_html(website_results, email_results, blacklist_results)
            text_body = self._build_text(website_results, email_results, blacklist_results)

            # Create email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = "📊 Domain & Email Monitoring Report"
            msg['From'] = self.email_from
            msg['To'] = self.email_to

            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))

            # Send
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.email_from, self.app_password)
                server.send_message(msg)

            if self.verbose:
                print("\n✓ Email report sent successfully!")
            return True
        except Exception as e:
            if self.verbose:
                print(f"\n✗ Email failed: {e}")
            return False

    def _build_html(self, website_results, email_results, blacklist_results):
        """Build HTML email body"""
        domain = CONFIG['DOMAIN']

        return f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>📊 Domain & Email Monitoring Report</h2>
                <p><strong>Report Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

                <h3>🔧 Website Health</h3>
                <table border="1" cellpadding="10">
                    <tr><td><strong>Check</strong></td><td><strong>Status</strong></td></tr>
                    <tr><td>DNS</td><td>{'✓ PASS' if website_results.get('dns') else '✗ FAIL'}</td></tr>
                    <tr><td>HTTP</td><td>{'✓ PASS' if website_results.get('http') else '✗ FAIL'}</td></tr>
                    <tr><td>SSL</td><td>{'✓ PASS' if website_results.get('ssl') else '✗ FAIL'}</td></tr>
                </table>

                <h3>📧 Email Infrastructure</h3>
                <table border="1" cellpadding="10">
                    <tr><td><strong>Check</strong></td><td><strong>Status</strong></td></tr>
                    <tr><td>MX Records</td><td>{'✓ PASS' if email_results.get('mx') else '✗ FAIL'}</td></tr>
                    <tr><td>SPF</td><td>{'✓ PASS' if email_results.get('spf') else '✗ FAIL'}</td></tr>
                    <tr><td>DMARC</td><td>{'✓ PASS' if email_results.get('dmarc') else '✗ FAIL'}</td></tr>
                    <tr><td>PTR</td><td>{'✓ PASS' if email_results.get('ptr') else '✗ FAIL'}</td></tr>
                </table>

                <h3>🔍 IP Blacklist Status</h3>
                <p><strong>Listed on:</strong> {len(blacklist_results.get('blacklists_detected', []))} blacklist(s)</p>
                <p><strong>Clean:</strong> {len(blacklist_results.get('clean_lists', []))} list(s)</p>

                <hr>
                <p style="color: #999; font-size: 12px;">
                    This is an automated report from your domain monitoring system.
                </p>
            </body>
        </html>
        """

    def _build_text(self, website_results, email_results, blacklist_results):
        """Build plain text email body"""
        return f"""
DOMAIN & EMAIL MONITORING REPORT
================================

Report Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

WEBSITE HEALTH:
  DNS:  {'PASS' if website_results.get('dns') else 'FAIL'}
  HTTP: {'PASS' if website_results.get('http') else 'FAIL'}
  SSL:  {'PASS' if website_results.get('ssl') else 'FAIL'}

EMAIL INFRASTRUCTURE:
  MX:    {'PASS' if email_results.get('mx') else 'FAIL'}
  SPF:   {'PASS' if email_results.get('spf') else 'FAIL'}
  DMARC: {'PASS' if email_results.get('dmarc') else 'FAIL'}
  PTR:   {'PASS' if email_results.get('ptr') else 'FAIL'}

BLACKLIST STATUS:
  Listed on: {len(blacklist_results.get('blacklists_detected', []))} blacklist(s)
  Clean: {len(blacklist_results.get('clean_lists', []))} list(s)
"""


# =====================
# MAIN ORCHESTRATOR
# =====================

class DomainMonitor:
    """Main orchestrator for all monitoring tasks"""

    def __init__(self, config):
        self.config = config

    def run_all_checks(self, check_types='all'):
        """Run all or selected checks"""
        print("\n" + "=" * 70)
        print("🔍 COMPLETE DOMAIN & EMAIL MONITORING SUITE")
        print("=" * 70)
        print(f"Domain: {self.config['DOMAIN']}")
        print(f"Email: {self.config['CHECK_EMAIL']}")
        print(f"IP: {self.config['CHECK_IP']}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        results = {}

        # Website checks
        if check_types in ['all', 'website']:
            website_check = WebsiteHealthCheck(
                self.config['DOMAIN'],
                self.config['URL'],
                self.config['SSL_WARNING_DAYS'],
                self.config['VERBOSE']
            )
            results['website'] = website_check.run_all()

        # Email infrastructure checks
        if check_types in ['all', 'email']:
            email_check = EmailInfrastructureCheck(
                self.config['DOMAIN'],
                self.config['CHECK_IP'],
                self.config['VERBOSE']
            )
            results['email'] = email_check.run_all()

        # Blacklist checks
        if check_types in ['all', 'blacklist']:
            blacklist_check = BlacklistCheck(
                self.config['CHECK_IP'],
                self.config['VERBOSE']
            )
            results['blacklist'] = blacklist_check.run_all()

        # Print summary
        self._print_summary(results)

        # Send email if configured
        if self.config['ENABLE_EMAIL_ALERTS']:
            alerter = EmailAlerts(
                self.config['EMAIL_FROM'],
                self.config['EMAIL_TO'],
                self.config['APP_PASSWORD'],
                self.config['VERBOSE']
            )
            alerter.send_report(results)

        print("\n" + "=" * 70 + "\n")

        return results

    def _print_summary(self, results):
        """Print comprehensive summary"""
        print("\n" + "=" * 70)
        print("📊 SUMMARY")
        print("=" * 70)

        if 'website' in results:
            web = results['website']
            print("\nWebsite Health:")
            print(f"  DNS:  {'✓ PASS' if web.get('dns') else '✗ FAIL'}")
            print(f"  HTTP: {'✓ PASS' if web.get('http') else '✗ FAIL'}")
            print(f"  SSL:  {'✓ PASS' if web.get('ssl') else '✗ FAIL'}")

        if 'email' in results:
            email = results['email']
            print("\nEmail Infrastructure:")
            print(f"  MX:    {'✓ PASS' if email.get('mx') else '✗ FAIL'}")
            print(f"  SPF:   {'✓ PASS' if email.get('spf') else '✗ FAIL'}")
            print(f"  DMARC: {'✓ PASS' if email.get('dmarc') else '✗ FAIL'}")
            print(f"  PTR:   {'✓ PASS' if email.get('ptr') else '✗ FAIL'}")

        if 'blacklist' in results:
            bl = results['blacklist']
            print("\nBlacklist Status:")
            print(f"  Listed on: {len(bl.get('blacklists_detected', []))} blacklist(s)")
            print(f"  Clean: {len(bl.get('clean_lists', []))} list(s)")
            if bl.get('blacklists_detected'):
                print(f"  ⚠️  WARNING: Listed on: {', '.join(bl['blacklists_detected'][:3])}")

        print("\n" + "=" * 70)


# =====================
# CLI INTERFACE
# =====================

def main():
    """Main entry point with command-line interface"""

    parser = argparse.ArgumentParser(
        description='Complete Domain & Email Monitoring Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python all_in_one_monitor.py                      # Run all checks
  python all_in_one_monitor.py --type website       # Website only
  python all_in_one_monitor.py --type email         # Email infrastructure only
  python all_in_one_monitor.py --type blacklist     # Blacklist check only
  python all_in_one_monitor.py --domain example.com # Custom domain
  python all_in_one_monitor.py --verbose false      # Quiet mode
        """
    )

    parser.add_argument('--domain', help='Domain to check', default=CONFIG['DOMAIN'])
    parser.add_argument('--url', help='Full URL to check', default=CONFIG['URL'])
    parser.add_argument('--email', help='Email to check', default=CONFIG['CHECK_EMAIL'])
    parser.add_argument('--ip', help='IP address to check', default=CONFIG['CHECK_IP'])
    parser.add_argument('--type', dest='check_type', choices=['all', 'website', 'email', 'blacklist'],
                        default='all', help='Type of check to run')
    parser.add_argument('--verbose', choices=['true', 'false'], default='true', help='Verbose output')
    parser.add_argument('--send-email', choices=['true', 'false'], default='true', help='Send email alerts')

    args = parser.parse_args()

    # Update config
    CONFIG['DOMAIN'] = args.domain
    CONFIG['URL'] = args.url
    CONFIG['CHECK_EMAIL'] = args.email
    CONFIG['CHECK_IP'] = args.ip
    CONFIG['VERBOSE'] = args.verbose.lower() == 'true'
    CONFIG['ENABLE_EMAIL_ALERTS'] = args.send_email.lower() == 'true'

    # Run monitor
    monitor = DomainMonitor(CONFIG)
    results = monitor.run_all_checks(args.check_type)
    return results

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
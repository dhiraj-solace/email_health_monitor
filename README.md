# Enterprise Email & Domain Health Monitor
A high-performance, parallelized monitoring tool designed to track the health, security, and infrastructure of multiple domains and subdomains simultaneously.

## 🚀 Key Features
- **Parallel Domain Monitoring**: Processes multiple domains concurrently using multi-threading for maximum speed.
- **Dynamic IP Discovery**: Automatically resolves mail server IPs via MX records—no manual IP entry required.
- **Website Health Checks**: Monitors DNS resolution, HTTP status (200 OK), and SSL certificate expiration.
- **Security Analysis**: Inspects critical security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
- **Email Infrastructure Checks**: Validates MX, SPF, DMARC, and PTR (Reverse DNS) records.
- **Advanced Blacklist Monitoring**: Cross-references mail server IPs against 20+ global DNSBL databases and reports specific blacklist names.
- **Detailed Tiered Reporting**: Professional HTML email reports and a clean terminal summary with performance metrics (load speeds).
- **Robust Input Validation**: Automatically skips malformed entries in the domain list.
- **Fail-Fast Configuration**: Dedicated validation ensuring all environment variables are correctly set before execution.

## 🛠️ Prerequisites

- Python 3.x
- pip (Python package installer)

## 📦 Installation

1. Clone or download the project repository.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: Requirements include `requests`, `python-dotenv`, and `dnspython`)*

## ⚙️ Configuration

1. **Environment Variables**: Create a `.env` file in the root directory (use `.env.example` as a template):
   ```ini
   # Email Credentials
   EMAIL_FROM=your-email@gmail.com
   EMAIL_TO=recipient-email@gmail.com
   APP_PASSWORD=your-google-app-password
   ENABLE_EMAIL_ALERTS=True

   # General Settings
   SSL_WARNING_DAYS=15
   VERBOSE=True
   DOMAIN_FILE=domains.txt
   MAX_WORKERS=10
   ```

2. **Domain List**: Add the domains and subdomains you want to monitor to `domains.txt` (one per line):
   ```text
   example.com
   sub.example.com
   company.co.in
   ```

## 🚀 Usage

Run the monitor using Python:

```bash
# Run all checks for all domains
python main.py

# Run specific check types
python main.py --type website
python main.py --type email
python main.py --type blacklist
```

## 📂 Project Structure
- `main.py`: Core monitoring logic and orchestration.
- `config.py`: Configuration loading and requirement validation.
- `domains.txt`: List of domains to be monitored.
- `.env`: Secret configuration and credentials (not committed to version control).
- `.env.example`: Template for creating the `.env` file.

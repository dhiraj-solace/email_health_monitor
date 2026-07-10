import os
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

CONFIG = {
    'EMAIL_FROM': os.getenv('EMAIL_FROM'),
    'EMAIL_TO': os.getenv('EMAIL_TO'),
    'APP_PASSWORD': os.getenv('APP_PASSWORD'),
    'SSL_WARNING_DAYS': int(os.getenv('SSL_WARNING_DAYS', 15)),
    'ENABLE_EMAIL_ALERTS': os.getenv('ENABLE_EMAIL_ALERTS', 'True').lower() == 'true',
    'VERBOSE': os.getenv('VERBOSE', 'True').lower() == 'true',
    'DOMAIN_FILE': os.getenv('DOMAIN_FILE', 'domains.csv'),
    'CHECK_IP': os.getenv('CHECK_IP'),
    'MAX_WORKERS': int(os.getenv('MAX_WORKERS', 10)),
    'DKIM_SELECTORS': [
        selector.strip()
        for selector in os.getenv('DKIM_SELECTORS', 'selector1,selector2,google,default,hostingermail1,hostingermail2').split(',')
        if selector.strip()
    ]
}

BLACKLIST_IP = {
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
    'MANITU': 'ix.dnsbl.manitu.net',
    'SPAMRATS': 'spam.spamrats.com',
    'SEM_FRESH': 'fresh.spameatingmonkey.net',
    'ABUSE_RO': 'dnsbl.abuse.ro',
    'BLOCKLIST_DE': 'bl.blocklist.de',
    'ZAPBL': 'dnsbl.zapbl.net',
    'UCEPROTECT_1': 'dnsbl-1.uceprotect.net'
}

BLACKLIST_DOMAIN = {
    'SPAMHAUS_DBL': 'dbl.spamhaus.org',
    'SURBL_MULTI': 'multi.surbl.org',
    'URIBL_BLACK': 'black.uribl.com'
}

BLACKLIST_EMAIL = {
    'URIBL_BLACK': 'black.uribl.com',
    'DBL_SPAMHAUS': 'dbl.spamhaus.org'
}

def validate_config():
    """Verify all required configuration parameters are present."""
    required = ['EMAIL_FROM', 'EMAIL_TO']
    if CONFIG['ENABLE_EMAIL_ALERTS']:
        required.append('APP_PASSWORD')
    
    missing = []
    for field in required:
        val = str(CONFIG.get(field, '')).strip()
        if not val:
            missing.append(field)
    
    if missing:
        logger.error(f"CRITICAL - Missing required environment variables: {', '.join(missing)}")
        print(f"\n[!] ERROR: Missing configuration in .env: {', '.join(missing)}")
        return False
        
    if not os.path.exists(CONFIG['DOMAIN_FILE']):
        logger.error(f"CRITICAL - Domain file not found: {CONFIG['DOMAIN_FILE']}")
        print(f"\n[!] ERROR: Domain file '{CONFIG['DOMAIN_FILE']}' not found.")
        return False
        
    return True

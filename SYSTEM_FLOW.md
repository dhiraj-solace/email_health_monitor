# Email & Domain Health Monitor - What We Check

This system checks the important health, security, and email reputation points for each domain. It helps find problems early before they affect website visitors, business emails, or customer trust.

## Checks Covered

| What We Check | Why We Check It | How The System Checks It |
| --- | --- | --- |
| Domain availability | To confirm the domain is active and reachable. | The system checks whether the domain can be found on the internet and returns a valid server address. |
| Website response | To confirm the website is opening properly. | The system opens the website using HTTPS and checks if it responds successfully. |
| Website speed | To identify slow-loading websites. | The system records how many seconds the website takes to respond. |
| SSL certificate | To avoid browser security warnings and expired certificate issues. | The system checks the website certificate expiry date and warns if it is close to expiry. |
| Security headers | To review basic website protection settings. | The system checks for common browser security protections such as secure transport, content protection, frame protection, and content-type protection. |
| Mail server records | To confirm the domain is ready to receive emails. | The system checks whether mail server records are available for the domain. |
| SPF record | To reduce the chance of fake emails being sent using the domain name. | The system checks whether the domain has sender verification configured. |
| DMARC record | To improve email trust and protect against spoofing. | The system checks whether the domain has an email protection policy configured. |
| Reverse DNS | To support better email delivery reputation. | The system checks whether the mail server IP points back to a valid name. |
| Mail server IP discovery | To find the correct server used for email checks. | The system automatically finds the mail server IP from the domain's mail setup. |
| IP blacklist status | To know if the mail server IP may be blocked by spam filters. | The system checks the mail server IP against multiple blacklist databases. |
| Domain blacklist status | To know if the domain itself has been flagged. | The system checks the domain against common domain blacklist databases. |
| Email reputation blacklist status | To find issues that may affect inbox delivery. | The system checks email-related blacklist sources for the domain. |

## Final Output

After all checks are completed, the system gives:

- A quick terminal summary for the technical team.
- A clear email summary for stakeholders.
- A detailed PDF report showing healthy domains and domains needing attention.
- Specific warning details, such as SSL expiry, missing email records, slow response, or blacklist listing.

## Simple Client Explanation

In simple terms, the system checks whether your domain is reachable, your website is secure, your email setup is correct, and your email reputation is clean. If anything looks risky, it highlights the issue and sends a report so the team can take action quickly.

## If Emails Are Going To Spam

If the client says emails from the domain are landing in spam, we need to check the possible reasons behind it. The system helps with many of these checks, but spam placement also depends on Gmail, Outlook, Yahoo, and the recipient's mailbox rules.

| What We Check | Why Emails May Go To Spam | How We Check It |
| --- | --- | --- |
| SPF setup | If SPF is missing or wrong, mail providers may not trust the sender. | We check whether the domain has a valid sender verification record. |
| DMARC setup | If DMARC is missing or weak, fake emails can be sent using the domain name. | We check whether the domain has an email protection policy. |
| Mail server records | If mail records are wrong, email providers may treat the domain as suspicious. | We check whether the domain has correct mail server records. |
| Reverse DNS | If the sending server does not identify itself properly, emails may be filtered. | We check whether the sending IP has a proper reverse lookup. |
| IP blacklist status | If the mail server IP is listed as spam, emails may go directly to spam. | We check the IP against multiple blacklist databases. |
| Domain blacklist status | If the domain has a bad reputation, emails may be blocked or filtered. | We check the domain against blacklist databases. |
| Email reputation blacklist status | If email reputation sources flag the domain, delivery can be affected. | We check email-related blacklist databases. |
| SSL and domain health | A poorly maintained domain can reduce trust signals. | We check website availability, SSL certificate, and basic security status. |

## Extra Checks Needed For Full Spam Investigation

Some spam reasons cannot be confirmed only by domain monitoring. For a complete investigation, we should also check:

- DKIM record and email signature setup.
- Whether SPF, DKIM, and DMARC are properly aligned.
- Actual email headers from a message that landed in spam.
- Bounce reports or rejection messages from Gmail, Outlook, or other providers.
- Sending volume and sudden spikes in email activity.
- Email content, links, attachments, and subject lines.
- Whether users are marking emails as spam.
- Google Postmaster Tools or Microsoft sender reputation data, if available.
- Test emails sent to Gmail, Outlook, Yahoo, and other inboxes to confirm placement.

## Client-Friendly Answer

We can check whether the domain and mail server are technically trusted by email providers. This includes email authentication, blacklist status, mail server setup, and domain health. If emails are still going to spam after these checks, we then review real email samples, sender reputation tools, and inbox placement tests to find the exact reason.

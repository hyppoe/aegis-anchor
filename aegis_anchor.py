# ==============================================================================
# AEGISANCHOR: LOCAL BUSINESS CYBERSECURITY AUDIT TOOL
# This script performs simple, non-intrusive security checks on any public website.
# ==============================================================================

import os
import ssl
import socket
import logging
from urllib.parse import urlparse
from datetime import datetime, timezone
import dns.resolver
import certifi

# Suppress xhtml2pdf internal warnings in console output
logging.getLogger("xhtml2pdf").setLevel(logging.ERROR)

# Third-party module imports with safe fallback checks
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import markdown
    from xhtml2pdf import pisa
    HAS_PDF_LIBS = True
except ImportError:
    HAS_PDF_LIBS = False

# Force default HTTPS connections to use certifi's trusted CA bundle
ssl._create_default_https_context = lambda: ssl.create_default_context(cafile=certifi.where())


# ------------------------------------------------------------------------------
# HELPER FUNCTION: Clean up messy inputs
# ------------------------------------------------------------------------------
def clean_domain(raw_input):
    cleaned = raw_input.strip()
    
    if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
        cleaned = "https://" + cleaned
    
    parsed = urlparse(cleaned)
    hostname = parsed.hostname or ""
    
    domain_parts = hostname.split('.')
    if len(domain_parts) >= 2:
        root_domain = ".".join(domain_parts[-2:])
    else:
        root_domain = hostname
        
    return hostname, root_domain


# ------------------------------------------------------------------------------
# MODULE 1: Check HTTPS / SSL Certificate Expiration
# ------------------------------------------------------------------------------
def check_ssl(hostname):
    print(f"\n[+] Checking SSL/TLS Certificate for: {hostname}")
    
    context = ssl.create_default_context(cafile=certifi.where())
    
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_date_str = cert['notAfter']
                expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z')
                expire_date_utc = expire_date.replace(tzinfo=timezone.utc)
                days_left = (expire_date_utc - datetime.now(timezone.utc)).days
                
                print(f"  [PASS] SSL Certificate is active and valid!")
                print(f"  [INFO] Certificate expires in {days_left} days ({expire_date.strftime('%Y-%m-%d')}).")
                return True
                
    except Exception as e:
        print(f"  [FAIL] SSL/TLS Issue detected: {e}")
        return False


# ------------------------------------------------------------------------------
# MODULE 2: Check HTTP Security Headers
# ------------------------------------------------------------------------------
def check_security_headers(hostname):
    print(f"\n[+] Inspecting HTTP Security Headers...")
    
    header_results = {
        'hsts': False,
        'x_frame': False,
        'x_content_type': False,
        'csp': False
    }

    if not HAS_REQUESTS:
        print("  [WARN] 'requests' module not found. Run 'pip install requests' in Terminal.")
        return header_results

    # Full modern browser headers to pass WAF inspection
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Upgrade-Insecure-Requests': '1'
    }

    targets = [f"https://www.{hostname}", f"https://{hostname}"]
    response_headers = None

    session = requests.Session()
    session.headers.update(headers)

    for target in targets:
        try:
            res = session.get(target, timeout=10, allow_redirects=True)
            if res.status_code < 500:
                response_headers = res.headers
                print(f"  [+] Connected successfully to: {res.url}")
                break
        except Exception:
            continue

    if response_headers is None:
        print("  [WARN] Target server or WAF dropped connection.")
        return header_results

    # Case-insensitive header lookup
    headers_lower = {k.lower(): v for k, v in response_headers.items()}

    if 'strict-transport-security' in headers_lower:
        header_results['hsts'] = True
        print("  [PASS] Strict-Transport-Security: Present")
    else:
        print("  [MISSING] Strict-Transport-Security: Not found.")

    if 'x-frame-options' in headers_lower:
        header_results['x_frame'] = True
        print("  [PASS] X-Frame-Options: Present")
    else:
        print("  [MISSING] X-Frame-Options: Not found.")

    if 'x-content-type-options' in headers_lower:
        header_results['x_content_type'] = True
        print("  [PASS] X-Content-Type-Options: Present")
    else:
        print("  [MISSING] X-Content-Type-Options: Not found.")

    if 'content-security-policy' in headers_lower:
        header_results['csp'] = True
        print("  [PASS] Content-Security-Policy: Present")
    else:
        print("  [MISSING] Content-Security-Policy: Not found.")

    return header_results


# ------------------------------------------------------------------------------
# MODULE 3: Check DNS Records for Email Security (SPF & DMARC)
# ------------------------------------------------------------------------------
def check_dns_security(root_domain):
    print(f"\n[+] Checking Email Security Records for domain: {root_domain}")
    
    dns_results = {
        'spf': False,
        'dmarc': False
    }

    # 1. Check SPF
    try:
        answers = dns.resolver.resolve(root_domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                dns_results['spf'] = True
                print(f"  [PASS] SPF Record found: {txt_record[:60]}...")
                break
                
        if not dns_results['spf']:
            print("  [MISSING] No valid SPF record found on root domain.")
            
    except Exception:
        print("  [MISSING] Unable to locate TXT/SPF records for email authentication.")

    # 2. Check DMARC
    dmarc_domain = f"_dmarc.{root_domain}"
    
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=DMARC1"):
                dns_results['dmarc'] = True
                print(f"  [PASS] DMARC Record found: {txt_record[:60]}...")
                break
                
        if not dns_results['dmarc']:
            print("  [MISSING] No valid DMARC record found at " + dmarc_domain)
            
    except Exception:
        print("  [MISSING] No DMARC record configured. Domain may be vulnerable to email spoofing.")

    return dns_results


# ------------------------------------------------------------------------------
# MODULE 4: Generate Executive Report (.md & .pdf)
# ------------------------------------------------------------------------------
def generate_executive_report(root_domain, results):
    today_date = datetime.now().strftime("%B %d, %Y")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Pads status code strings so columns align vertically
    def fmt_status(passed):
        return "`PASS`   " if passed else "`MISSING`"

    # Count missing controls
    missing_controls = [k for k, v in results.items() if not v]
    num_missing = len(missing_controls)

    # Determine overall risk posture based on worst vulnerability level
    has_high_vulnerability = (
        not results.get('hsts') or 
        not results.get('dmarc') or 
        not results.get('spf')
    )
    
    has_medium_vulnerability = (
        not results.get('x_frame') or 
        not results.get('x_content_type') or 
        not results.get('csp')
    )

    if has_high_vulnerability:
        overall_risk = "HIGH"
    elif has_medium_vulnerability:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    # Identify primary threat vectors
    threat_list = []
    if not results.get('hsts'):
        threat_list.append("SSL stripping")
    if not results.get('x_frame'):
        threat_list.append("clickjacking")
    if not results.get('csp'):
        threat_list.append("XSS")
    if not results.get('dmarc'):
        threat_list.append("email spoofing")

    main_threats = ", ".join(threat_list) if threat_list else "no major active vulnerabilities identified"

    # Dynamically build Priority 1 Remediation Items (Sub-bullets indented by 4 spaces)
    p1_items = []
    if not results.get('dmarc'):
        p1_items.append(
            f"* DMARC Policy Configuration:\n"
            f"    * Goal: Stop unauthorized email spoofing.\n"
            f"    * Recommended Value: `v=DMARC1; p=none; rua=mailto:dmarc-reports@{root_domain};`"
        )
    if not results.get('hsts'):
        p1_items.append(
            f"* Strict Transport Security (HSTS):\n"
            f"    * Goal: Enforce HTTPS across all subdomains.\n"
            f"    * Recommended Value: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`"
        )

    # Dynamically build Priority 2 Remediation Items (Sub-bullets indented by 4 spaces)
    p2_items = []
    if not results.get('spf'):
        p2_items.append(
            f"* Sender Policy Framework (SPF):\n"
            f"    * Goal: Restrict authorized outbound mail servers.\n"
            f"    * Recommended Value: `v=spf1 mx ~all`"
        )
    if not results.get('x_frame'):
        p2_items.append(
            f"* X-Frame-Options Header:\n"
            f"    * Goal: Prevent clickjacking framing.\n"
            f"    * Recommended Value: `X-Frame-Options: SAMEORIGIN`"
        )
    if not results.get('x_content_type'):
        p2_items.append(
            f"* X-Content-Type-Options Header:\n"
            f"    * Goal: Enforce strict content MIME types.\n"
            f"    * Recommended Value: `X-Content-Type-Options: nosniff`"
        )
    if not results.get('csp'):
        p2_items.append(
            f"* Content Security Policy (CSP):\n"
            f"    * Goal: Restrict unauthorized script execution.\n"
            f"    * Recommended Value: `Content-Security-Policy: default-src 'self'; script-src 'self' https://www.google-analytics.com; object-src 'none';`"
        )

    if p1_items:
        priority_1_section = "\n".join(p1_items)
    else:
        priority_1_section = "* No Priority 1 Action Items Required: All critical transport and email policy controls are active."

    if p2_items:
        priority_2_section = "\n".join(p2_items)
    else:
        priority_2_section = "* No Priority 2 Action Items Required: All secondary hardening controls are active."

    report_content = f"""# {root_domain.upper()} — Security Audit & Executive Remediation Plan

Target Domain: {root_domain}  
Audit Date: {today_date}  
Auditor / Tool: Aegis Anchor (aegis_anchor.py)  
Overall Risk Posture: {overall_risk}

---

## 1. Executive Summary

An automated security audit was performed against {root_domain} to assess its public-facing HTTP response headers and domain email authentication mechanisms. 

The audit identified {num_missing} missing security controls that expose the domain to potential threats such as {main_threats}. Implementing the recommended remediation steps will significantly reduce attack vectors, protect user interactions, and safeguard brand reputation.

---

## 2. Technical Findings & Risk Matrix

| Category        | Finding / Header               | Status    | Risk Level | Business & Technical Impact                                             |
| :-------------- | :----------------------------- | :-------: | :--------: | :---------------------------------------------------------------------- |
| Transport       | Strict-Transport-Security      | {fmt_status(results.get('hsts'))} | High       | Forces HTTPS connections, preventing SSL stripping attacks.             |
| UI Safety       | X-Frame-Options                | {fmt_status(results.get('x_frame'))} | Med        | Prevents clickjacking by stopping unauthorized site framing.             |
| MIME Safety     | X-Content-Type-Options         | {fmt_status(results.get('x_content_type'))} | Med        | Stops browsers from guessing file types (MIME-sniffing defense).        |
| Script Def.     | Content-Security-Policy (CSP)  | {fmt_status(results.get('csp'))} | Med        | Restricts script sources to block Cross-Site Scripting (XSS).            |
| Email Auth      | Sender Policy Framework (SPF)  | {fmt_status(results.get('spf'))} | High       | Authorizes specific mail servers/IPs to send domain emails.              |
| Email Policy    | DMARC Policy                   | {fmt_status(results.get('dmarc'))} | High       | Instructs receiving servers on fake emails; blocks domain spoofing.      |

---

## 3. Prioritized Remediation Roadmap

### Priority 1: High Impact / Urgent (24–48 Hours)
{priority_1_section}

---

### Priority 2: Medium / Hardening Items (Within 7 Days)
{priority_2_section}

---

## 4. Re-Testing & Sign-Off

Following server and DNS configuration updates:
1. Re-run `aegis_anchor.py` against `{root_domain}`.
2. Confirm all flagged items show `PASS`.
3. Schedule periodic automated scans to ensure configurations remain intact.
"""

    # --- DYNAMIC DIRECTORY SETUP ---
    user_home = os.path.expanduser("~")
    base_folder = os.path.join(user_home, "Documents", "Aegis Anchor Reports")
    domain_folder = os.path.join(base_folder, f"{root_domain} reports")

    os.makedirs(domain_folder, exist_ok=True)

    # 1. Save Markdown File
    md_filepath = os.path.join(domain_folder, f"{root_domain}_executive_report_{timestamp}.md")
    with open(md_filepath, "w", encoding="utf-8") as file:
        file.write(report_content)
        
    print(f"\n[+] Executive report saved successfully to:")
    print(f"    [MD]  {md_filepath}")

    # 2. Render & Save PDF File
    if HAS_PDF_LIBS:
        pdf_filepath = os.path.join(domain_folder, f"{root_domain}_executive_report_{timestamp}.pdf")
        
        # Convert Markdown to HTML
        html_body = markdown.markdown(report_content, extensions=['tables'])
        
        # Inject explicit width rules onto HTML table header tags for xhtml2pdf parsing
        html_body = html_body.replace('<th>Category</th>', '<th style="width: 15%;">Category</th>')
        html_body = html_body.replace('<th>Finding / Header</th>', '<th style="width: 32%;">Finding / Header</th>')
        html_body = html_body.replace('<th>Status</th>', '<th style="width: 10%;">Status</th>')
        html_body = html_body.replace('<th>Risk Level</th>', '<th style="width: 10%;">Risk Level</th>')
        html_body = html_body.replace('<th>Business &amp; Technical Impact</th>', '<th style="width: 33%;">Business &amp; Technical Impact</th>')

        # Insert soft wrap points into long hyphenated headers specifically for xhtml2pdf engine
        html_body = html_body.replace("Strict-Transport-Security", "Strict- Transport- Security")
        html_body = html_body.replace("X-Content-Type-Options", "X- Content- Type- Options")
        html_body = html_body.replace("Content-Security-Policy", "Content- Security- Policy")

        # Executive PDF Styling Template with CSS List Indentation
        styled_html = f"""
        <html>
        <head>
        <style>
            @page {{ size: letter; margin: 0.75in; }}
            body {{ font-family: Helvetica, Arial, sans-serif; font-size: 10pt; color: #1a1a1a; line-height: 1.5; }}
            h1 {{ font-size: 16pt; color: #0f172a; border-bottom: 2px solid #0284c7; padding-bottom: 6px; }}
            h2 {{ font-size: 13pt; color: #1e293b; margin-top: 18px; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; }}
            h3 {{ font-size: 11pt; color: #334155; margin-top: 12px; }}
            table {{ width: 100%; margin-top: 10px; margin-bottom: 15px; border: 1px solid #cbd5e1; }}
            th {{ background-color: #f1f5f9; color: #0f172a; font-weight: bold; text-align: left; padding: 6px 6px; border: 1px solid #cbd5e1; font-size: 8.5pt; }}
            td {{ padding: 6px 6px; border: 1px solid #e2e8f0; font-size: 8.5pt; }}
            code {{ background-color: #f8fafc; font-family: Courier, monospace; font-size: 8pt; color: #0f766e; padding: 2px 3px; }}
            ul {{ margin-top: 4px; padding-left: 18px; }}
            ul ul {{ margin-top: 2px; margin-bottom: 4px; padding-left: 20px; }}
            li {{ margin-bottom: 4px; }}
            hr {{ border: 0; border-top: 1px solid #e2e8f0; margin: 15px 0; }}
        </style>
        </head>
        <body>
            {html_body}
        </body>
        </html>
        """
        
        with open(pdf_filepath, "wb") as pdf_file:
            pisa_status = pisa.CreatePDF(styled_html, dest=pdf_file)
            
        if not pisa_status.err:
            print(f"    [PDF] {pdf_filepath}")
        else:
            print("    [WARN] PDF generation encountered a rendering issue.")
    else:
        print("    [INFO] To enable PDF exports, run: pip install requests markdown xhtml2pdf")


# ------------------------------------------------------------------------------
# MAIN PROGRAM CONTROLLER
# ------------------------------------------------------------------------------
def run_audit():
    print("=" * 60)
    print("          AEGISANCHOR COMMUNITY SECURITY AUDITOR          ")
    print("=" * 60)
    
    raw_input = input("\nEnter target domain or URL (e.g., example.com): ")
    
    if not raw_input.strip():
        print("[-] No input provided. Exiting.")
        return

    hostname, root_domain = clean_domain(raw_input)
    print(f"\nTarget Hostname: {hostname}")
    print(f"Target Root Domain: {root_domain}")
    
    check_ssl(hostname)
    header_results = check_security_headers(hostname)
    dns_results = check_dns_security(root_domain)
    
    # Combine results and generate report
    all_results = {**header_results, **dns_results}
    generate_executive_report(root_domain, all_results)
    
    print("\n" + "=" * 60)
    print("Audit Complete! Findings exported to Executive Report.")
    print("=" * 60)


if __name__ == "__main__":
    run_audit()

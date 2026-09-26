# ==============================================================================
# AEGISANCHOR: LOCAL BUSINESS CYBERSECURITY AUDIT TOOL
# This script performs simple, non-intrusive security checks on any public website.
# ==============================================================================

# Import built-in Python tools for security, web connection, parsing, and time
import ssl
import socket
import urllib.request
from urllib.parse import urlparse
from datetime import datetime

# Import 'dnspython' (must be installed via: pip install dnspython)
# This library allows us to query DNS domain records for SPF & DMARC
import dns.resolver


# ------------------------------------------------------------------------------
# HELPER FUNCTION: Clean up messy inputs (e.g., "https://example.com/about/")
# ------------------------------------------------------------------------------
def clean_domain(raw_input):
    # Remove any accidental extra spaces at the start or end of the text
    cleaned = raw_input.strip()
    
    # If the user typed "example.com", add "https://" so the parser works correctly
    if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
        cleaned = "https://" + cleaned
    
    # Break the web address into structured parts (protocol, hostname, path)
    parsed = urlparse(cleaned)
    
    # Extract just the hostname (e.g., "www.example.com")
    hostname = parsed.hostname or ""
    
    # Split the hostname by dots to locate the root domain
    domain_parts = hostname.split('.')
    
    # Take the last two parts to get the root domain (e.g., "example.com")
    if len(domain_parts) >= 2:
        root_domain = ".".join(domain_parts[-2:])
    else:
        root_domain = hostname
        
    # Return both clean values to the main program
    return hostname, root_domain


# ------------------------------------------------------------------------------
# MODULE 1: Check HTTPS / SSL Certificate Expiration
# ------------------------------------------------------------------------------
def check_ssl(hostname):
    # Print a progress title showing which host we are testing
    print(f"\n[+] Checking SSL/TLS Certificate for: {hostname}")
    
    # Create default secure settings for our network connection
    context = ssl.create_default_context()
    
    try:
        # Open a direct network connection over port 443 (HTTPS port) with a 5-second timeout limit
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            
            # Encrypt the connection with SSL/TLS
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                
                # Fetch the digital certificate sent back by the server
                cert = ssock.getpeercert()
                
                # Extract the expiration date text string
                expire_date_str = cert['notAfter']
                
                # Convert the text date into a Python 'datetime' object
                expire_date = datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z')
                
                # Calculate how many days remain before the certificate expires
                days_left = (expire_date - datetime.utcnow()).days
                
                # Print successful result and remaining days
                print(f"  [PASS] SSL Certificate is active and valid!")
                print(f"  [INFO] Certificate expires in {days_left} days ({expire_date.strftime('%Y-%m-%d')}).")
                return True
                
    except Exception as e:
        # If the connection fails or certificate is invalid, show the error
        print(f"  [FAIL] SSL/TLS Issue detected: {e}")
        return False


# ------------------------------------------------------------------------------
# MODULE 2: Check HTTP Security Headers
# ------------------------------------------------------------------------------
def check_security_headers(hostname):
    # Rebuild full HTTPS URL for the request
    target_url = f"https://{hostname}"
    print(f"\n[+] Inspecting HTTP Security Headers for: {target_url}")
    
    # Define a list (dictionary) of crucial security headers and what they protect
    important_headers = {
        'Strict-Transport-Security': 'Forces browsers to use encrypted HTTPS connections only.',
        'X-Frame-Options': 'Prevents clickjacking (stopping malicious overlays on the site).',
        'X-Content-Type-Options': 'Prevents MIME-sniffing vulnerabilities.',
        'Content-Security-Policy': 'Restricts sources for scripts to prevent cross-site scripting (XSS).'
    }
    
    try:
        # Prepare a web request with a custom User-Agent identifying our audit tool
        req = urllib.request.Request(
            target_url, 
            headers={'User-Agent': 'Mozilla/5.0 (AegisAnchor Audit Tool)'}
        )
        
        # Connect to the website (automatically follows HTTP redirects)
        with urllib.request.urlopen(req, timeout=7) as response:
            
            # Read all header key-value pairs returned by the web server
            headers = response.info()
            
            # Check each important header one by one
            for header, purpose in important_headers.items():
                if header in headers:
                    # Header is enabled on the server
                    print(f"  [PASS] {header}: Present")
                else:
                    # Header is missing from the server response
                    print(f"  [MISSING] {header}: Not found. ({purpose})")
                    
    except Exception as e:
        # Catch connection errors or blocked requests
        print(f"  [WARN] Could not retrieve HTTP headers: {e}")


# ------------------------------------------------------------------------------
# MODULE 3: Check DNS Records for Email Security (SPF & DMARC)
# ------------------------------------------------------------------------------
def check_dns_security(root_domain):
    print(f"\n[+] Checking Email Security Records for domain: {root_domain}")
    
    # --- Part A: Check Sender Policy Framework (SPF) ---
    try:
        # Ask public DNS servers for all 'TXT' records attached to the root domain
        answers = dns.resolver.resolve(root_domain, 'TXT')
        spf_found = False
        
        # Look through all returned text records for one starting with "v=spf1"
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                spf_found = True
                print(f"  [PASS] SPF Record found: {txt_record[:60]}...")
                break
                
        # If no record starts with "v=spf1", flag it as missing
        if not spf_found:
            print("  [MISSING] No valid SPF record found on root domain.")
            
    except Exception:
        # Handle cases where no TXT records exist
        print("  [MISSING] Unable to locate TXT/SPF records for email authentication.")

    # --- Part B: Check DMARC Policy ---
    # Construct the standard domain prefix where DMARC rules reside
    dmarc_domain = f"_dmarc.{root_domain}"
    
    try:
        # Ask DNS for TXT records at "_dmarc.domain.com"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_found = False
        
        # Look for a text record starting with "v=DMARC1"
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=DMARC1"):
                dmarc_found = True
                print(f"  [PASS] DMARC Record found: {txt_record[:60]}...")
                break
                
        # If no DMARC record is found, flag the spoofing risk
        if not dmarc_found:
            print("  [MISSING] No valid DMARC record found at _dmarc." + root_domain)
            
    except Exception:
        # Handle cases where DMARC query returns no record
        print("  [MISSING] No DMARC record configured. Domain may be vulnerable to email spoofing.")


# ------------------------------------------------------------------------------
# MAIN PROGRAM CONTROLLER
# ------------------------------------------------------------------------------
def run_audit():
    # Print welcome banner
    print("=" * 60)
    print("          AEGISANCHOR COMMUNITY SECURITY AUDITOR          ")
    print("=" * 60)
    
    # Ask the user to type in a web domain
    raw_input = input("\nEnter target domain or URL (e.g., example.com): ")
    
    # If nothing was typed, exit the script gracefully
    if not raw_input.strip():
        print("[-] No input provided. Exiting.")
        return

    # Clean the domain string using our helper function
    hostname, root_domain = clean_domain(raw_input)
    print(f"\nTarget Hostname: {hostname}")
    print(f"Target Root Domain: {root_domain}")
    
    # Run the three security inspection functions sequentially
    check_ssl(hostname)
    check_security_headers(hostname)
    check_dns_security(root_domain)
    
    # Print completion footer
    print("\n" + "=" * 60)
    print("Audit Complete! Use these findings to populate the AegisAnchor report.")
    print("=" * 60)


# This line tells Python to execute run_audit() when the script file is run directly
if __name__ == "__main__":
    run_audit()
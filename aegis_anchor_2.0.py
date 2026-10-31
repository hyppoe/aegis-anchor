import subprocess
import urllib.request
score = 0
domain = input("Enter a domain to audit (e.g., example.com): ")
print(f"\nChecking email records for: {domain}\n")

# --- Checking SPF ---
print("--- Checking SPF ---")
spf_result = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, text=True)

if "v=spf1" in spf_result.stdout:
    print("[PASS] Found SPF record!")
    score += 15
else:
    print("[MISSING] No SPF record found.")

# --- Checking DMARC ---
print("\n--- Checking DMARC ---")
dmarc_domain = f"_dmarc.{domain}"
dmarc_result = subprocess.run(["nslookup", "-type=TXT", dmarc_domain], capture_output=True, text=True)

if "v=DMARC1" in dmarc_result.stdout:
    print("[PASS] Found DMARC record!")
    score += 15
else:
    print("[MISSING] No DMARC record found.")

# --- Checking HTTP Security Headers ---
print("\n--- Checking HTTP Security Headers ---")
url = f"https://{domain}"

try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    
    with urllib.request.urlopen(req) as response:
        headers = {k.lower(): v for k, v in response.headers.items()}

        if "strict-transport-security" in headers:
            print("[PASS] HSTS header present.")
            score += 20
        else:
            print("[MISSING] HSTS header missing.")

        if "x-frame-options" in headers:
            print("[PASS] X-Frame-Options header present.")
            score += 15
        else:
            print("[MISSING] X-Frame-Options header missing.")

        if "x-content-type-options" in headers:
            print("[PASS] X-Content-Type-Options header present.")
            score += 15
        else:
            print("[MISSING] X-Content-Type-Options header missing.")

        if "content-security-policy" in headers:
            print("[PASS] Content-Security-Policy header present.")
            score += 20
        else:
            print("[MISSING] Content-Security-Policy header missing.")

except Exception as e: 
    print(f"[ERROR] Could not connect to {url}: {e}")
print("\nFinal security score:  " + str(score) + " points / 100. ")

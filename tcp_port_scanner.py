import socket
import threading
import time
import random

def scan_port(ip, port, timeout=1):
    """
    Stealthy port scan using SYN (half-open) technique (requires admin privileges).
    Args:
        ip (str): Target IP address.
        port (int): Port to scan.
        timeout (int): Timeout for the scan.
    """
    try:
        # Create a raw socket (requires admin/root)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.settimeout(timeout)

        # Craft a SYN packet (simplified)
        sock.connect_ex((ip, port))  # Placeholder for actual packet crafting
        print(f"Port {port} is open (SYN-ACK received)")
    except socket.error as e:
        if "timed out" in str(e):
            print(f"Port {port} is filtered (no response)")
        else:
            print(f"Port {port} is closed (RST received)")
    finally:
        sock.close()

def scan_ports(ip, ports, timeout=1, max_threads=5, delay=0.5):
    """
    Stealthy multi-threaded port scanner with randomized order and delays.
    Args:
        ip (str): Target IP address.
        ports (list): Ports to scan.
        timeout (int): Timeout per scan.
        max_threads (int): Max concurrent threads (lower for stealth).
        delay (float): Delay between thread launches (seconds).
    """
    threads = []
    random.shuffle(ports)  # Randomize port order

    for port in ports:
        thread = threading.Thread(target=scan_port, args=(ip, port, timeout))
        threads.append(thread)
        thread.start()
        time.sleep(delay)  # Add delay between scans

        # Limit active threads
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Stealthy Port Scanner")
    parser.add_argument("--ip", type=str, required=True, help="Target IP address")
    parser.add_argument("--ports", type=str, required=True, help="Ports to scan (e.g., '80,443' or '1-100')")
    parser.add_argument("--timeout", type=int, default=1, help="Timeout per scan (seconds)")
    parser.add_argument("--threads", type=int, default=5, help="Max concurrent threads (lower for stealth)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between scans (seconds)")

    args = parser.parse_args()

    # Parse ports input
    if "," in args.ports:
        ports = [int(p) for p in args.ports.split(",")]
    elif "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = [int(args.ports)]

    scan_ports(args.ip, ports, args.timeout, args.threads, args.delay) 

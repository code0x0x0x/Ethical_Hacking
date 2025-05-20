import socket
import threading
import time
import random

def scan_udp_port(ip, port, timeout=1, stealth=False):
    """
    Scan a UDP port by sending a probe packet and interpreting the response.
    Args:
        ip (str): Target IP address.
        port (int): Port to scan.
        timeout (int): Timeout for the scan.
        stealth (bool): Enable stealth mode (random source port, smaller payload).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Randomize source port in stealth mode
        if stealth:
            sock.bind(('0.0.0.0', random.randint(1024, 65535)))
        
        # Send a probe packet (smaller payload in stealth mode)
        payload = b"scan" if not stealth else b"\x00"
        sock.sendto(payload, (ip, port))
        
        try:
            # Check for a response (unlikely for UDP)
            data, addr = sock.recvfrom(1024)
            print(f"Port {port} is open (unexpected response: {data})")
        except socket.timeout:
            # No response: port may be open or filtered
            print(f"Port {port} is open|filtered (no response)")
    except socket.error as e:
        if "ICMP" in str(e):
            print(f"Port {port} is closed (ICMP error)")
        else:
            print(f"Port {port} error: {e}")
    finally:
        sock.close()

def scan_udp_ports(ip, ports, timeout=1, max_threads=5, delay=0.5, stealth=False):
    """
    Multi-threaded UDP port scanner with randomized order and delays.
    Args:
        ip (str): Target IP address.
        ports (list): Ports to scan.
        timeout (int): Timeout per scan.
        max_threads (int): Max concurrent threads.
        delay (float): Base delay between scans (seconds).
        stealth (bool): Enable stealth mode (random delays, smaller payloads).
    """
    threads = []
    random.shuffle(ports)  # Randomize port order

    for port in ports:
        thread = threading.Thread(target=scan_udp_port, args=(ip, port, timeout, stealth))
        threads.append(thread)
        thread.start()
        
        # Add jitter to the delay in stealth mode
        current_delay = delay if not stealth else delay * random.uniform(0.5, 1.5)
        time.sleep(current_delay)

        # Limit active threads
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="UDP Port Scanner")
    parser.add_argument("--ip", type=str, required=True, help="Target IP address")
    parser.add_argument("--ports", type=str, required=True, help="Ports to scan (e.g., '53,67' or '1-100')")
    parser.add_argument("--timeout", type=int, default=1, help="Timeout per scan (seconds)")
    parser.add_argument("--threads", type=int, default=5, help="Max concurrent threads")
    parser.add_argument("--delay", type=float, default=0.5, help="Base delay between scans (seconds)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (random source port, jittered delays, smaller payload)")

    args = parser.parse_args()

    # Parse ports input
    if "," in args.ports:
        ports = [int(p) for p in args.ports.split(",")]
    elif "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = [int(args.ports)]

    scan_udp_ports(args.ip, ports, args.timeout, args.threads, args.delay, args.stealth)

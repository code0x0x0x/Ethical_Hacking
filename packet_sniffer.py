import argparse
from scapy.all import sniff, IP, TCP, UDP, Raw, wrpcap
from scapy.layers.ssl_tls import TLS, SSL
import warnings

# Suppress Scapy warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Decryption setup (placeholder for actual key/cert logic)
def decrypt_tls_payload(packet):
    """Attempt to decrypt TLS payload if keys are available."""
    if packet.haslayer(TLS):
        print("[!] TLS packet detected (decryption requires key setup).")
        # Add decryption logic here if keys are available
    elif packet.haslayer(SSL):
        print("[!] SSL packet detected (decryption requires key setup).")

# Real-time analysis rules
def analyze_packet(packet, malicious_ips):
    """Analyze packets for suspicious activity."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Rule 1: Detect port scans (multiple SYN packets to different ports)
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            print(f"[!] Potential port scan detected from {src_ip}")

        # Rule 2: Detect malicious IPs
        if src_ip in malicious_ips or dst_ip in malicious_ips:
            print(f"[ALERT] Malicious IP detected: {src_ip} -> {dst_ip}")

        # Rule 3: Detect plaintext credentials (HTTP)
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = str(packet[Raw].load)
            if "password=" in payload.lower() or "login=" in payload.lower():
                print(f"[ALERT] Possible credentials in plaintext from {src_ip}")

# Combined callback
def packet_callback(packet, malicious_ips, output_file=None):
    """Process each packet: dissection, decryption, and analysis."""
    # Dissection
    if packet.haslayer(IP):
        print(f"\n[IP] {packet[IP].src} -> {packet[IP].dst} | Proto: {packet[IP].proto}")
        if packet.haslayer(TCP):
            print(f"[TCP] Ports: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"[UDP] Ports: {packet[UDP].sport} -> {packet[UDP].dport}")

    # Decryption
    decrypt_tls_payload(packet)

    # Real-time analysis
    analyze_packet(packet, malicious_ips)

    # Save to file if specified
    if output_file:
        wrpcap(output_file, packet, append=True)

def main():
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer with CLI")
    parser.add_argument("--interface", help="Network interface to sniff (default: auto-detect)", default=None)
    parser.add_argument("--filter", help="BPF filter (e.g., 'tcp port 80')", default="")
    parser.add_argument("--count", type=int, help="Number of packets to capture (default: unlimited)", default=0)
    parser.add_argument("--output", help="Save packets to a .pcap file", default=None)
    parser.add_argument("--malicious-ips", help="Comma-separated list of malicious IPs", default="1.1.1.1,2.2.2.2")

    args = parser.parse_args()
    malicious_ips = args.malicious_ips.split(",") if args.malicious_ips else []

    print(f"[*] Starting sniffer on interface: {args.interface or 'default'}")
    print(f"[*] Filter: {args.filter or 'none'}")
    print(f"[*] Malicious IPs: {malicious_ips}")

    sniff(
        prn=lambda pkt: packet_callback(pkt, malicious_ips, args.output),
        store=0,
        count=args.count,
        iface=args.interface,
        filter=args.filter
    )

if __name__ == "__main__":
    main() 

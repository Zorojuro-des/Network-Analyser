from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, Counter
from datetime import datetime
import threading

# Statistics
protocol_counter = Counter()
ip_traffic = defaultdict(int)
connection_tracker = defaultdict(list)

def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        ip_traffic[src] += 1
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags

            # Track SYN packets for port scan detection
            if flags == 'S':
                connection_tracker[src].append((dst, dport))

        elif UDP in packet:
            protocol = "UDP"

        protocol_counter[protocol] += 1
        print(f"{src} -> {dst} | Protocol: {protocol}")

def detect_port_scans():
    while True:
        for ip, connections in list(connection_tracker.items()):
            ports = [port for _, port in connections]
            if len(set(ports)) > 10:
                print(f"[!] Possible Port Scan Detected from {ip} on ports: {sorted(set(ports))}")
                del connection_tracker[ip]
        threading.Event().wait(10)  # Check every 10 seconds

def display_stats():
    print("\n--- Traffic Summary ---")
    print(f"Protocol Count: {dict(protocol_counter)}")
    print("Top Talkers:")
    for ip, count in sorted(ip_traffic.items(), key=lambda x: -x[1])[:5]:
        print(f"  {ip}: {count} packets")

# Start port scan detection in a background thread
scan_thread = threading.Thread(target=detect_port_scans, daemon=True)
scan_thread.start()

# Start sniffing
try:
    print("[*] Starting packet capture. Press Ctrl+C to stop...")
    sniff(prn=analyze_packet, filter="ip", store=False)
except KeyboardInterrupt:
    display_stats()
finally:
    display_stats()
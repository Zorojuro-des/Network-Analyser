import threading
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, Counter
import time

# Simulated blacklist (could be loaded from a file or API)
SUSPICIOUS_IPS = {
    "192.168.1.66",     # Example internal attacker
    "45.83.122.5",      # Malicious external IP
    "10.0.0.99"         # Unauthorized internal scanner
}

protocol_counter = Counter()
ip_traffic = defaultdict(int)
connection_tracker = defaultdict(list)

# GUI setup
root = tk.Tk()
root.title("Advanced Network Analyzer")
root.geometry("auto")

tree = ttk.Treeview(root, columns=("src", "dst", "proto", "info"), show='headings')
tree.heading("src", text="Source IP")
tree.heading("dst", text="Destination IP")
tree.heading("proto", text="Protocol")
tree.heading("info", text="Info")
tree.pack(fill=tk.BOTH, expand=True)

alert_label = tk.Label(root, text="", fg="red", font=("Helvetica", 12, "bold"))
alert_label.pack(pady=5)

def update_alert(message):
    alert_label.config(text=message)
    root.after(10000, lambda: alert_label.config(text=""))

def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = "OTHER"
        info = ""

        ip_traffic[src] += 1

        if TCP in packet:
            proto = "TCP"
            flags = packet[TCP].flags
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            info = f"{sport} → {dport} Flags: {flags}"
            if flags == 'S':
                connection_tracker[src].append((dst, dport))

        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            info = f"{sport} → {dport}"

        protocol_counter[proto] += 1

        # Show in GUI
        tree.insert('', 'end', values=(src, dst, proto, info))

        # Detect suspicious IPs
        if src in SUSPICIOUS_IPS:
            update_alert(f"[!] Suspicious IP Detected: {src}")

def detect_port_scans():
    while True:
        for ip, connections in list(connection_tracker.items()):
            ports = [port for _, port in connections]
            if len(set(ports)) > 10:
                update_alert(f"[!] Port Scan from {ip} on ports {sorted(set(ports))}")
                del connection_tracker[ip]
        time.sleep(10)

def start_sniffing():
    sniff(prn=analyze_packet, filter="ip", store=False)

# Start background threads
sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()

scan_thread = threading.Thread(target=detect_port_scans, daemon=True)
scan_thread.start()

root.mainloop()

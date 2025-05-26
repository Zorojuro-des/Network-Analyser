from scapy.all import *

def analyze(packet):
    if IP in packet:
        print(f"{packet[IP].src} -> {packet[IP].dst}")
        if TCP in packet:
            print(f"  Protocol: TCP | Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"  Protocol: UDP | Port: {packet[UDP].sport} -> {packet[UDP].dport}")

conf.L3socket  # Using default IP-level socket
sniff(prn=analyze, count=10, filter="ip")

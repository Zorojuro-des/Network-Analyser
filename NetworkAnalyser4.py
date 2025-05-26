import sys
import threading
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QLabel
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from scapy.all import sniff, IP, TCP, UDP

# Simulated blacklist
SUSPICIOUS_IPS = {"192.168.1.66", "45.83.122.5", "10.0.0.99"}
connection_tracker = {}

# Signal manager to send data safely across threads
class PacketSignal(QObject):
    new_packet = pyqtSignal(str, str, str, str)
    alert_signal = pyqtSignal(str)

signal_manager = PacketSignal()

class NetworkAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Analyzer - PyQt5")
        self.setGeometry(100, 100, 900, 600)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(4)
        self.packet_table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Protocol", "Info"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)

        self.alert_label = QLabel("")
        self.alert_label.setStyleSheet("color: red; font-weight: bold; font-size: 14px;")

        layout = QVBoxLayout()
        layout.addWidget(self.packet_table)
        layout.addWidget(self.alert_label)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        signal_manager.new_packet.connect(self.add_packet)
        signal_manager.alert_signal.connect(self.show_alert)

    def add_packet(self, src, dst, proto, info):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row, 0, QTableWidgetItem(src))
        self.packet_table.setItem(row, 1, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 2, QTableWidgetItem(proto))
        self.packet_table.setItem(row, 3, QTableWidgetItem(info))

    def show_alert(self, message):
        self.alert_label.setText(message)
        # Clear after 10 seconds
        threading.Timer(10, lambda: self.alert_label.setText("")).start()

# Packet analysis logic
def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = "OTHER"
        info = ""

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            info = f"{sport} → {dport} Flags: {flags}"

            if flags == 'S':  # SYN
                if src not in connection_tracker:
                    connection_tracker[src] = []
                connection_tracker[src].append(dport)

        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            info = f"{sport} → {dport}"

        signal_manager.new_packet.emit(src, dst, proto, info)

        if src in SUSPICIOUS_IPS:
            signal_manager.alert_signal.emit(f"[!] Suspicious IP Detected: {src}")

def detect_port_scans():
    while True:
        for ip, ports in list(connection_tracker.items()):
            if len(set(ports)) > 10:
                signal_manager.alert_signal.emit(f"[!] Port Scan Detected from {ip} on ports {sorted(set(ports))}")
                del connection_tracker[ip]
        time.sleep(10)

def start_sniffing():
    sniff(prn=analyze_packet, filter="ip", store=False)

# Run the app
def main():
    app = QApplication(sys.argv)
    gui = NetworkAnalyzerGUI()

    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=detect_port_scans, daemon=True).start()

    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
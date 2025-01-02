import logging
from scapy.all import *
from firewall import FirewallManager
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import time

# Configuration
BLOCK_DURATION = timedelta(minutes=10)
SCAN_LIMIT = 5

# Tracking dictionary for IP scans
scan_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def handle_packet(packet):
    if TCP in packet and packet[TCP].flags == "S":  # SYN flag detected
        src_ip = packet[IP].src
        dst_port = packet[IP].dport
        src_port = packet[IP].sport

        logging.info(f"Scan detected on port {dst_port} from {src_ip}")

        # Update scan count and timestamp
        current_time = datetime.now()
        tracker = scan_tracker[src_ip]

        if tracker["timestamp"] and current_time - tracker["timestamp"] > BLOCK_DURATION:
            tracker["count"] = 0

        tracker["count"] += 1
        tracker["timestamp"] = current_time

        if tracker["count"] > SCAN_LIMIT:
            logging.warning(f"IP {src_ip} exceeded scan limit. Blocking for 10 minutes...")
            FirewallManager.block_ip(src_ip)
            unblock_time = current_time + BLOCK_DURATION
            unblock_tasks.append((src_ip, unblock_time))
            return

        # Send SYN-ACK
        syn_ack = (
            IP(dst=src_ip, src=packet[IP].dst) /
            TCP(sport=dst_port, dport=src_port, flags="SA", seq=100, ack=packet[TCP].seq + 1)
        )
        send(syn_ack, verbose=0)
        logging.info(f"Sent SYN-ACK to {src_ip} on port {dst_port}")

        # Send "try harder" message
        data_packet = (
            IP(dst=src_ip, src=packet[IP].dst) /
            TCP(sport=dst_port, dport=src_port, flags="PA", seq=101, ack=packet[TCP].seq + 1) /
            Raw(load="Try Harder! :)")
        )
        send(data_packet, verbose=0)
        logging.info(f"Sent data packet with message 'try harder' to {src_ip} on port {dst_port}")

def unblock_expired_ips():
    """Unblock IPs whose block duration has expired."""
    current_time = datetime.now()
    for ip, unblock_time in list(unblock_tasks):
        if current_time >= unblock_time:
            FirewallManager.unblock_ip(ip)
            unblock_tasks.remove((ip, unblock_time))

if __name__ == "__main__":
    unblock_tasks = []

    FirewallManager.init()

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=lambda: sniff(filter="tcp", prn=handle_packet), daemon=True)
    sniff_thread.start()

    # Monitor unblock tasks in the main thread
    try:
        while True:
            unblock_expired_ips()
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("Stopping...")

import logging
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import *

from firewall import FirewallManager

# Configuration
BLOCK_DURATION = timedelta(minutes=10)
SCAN_LIMIT = 3  # block after this many SYN attempts

# Tracking dictionary for IP scans
scan_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})
tracker_lock = threading.Lock()

# unblock_tasks: map ip -> unblock_time
unblock_tasks = {}
unblock_lock = threading.Lock()

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def handle_packet(packet):
    # TCP packet detected
    if not packet.haslayer(TCP):
        return

    # SYN flag detected
    if str(packet[TCP].flags) != "S":
        return

    src_ip = packet[IP].src
    dst_port = packet[TCP].dport
    src_port = packet[TCP].sport

    # If the IP is already blocked in iptables, skip further processing
    if FirewallManager.check_ip(src_ip):
        logging.debug(f"Packet from {src_ip} ignored because IP is blocked.")
        return

    logging.info(f"Scan detected on port {dst_port} from {src_ip}")

    # Update scan count and timestamp
    current_time = datetime.now()
    with tracker_lock:
        tracker = scan_tracker[src_ip]

        # If last scan was longer than BLOCK_DURATION ago, reset the counter
        if tracker["timestamp"] and current_time - tracker["timestamp"] > BLOCK_DURATION:
            tracker["count"] = 0

        tracker["count"] += 1
        tracker["timestamp"] = current_time

        # Block when count reaches (>=) the SCAN_LIMIT
        if tracker["count"] >= SCAN_LIMIT:
            logging.warning(f"IP {src_ip} exceeded scan limit ({SCAN_LIMIT}). Blocking for 10 minutes...")
            FirewallManager.block_ip(src_ip)
            unblock_time = current_time + BLOCK_DURATION
            # schedule unblock
            with unblock_lock:
                unblock_tasks[src_ip] = unblock_time

            # reset tracker so next scans after unblock start fresh
            tracker["count"] = 0
            tracker["timestamp"] = None
            return

    # Send SYN-ACK and a data packet in response to the scan
    try:
        syn_ack = (
            IP(dst=src_ip, src=packet[IP].dst) /
            TCP(sport=dst_port, dport=src_port, flags="SA", seq=100, ack=packet[TCP].seq + 1)
        )
        send(syn_ack, verbose=0)
        logging.info(f"Sent SYN-ACK to {src_ip} on port {dst_port}")

        data_packet = (
            IP(dst=src_ip, src=packet[IP].dst) /
            TCP(sport=dst_port, dport=src_port, flags="PA", seq=101, ack=packet[TCP].seq + 1) /
            Raw(load=b"Try Harder! :)")
        )
        send(data_packet, verbose=0)
        logging.info(f"Sent data packet with message to {src_ip} on port {dst_port}")
    except Exception as e:
        logging.error(f"Error sending response packets to {src_ip}: {e}")


def unblock_expired_ips():
    """Unblock IPs whose block duration has expired."""
    current_time = datetime.now()
    expired = []

    with unblock_lock:
        for ip, unblock_time in unblock_tasks.items():
            if current_time >= unblock_time:
                expired.append(ip)

    for ip in expired:
        FirewallManager.unblock_ip(ip)
        with unblock_lock:
            # remove from schedule
            unblock_tasks.pop(ip, None)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[-] Usage: sudo python3 main.py <host_ip>")
        sys.exit(1)

    host_ip = sys.argv[1]

    FirewallManager.init()

    # Start sniffing in a separate thread
    bpf_filter = f"tcp and not src host {host_ip}"
    sniff_thread = threading.Thread(target=lambda: sniff(filter=bpf_filter, prn=handle_packet, store=False), daemon=True)
    sniff_thread.start()

    # Monitor unblock tasks in the main thread
    try:
        while True:
            unblock_expired_ips()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping...")

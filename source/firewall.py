import subprocess
import logging
import socket
import os
import sys

# Ensure script is run as root
def ensure_root_permissions():
    if os.geteuid() != 0:
        logging.critical("This script must be run as root. Exiting.")
        sys.exit(1)

# Call the function to check root permissions
ensure_root_permissions()

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class FirewallManager:
     @staticmethod
    def get_host_ip():
        """Get the IP address of the host machine."""
        try:
            # Dynamically find the host IP address
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            logging.error(f"Error getting host IP: {e}")
            return None

    @staticmethod
    def is_ip_blocked(ip):
        """Check if the IP is already blocked in iptables."""
        result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
        return ip in result.stdout

    @staticmethod
    def block_ip(ip):
        """Block the given IP using iptables."""
        host_ip = FirewallManager.get_host_ip()
        if ip==host_ip:
            return

        if FirewallManager.is_ip_blocked(ip):
            logging.info(f"IP {ip} is already blocked. Skipping...")
            return

        logging.info(f"Blocking IP: {ip}")
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error blocking IP {ip}: {e}")

    @staticmethod
    def unblock_ip(ip):
        """Unblock the given IP using iptables."""
        logging.info(f"Unblocking IP: {ip}")
        host_ip = FirewallManager.get_host_ip()
        if ip==host_ip:
            return

        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error unblocking IP {ip}: {e}")

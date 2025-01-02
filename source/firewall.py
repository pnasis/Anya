import subprocess
import logging
import socket
import os
import sys
from pyfiglet import Figlet

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
    def init():
        """Initialize the program by displaying ASCII art and credits, and logging the start."""
        # Generate ASCII art for the program name
        program_name = "Anya"
        ascii_art = Figlet(font='slant').renderText(program_name)
        print(ascii_art)

        # Display credits
        credits = "\nCreated by: pnasis\nVersion: v1.0\n"
        print(credits)

        # Log the program start
        logging.info("Program started.")

    @staticmethod
    def check_ip(ip):
        """Check if the IP is already blocked in iptables."""
        result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
        return ip in result.stdout

    @staticmethod
    def block_ip(ip):
        """Block the given IP using iptables."""
        if FirewallManager.check_ip(ip):
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
        if FirewallManager.check_ip(ip):
            logging.info(f"IP {ip} is already unblocked. Skipping...")
            return

        logging.info(f"Unblocking IP: {ip}")
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error unblocking IP {ip}: {e}")

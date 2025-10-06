import subprocess
import logging
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
    def check_ip(ip: str) -> bool:
        """Return True if there is an INPUT DROP rule for this IP."""
        try:
            subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except subprocess.CalledProcessError:
            return False
        except FileNotFoundError:
            logging.error("iptables command not found on this system.")
            return False

    @staticmethod
    def block_ip(ip: str) -> None:
        """Block the given IP using iptables."""
        if FirewallManager.check_ip(ip):
            logging.info(f"IP {ip} is already blocked. Skipping...")
            return

        logging.info(f"Blocking IP: {ip}")
        try:
            # Use -I to insert at top so the DROP is effective immediately
            subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logging.info(f"IP {ip} successfully blocked.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error blocking IP {ip}: {e}")

    @staticmethod
    def unblock_ip(ip: str) -> None:
        """Unblock the given IP using iptables."""
        if not FirewallManager.check_ip(ip):
            logging.info(f"IP {ip} is not blocked. Skipping unblock...")
            return

        logging.info(f"Unblocking IP: {ip}")
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logging.info(f"IP {ip} successfully unblocked.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error unblocking IP {ip}: {e}")
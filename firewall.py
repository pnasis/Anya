import subprocess

class FirewallManager:
    @staticmethod
    def is_ip_blocked(ip):
        """Check if the IP is already blocked in iptables."""
        result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
        return ip in result.stdout

    @staticmethod
    def block_ip(ip):
        """Block the given IP using iptables."""
        if FirewallManager.is_ip_blocked(ip):
            print(f"IP {ip} is already blocked. Skipping...")
            return

        print(f"Blocking IP: {ip}")
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP {ip}: {e}")

    @staticmethod
    def unblock_ip(ip):
        """Unblock the given IP using iptables."""
        print(f"Unblocking IP: {ip}")
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP {ip}: {e}")

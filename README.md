# Anya
![Project Logo](assets/logo.png)

This project is a Python-based firewall designed to detect TCP SYN scans and block malicious IP addresses using iptables. It also responds to detected scans with custom messages.

## Features

- Detects TCP SYN scans.
- Blocks IPs that exceed a configurable scan limit using iptables.
- Automatically unblocks IPs after a specified duration.
- Sends SYN-ACK packets in response to scans.
- Includes modular design with a dedicated `FirewallManager` class for managing iptables.

## Requirements

- Python 3.x
- Root privileges (for modifying iptables)
- Required Python libraries:
  - `scapy`
  - `datetime`
  - `threading`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/pnasis/Anya.git
   cd Anya
   ```

2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure the script has execution permissions:
   ```bash
   chmod +x main.py
   ```

## Usage

1. Run the script with root privileges:
   ```bash
   sudo python main.py
   ```

2. The program will start sniffing network packets and automatically handle blocking/unblocking IPs based on detected SYN scans.

3. To stop the script, use `Ctrl+C`.

## Configuration

- The following parameters can be configured in `main.py`:
  - `BLOCK_DURATION`: Duration to block an IP address (default: 10 minutes).
  - `SCAN_LIMIT`: Maximum number of scans allowed before blocking an IP (default: 5).

## File Structure

```
.
├── main.py               # Main script for packet sniffing and handling
├── firewall.py           # Class for managing iptables operations
├── requirements.txt      # Python library dependencies
├── README.md             # Project documentation
```

## Security Notes

- This program modifies iptables rules and requires root privileges. Ensure you understand the implications before using it in a production environment.
- Make sure your system has a proper backup of iptables rules before running the script.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests for new features, bug fixes, or documentation improvements.


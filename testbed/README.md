# Firewall Testbed Environment with Docker

This project sets up a test environment using Docker to evaluate the behavior of a Python-based firewall program. The setup includes two machines:
1. Firewall Machine: Runs the Python firewall program.
2. Scanner Machine: Used to scan the firewall machine using nmap.

## Features

* Simulates a real-world network environment for testing the firewall.
* Provides isolation between the firewall and scanner.
* Easy setup and teardown using Docker Compose.

## Prerequisites

* Docker (`docker`)
* Docker Compose (`docker-compose`)

## Setup Instructions
### 1. Clone the repository:
```bash
git clone https://github.com/pnasis/Anya.git
cd Anya/testbed
```

### 2. Create a Docker Network:
```bash
docker network create firewall-net
```

### 3. Build and Start the Environment

Run the following command to build the Docker images and start the containers:
```bash
docker-compose up --build
```

### 4. Verify the Firewall Program

Check the logs of the firewall-machine to ensure it has started with its IP address:
```bash
docker logs firewall-machine

```

### 5. Test the Setup
#### Access the scanner machine

In a new terminal, run:
```bash
docker exec -it scanner-machine bash
```

#### Perform scans:

Use `nmap` to scan the firewall machine:
```bash
nmap firewall-machine
nmap -p 80,443 firewall-machine
```

#### Stop the Environment

To stop and remove the containers, run:
```bash
docker-compose down
```

## File Structure

```
.
├── testbed/                    # Directory containing required testbed files
│   ├── Dockerfile.firewall     # Dockerfile for building the firewall container
│   ├── Dockerfile.scanner      # Dockerfile for building the scanner container
│   ├── entrypoint.sh           # Script to dynamically set the IP and run the firewall
│   ├── docker-compose.yml      # Docker compose file for orchestrating the testbed
│   └── README.md               # Testbed documentation
```

## Customization

1. Modify docker-compose.yml to expose additional ports or change container settings.
2. Update the Dockerfile.firewall or Dockerfile.scanner to add more tools or dependencies.

## Troubleshooting
### Containers Can't Communicate

1. Ensure the containers are on the same network (test-network).
2. Verify the service names (`firewall-machine`, `scanner-machine`) are used correctly.

### Firewall Program Errors

Check the logs of the firewall machine:
```bash
    docker logs firewall-machine
```

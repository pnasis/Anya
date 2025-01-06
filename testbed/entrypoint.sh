#!/bin/bash

echo "telnet stream tcp nowait telnetd /usr/sbin/telnetd telnetd" >> /etc/inetd.conf

service apache2 start && service ssh start && service inetutils-inetd start

# Get the container's IP address
CONTAINER_IP=$(hostname -I | awk '{print $1}')

echo "Starting firewall with IP address: $CONTAINER_IP"

# Run the firewall program with the container's IP as an argument
exec python /app/source/main.py "$CONTAINER_IP"

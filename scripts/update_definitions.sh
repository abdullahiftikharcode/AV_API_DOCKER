#!/bin/bash

# Exit on any error
set -e

echo "Updating virus definitions..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Stop ClamAV daemon
echo "Stopping ClamAV daemon..."
service clamav-daemon stop

# Update virus definitions
echo "Running freshclam..."
freshclam

# Start ClamAV daemon
echo "Starting ClamAV daemon..."
service clamav-daemon start

# Wait for daemon to start
echo "Waiting for daemon to start..."
sleep 5

# Test daemon connection
echo "Testing daemon connection..."
if clamdscan --ping; then
    echo "ClamAV daemon is running and responding"
else
    echo "Error: ClamAV daemon is not responding"
    exit 1
fi

echo "Virus definitions updated successfully" 
#!/bin/bash

# Exit on any error
set -e

echo "Setting up virus scanner environment..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Install system dependencies
echo "Installing system dependencies..."
apt-get update
apt-get install -y \
    clamav \
    clamav-daemon \
    libmagic1 \
    python3.11 \
    python3.11-venv \
    python3-pip

# Create virtual environment
echo "Creating Python virtual environment..."
python3.11 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo "Creating directories..."
mkdir -p \
    /tmp/virus-scanner \
    data/ml_models \
    data/threat_intel \
    rules/malware \
    rules/packers \
    rules/heuristic

# Set permissions
echo "Setting permissions..."
chown -R clamav:clamav /var/run/clamav
chmod 750 /var/run/clamav
chmod 755 /tmp/virus-scanner

# Update virus definitions
echo "Updating virus definitions..."
freshclam

# Configure ClamAV
echo "Configuring ClamAV..."
cp docker/clamav/clamd.conf /etc/clamav/clamd.conf
chown clamav:clamav /etc/clamav/clamd.conf
chmod 644 /etc/clamav/clamd.conf

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

# Create example .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating example .env file..."
    cat > .env << EOL
# Server Configuration
VIRUS_SCANNER_PORT=8080
VIRUS_SCANNER_HOST=0.0.0.0
MAX_FILE_SIZE_MB=100
SCAN_TIMEOUT_SECONDS=45
TEMP_DIR=/tmp/virus-scanner
LOG_LEVEL=INFO

# Memory Management
MAX_CONCURRENT_SCANS=6
MEMORY_LIMIT_MB=3000
ENABLE_RESULT_CACHING=true
CACHE_TTL_HOURS=24

# ClamAV Configuration
CLAMAV_HOST=127.0.0.1
CLAMAV_PORT=3310
EOL
fi

echo "Setup completed successfully!"
echo "You can now start the server with: uvicorn app.main:app --host 0.0.0.0 --port 8080" 
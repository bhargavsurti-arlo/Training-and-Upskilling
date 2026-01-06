#!/bin/bash
# Upload and Start Script for EC2 Inventory Portal
# Run this after the EC2 instance is ready

set -e

if [ -z "$1" ]; then
    echo "Usage: ./upload-and-start.sh <PUBLIC_IP> [KEY_FILE]"
    echo "Example: ./upload-and-start.sh 52.123.45.67 ec2-inventory-key.pem"
    exit 1
fi

PUBLIC_IP=$1
KEY_FILE=${2:-"ec2-inventory-key.pem"}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "Uploading Application to EC2 Instance"
echo "=========================================="

echo ""
echo "Target: ec2-user@$PUBLIC_IP"
echo "Key File: $KEY_FILE"
echo ""

# Check if key file exists
if [ ! -f "$KEY_FILE" ]; then
    echo "Error: Key file '$KEY_FILE' not found!"
    exit 1
fi

echo "[1/3] Uploading application files..."

# Upload files
scp -i "$KEY_FILE" -o StrictHostKeyChecking=no \
    "$SCRIPT_DIR/app.py" \
    "$SCRIPT_DIR/requirements.txt" \
    "ec2-user@$PUBLIC_IP:/tmp/"

# Upload templates directory
scp -i "$KEY_FILE" -o StrictHostKeyChecking=no -r \
    "$SCRIPT_DIR/templates" \
    "ec2-user@$PUBLIC_IP:/tmp/"

echo ""
echo "[2/3] Moving files and installing dependencies..."

ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no "ec2-user@$PUBLIC_IP" << 'ENDSSH'
sudo mv /tmp/app.py /opt/ec2-inventory/
sudo mv /tmp/requirements.txt /opt/ec2-inventory/
sudo rm -rf /opt/ec2-inventory/templates
sudo mv /tmp/templates /opt/ec2-inventory/
cd /opt/ec2-inventory
sudo /opt/ec2-inventory/venv/bin/pip install -r requirements.txt
ENDSSH

echo ""
echo "[3/3] Starting the application..."

ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no "ec2-user@$PUBLIC_IP" \
    "sudo systemctl start ec2-inventory && sudo systemctl status ec2-inventory"

echo ""
echo "=========================================="
echo "Application Deployed Successfully!"
echo "=========================================="
echo ""
echo "Access your portal at:"
echo "  http://$PUBLIC_IP:5000"
echo ""
echo "Splunk Dashboard:"
echo "  http://$PUBLIC_IP:5000/splunk-dashboard"
echo ""




#!/bin/bash
# OctoBrowser Setup Script for Linux
# Run this before using OctoBrowser for the first time

set -e

echo "=== OctoBrowser Linux Setup ==="

# Install unzip
echo "[1/3] Installing unzip..."
sudo apt update && sudo apt install -y unzip

# Stop and disable AppArmor
echo "[2/3] Disabling AppArmor..."
sudo systemctl stop apparmor
sudo systemctl disable apparmor

# Remove AppArmor
echo "[3/3] Removing AppArmor..."
sudo apt remove -y apparmor

echo ""
echo "=== Setup Complete ==="
echo "A reboot is required for changes to take effect."
echo ""
read -p "Reboot now? (y/n): " answer
if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
    sudo reboot
else
    echo "Remember to reboot before using OctoBrowser!"
fi

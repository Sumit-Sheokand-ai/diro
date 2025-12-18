#!/bin/bash

# DIRO Installation Script for Kali Linux
# This script installs DIRO and its dependencies

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║           DIRO Installation Script                        ║"
echo "║           Multi-Task Ethical Hacking Tool                 ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root (use sudo)"
    exit 1
fi

echo "[*] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed. Installing..."
    apt-get update
    apt-get install -y python3 python3-pip
else
    echo "[+] Python 3 is installed"
fi

echo ""
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "[+] Dependencies installed successfully"
else
    echo "[!] Failed to install dependencies"
    exit 1
fi

echo ""
echo "[*] Making diro.py executable..."
chmod +x diro.py

echo ""
echo "[*] Creating symbolic link in /usr/local/bin..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ln -sf "$SCRIPT_DIR/diro.py" /usr/local/bin/diro

if [ $? -eq 0 ]; then
    echo "[+] Symbolic link created successfully"
else
    echo "[!] Failed to create symbolic link"
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║              Installation Complete!                       ║"
echo "║                                                           ║"
echo "║  You can now run DIRO from anywhere by typing: diro       ║"
echo "║  Or run it directly: python3 diro.py                      ║"
echo "║                                                           ║"
echo "║  Remember: Use only on authorized systems!                ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

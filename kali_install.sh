#!/bin/bash

# ==============================================
# KALI LINUX INSTALLATION SCRIPT
# Ultimate Security Scanner - Kali Optimized
# ==============================================

echo "🔥 Installing Ultimate Security Scanner for Kali Linux..."
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on Kali Linux
if ! grep -q "Kali" /etc/os-release; then
    print_warning "Warning: This script is optimized for Kali Linux"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update package lists
print_status "Updating package lists..."
sudo apt update

# Install system packages (Kali has most pre-installed)
print_status "Installing system dependencies..."
sudo apt install -y python3-pip python3-venv nmap nikto dirb sqlmap \
    chromium-chromedriver tor proxychains netcat-traditional \
    whois dnsutils curl wget git vim htop

# Install Python dependencies
print_status "Installing Python packages..."
pip3 install -r requirements.txt

# Create virtual environment (recommended)
print_status "Creating Python virtual environment..."
python3 -m venv scanner_env
source scanner_env/bin/activate

# Install packages in virtual environment
print_status "Installing packages in virtual environment..."
scanner_env/bin/pip install -r requirements.txt

print_success "Installation completed!"
echo ""
echo "=================================================="
echo "🚀 To use the scanner:"
echo ""
echo "1. Activate virtual environment (recommended):"
echo "   source scanner_env/bin/activate"
echo ""
echo "2. Run GUI:"
echo "   python gui_launcher.py"
echo ""
echo "3. Run CLI:"
echo "   python scan.py example.com -t full"
echo ""
echo "4. For maximum performance, run as root:"
echo "   sudo python scan.py target -t ultra"
echo "=================================================="
echo ""
print_success "Happy Hacking! 🔒💀"
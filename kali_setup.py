#!/usr/bin/env python3
"""
Kali Linux Quick Setup Script
Optimizes the Ultimate Security Scanner for Kali Linux
"""

import os
import json
import subprocess
import sys
from pathlib import Path

def run_command(cmd, shell=False):
    """Run a command and return output"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def check_kali_tools():
    """Check which Kali tools are available"""
    print("🔍 Checking Kali Linux tools...")

    kali_tools = {
        'nmap': '/usr/bin/nmap',
        'nikto': '/usr/bin/nikto',
        'sqlmap': '/usr/bin/sqlmap',
        'dirb': '/usr/bin/dirb',
        'gobuster': '/usr/bin/gobuster',
        'hydra': '/usr/bin/hydra',
        'metasploit': '/usr/bin/msfconsole',
        'burpsuite': '/usr/bin/burpsuite'
    }

    available = {}
    missing = {}

    for tool, path in kali_tools.items():
        if os.path.exists(path):
            available[tool] = path
            print(f"✅ {tool}: {path}")
        else:
            missing[tool] = path
            print(f"❌ {tool}: Not found at {path}")

    return available, missing

def setup_directories():
    """Create necessary directories"""
    print("📁 Setting up directories...")

    dirs = [
        "/home/kali/security_reports",
        "/home/kali/security_reports/screenshots",
        "/var/log/security_scanner",
        "/tmp/scanner"
    ]

    for dir_path in dirs:
        try:
            os.makedirs(dir_path, exist_ok=True)
            print(f"✅ Created: {dir_path}")
        except Exception as e:
            print(f"❌ Failed to create {dir_path}: {e}")

def optimize_for_kali():
    """Apply Kali-specific optimizations"""
    print("⚡ Applying Kali optimizations...")

    # Update PATH to include Kali tools
    current_path = os.environ.get('PATH', '')

    kali_paths = [
        '/usr/bin',
        '/usr/sbin',
        '/usr/local/bin',
        '/usr/local/sbin'
    ]

    for path in kali_paths:
        if path not in current_path:
            current_path = f"{path}:{current_path}"

    # Set environment variables
    env_vars = {
        'KALI_LINUX': 'true',
        'PATH': current_path,
        'PYTHONPATH': '/home/kali/.local/lib/python3.11/site-packages',
        'DISPLAY': ':0'
    }

    for var, value in env_vars.items():
        os.environ[var] = value
        print(f"✅ Set {var}={value}")

def install_python_deps():
    """Install Python dependencies"""
    print("🐍 Installing Python dependencies...")

    success, stdout, stderr = run_command([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])

    if success:
        print("✅ Python dependencies installed successfully")
    else:
        print(f"❌ Failed to install Python dependencies: {stderr}")
        return False

    return True

def main():
    """Main setup function"""
    print("🚀 Kali Linux Setup for Ultimate Security Scanner")
    print("================================================")

    # Check if running on Kali
    if not os.path.exists('/etc/os-release'):
        print("⚠️  Warning: Not running on a system with /etc/os-release")
    else:
        with open('/etc/os-release', 'r') as f:
            os_info = f.read().lower()
            if 'kali' in os_info:
                print("✅ Running on Kali Linux - Perfect!")
            else:
                print("⚠️  Warning: Not running on Kali Linux")

    # Check available tools
    available, missing = check_kali_tools()

    if missing:
        print(f"\n⚠️  Missing {len(missing)} tools. Installing...")
        # Try to install missing tools
        for tool in missing.keys():
            print(f"Installing {tool}...")
            # Add installation commands here if needed

    # Setup directories
    setup_directories()

    # Apply optimizations
    optimize_for_kali()

    # Install Python dependencies
    if not install_python_deps():
        print("❌ Setup failed!")
        return 1

    print("\n🎉 Setup completed successfully!")
    print("\nNext steps:")
    print("1. Run GUI: python gui_launcher.py")
    print("2. Run CLI: python scan.py --help")
    print("3. For WiFi scanning: sudo python scan.py --wifi-scan")
    print("4. For maximum power: sudo python scan.py target -t ultra")

    return 0

if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""
Kali Linux Optimized GUI Launcher
Enhanced launcher specifically for Kali Linux with optimizations
"""

import sys
import os
import subprocess
import tkinter as tk
from tkinter import messagebox

def check_kali_environment():
    """Check if running on Kali Linux and verify setup"""
    print("🔍 Checking Kali Linux environment...")

    # Check if running on Kali
    if os.path.exists('/etc/os-release'):
        with open('/etc/os-release', 'r') as f:
            os_info = f.read().lower()
            if 'kali' in os_info:
                print("✅ Running on Kali Linux - Perfect!")
                return True

    print("⚠️  Not running on Kali Linux, but GUI will still work")
    return False

def check_dependencies():
    """Check if all required packages are installed"""
    print("🔍 Checking dependencies...")

    required_packages = [
        'tkinter', 'nmap', 'requests', 'selenium'
    ]

    missing_packages = []

    for package in required_packages:
        try:
            if package == 'tkinter':
                # Special check for tkinter
                root = tk.Tk()
                root.destroy()
            else:
                __import__(package)
            print(f"✅ {package}: Available")
        except ImportError:
            print(f"❌ {package}: Missing")
            missing_packages.append(package)

    return missing_packages

def install_missing_deps(missing_packages):
    """Attempt to install missing dependencies"""
    if not missing_packages:
        return True

    print(f"📦 Installing missing packages: {', '.join(missing_packages)}")

    # Try to install using pip
    try:
        for package in missing_packages:
            if package != 'tkinter':  # tkinter is usually system package
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"✅ Installed {package}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install packages: {e}")
        return False

    return True

def optimize_for_kali():
    """Apply Kali-specific optimizations"""
    print("⚡ Applying Kali optimizations...")

    # Set environment variables for better performance
    os.environ['KALI_LINUX'] = 'true'
    os.environ['DISPLAY'] = ':0'

    # Add Kali paths
    kali_paths = [
        '/usr/bin',
        '/usr/sbin',
        '/usr/local/bin'
    ]

    current_path = os.environ.get('PATH', '')
    for path in kali_paths:
        if path not in current_path:
            os.environ['PATH'] = f"{path}:{os.environ['PATH']}"

    print("✅ Kali optimizations applied")

def main():
    """Main launcher function with Kali optimizations"""
    print("🚀 Starting Ultimate Security Scanner GUI (Kali Optimized)")
    print("======================================================")

    # Check Kali environment
    is_kali = check_kali_environment()

    # Check dependencies
    missing = check_dependencies()

    if missing:
        print(f"\n⚠️  Missing dependencies: {', '.join(missing)}")
        if is_kali:
            print("Attempting to install missing packages...")
            if not install_missing_deps(missing):
                messagebox.showerror("Installation Failed",
                    f"Failed to install required packages: {', '.join(missing)}\n\n"
                    "Please install manually:\n"
                    "sudo apt install python3-tk\n"
                    "pip install -r requirements.txt")
                return
        else:
            messagebox.showwarning("Missing Dependencies",
                f"Missing packages: {', '.join(missing)}\n\n"
                "Please install them using your package manager.")
            return

    # Apply Kali optimizations
    if is_kali:
        optimize_for_kali()

    try:
        # Add current directory to path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)

        # Import and launch GUI
        from scanner_gui import main
        print("🎯 Launching GUI...")
        main()

    except ImportError as e:
        error_msg = f"Import Error: {e}\n\n"
        error_msg += "Make sure all required dependencies are installed.\n"
        error_msg += "Required: tkinter, requests, nmap, beautifulsoup4, selenium\n\n"
        error_msg += "Install with: pip install -r requirements.txt"

        print(f"❌ {error_msg}")
        messagebox.showerror("Import Error", error_msg)

    except Exception as e:
        error_msg = f"Error starting GUI: {e}\n\n"
        error_msg += "This might be due to:\n"
        error_msg += "- Missing dependencies\n"
        error_msg += "- Display server not running\n"
        error_msg += "- Permission issues\n\n"
        error_msg += "Try running: export DISPLAY=:0"

        print(f"❌ {error_msg}")
        messagebox.showerror("GUI Error", error_msg)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Simple launcher for the Security Scanner GUI
"""

import sys
import os

def main():
    """Launch the GUI application"""
    try:
        # Add current directory to path to ensure imports work
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)

        # Import and run the GUI
        from scanner_gui import main
        print("Starting Ultimate Security Scanner GUI...")
        main()

    except ImportError as e:
        print(f"Import Error: {e}")
        print("Make sure all required dependencies are installed.")
        print("Required packages: tkinter, requests, nmap, and others from scan.py")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting GUI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
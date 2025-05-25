#!/usr/bin/env python3
"""
Main entry point for the Malware Detector application.
"""

import sys
import os
import tkinter as tk
from malware_detector import MalwareDetectorApp

def main():
    """Start the malware detector application."""
    print("Starting Malware Detector...")
    
    # Ensure the test_files directory exists
    if not os.path.exists("test_files"):
        os.makedirs("test_files")
        print("Created test_files directory")
    
    # Start the UI
    root = tk.Tk()
    app = MalwareDetectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1) 
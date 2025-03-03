# main.py
import sys
import tkinter as tk
from core.scanner import VulnerabilityScanner
from ui.cli import CommandLineInterface
from ui.gui import ScannerApp

def main():
    """Main entry point for the web vulnerability scanner"""
    scanner = VulnerabilityScanner()
    
    # If command line arguments are provided, use CLI
    if len(sys.argv) > 1:
        cli = CommandLineInterface(scanner)
        cli.run()
    else:
        # Otherwise, launch the GUI
        root = tk.Tk()
        app = ScannerApp(root, scanner)
        root.mainloop()

if __name__ == "__main__":
    main()
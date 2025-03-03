#!/usr/bin/env python3
"""
Enhanced GUI interface for the web vulnerability scanner.
Provides a modern user-friendly interface to configure and run scans.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import json
import requests
import threading
import os
import sys
from datetime import datetime
import webbrowser
from PIL import Image, ImageTk
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class ScannerApp:
    """Enhanced GUI application for the vulnerability scanner"""
    
    def __init__(self, root, scanner):
        """Initialize the GUI application
        
        Args:
            root: Tkinter root window
            scanner: VulnerabilityScanner instance
        """
        self.root = root
        self.root.title("Web Vulnerability Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Set dark theme colors
        self.bg_color = "#2d2d2d"
        self.fg_color = "#ffffff"
        self.accent_color = "#4c8bf5"  # Blue accent
        self.success_color = "#4CAF50"  # Green
        self.warning_color = "#FFC107"  # Yellow/Orange
        self.danger_color = "#F44336"   # Red
        
        # Configure styles
        self.configure_styles()
        
        self.scanner = scanner
        self.scan_thread = None
        self.create_ui()
        
        # Initialize data visualization variables
        self.vulnerability_counts = {}
        
        # Load saved settings
        self.load_settings()
    
    def configure_styles(self):
        """Configure custom styles for the application"""
        style = ttk.Style()
        style.theme_use('clam')  # Use a theme that's easy to customize
        
        # Configure colors
        style.configure(".", 
                        background=self.bg_color, 
                        foreground=self.fg_color, 
                        fieldbackground=self.bg_color,
                        troughcolor=self.bg_color,
                        bordercolor=self.accent_color)
        
        # Configure TButton
        style.configure("TButton", 
                        background=self.accent_color, 
                        foreground=self.fg_color,
                        padding=10,
                        font=('Arial', 10, 'bold'))
        style.map("TButton",
                 background=[('active', self.accent_color), ('pressed', '#3a7af5')])
        
        # Configure danger button
        style.configure("Danger.TButton", 
                        background=self.danger_color, 
                        foreground=self.fg_color)
        style.map("Danger.TButton",
                 background=[('active', self.danger_color), ('pressed', '#d32f2f')])
        
        # Configure success button
        style.configure("Success.TButton", 
                        background=self.success_color, 
                        foreground=self.fg_color)
        style.map("Success.TButton",
                 background=[('active', self.success_color), ('pressed', '#388E3C')])
        
        # Configure TLabel
        style.configure("TLabel", 
                        background=self.bg_color, 
                        foreground=self.fg_color)
        
        # Configure TFrame
        style.configure("TFrame", 
                        background=self.bg_color)
        
        # Configure TLabelframe
        style.configure("TLabelframe", 
                        background=self.bg_color, 
                        foreground=self.fg_color)
        style.configure("TLabelframe.Label", 
                        background=self.bg_color, 
                        foreground=self.fg_color,
                        font=('Arial', 10, 'bold'))
        
        # Configure TNotebook
        style.configure("TNotebook", 
                        background=self.bg_color, 
                        tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", 
                        background="#1f1f1f", 
                        foreground=self.fg_color,
                        padding=[10, 5],
                        font=('Arial', 10))
        style.map("TNotebook.Tab",
                 background=[('selected', self.accent_color)],
                 foreground=[('selected', "#ffffff")])
        
        # Configure Treeview
        style.configure("Treeview", 
                        background="#3d3d3d", 
                        foreground=self.fg_color,
                        rowheight=25,
                        borderwidth=0,
                        font=('Arial', 9))
        style.configure("Treeview.Heading", 
                        background="#1f1f1f", 
                        foreground=self.fg_color,
                        font=('Arial', 10, 'bold'))
        style.map("Treeview",
                 background=[('selected', self.accent_color)])
        
        # Configure TEntry
        style.configure("TEntry", 
                        fieldbackground="#3d3d3d", 
                        foreground=self.fg_color,
                        borderwidth=1,
                        padding=5)
        
        # Configure TCheckbutton
        style.configure("TCheckbutton", 
                        background=self.bg_color, 
                        foreground=self.fg_color)
        
        # Configure TRadiobutton
        style.configure("TRadiobutton", 
                        background=self.bg_color, 
                        foreground=self.fg_color)
        
        # Configure TCombobox
        style.configure("TCombobox", 
                        fieldbackground="#3d3d3d", 
                        foreground=self.fg_color,
                        padding=5)
        
        # Configure TSpinbox
        style.configure("TSpinbox", 
                        fieldbackground="#3d3d3d", 
                        foreground=self.fg_color,
                        padding=5)
        
        # Configure Horizontal TProgressbar
        style.configure("Horizontal.TProgressbar", 
                        background=self.accent_color, 
                        troughcolor="#1f1f1f")
    
    def create_ui(self):
        """Create the main UI components"""
        # Create main container with padding
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add application logo/header
        self.create_header()
        
        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create tabs
        self.scan_tab = ttk.Frame(self.notebook)
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.results_tab = ttk.Frame(self.notebook)
        self.report_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.scan_tab, text="Scan")
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.results_tab, text="Results")
        self.notebook.add(self.report_tab, text="Report")
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Set up individual tabs
        self.setup_scan_tab()
        self.setup_dashboard_tab()
        self.setup_results_tab()
        self.setup_report_tab()
        self.setup_settings_tab()
        
        # Add a status bar
        self.create_status_bar()
    
    def show_help(self):
        """Show help information"""
        help_text = """
        Web Vulnerability Scanner Help
        
        This application allows you to scan websites for common security vulnerabilities.
        
        Basic Usage:
        1. Enter a target URL in the URL field
        2. Select which vulnerability checks to run
        3. Click 'Start Scan' to begin scanning
        4. View results in the Results tab
        
        For more information and documentation, visit:
        https://github.com/your-username/web-vulnerability-scanner
        """
        messagebox.showinfo("Help", help_text)

    def show_url_history(self):
        """Show URL history dropdown"""
        # This would normally display a dropdown of previously scanned URLs
        # For now, we'll just show a placeholder message
        messagebox.showinfo("URL History", "URL history feature will be implemented in a future version.")

    def toggle_auth_options(self):
        """Enable/disable authentication options based on checkbox state"""
        state = tk.NORMAL if self.auth_var.get() else tk.DISABLED
        self.username_entry.config(state=state)
        self.password_entry.config(state=state)
        self.login_url_entry.config(state=state)

    def toggle_logo_options(self):
        """Enable/disable logo selection based on checkbox state"""
        state = tk.NORMAL if self.include_logo_var.get() else tk.DISABLED
        self.logo_button.config(state=state)

    def select_logo(self):
        """Open file dialog to select a logo file"""
        logo_file = filedialog.askopenfilename(
            title="Select Logo",
            filetypes=[("Image Files", "*.png *.jpg *.jpeg *.gif")]
        )
        if logo_file:
            self.update_status(f"Logo selected: {os.path.basename(logo_file)}")

    def toggle_proxy_options(self):
        """Enable/disable proxy options based on checkbox state"""
        state = tk.NORMAL if self.use_proxy.get() else tk.DISABLED
        self.proxy_url.config(state=state)
        self.test_proxy_button.config(state=state)
        # Also update the auth checkbox state
        self.proxy_auth_var.set(False)  # Reset when toggling
        ttk.Checkbutton(self.proxy_frame, text="Proxy Authentication", 
                    variable=self.proxy_auth_var,
                    command=self.toggle_proxy_auth, state=state)

    def toggle_proxy_auth(self):
        """Enable/disable proxy authentication options based on checkbox state"""
        state = tk.NORMAL if self.proxy_auth_var.get() else tk.DISABLED
        self.proxy_username.config(state=state)
        self.proxy_password.config(state=state)

    def test_proxy_connection(self):
        """Test the proxy connection"""
        proxy_url = self.proxy_url.get()
        if not proxy_url:
            messagebox.showerror("Error", "Please enter a proxy URL")
            return
        
        try:
            # Dummy request to test proxy
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            requests.get("https://www.google.com", proxies=proxies, timeout=5)
            messagebox.showinfo("Success", "Proxy connection successful!")
        except Exception as e:
            messagebox.showerror("Error", f"Proxy connection failed: {str(e)}")

    def browse_report_dir(self):
        """Open directory browser to select report directory"""
        report_dir = filedialog.askdirectory(title="Select Report Directory")
        if report_dir:
            self.report_dir_entry.delete(0, tk.END)
            self.report_dir_entry.insert(0, report_dir)

    def toggle_all_checks(self):
        """Toggle all vulnerability checks based on the 'Select All' checkbox"""
        state = self.check_all_var.get()
        for var in self.check_vars.values():
            var.set(state)

    def filter_results(self, event=None):
        """Filter results based on selected filter"""
        filter_value = self.filter_var.get()
        # Clear current items
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # This is a placeholder - in a real implementation, you'd filter the actual results
        # For now, we'll just show a message
        self.update_status(f"Results filtered: {filter_value}")

    def export_results(self):
        """Export scan results to a file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if file_path:
            # Placeholder - would actually save results to the file
            messagebox.showinfo("Export", f"Results would be exported to {file_path}")

    def show_vulnerability_details(self, event):
        """Display details for the selected vulnerability"""
        selected_items = self.results_tree.selection()
        if not selected_items:
            return
        
        # Get the vulnerability type from the selected item
        item = selected_items[0]
        values = self.results_tree.item(item, 'values')
        if not values or len(values) < 1:
            return
            
        vuln_type = values[0]
        status = values[1]
        severity = values[2]
        
        # Display details (this is just a placeholder with sample data)
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        self.details_text.insert(tk.END, f"{vuln_type}\n", "title")
        self.details_text.insert(tk.END, f"\nStatus: {status}\n")
        self.details_text.insert(tk.END, f"Severity: {severity}\n", severity.lower())
        self.details_text.insert(tk.END, "\nDescription:\n", "section")
        self.details_text.insert(tk.END, "This is a sample description of the vulnerability.\n")
        self.details_text.insert(tk.END, "\nAffected URLs:\n", "section")
        self.details_text.insert(tk.END, "https://example.com/vulnerable-page\n")
        
        self.details_text.config(state=tk.DISABLED)
        
        # Evidence tab
        self.evidence_text.config(state=tk.NORMAL)
        self.evidence_text.delete(1.0, tk.END)
        self.evidence_text.insert(tk.END, "Sample evidence for the vulnerability would be shown here.\n")
        self.evidence_text.insert(tk.END, "Request and response data that demonstrates the issue.\n")
        self.evidence_text.config(state=tk.DISABLED)
        
        # Remediation tab
        self.remediation_text.config(state=tk.NORMAL)
        self.remediation_text.delete(1.0, tk.END)
        self.remediation_text.insert(tk.END, "Recommendations to fix this vulnerability:\n\n")
        self.remediation_text.insert(tk.END, "1. Implement proper input validation\n")
        self.remediation_text.insert(tk.END, "2. Apply output encoding\n")
        self.remediation_text.insert(tk.END, "3. Consider using a Web Application Firewall\n")
        self.remediation_text.config(state=tk.DISABLED)
        
        # References tab
        self.reference_text.config(state=tk.NORMAL)
        self.reference_text.delete(1.0, tk.END)
        self.reference_text.insert(tk.END, "References:\n\n")
        self.reference_text.insert(tk.END, "- OWASP: https://owasp.org/\n")
        self.reference_text.insert(tk.END, "- CWE: https://cwe.mitre.org/\n")
        self.reference_text.insert(tk.END, "- NIST: https://www.nist.gov/\n")
        self.reference_text.config(state=tk.DISABLED)

    def preview_report(self):
        """Generate a report preview"""
        # This is a placeholder - would generate an actual report preview
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete(1.0, tk.END)
        
        report_title = self.report_title.get()
        report_format = self.report_format.get()
        
        self.preview_text.insert(tk.END, f"# {report_title}\n\n")
        self.preview_text.insert(tk.END, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        self.preview_text.insert(tk.END, "## Executive Summary\n\n")
        self.preview_text.insert(tk.END, "This is a sample report preview in {report_format} format.\n")
        self.preview_text.insert(tk.END, "The actual report would contain detailed vulnerability information.\n\n")
        self.preview_text.insert(tk.END, "## Vulnerabilities Found\n\n")
        self.preview_text.insert(tk.END, "- Sample Vulnerability 1 (High)\n")
        self.preview_text.insert(tk.END, "- Sample Vulnerability 2 (Medium)\n")
        
        self.preview_text.config(state=tk.DISABLED)
        self.update_status(f"Report preview generated in {report_format} format")

    def save_report(self):
        """Save the generated report to a file"""
        report_format = self.report_format.get().lower()
        file_extensions = {'html': '.html', 'pdf': '.pdf', 'json': '.json', 'text': '.txt'}
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=file_extensions.get(report_format, '.html'),
            filetypes=[(f"{report_format.upper()} Files", f"*{file_extensions.get(report_format, '.html')}"), 
                    ("All Files", "*.*")]
        )
        
        if file_path:
            # Placeholder - would actually save the report
            messagebox.showinfo("Save Report", f"Report would be saved to {file_path}")

    def clear_scan_form(self):
        """Clear the scan form inputs"""
        self.url_entry.delete(0, tk.END)
        self.check_all_var.set(True)
        self.toggle_all_checks()

    def clear_log(self):
        """Clear the log text area"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def save_log(self):
        """Save log contents to a file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                self.log_text.config(state=tk.NORMAL)
                log_content = self.log_text.get(1.0, tk.END)
                self.log_text.config(state=tk.DISABLED)
                
                with open(file_path, 'w') as f:
                    f.write(log_content)
                    
                messagebox.showinfo("Success", f"Log saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {str(e)}")

    def clear_cookies(self):
        """Clear stored cookies"""
        # This is a placeholder - would actually clear cookies
        messagebox.showinfo("Cookies Cleared", "All stored cookies have been cleared.")

    def reset_settings(self):
        """Reset all settings to defaults"""
        confirm = messagebox.askyesno("Confirm Reset", 
                                    "Are you sure you want to reset all settings to default values?")
        if confirm:
            # This is a placeholder - would actually reset settings
            messagebox.showinfo("Settings Reset", "All settings have been reset to default values.")

    def save_settings(self):
        """Save current settings"""
        # This is a placeholder - would actually save settings
        messagebox.showinfo("Settings Saved", "Settings have been saved successfully.")

    def load_settings(self):
        """Load saved settings"""
        # This is a placeholder - would actually load settings
        pass

    def start_scan(self):
        """Start the vulnerability scan"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to scan")
            return
        
        # Get scan options - which checks to run
        selected_checks = [
            check_name for check_name, var in self.check_vars.items() 
            if var.get()
        ]
        
        if not selected_checks:
            messagebox.showerror("Error", "Please select at least one vulnerability check")
            return
        
        # Get max workers
        try:
            max_workers = int(self.max_workers.get())
        except ValueError:
            max_workers = 5
        
        # Update UI state
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_log()
        self.progress['value'] = 0
        self.current_task_label.config(text="Initializing scan...")
        
        # Log the scan start
        self.log_message(f"Starting scan of {url}", "info")
        self.log_message(f"Selected checks: {', '.join(selected_checks)}", "info")
        
        # Start scan in a separate thread
        self.scan_thread = threading.Thread(
            target=self.scanner.scan,
            args=(url, selected_checks, max_workers),
            kwargs={'progress_callback': self.update_progress}
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Poll for completion
        self.root.after(100, self.check_scan_complete)

    def update_progress(self, percentage, check_name, result):
        """Update progress in the UI
        
        Args:
            percentage: Scan progress percentage (0-100)
            check_name: Name of the current check
            result: Result of the check
        """
        self.progress['value'] = percentage
        self.current_task_label.config(text=f"Running: {check_name}")
        
        # Log the result
        if result.get('vulnerable', False):
            status = "VULNERABLE"
            tag = "error"
        else:
            status = "SECURE"
            tag = "success"
        
        self.log_message(f"{check_name}: {status}", tag)
        
        # Update results in real-time
        self.update_results_tree(check_name, result)

    def stop_scan(self):
        """Stop the current scan"""
        self.scanner.stop_scan()
        self.log_message("Scan stopped by user", "warning")
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.current_task_label.config(text="Scan stopped")

    def check_scan_complete(self):
        """Check if the scan has completed"""
        if self.scan_thread and self.scan_thread.is_alive():
            self.root.after(100, self.check_scan_complete)
        else:
            self.scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.log_message("Scan completed!", "success")
            self.current_task_label.config(text="Scan completed")
            self.notebook.select(self.results_tab)
            
            # Update the dashboard with scan results
            self.update_dashboard()

    def log_message(self, message, tag="info"):
        """Add a message to the log with appropriate tag
        
        Args:
            message: Message to log
            tag: Message tag for styling (info, success, warning, error)
        """
        self.log_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.log_text.insert(tk.END, f"{message}\n", tag)
        
        if self.autoscroll_var.get():
            self.log_text.see(tk.END)
        
        self.log_text.config(state=tk.DISABLED)

    def update_results_tree(self, check_name, result):
        """Update the results treeview with a new result"""
        # Add to treeview
        status = "Vulnerable" if result.get('vulnerable', False) else "Secure"
        details_count = len(result.get('details', []))
        
        # Determine severity (placeholder logic - would be more sophisticated in real implementation)
        if result.get('vulnerable', False):
            if check_name.lower() in ['sqli', 'xss', 'rce']:
                severity = "High"
            elif check_name.lower() in ['csrf', 'open_redirect', 'xxe']:
                severity = "Medium"
            else:
                severity = "Low"
        else:
            severity = "None"
        
        # Format details summary
        if details_count > 0:
            details_text = f"{details_count} issues found"
        else:
            details_text = "No issues found"
        
        # Insert or update the item
        item_id = f"check_{check_name}"
        
        # Check if item already exists
        existing_items = self.results_tree.get_children('')
        for item in existing_items:
            if self.results_tree.item(item, 'text') == item_id:
                self.results_tree.delete(item)
                break
        
        # Add new item
        self.results_tree.insert(
            '', tk.END, 
            text=item_id,
            values=(check_name, status, severity, details_text), 
            tags=(status.lower(),)
        )
        
        # Configure tag colors
        self.results_tree.tag_configure('vulnerable', background='#ffcccc')
        self.results_tree.tag_configure('secure', background='#ccffcc')

    def update_dashboard(self):
        """Update dashboard with current scan data"""
        # This is a placeholder - would update with actual scan data
        # In a real implementation, this would pull data from the scanner results
        
        # Update vulnerability counts for the pie chart
        self.vulnerability_counts = {
            'XSS': 2,
            'SQLi': 1,
            'CSRF': 0,
            'Headers': 3,
            'Other': 1
        }
        
        # You would update the actual charts and summary cards here
        # For now, we'll just log that the dashboard was updated
        self.update_status("Dashboard updated with latest scan results")















    def create_header(self):
        """Create the application header with logo"""
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # App name/logo
        title_label = ttk.Label(header_frame, text="Web Vulnerability Scanner", 
                               font=('Arial', 18, 'bold'), foreground=self.accent_color)
        title_label.pack(side=tk.LEFT)
        
        # Version info
        version_label = ttk.Label(header_frame, text="v1.0.0", font=('Arial', 9))
        version_label.pack(side=tk.LEFT, padx=10)
        
        # Help button
        help_button = ttk.Button(header_frame, text="?", width=3, 
                                command=self.show_help)
        help_button.pack(side=tk.RIGHT, padx=5)
    
    def create_status_bar(self):
        """Create a status bar at the bottom of the window"""
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, padding=(5, 2))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_status(self, message):
        """Update the status bar message"""
        self.status_bar.config(text=message)
    
    def setup_scan_tab(self):
        """Set up the scan tab interface"""
        # Create left and right panes
        scan_panes = ttk.PanedWindow(self.scan_tab, orient=tk.HORIZONTAL)
        scan_panes.pack(fill=tk.BOTH, expand=True)
        
        # Left pane for scan configuration
        left_pane = ttk.Frame(scan_panes)
        scan_panes.add(left_pane, weight=1)
        
        # Right pane for scan log
        right_pane = ttk.Frame(scan_panes)
        scan_panes.add(right_pane, weight=1)
        
        # ===== Left Pane - Scan Configuration =====
        # Target URL input
        target_frame = ttk.LabelFrame(left_pane, text="Target")
        target_frame.pack(fill=tk.X, pady=5, padx=5)
        
        ttk.Label(target_frame, text="URL:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        url_frame = ttk.Frame(target_frame)
        url_frame.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.url_history_button = ttk.Button(url_frame, text="▼", width=3, 
                                           command=self.show_url_history)
        self.url_history_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        ttk.Label(target_frame, text="Examples: example.com, https://example.com/path").grid(row=1, column=0, columnspan=2, padx=5, pady=(0, 5), sticky=tk.W)
        
        # Scan scope options
        scope_frame = ttk.LabelFrame(left_pane, text="Scan Scope")
        scope_frame.pack(fill=tk.X, pady=5, padx=5)
        
        self.crawl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(scope_frame, text="Crawl website", variable=self.crawl_var).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(scope_frame, text="Crawl depth:").grid(row=0, column=1, padx=(20, 5), pady=5, sticky=tk.W)
        self.crawl_depth = ttk.Spinbox(scope_frame, from_=1, to=10, width=5)
        self.crawl_depth.set(3)
        self.crawl_depth.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        
        self.same_domain_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(scope_frame, text="Same domain only", variable=self.same_domain_var).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.respect_robots_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(scope_frame, text="Respect robots.txt", variable=self.respect_robots_var).grid(row=1, column=1, columnspan=2, padx=(20, 5), pady=5, sticky=tk.W)
        
        # Authentication options frame
        auth_frame = ttk.LabelFrame(left_pane, text="Authentication (Optional)")
        auth_frame.pack(fill=tk.X, pady=5, padx=5)
        
        self.auth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(auth_frame, text="Login required", variable=self.auth_var, 
                      command=self.toggle_auth_options).grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(auth_frame, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.username_entry = ttk.Entry(auth_frame, state=tk.DISABLED)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(auth_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(auth_frame, show="•", state=tk.DISABLED)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(auth_frame, text="Login URL:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.login_url_entry = ttk.Entry(auth_frame, state=tk.DISABLED)
        self.login_url_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Vulnerability checks frame
        checks_frame = ttk.LabelFrame(left_pane, text="Vulnerability Checks")
        checks_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)
        
        # Create a scrollable frame for checks
        canvas = tk.Canvas(checks_frame, background=self.bg_color, highlightthickness=0)
        scrollbar = ttk.Scrollbar(checks_frame, orient="vertical", command=canvas.yview)
        
        scrollable_frame = ttk.Frame(canvas)
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Create checkboxes for vulnerability checks
        self.check_vars = {}
        
        # Add the check all option
        self.check_all_var = tk.BooleanVar(value=True)
        check_all_btn = ttk.Checkbutton(scrollable_frame, text="Select All", variable=self.check_all_var, 
                                     command=self.toggle_all_checks)
        check_all_btn.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Add a separator
        ttk.Separator(scrollable_frame, orient=tk.HORIZONTAL).grid(row=1, column=0, columnspan=2, sticky=tk.EW, pady=5)
        
        # Create a checkbutton for each available vulnerability check
        row, col = 2, 0
        for check_name, check_obj in self.scanner.checks.items():
            self.check_vars[check_name] = tk.BooleanVar(value=True)
            ttk.Checkbutton(
                scrollable_frame, 
                text=check_obj.name if hasattr(check_obj, 'name') else check_name.capitalize(),
                variable=self.check_vars[check_name]
            ).grid(row=row, column=col, padx=5, pady=2, sticky=tk.W)
            
            col += 1
            if col > 1:  # Two columns of checkboxes
                col = 0
                row += 1
        
        # Buttons frame
        buttons_frame = ttk.Frame(left_pane)
        buttons_frame.pack(fill=tk.X, pady=10, padx=5)
        
        self.scan_button = ttk.Button(buttons_frame, text="Start Scan", style="Success.TButton",
                                    command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="Stop Scan", style="Danger.TButton",
                                    command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(buttons_frame, text="Clear",
                                     command=self.clear_scan_form)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # ===== Right Pane - Scan Log =====
        log_frame = ttk.LabelFrame(right_pane, text="Scan Log")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)
        
        # Progress indicators
        progress_frame = ttk.Frame(log_frame)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(progress_frame, text="Progress:").grid(row=0, column=0, sticky=tk.W)
        self.progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.grid(row=0, column=1, sticky=tk.W+tk.E, padx=(5, 0))
        progress_frame.columnconfigure(1, weight=1)
        
        # Current task label
        self.current_task_label = ttk.Label(log_frame, text="Ready")
        self.current_task_label.pack(fill=tk.X, padx=5, pady=(0, 5), anchor=tk.W)
        
        # Log area
        log_container = ttk.Frame(log_frame)
        log_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_container, height=15, background="#1c1c1c", foreground="#e0e0e0", font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Apply custom tags for log formatting
        self.log_text.tag_configure("info", foreground="#ffffff")
        self.log_text.tag_configure("success", foreground="#4CAF50")
        self.log_text.tag_configure("warning", foreground="#FFC107")
        self.log_text.tag_configure("error", foreground="#F44336")
        self.log_text.tag_configure("timestamp", foreground="#888888")
        
        # Log controls
        log_controls = ttk.Frame(log_frame)
        log_controls.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        self.autoscroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_controls, text="Auto-scroll", variable=self.autoscroll_var).pack(side=tk.LEFT)
        
        clear_log_btn = ttk.Button(log_controls, text="Clear Log", command=self.clear_log)
        clear_log_btn.pack(side=tk.RIGHT)
        
        save_log_btn = ttk.Button(log_controls, text="Save Log", command=self.save_log)
        save_log_btn.pack(side=tk.RIGHT, padx=(0, 5))
    
    def setup_dashboard_tab(self):
        """Set up the dashboard tab with data visualization"""
        # Create a container frame
        dashboard_container = ttk.Frame(self.dashboard_tab)
        dashboard_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top section - Summary cards
        top_frame = ttk.Frame(dashboard_container)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create summary cards
        self.create_summary_card(top_frame, "Total Scans", "0", "#4c8bf5")
        self.create_summary_card(top_frame, "Vulnerabilities Found", "0", "#F44336")
        self.create_summary_card(top_frame, "Scanned URLs", "0", "#4CAF50")
        self.create_summary_card(top_frame, "Avg. Scan Time", "0 min", "#FFC107")
        
        # Middle section - Charts
        middle_frame = ttk.Frame(dashboard_container)
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create left and right chart containers
        chart_left = ttk.LabelFrame(middle_frame, text="Vulnerability Distribution")
        chart_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        chart_right = ttk.LabelFrame(middle_frame, text="Vulnerability Severity")
        chart_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Create charts
        self.create_pie_chart(chart_left)
        self.create_bar_chart(chart_right)
        
        # Bottom section - Recent scans
        bottom_frame = ttk.LabelFrame(dashboard_container, text="Recent Scans")
        bottom_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create a treeview for recent scans
        columns = ('timestamp', 'target', 'vulnerabilities', 'status')
        self.recent_scans_tree = ttk.Treeview(bottom_frame, columns=columns, show='headings')
        
        # Define headings
        self.recent_scans_tree.heading('timestamp', text='Date & Time')
        self.recent_scans_tree.heading('target', text='Target')
        self.recent_scans_tree.heading('vulnerabilities', text='Vulnerabilities')
        self.recent_scans_tree.heading('status', text='Status')
        
        # Set column widths
        self.recent_scans_tree.column('timestamp', width=150)
        self.recent_scans_tree.column('target', width=250)
        self.recent_scans_tree.column('vulnerabilities', width=120)
        self.recent_scans_tree.column('status', width=100)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(bottom_frame, orient=tk.VERTICAL, command=self.recent_scans_tree.yview)
        self.recent_scans_tree.configure(yscroll=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.recent_scans_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add some sample data
        for i in range(5):
            self.recent_scans_tree.insert('', tk.END, values=(
                f"2023-05-{10+i} 14:30:45",
                f"https://example{i}.com",
                f"{i*2} (High: {i})",
                "Completed"
            ))
    
    def create_summary_card(self, parent, title, value, color):
        """Create a summary card widget
        
        Args:
            parent: Parent widget
            title: Card title
            value: Card value
            color: Card accent color
        """
        # Create a frame with a standard tkinter Frame for the border
        card = ttk.Frame(parent, style="TFrame")
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Add a colored top border using standard tk.Frame (not ttk)
        border = tk.Frame(card, height=3, background=color)
        border.pack(fill=tk.X)
        
        # Add card content
        value_label = ttk.Label(card, text=value, font=('Arial', 24, 'bold'))
        value_label.pack(pady=(20, 5))
        
        title_label = ttk.Label(card, text=title, font=('Arial', 10))
        title_label.pack(pady=(0, 20))
        
        # Store references to labels for updating
        card.value_label = value_label
        card.title_label = title_label
        
        return card
    
    def create_pie_chart(self, parent):
        """Create a pie chart for vulnerability distribution"""
        # Sample data
        labels = ['XSS', 'SQLi', 'CSRF', 'Headers', 'Other']
        sizes = [25, 20, 15, 30, 10]
        colors = ['#4c8bf5', '#F44336', '#4CAF50', '#FFC107', '#9C27B0']
        
        # Create figure and axis
        figure = Figure(figsize=(4, 3), dpi=100, facecolor=self.bg_color)
        axis = figure.add_subplot(111)
        
        # Create pie chart
        wedges, texts, autotexts = axis.pie(
            sizes, 
            labels=labels, 
            autopct='%1.1f%%',
            startangle=90,
            colors=colors
        )
        
        # Set properties
        for text in texts + autotexts:
            text.set_color(self.fg_color)
        axis.set_facecolor(self.bg_color)
        figure.patch.set_facecolor(self.bg_color)
        
        # Create canvas
        canvas = FigureCanvasTkAgg(figure, parent)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_bar_chart(self, parent):
        """Create a bar chart for vulnerability severity"""
        # Sample data
        categories = ['High', 'Medium', 'Low', 'Info']
        values = [12, 19, 15, 8]
        colors = ['#F44336', '#FFC107', '#4CAF50', '#2196F3']
        
        # Create figure and axis
        figure = Figure(figsize=(4, 3), dpi=100, facecolor=self.bg_color)
        axis = figure.add_subplot(111)
        
        # Create bar chart
        bars = axis.bar(
            categories, 
            values,
            color=colors,
            width=0.6
        )
        
        # Set properties
        axis.set_facecolor(self.bg_color)
        axis.spines['bottom'].set_color(self.fg_color)
        axis.spines['top'].set_color(self.bg_color)
        axis.spines['right'].set_color(self.bg_color)
        axis.spines['left'].set_color(self.fg_color)
        axis.tick_params(axis='x', colors=self.fg_color)
        axis.tick_params(axis='y', colors=self.fg_color)
        
        # Add labels on top of bars
        for bar in bars:
            height = bar.get_height()
            axis.text(
                bar.get_x() + bar.get_width()/2.,
                height,
                '%d' % int(height),
                ha='center',
                va='bottom',
                color=self.fg_color
            )
        
        # Create canvas
        canvas = FigureCanvasTkAgg(figure, parent)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def setup_results_tab(self):
        """Set up the results tab interface"""
        # Create a container frame
        results_container = ttk.Frame(self.results_tab)
        results_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create a paned window
        results_pane = ttk.PanedWindow(results_container, orient=tk.VERTICAL)
        results_pane.pack(fill=tk.BOTH, expand=True)
        
        # Top pane - Results treeview
        top_frame = ttk.Frame(results_pane)
        results_pane.add(top_frame, weight=1)
        
        # Create a frame to hold the treeview
        tree_frame = ttk.Frame(top_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add filter controls
        filter_frame = ttk.Frame(tree_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.filter_var = tk.StringVar(value="All")
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, 
                                values=["All", "Vulnerable", "Secure"], 
                                state="readonly", width=15)
        filter_combo.pack(side=tk.LEFT)
        filter_combo.bind("<<ComboboxSelected>>", self.filter_results)
        
        export_button = ttk.Button(filter_frame, text="Export Results", 
                                command=self.export_results)
        export_button.pack(side=tk.RIGHT)
        
        # Create the treeview with columns
        columns = ('vulnerability', 'status', 'severity', 'details')
        self.results_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        
        # Define headings
        self.results_tree.heading('vulnerability', text='Vulnerability Type')
        self.results_tree.heading('status', text='Status')
        self.results_tree.heading('severity', text='Severity')
        self.results_tree.heading('details', text='Details')
        
        # Set column widths
        self.results_tree.column('vulnerability', width=200)
        self.results_tree.column('status', width=100)
        self.results_tree.column('severity', width=100)
        self.results_tree.column('details', width=600)
        
        # Add a scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscroll=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bottom pane - Details view with tabs
        bottom_frame = ttk.Frame(results_pane)
        results_pane.add(bottom_frame, weight=1)
        
        # Create detail tabs
        detail_notebook = ttk.Notebook(bottom_frame)
        detail_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Details tab
        details_tab = ttk.Frame(detail_notebook)
        detail_notebook.add(details_tab, text="Details")
        
        # Details text area
        details_frame = ttk.Frame(details_tab)
        details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=10,
                                                    background="#1c1c1c", foreground="#e0e0e0",
                                                    font=('Consolas', 9))
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)
        
        # Apply custom tags for details formatting
        self.details_text.tag_configure("title", foreground="#4c8bf5", font=('Consolas', 10, 'bold'))
        self.details_text.tag_configure("section", foreground="#ffffff", font=('Consolas', 9, 'bold'))
        self.details_text.tag_configure("high", foreground="#F44336")
        self.details_text.tag_configure("medium", foreground="#FFC107")
        self.details_text.tag_configure("low", foreground="#4CAF50")
        
        # Evidence tab
        evidence_tab = ttk.Frame(detail_notebook)
        detail_notebook.add(evidence_tab, text="Evidence")
        
        self.evidence_text = scrolledtext.ScrolledText(evidence_tab, height=10,
                                                    background="#1c1c1c", foreground="#e0e0e0",
                                                    font=('Consolas', 9))
        self.evidence_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.evidence_text.config(state=tk.DISABLED)
        
        # Remediation tab
        remediation_tab = ttk.Frame(detail_notebook)
        detail_notebook.add(remediation_tab, text="Remediation")
        
        self.remediation_text = scrolledtext.ScrolledText(remediation_tab, height=10,
                                                        background="#1c1c1c", foreground="#e0e0e0",
                                                        font=('Consolas', 9))
        self.remediation_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.remediation_text.config(state=tk.DISABLED)
        
        # Reference tab
        reference_tab = ttk.Frame(detail_notebook)
        detail_notebook.add(reference_tab, text="References")
        
        self.reference_text = scrolledtext.ScrolledText(reference_tab, height=10,
                                                    background="#1c1c1c", foreground="#e0e0e0",
                                                    font=('Consolas', 9))
        self.reference_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.reference_text.config(state=tk.DISABLED)
        
        # Bind selection event to show details
        self.results_tree.bind('<<TreeviewSelect>>', self.show_vulnerability_details)

    def setup_report_tab(self):
        """Set up the report tab interface"""
        # Create a container frame
        report_container = ttk.Frame(self.report_tab)
        report_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Split into left and right panes
        report_panes = ttk.PanedWindow(report_container, orient=tk.HORIZONTAL)
        report_panes.pack(fill=tk.BOTH, expand=True)
        
        # Left pane - Report options
        left_pane = ttk.Frame(report_panes)
        report_panes.add(left_pane, weight=1)
        
        # Report options frame
        options_frame = ttk.LabelFrame(left_pane, text="Report Options")
        options_frame.pack(fill=tk.X, pady=5, padx=5)
        
        # Report title
        ttk.Label(options_frame, text="Report Title:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.report_title = ttk.Entry(options_frame)
        self.report_title.insert(0, "Web Vulnerability Scan Report")
        self.report_title.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Report format
        ttk.Label(options_frame, text="Report Format:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.report_format = ttk.Combobox(options_frame, values=['HTML', 'PDF', 'JSON', 'Text'], state='readonly')
        self.report_format.current(0)
        self.report_format.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Report style (for HTML/PDF)
        ttk.Label(options_frame, text="Report Style:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.report_style = ttk.Combobox(options_frame, values=['Professional', 'Technical', 'Executive'], state='readonly')
        self.report_style.current(0)
        self.report_style.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Include company logo
        self.include_logo_var = tk.BooleanVar(value=False)
        logo_check = ttk.Checkbutton(options_frame, text="Include Company Logo", variable=self.include_logo_var,
                                command=self.toggle_logo_options)
        logo_check.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        
        # Logo selector
        self.logo_button = ttk.Button(options_frame, text="Select Logo", state=tk.DISABLED,
                                    command=self.select_logo)
        self.logo_button.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Report content options
        content_frame = ttk.LabelFrame(left_pane, text="Include in Report")
        content_frame.pack(fill=tk.X, pady=5, padx=5)
        
        # Create content options
        self.include_options = {}
        
        self.include_options['executive_summary'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="Executive Summary", 
                    variable=self.include_options['executive_summary']).grid(
            row=0, column=0, padx=5, pady=2, sticky=tk.W)
        
        self.include_options['scan_details'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="Scan Details", 
                    variable=self.include_options['scan_details']).grid(
            row=1, column=0, padx=5, pady=2, sticky=tk.W)
        
        self.include_options['vulnerability_summary'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="Vulnerability Summary", 
                    variable=self.include_options['vulnerability_summary']).grid(
            row=2, column=0, padx=5, pady=2, sticky=tk.W)
        
        self.include_options['vulnerabilities'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="Detailed Vulnerabilities", 
                    variable=self.include_options['vulnerabilities']).grid(
            row=0, column=1, padx=5, pady=2, sticky=tk.W)
        
        self.include_options['remediation'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="Remediation Tips", 
                    variable=self.include_options['remediation']).grid(
            row=1, column=1, padx=5, pady=2, sticky=tk.W)
        
        self.include_options['references'] = tk.BooleanVar(value=True)
        ttk.Checkbutton(content_frame, text="References", 
                    variable=self.include_options['references']).grid(
            row=2, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Custom notes frame
        notes_frame = ttk.LabelFrame(left_pane, text="Custom Notes")
        notes_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)
        
        self.report_notes = scrolledtext.ScrolledText(notes_frame, height=10)
        self.report_notes.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Report actions
        actions_frame = ttk.Frame(left_pane)
        actions_frame.pack(fill=tk.X, pady=10, padx=5)
        
        self.preview_button = ttk.Button(actions_frame, text="Generate Preview", 
                                    command=self.preview_report)
        self.preview_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(actions_frame, text="Save Report", 
                                    command=self.save_report)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # Right pane - Report preview
        right_pane = ttk.Frame(report_panes)
        report_panes.add(right_pane, weight=2)
        
        preview_frame = ttk.LabelFrame(right_pane, text="Report Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)
        
        # Create preview notebook with tabs for different views
        preview_notebook = ttk.Notebook(preview_frame)
        preview_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Rendered HTML tab
        html_frame = ttk.Frame(preview_notebook)
        preview_notebook.add(html_frame, text="Rendered")
        
        # Create an HTML preview frame (only works when HTML is selected)
        self.html_preview = ttk.Frame(html_frame)
        self.html_preview.pack(fill=tk.BOTH, expand=True)
        
        # Source tab
        source_frame = ttk.Frame(preview_notebook)
        preview_notebook.add(source_frame, text="Source")
        
        self.preview_text = scrolledtext.ScrolledText(source_frame)
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        self.preview_text.config(state=tk.DISABLED)

    def setup_settings_tab(self):
        """Set up the settings tab interface"""
        # Create a container frame with tabs for different settings
        settings_container = ttk.Frame(self.settings_tab)
        settings_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create settings notebook
        settings_notebook = ttk.Notebook(settings_container)
        settings_notebook.pack(fill=tk.BOTH, expand=True)
        
        # General settings tab
        general_tab = ttk.Frame(settings_notebook)
        settings_notebook.add(general_tab, text="General")
        
        # Scan settings tab
        scan_tab = ttk.Frame(settings_notebook)
        settings_notebook.add(scan_tab, text="Scanner")
        
        # Proxy settings tab
        proxy_tab = ttk.Frame(settings_notebook)
        settings_notebook.add(proxy_tab, text="Proxy")
        
        # Authentication settings tab
        auth_tab = ttk.Frame(settings_notebook)
        settings_notebook.add(auth_tab, text="Authentication")
        
        # Advanced settings tab
        advanced_tab = ttk.Frame(settings_notebook)
        settings_notebook.add(advanced_tab, text="Advanced")
        
        # ===== General Settings =====
        general_frame = ttk.LabelFrame(general_tab, text="General Settings")
        general_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Theme setting
        ttk.Label(general_frame, text="Theme:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.theme_combo = ttk.Combobox(general_frame, values=['Dark', 'Light'], state='readonly')
        self.theme_combo.current(0)  # Default to Dark
        self.theme_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Default report format
        ttk.Label(general_frame, text="Default Report Format:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.default_report_format = ttk.Combobox(general_frame, values=['HTML', 'PDF', 'JSON', 'Text'], state='readonly')
        self.default_report_format.current(0)
        self.default_report_format.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Default report directory
        ttk.Label(general_frame, text="Report Directory:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        
        report_dir_frame = ttk.Frame(general_frame)
        report_dir_frame.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        self.report_dir_entry = ttk.Entry(report_dir_frame)
        self.report_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_button = ttk.Button(report_dir_frame, text="Browse...", width=10,
                                command=self.browse_report_dir)
        browse_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Startup option
        self.startup_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(general_frame, text="Show scan tab on startup", 
                    variable=self.startup_scan_var).grid(
            row=3, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # ===== Scanner Settings =====
        scan_frame = ttk.LabelFrame(scan_tab, text="Scanner Settings")
        scan_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Concurrent requests
        ttk.Label(scan_frame, text="Max Concurrent Checks:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_workers = ttk.Spinbox(scan_frame, from_=1, to=20, width=5)
        self.max_workers.set(5)
        self.max_workers.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Request timeout
        ttk.Label(scan_frame, text="Request Timeout (seconds):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.request_timeout = ttk.Spinbox(scan_frame, from_=1, to=60, width=5)
        self.request_timeout.set(10)
        self.request_timeout.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Request delay
        ttk.Label(scan_frame, text="Request Delay (seconds):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.request_delay = ttk.Spinbox(scan_frame, from_=0, to=10, increment=0.1, width=5)
        self.request_delay.set(0.5)
        self.request_delay.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Follow redirects
        self.follow_redirects_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(scan_frame, text="Follow Redirects", 
                    variable=self.follow_redirects_var).grid(
            row=3, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # User agent
        ttk.Label(scan_frame, text="User Agent:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.user_agent = ttk.Entry(scan_frame, width=50)
        self.user_agent.insert(0, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)")
        self.user_agent.grid(row=4, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # ===== Proxy Settings =====
        proxy_frame = ttk.LabelFrame(proxy_tab, text="Proxy Settings")
        proxy_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Enable proxy
        self.use_proxy = tk.BooleanVar(value=False)
        proxy_check = ttk.Checkbutton(proxy_frame, text="Use Proxy", variable=self.use_proxy,
                                    command=self.toggle_proxy_options)
        proxy_check.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Proxy URL
        ttk.Label(proxy_frame, text="Proxy URL:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.proxy_url = ttk.Entry(proxy_frame, width=40, state=tk.DISABLED)
        self.proxy_url.insert(0, "http://127.0.0.1:8080")
        self.proxy_url.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Proxy authentication
        self.proxy_auth_var = tk.BooleanVar(value=False)
        proxy_auth_check = ttk.Checkbutton(proxy_frame, text="Proxy Authentication", 
                                        variable=self.proxy_auth_var,
                                        command=self.toggle_proxy_auth, state=tk.DISABLED)
        proxy_auth_check.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Proxy username
        ttk.Label(proxy_frame, text="Username:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.proxy_username = ttk.Entry(proxy_frame, width=30, state=tk.DISABLED)
        self.proxy_username.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Proxy password
        ttk.Label(proxy_frame, text="Password:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.proxy_password = ttk.Entry(proxy_frame, width=30, show="•", state=tk.DISABLED)
        self.proxy_password.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Test proxy connection
        self.test_proxy_button = ttk.Button(proxy_frame, text="Test Connection", state=tk.DISABLED,
                                        command=self.test_proxy_connection)
        self.test_proxy_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
        
        # ===== Authentication Settings =====
        auth_frame = ttk.LabelFrame(auth_tab, text="Authentication Settings")
        auth_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Authentication method
        ttk.Label(auth_frame, text="Default Auth Method:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.auth_method = ttk.Combobox(auth_frame, 
                                    values=['Form-based Login', 'HTTP Basic', 'Bearer Token'], 
                                    state='readonly')
        self.auth_method.current(0)
        self.auth_method.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # Save credentials option
        self.save_creds_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(auth_frame, text="Save credentials for quick scan (not recommended)", 
                    variable=self.save_creds_var).grid(
            row=1, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # ===== Advanced Settings =====
        advanced_frame = ttk.LabelFrame(advanced_tab, text="Advanced Settings")
        advanced_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Debug mode
        self.debug_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(advanced_frame, text="Debug Mode (verbose logging)", 
                    variable=self.debug_mode_var).grid(
            row=0, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Logging level
        ttk.Label(advanced_frame, text="Logging Level:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.log_level = ttk.Combobox(advanced_frame, 
                                    values=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
                                    state='readonly')
        self.log_level.current(1)  # Default to INFO
        self.log_level.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Cookie jar
        self.persistent_cookies_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Use persistent cookie jar", 
                    variable=self.persistent_cookies_var).grid(
            row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Clear cookies button
        clear_cookies_button = ttk.Button(advanced_frame, text="Clear Cookies", 
                                        command=self.clear_cookies)
        clear_cookies_button.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        
        # Reset settings button
        reset_button = ttk.Button(advanced_frame, text="Reset All Settings", 
                                command=self.reset_settings, style="Danger.TButton")
        reset_button.grid(row=4, column=0, padx=5, pady=20, sticky=tk.W)
        
        # Save settings button
        save_button = ttk.Button(advanced_frame, text="Save Settings", 
                            command=self.save_settings, style="Success.TButton")
        save_button.grid(row=4, column=1, padx=5, pady=20, sticky=tk.E)
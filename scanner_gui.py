#!/usr/bin/env python3
"""
Ultimate Security Scanner GUI
A comprehensive graphical interface for the Ultimate Linux Network Security Scanner
"""
# Import required modules
from scan import UltimateScanner, CONFIG
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
import os
from datetime import datetime
import queue
import sys

class SecurityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ultimate Security Scanner - GUI Edition")
        self.root.geometry("1200x800")

        # Queue for thread communication
        self.queue = queue.Queue()
        self.scanning = False

        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create tabs
        self.create_scan_tab()
        self.create_results_tab()
        self.create_config_tab()
        self.create_about_tab()

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Check queue periodically
        self.check_queue()

    def create_scan_tab(self):
        """Create the main scanning interface"""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="Scan")

        # Target input section
        target_frame = ttk.LabelFrame(scan_frame, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(target_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(target_frame, textvariable=self.target_var, width=50)
        self.target_entry.grid(row=0, column=1, padx=5, pady=2)

        # Load targets from file button
        self.load_targets_button = ttk.Button(target_frame, text="Load Targets", command=self.load_targets_from_file)
        self.load_targets_button.grid(row=0, column=2, padx=5, pady=2, sticky=tk.W)

        # Scan type selection
        scan_type_frame = ttk.LabelFrame(scan_frame, text="Scan Type", padding=10)
        scan_type_frame.pack(fill=tk.X, padx=5, pady=5)

        self.scan_type_var = tk.StringVar(value="full")
        scan_types = [
            ("Quick Scan", "quick"),
            ("Full Scan", "full"),
            ("Web Scan", "web"),
            ("Network Scan", "network"),
            ("Vulnerability Scan", "vulnerability"),
            ("Ultra Scan (ML + Advanced)", "ultra")
        ]

        for i, (text, value) in enumerate(scan_types):
            ttk.Radiobutton(scan_type_frame, text=text, variable=self.scan_type_var,
                          value=value).grid(row=i//2, column=i%2, sticky=tk.W, padx=5)

        # Scan options
        options_frame = ttk.LabelFrame(scan_frame, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        self.aggressive_var = tk.BooleanVar()
        self.stealth_var = tk.BooleanVar()
        self.verbose_var = tk.BooleanVar()

        ttk.Checkbutton(options_frame, text="Aggressive Mode", variable=self.aggressive_var).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="Stealth Mode", variable=self.stealth_var).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Checkbutton(options_frame, text="Verbose Output", variable=self.verbose_var).grid(row=1, column=0, sticky=tk.W, padx=5)

        # Control buttons
        button_frame = ttk.Frame(scan_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=10)

        self.start_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Results", command=self.export_results).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Export HTML", command=self.export_results_html).pack(side=tk.RIGHT, padx=5)

        # Log area
        log_frame = ttk.LabelFrame(scan_frame, text="Scan Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def create_results_tab(self):
        """Create the results display interface"""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")

        # Results notebook for different result types
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create result sections
        self.create_executive_summary_section()
        self.create_vulnerabilities_section()
        self.create_ports_section()
        self.create_web_section()
        self.create_network_section()

    def create_executive_summary_section(self):
        """Create executive summary display"""
        summary_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(summary_frame, text="Executive Summary")

        # Summary text area
        self.summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_vulnerabilities_section(self):
        """Create vulnerabilities display"""
        vuln_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(vuln_frame, text="Vulnerabilities")

        # Vulnerability tree
        columns = ("Severity", "Type", "Description", "Status")
        self.vuln_tree = ttk.Treeview(vuln_frame, columns=columns, show="headings")

        for col in columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=150)

        scrollbar = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscroll=scrollbar.set)

        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_ports_section(self):
        """Create ports display"""
        ports_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(ports_frame, text="Open Ports")

        # Ports tree
        columns = ("Port", "Protocol", "Service", "Version", "Status")
        self.ports_tree = ttk.Treeview(ports_frame, columns=columns, show="headings")

        for col in columns:
            self.ports_tree.heading(col, text=col)
            self.ports_tree.column(col, width=100)

        scrollbar = ttk.Scrollbar(ports_frame, orient=tk.VERTICAL, command=self.ports_tree.yview)
        self.ports_tree.configure(yscroll=scrollbar.set)

        self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_web_section(self):
        """Create web findings display"""
        web_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(web_frame, text="Web Findings")

        # Web findings text
        self.web_text = scrolledtext.ScrolledText(web_frame, wrap=tk.WORD)
        self.web_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_network_section(self):
        """Create network findings display"""
        network_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(network_frame, text="Network Analysis")

        # Network findings text
        self.network_text = scrolledtext.ScrolledText(network_frame, wrap=tk.WORD)
        self.network_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_config_tab(self):
        """Create configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")

        # API Keys section
        api_frame = ttk.LabelFrame(config_frame, text="API Keys", padding=10)
        api_frame.pack(fill=tk.X, padx=5, pady=5)

        # VirusTotal
        ttk.Label(api_frame, text="VirusTotal:").grid(row=0, column=0, sticky=tk.W)
        self.vt_key_var = tk.StringVar(value=CONFIG['api_keys']['virustotal'])
        ttk.Entry(api_frame, textvariable=self.vt_key_var, width=50, show="*").grid(row=0, column=1, padx=5, pady=2)

        # Shodan
        ttk.Label(api_frame, text="Shodan:").grid(row=1, column=0, sticky=tk.W)
        self.shodan_key_var = tk.StringVar(value=CONFIG['api_keys']['shodan'])
        ttk.Entry(api_frame, textvariable=self.shodan_key_var, width=50, show="*").grid(row=1, column=1, padx=5, pady=2)

        # Scan settings
        settings_frame = ttk.LabelFrame(config_frame, text="Scan Settings", padding=10)
        settings_frame.pack(fill=tk.X, padx=5, pady=5)

        # Threads
        ttk.Label(settings_frame, text="Max Threads:").grid(row=0, column=0, sticky=tk.W)
        self.threads_var = tk.StringVar(value=str(CONFIG['scan']['max_threads']))
        ttk.Entry(settings_frame, textvariable=self.threads_var, width=10).grid(row=0, column=1, sticky=tk.W, padx=5)

        # Timeout
        ttk.Label(settings_frame, text="Timeout (s):").grid(row=0, column=2, sticky=tk.W)
        self.timeout_var = tk.StringVar(value=str(CONFIG['scan']['timeout']))
        ttk.Entry(settings_frame, textvariable=self.timeout_var, width=10).grid(row=0, column=3, sticky=tk.W, padx=5)

        # Rate limiting
        ttk.Label(settings_frame, text="Rate Limit Delay:").grid(row=1, column=0, sticky=tk.W)
        self.rate_delay_var = tk.StringVar(value=str(CONFIG['advanced']['rate_limit_delay']))
        ttk.Entry(settings_frame, textvariable=self.rate_delay_var, width=10).grid(row=1, column=1, sticky=tk.W, padx=5)

        # Config actions
        actions_frame = ttk.Frame(config_frame)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(actions_frame, text="Save Configuration", command=self.save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Save Config As...", command=self.save_config_to_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Load Configuration...", command=self.load_config_from_file).pack(side=tk.LEFT, padx=5)

    def create_about_tab(self):
        """Create about tab"""
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="About")

        about_text = """
        Ultimate Security Scanner - GUI Edition

        A comprehensive security scanning tool with advanced features:

        • Network Scanning (Ports, Services, OS Detection)
        • Web Application Security (SQLi, XSS, IDOR, SSRF, etc.)
        • Database Security Testing
        • SSL/TLS Analysis
        • Container Security Scanning
        • IoT Device Detection
        • Machine Learning-based Vulnerability Detection
        • Advanced Evasion Techniques

        Features:
        • Multiple scan types (Quick, Full, Web, Network, Ultra)
        • Real-time progress tracking
        • Comprehensive reporting
        • Export functionality
        • Configurable scan options

        Version: 5.0-Ultra
        """

        text_widget = tk.Text(about_frame, wrap=tk.WORD, padx=20, pady=20)
        text_widget.insert(tk.END, about_text)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True)

    def start_scan(self):
        """Start the security scan in a separate thread"""
        target_text = self.target_var.get().strip()
        if not target_text:
            messagebox.showerror("Error", "Please enter a target to scan")
            return

        # Parse multi-targets (comma, whitespace, or newline separated)
        targets = [t for t in [s.strip() for s in target_text.replace("\r", "\n").replace(",", "\n").split("\n")] if t]

        # Update UI
        self.scanning = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_var.set(0)
        self.status_var.set("Starting scan...")

        # Clear previous results
        self.clear_results()

        # Add initial log entry
        self.log_message(f"Starting {self.scan_type_var.get()} scan of {', '.join(targets)}")

        # Start scan in background thread
        scan_thread = threading.Thread(target=self.run_scan, args=(targets,))
        scan_thread.daemon = True
        scan_thread.start()

    def run_scan(self, targets):
        """Run the actual scan (called in background thread)"""
        try:
            # Apply runtime settings from GUI immediately
            CONFIG['advanced']['aggressive_scan'] = self.aggressive_var.get()
            CONFIG['advanced']['stealth_mode'] = self.stealth_var.get()
            CONFIG['api_keys']['virustotal'] = self.vt_key_var.get()
            CONFIG['api_keys']['shodan'] = self.shodan_key_var.get()
            # Apply numeric settings
            try:
                CONFIG['scan']['max_threads'] = int(self.threads_var.get())
                CONFIG['scan']['timeout'] = int(self.timeout_var.get())
                CONFIG['advanced']['rate_limit_delay'] = float(self.rate_delay_var.get())
            except Exception:
                pass

            self.queue.put(("status", "Initializing scanner..."))

            aggregated = { 'combined': True, 'targets': [], 'executive_summary': { 'scan_overview': { 'target': ', '.join(targets), 'scan_type': self.scan_type_var.get() } } }
            for idx, target in enumerate(targets, start=1):
                if not self.scanning:
                    self.queue.put(("status", "Scan stopped by user"))
                    break
                self.queue.put(("status", f"Scanning target {idx}/{len(targets)}: {target}"))
                scanner = UltimateScanner(target)
                result = scanner.run_scan(
                    scan_type=self.scan_type_var.get(),
                    aggressive=self.aggressive_var.get()
                )
                aggregated['targets'].append({ 'target': target, 'result': result })
                progress = (idx / len(targets)) * 100.0
                self.queue.put(("progress", progress))

            # Send aggregated results to main thread
            if self.scanning:
                self.queue.put(("results", aggregated if len(targets) > 1 else aggregated['targets'][0]['result']))
            else:
                self.queue.put(("status", "Scan stopped before completion"))

        except Exception as e:
            self.queue.put(("error", str(e)))

    def load_targets_from_file(self):
        """Load list of targets from a text file (one per line)"""
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not filename:
            return
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.strip() for line in f.readlines()]
            targets = [line for line in lines if line]
            if targets:
                self.target_var.set("\n".join(targets))
                self.log_message(f"Loaded {len(targets)} targets from file")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load targets: {str(e)}")

    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        self.status_var.set("Stopping scan...")
        self.log_message("Scan stopping requested by user")

    def clear_results(self):
        """Clear all results and logs"""
        self.summary_text.delete(1.0, tk.END)
        self.web_text.delete(1.0, tk.END)
        self.network_text.delete(1.0, tk.END)
        self.log_text.delete(1.0, tk.END)

        # Clear trees
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)

        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)

    def export_results(self):
        """Export scan results to file"""
        if not hasattr(self, 'scan_results'):
            messagebox.showwarning("Warning", "No scan results to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")
    
        def export_results_html(self):
            """Export scan results to a simple HTML report"""
            if not hasattr(self, 'scan_results'):
                messagebox.showwarning("Warning", "No scan results to export")
                return
		filename = filedialog.asksaveasfilename(
			defaultextension=".html",
			filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
		)
		if not filename:
			return
		try:
			html = self._generate_html_report(self.scan_results)
			with open(filename, 'w', encoding='utf-8') as f:
				f.write(html)
			messagebox.showinfo("Success", f"HTML report exported to {filename}")
		except Exception as e:
			messagebox.showerror("Error", f"Failed to export HTML: {str(e)}")

	def _generate_html_report(self, results: dict) -> str:
		"""Generate a minimal HTML report from results"""
		def esc(s):
			return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
		sections = []
		if isinstance(results, dict) and results.get('combined') and isinstance(results.get('targets'), list):
			sections.append("<h1>Multi-Target Security Scan Report</h1>")
			for entry in results['targets']:
				t = entry.get('target', 'Unknown')
				res = entry.get('result', {})
				sections.append(f"<h2>Target: {esc(t)}</h2>")
				sections.append(self._html_section_for_single(res))
			return "<html><body>" + "\n".join(sections) + "</body></html>"
		else:
			return "<html><body>" + self._html_section_for_single(results) + "</body></html>"

	def _html_section_for_single(self, res: dict) -> str:
		parts = []
		summary = res.get('executive_summary', {})
		if summary:
			overview = summary.get('scan_overview', {})
			parts.append("<h3>Executive Summary</h3>")
			parts.append("<ul>")
			for k in ['target', 'scan_type', 'duration_seconds', 'start_time', 'end_time']:
				if k in overview:
					parts.append(f"<li>{k.replace('_', ' ').title()}: {overview.get(k)}</li>")
			parts.append("</ul>")
			fs = summary.get('findings_summary', {})
			if fs:
				parts.append("<h4>Findings Summary</h4>")
				parts.append("<ul>")
				for k, v in fs.items():
					parts.append(f"<li>{k.replace('_', ' ').title()}: {v}</li>")
				parts.append("</ul>")
		results_section = res.get('results', {})
		if isinstance(results_section, dict):
			if 'port_scan' in results_section:
				ports = results_section['port_scan']
				parts.append("<h3>Open Ports</h3>")
				rows = []
				for host, data in ports.items():
					protocols = data.get('protocols', {}) if isinstance(data, dict) else {}
					for proto, plist in protocols.items():
						for port, info in (plist.items() if isinstance(plist, dict) else []):
							service = info.get('name', 'Unknown') if isinstance(info, dict) else 'Unknown'
							version = info.get('version', 'Unknown') if isinstance(info, dict) else 'Unknown'
							rows.append(f"<tr><td>{esc(host)}</td><td>{esc(proto)}</td><td>{esc(port)}</td><td>{esc(service)}</td><td>{esc(version)}</td></tr>")
				if rows:
					parts.append("<table border=1 cellpadding=4 cellspacing=0><tr><th>Host</th><th>Proto</th><th>Port</th><th>Service</th><th>Version</th></tr>" + "".join(rows) + "</table>")
			if 'vulnerability_scan' in results_section:
				parts.append("<h3>Vulnerabilities</h3>")
				vuln = results_section['vulnerability_scan']
				if isinstance(vuln, dict):
					parts.append("<ul>")
					for k, v in vuln.items():
						count = len(v) if isinstance(v, list) else (v if isinstance(v, int) else 0)
						parts.append(f"<li>{esc(k)}: {esc(count)}</li>")
					parts.append("</ul>")
		return "\n".join(parts)

    def save_config(self):
        """Save current configuration"""
        try:
            # Update CONFIG with GUI values
            CONFIG['api_keys']['virustotal'] = self.vt_key_var.get()
            CONFIG['api_keys']['shodan'] = self.shodan_key_var.get()
            CONFIG['scan']['max_threads'] = int(self.threads_var.get())
            CONFIG['scan']['timeout'] = int(self.timeout_var.get())
            CONFIG['advanced']['rate_limit_delay'] = float(self.rate_delay_var.get())

            messagebox.showinfo("Success", "Configuration saved")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

	def save_config_to_file(self):
		"""Persist configuration to a JSON file"""
		self.save_config()  # sync GUI to CONFIG
		filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
		if not filename:
			return
		try:
			with open(filename, 'w', encoding='utf-8') as f:
				json.dump(CONFIG, f, indent=2)
			messagebox.showinfo("Success", f"Configuration saved to {filename}")
		except Exception as e:
			messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

	def load_config_from_file(self):
		"""Load configuration from a JSON file and update GUI"""
		filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
		if not filename:
			return
		try:
			with open(filename, 'r', encoding='utf-8') as f:
				loaded = json.load(f)
			# Merge minimal expected keys
			if 'api_keys' in loaded:
				CONFIG['api_keys'].update({k: v for k, v in loaded['api_keys'].items() if k in CONFIG['api_keys']})
			if 'scan' in loaded:
				for k in ['max_threads', 'timeout']:
					if k in loaded['scan']:
						CONFIG['scan'][k] = loaded['scan'][k]
			if 'advanced' in loaded and 'rate_limit_delay' in loaded['advanced']:
				CONFIG['advanced']['rate_limit_delay'] = loaded['advanced']['rate_limit_delay']
			# Update GUI widgets
			self.vt_key_var.set(CONFIG['api_keys']['virustotal'])
			self.shodan_key_var.set(CONFIG['api_keys']['shodan'])
			self.threads_var.set(str(CONFIG['scan']['max_threads']))
			self.timeout_var.set(str(CONFIG['scan']['timeout']))
			self.rate_delay_var.set(str(CONFIG['advanced']['rate_limit_delay']))
			messagebox.showinfo("Success", f"Configuration loaded from {filename}")
		except Exception as e:
			messagebox.showerror("Error", f"Failed to load configuration: {str(e)}")

    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)

    def check_queue(self):
        """Check for messages from background thread"""
        try:
            while True:
                msg_type, data = self.queue.get_nowait()

                if msg_type == "status":
                    self.status_var.set(data)
                    self.log_message(data)

                elif msg_type == "progress":
                    self.progress_var.set(data)

                elif msg_type == "results":
                    self.display_results(data)
                    self.scan_results = data
                    self.scanning = False
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)

                elif msg_type == "error":
                    self.status_var.set("Error occurred")
                    self.log_message(f"ERROR: {data}")
                    messagebox.showerror("Scan Error", f"An error occurred during scanning:\n\n{data}")
                    self.scanning = False
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)

        except queue.Empty:
            pass

        # Schedule next check
        self.root.after(100, self.check_queue)

	def display_results(self, results):
        """Display scan results in the GUI"""
        try:
            # Update status
            self.status_var.set("Displaying results...")
            self.progress_var.set(100)

            # Executive Summary
            summary = results.get('executive_summary', {})
            if summary:
                self.summary_text.delete(1.0, tk.END)
                scan_overview = summary.get('scan_overview', {})

                summary_text = f"""
SECURITY SCAN REPORT
===================

Target: {scan_overview.get('target', 'Unknown')}
Scan Type: {scan_overview.get('scan_type', 'Unknown')}
Duration: {scan_overview.get('duration_seconds', 0):.2f} seconds
Start Time: {scan_overview.get('start_time', 'Unknown')}
End Time: {scan_overview.get('end_time', 'Unknown')}

FINDINGS SUMMARY
================
Total Vulnerabilities: {summary.get('findings_summary', {}).get('total_vulnerabilities', 0)}
Critical Vulnerabilities: {summary.get('findings_summary', {}).get('critical_vulnerabilities', 0)}
High Vulnerabilities: {summary.get('findings_summary', {}).get('high_vulnerabilities', 0)}
Medium Vulnerabilities: {summary.get('findings_summary', {}).get('medium_vulnerabilities', 0)}
Open Ports: {summary.get('findings_summary', {}).get('open_ports', 0)}
Web Pages Found: {summary.get('findings_summary', {}).get('web_pages_found', 0)}

RECOMMENDATIONS
===============
"""
                for rec in summary.get('recommendations', []):
                    summary_text += f"• {rec}\n"

                self.summary_text.insert(tk.END, summary_text)

			# Vulnerabilities
			self.vuln_tree.delete(*self.vuln_tree.get_children())
			if isinstance(results, dict) and results.get('combined') and isinstance(results.get('targets'), list):
				for entry in results['targets']:
					res = entry.get('result', {})
					risk_assessment = res.get('risk_assessment', {})
					for severity, vulns in risk_assessment.items():
						for vuln in (vulns or []):
							vuln_type = vuln.get('type', 'Unknown') if isinstance(vuln, dict) else str(vuln)
							details = str(vuln.get('details', '')) if isinstance(vuln, dict) else ''
							self.vuln_tree.insert("", tk.END, values=(severity.title(), vuln_type, details[:100], "Found"))
			else:
				risk_assessment = results.get('risk_assessment', {})
				for severity, vulns in risk_assessment.items():
					for vuln in vulns:
						vuln_type = vuln.get('type', 'Unknown')
						details = str(vuln.get('details', ''))
						self.vuln_tree.insert("", tk.END, values=(severity.title(), vuln_type, details[:100], "Found"))

			# Open Ports
			self.ports_tree.delete(*self.ports_tree.get_children())
			if isinstance(results, dict) and results.get('combined') and isinstance(results.get('targets'), list):
				for entry in results['targets']:
					res = entry.get('result', {})
					port_scan = res.get('results', {}).get('port_scan', {})
					for host, data in port_scan.items():
						protocols = data.get('protocols', {}) if isinstance(data, dict) else {}
						for proto, ports in protocols.items():
							for port, info in ports.items():
								service = info.get('name', 'Unknown') if isinstance(info, dict) else 'Unknown'
								version = info.get('version', 'Unknown') if isinstance(info, dict) else 'Unknown'
								self.ports_tree.insert("", tk.END, values=(port, proto, service, version, "Open"))
			else:
				port_scan = results.get('results', {}).get('port_scan', {})
				for host, data in port_scan.items():
					protocols = data.get('protocols', {})
					for proto, ports in protocols.items():
						for port, info in ports.items():
							service = info.get('name', 'Unknown')
							version = info.get('version', 'Unknown')
							self.ports_tree.insert("", tk.END, values=(port, proto, service, version, "Open"))

            # Web Findings
			web_findings = []
			web_results = results.get('results', {}) if not (isinstance(results, dict) and results.get('combined')) else {}

			if 'web_spider' in web_results:
                spider = web_results['web_spider']
                web_findings.append(f"Pages Found: {len(spider.get('pages', []))}")
                web_findings.append(f"Forms Found: {len(spider.get('forms', []))}")
                web_findings.append(f"Resources Found: {len(spider.get('resources', []))}")

            if 'tech_stack' in web_results:
                tech = web_results['tech_stack']
                if isinstance(tech, dict) and 'error' not in tech:
                    web_findings.append(f"Technologies Detected: {len(tech)}")

            if 'vulnerability_scan' in web_results:
                vuln_scan = web_results['vulnerability_scan']
                for scan_type, findings in vuln_scan.items():
                    if isinstance(findings, list):
                        web_findings.append(f"{scan_type}: {len(findings)} findings")

            self.web_text.delete(1.0, tk.END)
            self.web_text.insert(tk.END, "\n".join(web_findings))

            # Network Analysis
            network_findings = []
            if 'os_detection' in web_results:
                os_info = web_results['os_detection']
                if isinstance(os_info, dict) and 'error' not in os_info:
                    network_findings.append(f"OS Detection: {os_info}")

            if 'service_detection' in web_results:
                services = web_results['service_detection']
                if isinstance(services, dict) and 'error' not in services:
                    network_findings.append(f"Services Detected: {len(services)}")

			self.network_text.delete(1.0, tk.END)
			self.network_text.insert(tk.END, "\n".join(network_findings))

            self.status_var.set("Results displayed")
            self.log_message("Results displayed successfully")

        except Exception as e:
            self.log_message(f"Error displaying results: {str(e)}")

def main():
    """Main function to start the GUI"""
    root = tk.Tk()
    app = SecurityScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
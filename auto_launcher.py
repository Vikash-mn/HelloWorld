#!/usr/bin/env python3
"""
Universal Auto Launcher

Run this file to automatically detect the environment (Windows, Linux, Kali)
and launch the appropriate GUI for the Ultimate Security Scanner.

Behavior:
- Detect Kali Linux and prefer kali-optimized launcher
- Else, use the generic GUI launcher
- Verify Python dependencies and try to install those listed in requirements.txt
- Fall back to importing scanner_gui.main directly if needed
"""

import os
import sys
import subprocess
import platform
import argparse
import json


def is_kali_linux() -> bool:
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r', encoding='utf-8', errors='ignore') as f:
                return 'kali' in f.read().lower()
    except Exception:
        pass
    return False


def ensure_project_on_path() -> None:
    project_dir = os.path.dirname(os.path.abspath(__file__))
    if project_dir not in sys.path:
        sys.path.insert(0, project_dir)


def install_requirements_if_available(skip: bool = False) -> None:
    if skip:
        return
    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'requirements.txt')
    if not os.path.isfile(req_path):
        return
    # Attempt a non-interactive install; ignore failures (will fall back gracefully)
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', req_path])
    except subprocess.CalledProcessError:
        pass


def check_basic_imports() -> None:
    # Soft checks; raise only for critical GUI components
    try:
        import tkinter  # noqa: F401
    except Exception as e:
        print(f"[!] Tkinter not available or failed to load: {e}")
        print("    GUI may not start. Install tkinter or use a system package manager.")


def try_launch_kali_gui() -> bool:
    try:
        from kali_gui_launcher import main as kali_main
        print("[+] Launching Kali-optimized GUI...")
        kali_main()
        return True
    except Exception as e:
        print(f"[!] Kali GUI launcher failed: {e}")
        return False


def try_launch_generic_gui() -> bool:
    try:
        from gui_launcher import main as generic_main
        print("[+] Launching generic GUI...")
        generic_main()
        return True
    except Exception as e:
        print(f"[!] Generic GUI launcher failed: {e}")
        return False


def fallback_import_scanner_gui() -> bool:
    try:
        from scanner_gui import main as gui_main
        print("[+] Launching scanner GUI directly...")
        gui_main()
        return True
    except Exception as e:
        print(f"[!] Direct GUI import failed: {e}")
        return False


def generate_html_report(results: dict) -> str:
    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    def html_single(res: dict) -> str:
        parts = []
        summary = res.get('executive_summary', {}) if isinstance(res, dict) else {}
        if summary:
            ov = summary.get('scan_overview', {})
            parts.append('<h3>Executive Summary</h3>')
            parts.append('<ul>')
            for k in ['target', 'scan_type', 'duration_seconds', 'start_time', 'end_time']:
                if k in ov:
                    parts.append(f"<li>{esc(k.replace('_',' ').title())}: {esc(ov.get(k))}</li>")
            parts.append('</ul>')
            fs = summary.get('findings_summary', {})
            if fs:
                parts.append('<h4>Findings Summary</h4>')
                parts.append('<ul>')
                for k, v in fs.items():
                    parts.append(f"<li>{esc(k.replace('_',' ').title())}: {esc(v)}</li>")
                parts.append('</ul>')
        results_section = res.get('results', {}) if isinstance(res, dict) else {}
        if isinstance(results_section, dict) and 'port_scan' in results_section:
            ports = results_section['port_scan']
            rows = []
            for host, data in ports.items():
                protocols = data.get('protocols', {}) if isinstance(data, dict) else {}
                for proto, plist in protocols.items():
                    for port, info in (plist.items() if isinstance(plist, dict) else []):
                        service = info.get('name', 'Unknown') if isinstance(info, dict) else 'Unknown'
                        version = info.get('version', 'Unknown') if isinstance(info, dict) else 'Unknown'
                        rows.append(f"<tr><td>{esc(host)}</td><td>{esc(proto)}</td><td>{esc(port)}</td><td>{esc(service)}</td><td>{esc(version)}</td></tr>")
            if rows:
                parts.append('<h3>Open Ports</h3>')
                parts.append('<table border=1 cellpadding=4 cellspacing=0><tr><th>Host</th><th>Proto</th><th>Port</th><th>Service</th><th>Version</th></tr>' + ''.join(rows) + '</table>')
        return '\n'.join(parts)
    if isinstance(results, dict) and results.get('combined') and isinstance(results.get('targets'), list):
        sections = ['<h1>Multi-Target Security Scan Report</h1>']
        for entry in results['targets']:
            t = entry.get('target', 'Unknown')
            res = entry.get('result', {})
            sections.append(f"<h2>Target: {esc(t)}</h2>")
            sections.append(html_single(res))
        return '<html><body>' + '\n'.join(sections) + '</body></html>'
    else:
        return '<html><body>' + html_single(results if isinstance(results, dict) else {}) + '</body></html>'


def run_cli_mode(args: argparse.Namespace) -> int:
    ensure_project_on_path()
    from scan import UltimateScanner, CONFIG  # type: ignore

    # Targets
    targets: list[str] = []
    if args.targets:
        for chunk in args.targets:
            for t in chunk.replace('\r', '\n').replace(',', '\n').split('\n'):
                t = t.strip()
                if t:
                    targets.append(t)
    if args.targets_file:
        with open(args.targets_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                t = line.strip()
                if t:
                    targets.append(t)
    targets = list(dict.fromkeys(targets))
    if not targets:
        print('[x] No targets provided. Use --targets or --targets-file')
        return 2

    # Apply settings
    if args.vt_key:
        CONFIG['api_keys']['virustotal'] = args.vt_key
    if args.shodan_key:
        CONFIG['api_keys']['shodan'] = args.shodan_key
    if args.threads is not None:
        CONFIG['scan']['max_threads'] = int(args.threads)
    if args.timeout is not None:
        CONFIG['scan']['timeout'] = int(args.timeout)
    if args.rate is not None:
        CONFIG['advanced']['rate_limit_delay'] = float(args.rate)
    CONFIG['advanced']['aggressive_scan'] = bool(args.aggressive)
    CONFIG['advanced']['stealth_mode'] = bool(args.stealth)

    results_agg: dict = { 'combined': True, 'targets': [] }
    for idx, target in enumerate(targets, start=1):
        print(f"[*] ({idx}/{len(targets)}) Scanning: {target}")
        scanner = UltimateScanner(target)
        result = scanner.run_scan(scan_type=args.type, aggressive=bool(args.aggressive))
        results_agg['targets'].append({ 'target': target, 'result': result })

    # Output handling
    final = results_agg if len(targets) > 1 else results_agg['targets'][0]['result']
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(final, f, indent=2)
        print(f"[+] JSON saved: {args.output}")
    if args.html:
        html = generate_html_report(final)
        with open(args.html, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] HTML report saved: {args.html}")

    # Basic console summary
    print('[+] Scan completed')
    return 0


def build_arg_parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Ultimate Security Scanner - Auto Launcher')
    parser.add_argument('--cli', action='store_true', help='Run in CLI scan mode instead of GUI')
    parser.add_argument('--no-install', action='store_true', help='Skip auto pip install of requirements.txt')
    # CLI scan options
    parser.add_argument('--targets', nargs='*', help='Targets (comma/newline separated allowed)')
    parser.add_argument('--targets-file', help='Path to file with one target per line')
    parser.add_argument('-t', '--type', default='full', help='Scan type: quick, full, web, network, vulnerability, ultra')
    parser.add_argument('--aggressive', action='store_true', help='Enable aggressive mode')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--threads', type=int, help='Max threads to use')
    parser.add_argument('--timeout', type=int, help='Request timeout (seconds)')
    parser.add_argument('--rate', type=float, help='Rate limit delay (seconds)')
    parser.add_argument('--vt-key', help='VirusTotal API key')
    parser.add_argument('--shodan-key', help='Shodan API key')
    parser.add_argument('-o', '--output', help='JSON output file')
    parser.add_argument('--html', help='HTML report output file')
    return parser.parse_args()


def main() -> None:
    args = build_arg_parser()
    print("=== Ultimate Security Scanner - Auto Launcher ===")
    print(f"Platform: {platform.system()} {platform.release()}")

    ensure_project_on_path()
    install_requirements_if_available(skip=bool(args.no_install))
    check_basic_imports()

    if args.cli:
        code = run_cli_mode(args)
        sys.exit(code)

    launched = False

    if platform.system().lower() == 'linux' and is_kali_linux():
        launched = try_launch_kali_gui()

    if not launched:
        launched = try_launch_generic_gui()

    if not launched:
        launched = fallback_import_scanner_gui()

    if not launched:
        print("[x] Unable to start the GUI. Please ensure dependencies are installed.")
        print("    Try: pip install -r requirements.txt")
        sys.exit(1)


if __name__ == '__main__':
    main()



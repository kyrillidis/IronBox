#!/usr/bin/env python3
"""
Command Line Interface for the web vulnerability scanner.
Allows for automation and integration with other tools.
"""

import argparse
import sys
import json
from datetime import datetime
import colorama
from colorama import Fore, Style

class CommandLineInterface:
    """CLI for the vulnerability scanner"""
    
    def __init__(self, scanner):
        """Initialize the CLI
        
        Args:
            scanner: VulnerabilityScanner instance
        """
        self.scanner = scanner
        colorama.init()
    
    def run(self):
        """Run the CLI interface"""
        parser = self.setup_argument_parser()
        args = parser.parse_args()
        
        if not args.url:
            parser.print_help()
            sys.exit(1)
        
        # Determine which checks to run
        selected_checks = []
        
        if args.all:
            # Run all available checks
            print(f"{Fore.BLUE}Running all available vulnerability checks{Style.RESET_ALL}")
            selected_checks = list(self.scanner.checks.keys())
        else:
            # Only run specified checks
            for check_name in self.scanner.checks.keys():
                arg_name = check_name.replace('-', '_')
                if hasattr(args, arg_name) and getattr(args, arg_name):
                    selected_checks.append(check_name)
            
            # If no specific checks were requested, run all by default
            if not selected_checks:
                print(f"{Fore.YELLOW}No specific checks selected, running all checks by default{Style.RESET_ALL}")
                selected_checks = list(self.scanner.checks.keys())
        
        # Set up progress callback
        def progress_callback(percentage, check_name, result):
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if not result.get('vulnerable', False) else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"{status} {check_name}: {'Vulnerable' if result.get('vulnerable', False) else 'Secure'}")
        
        # Run the scan
        print(f"{Fore.BLUE}Starting scan of {args.url}{Style.RESET_ALL}")
        print("This may take a while depending on the target site and selected options...")
        
        results = self.scanner.scan(
            args.url, 
            selected_checks,
            max_workers=args.max_workers,
            progress_callback=progress_callback
        )
        
        # Print summary
        print("\nScan Summary:")
        print("-" * 50)
        
        vulnerable_count = sum(
            1 for check_name, result in results['vulnerabilities'].items() 
            if result.get('vulnerable', False)
        )
        
        if vulnerable_count > 0:
            print(f"{Fore.RED}Found {vulnerable_count} vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}No vulnerabilities found!{Style.RESET_ALL}")
        
        # Generate report if output file is specified
        if args.output:
            self.generate_report(args.output, args.format, results)
            print(f"\nReport saved to: {args.output}")
    
    def setup_argument_parser(self):
        """Set up command line argument parser"""
        parser = argparse.ArgumentParser(
            description='Web Vulnerability Scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python main.py example.com --all
  python main.py https://example.com --xss --sqli --output report.html
            """
        )
        
        parser.add_argument('url', help='Target URL to scan')
        
        # Create an argument for each available check
        check_group = parser.add_argument_group('Vulnerability Checks')
        
        for check_name, check_obj in self.scanner.checks.items():
            help_text = getattr(check_obj, 'description', f"Check for {check_name} vulnerabilities")
            arg_name = f"--{check_name}"
            check_group.add_argument(
                arg_name, 
                action='store_true',
                help=help_text
            )
        
        check_group.add_argument('--all', action='store_true', help='Run all vulnerability checks')
        
        # Scan options
        scan_group = parser.add_argument_group('Scan Options')
        scan_group.add_argument('--max-workers', type=int, default=5, help='Maximum number of concurrent checks (default: 5)')
        scan_group.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
        
        # Output options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument('-o', '--output', help='Output file for the report')
        output_group.add_argument('-f', '--format', choices=['json', 'text', 'html'], default='text', 
                          help='Output format (default: text)')
        
        return parser
    
    def generate_report(self, output_file, format_type, results):
        """Generate and save a report
        
        Args:
            output_file: Path to save the report
            format_type: Report format (json, text, html)
            results: Scan results to include in the report
        """
        if format_type == 'json':
            content = json.dumps(results, indent=4)
        elif format_type == 'html':
            content = self.generate_html_report(results)
        else:  # text
            content = self.generate_text_report(results)
        
        with open(output_file, 'w') as f:
            f.write(content)
    
    def generate_text_report(self, results):
        """Generate a text report
        
        Args:
            results: Scan results
            
        Returns:
            str: Text report content
        """
        lines = [
            "Web Vulnerability Scan Report",
            "=" * 50,
            ""
        ]
        
        # Scan details
        lines.extend([
            "Scan Details",
            "-" * 20,
            f"Target: {results.get('target', 'N/A')}",
            f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Checks: {len(results.get('vulnerabilities', {}))}",
            ""
        ])
        
        # Results for each check
        lines.append("Scan Results")
        lines.append("-" * 20)
        
        for check_name, result in results.get('vulnerabilities', {}).items():
            status = "VULNERABLE" if result.get('vulnerable', False) else "SECURE"
            lines.append(f"{check_name}: {status}")
            lines.append(f"Description: {result.get('description', 'N/A')}")
            
            details = result.get('details', [])
            if details:
                lines.append(f"Issues found: {len(details)}")
                
                for i, detail in enumerate(details):
                    lines.append(f"  Issue {i+1}:")
                    for key, value in detail.items():
                        lines.append(f"    {key}: {value}")
            else:
                lines.append("No issues found")
            
            lines.append("")
        
        lines.append("")
        lines.append("Report generated by Web Vulnerability Scanner")
        
        return "\n".join(lines)
    
    def generate_html_report(self, results):
        """Generate an HTML report
        
        Args:
            results: Scan results
            
        Returns:
            str: HTML report content
        """
        html = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "    <title>Web Vulnerability Scan Report</title>",
            "    <style>",
            "        body { font-family: Arial, sans-serif; margin: 20px; }",
            "        h1, h2, h3 { color: #333; }",
            "        .vulnerable { background-color: #ffcccc; }",
            "        .secure { background-color: #ccffcc; }",
            "        table { border-collapse: collapse; width: 100%; }",
            "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "        th { background-color: #f2f2f2; }",
            "    </style>",
            "</head>",
            "<body>",
            f"    <h1>Web Vulnerability Scan Report</h1>"
        ]
        
        # Scan details
        html.extend([
            "    <h2>Scan Details</h2>",
            "    <table>",
            "        <tr><th>Target</th><td>" + results.get('target', 'N/A') + "</td></tr>",
            "        <tr><th>Scan Time</th><td>" + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "</td></tr>",
            "        <tr><th>Total Checks</th><td>" + str(len(results.get('vulnerabilities', {}))) + "</td></tr>",
            "    </table>"
        ])
        
        # Vulnerabilities summary
        html.append("    <h2>Vulnerabilities Summary</h2>")
        html.append("    <table>")
        html.append("        <tr><th>Vulnerability Type</th><th>Status</th><th>Details</th></tr>")
        
        for check_name, result in results.get('vulnerabilities', {}).items():
            status = "Vulnerable" if result.get('vulnerable', False) else "Secure"
            row_class = "vulnerable" if result.get('vulnerable', False) else "secure"
            
            html.append(f"        <tr class=\"{row_class}\">")
            html.append(f"            <td>{check_name}</td>")
            html.append(f"            <td>{status}</td>")
            
            details_count = len(result.get('details', []))
            if details_count > 0:
                html.append(f"            <td>{details_count} issues found</td>")
            else:
                html.append("            <td>No issues found</td>")
            
            html.append("        </tr>")
        
        html.append("    </table>")
        
        # Detailed findings
        html.append("    <h2>Detailed Findings</h2>")
        
        for check_name, result in results.get('vulnerabilities', {}).items():
            html.append(f"    <h3>{check_name}</h3>")
            html.append(f"    <p>{result.get('description', 'N/A')}</p>")
            
            if result.get('vulnerable', False):
                for i, detail in enumerate(result.get('details', [])):
                    html.append(f"    <div class=\"vulnerable\">")
                    html.append(f"        <h4>Issue {i+1}</h4>")
                    html.append("        <ul>")
                    
                    for key, value in detail.items():
                        html.append(f"            <li><strong>{key}:</strong> {value}</li>")
                    
                    html.append("        </ul>")
                    html.append("    </div>")
            else:
                html.append("    <p class=\"secure\">No vulnerabilities detected.</p>")
        
        html.extend([
            "    <p><i>Report generated by Web Vulnerability Scanner</i></p>",
            "</body>",
            "</html>"
        ])
        
        return "\n".join(html)
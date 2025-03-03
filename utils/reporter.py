#!/usr/bin/env python3
"""
Report generator for the web vulnerability scanner.
Creates detailed reports in various formats (HTML, JSON, PDF, etc.).
"""

import json
import os
import datetime
import markdown
import jinja2
import weasyprint

class ReportGenerator:
    """Generates vulnerability scan reports in various formats"""
    
    def __init__(self, template_dir="templates"):
        """Initialize the report generator
        
        Args:
            template_dir: Directory containing report templates
        """
        self.template_dir = template_dir
        self.jinja_env = None
        
        # Initialize Jinja environment if template directory exists
        if os.path.exists(template_dir):
            self.jinja_env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(template_dir),
                autoescape=jinja2.select_autoescape(['html', 'xml'])
            )
    
    def generate(self, results, output_file, format='html', include_remediation=True):
        """Generate a report from scan results
        
        Args:
            results: Scan results
            output_file: Path to save the report
            format: Report format (html, json, pdf, text)
            include_remediation: Whether to include remediation tips
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        try:
            if format.lower() == 'json':
                return self.generate_json(results, output_file)
            elif format.lower() == 'html':
                return self.generate_html(results, output_file, include_remediation)
            elif format.lower() == 'pdf':
                return self.generate_pdf(results, output_file, include_remediation)
            elif format.lower() == 'text':
                return self.generate_text(results, output_file, include_remediation)
            else:
                print(f"Unsupported report format: {format}")
                return False
                
        except Exception as e:
            print(f"Error generating report: {str(e)}")
            return False
    
    def generate_json(self, results, output_file):
        """Generate a JSON report
        
        Args:
            results: Scan results
            output_file: Path to save the report
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        try:
            # Add report metadata
            report_data = {
                'generated_at': datetime.datetime.now().isoformat(),
                'scan_results': results
            }
            
            # Write to file
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=4)
            
            return True
            
        except Exception as e:
            print(f"Error generating JSON report: {str(e)}")
            return False
    
    def generate_html(self, results, output_file, include_remediation=True):
        """Generate an HTML report
        
        Args:
            results: Scan results
            output_file: Path to save the report
            include_remediation: Whether to include remediation tips
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        try:
            # Check if Jinja environment is available
            if not self.jinja_env:
                return self._generate_html_fallback(results, output_file, include_remediation)
            
            # Load template
            template = self.jinja_env.get_template('report.html')
            
            # Prepare data for template
            template_data = {
                'title': 'Web Vulnerability Scan Report',
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'results': results,
                'include_remediation': include_remediation,
                'remediation_tips': self._get_remediation_tips()
            }
            
            # Render template
            output = template.render(**template_data)
            
            # Write to file
            with open(output_file, 'w') as f:
                f.write(output)
            
            return True
            
        except Exception as e:
            print(f"Error generating HTML report: {str(e)}")
            # Fallback to basic HTML generation if template fails
            return self._generate_html_fallback(results, output_file, include_remediation)
    
    def _generate_html_fallback(self, results, output_file, include_remediation=True):
        """Generate a basic HTML report without templates
        
        Args:
            results: Scan results
            output_file: Path to save the report
            include_remediation: Whether to include remediation tips
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        try:
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
                "    <h1>Web Vulnerability Scan Report</h1>",
                f"    <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
            ]
            
            # Target info
            html.append(f"    <h2>Target: {results.get('target', 'N/A')}</h2>")
            
            # Vulnerabilities summary
            html.append("    <h2>Vulnerabilities Summary</h2>")
            html.append("    <table>")
            html.append("        <tr><th>Vulnerability Type</th><th>Status</th><th>Details</th></tr>")
            
            for check_name, result in results.get('vulnerabilities', {}).items():
                status = "Vulnerable" if result.get('vulnerable', False) else "Secure"
                row_class = "vulnerable" if result.get('vulnerable', False) else "secure"
                
                html.append(f'        <tr class="{row_class}">')
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
                        html.append(f'    <div class="vulnerable">')
                        html.append(f"        <h4>Issue {i+1}</h4>")
                        html.append("        <ul>")
                        
                        for key, value in detail.items():
                            html.append(f"            <li><strong>{key}:</strong> {value}</li>")
                        
                        html.append("        </ul>")
                        html.append("    </div>")
                else:
                    html.append('    <p class="secure">No vulnerabilities detected.</p>')
            
            # Remediation tips
            if include_remediation:
                html.append("    <h2>Remediation Tips</h2>")
                remediation_tips = self._get_remediation_tips()
                
                for check_name, result in results.get('vulnerabilities', {}).items():
                    if result.get('vulnerable', False):
                        html.append(f"    <h3>{check_name}</h3>")
                        tip = remediation_tips.get(check_name.lower(), "No specific remediation tips available.")
                        html.append(f"    <p>{tip}</p>")
            
            html.append("</body>")
            html.append("</html>")
            
            # Write to file
            with open(output_file, 'w') as f:
                f.write("\n".join(html))
            
            return True
            
        except Exception as e:
            print(f"Error generating HTML fallback report: {str(e)}")
            return False
    
    def generate_pdf(self, results, output_file, include_remediation=True):
        """Generate a PDF report (uses HTML as intermediate format)
        
        Args:
            results: Scan results
            output_file: Path to save the report
            include_remediation: Whether to include remediation tips
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        try:
            # Generate HTML first
            html_file = output_file + '.html'
            if not self.generate_html(results, html_file, include_remediation):
                return False
            
            # Convert HTML to PDF
            with open(html_file, 'r') as f:
                html_content = f.read()
            
            pdf = weasyprint.HTML(string=html_content).write_pdf()
            
            with open(output_file, 'wb') as f:
                f.write(pdf)
            
            # Clean up temporary HTML file
            os.remove(html_file)
            
            return True
            
        except Exception as e:
            print(f"Error generating PDF report: {str(e)}")
            return False
    
    def generate_text(self, results, output_file, include_remediation=True):
        """Generate a text report
        
        Args:
            results: Scan results
            output_file: Path to save the report
            include_remediation: Whether to include remediation tips
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        try:
            lines = [
                "Web Vulnerability Scan Report",
                "=" * 30,
                "",
                f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Target: {results.get('target', 'N/A')}",
                ""
            ]
            
            # Vulnerabilities summary
            lines.append("Vulnerabilities Summary")
            lines.append("-" * 24)
            
            for check_name, result in results.get('vulnerabilities', {}).items():
                status = "VULNERABLE" if result.get('vulnerable', False) else "SECURE"
                lines.append(f"{check_name}: {status}")
            
            lines.append("")
            
            # Detailed findings
            lines.append("Detailed Findings")
            lines.append("-" * 17)
            lines.append("")
            
            for check_name, result in results.get('vulnerabilities', {}).items():
                lines.append(f"{check_name}:")
                lines.append("-" * len(check_name))
                lines.append(f"Description: {result.get('description', 'N/A')}")
                
                if result.get('vulnerable', False):
                    details = result.get('details', [])
                    lines.append(f"Issues found: {len(details)}")
                    
                    for i, detail in enumerate(details):
                        lines.append(f"  Issue {i+1}:")
                        for key, value in detail.items():
                            lines.append(f"    {key}: {value}")
                else:
                    lines.append("No vulnerabilities detected.")
                
                lines.append("")
            
            # Remediation tips
            if include_remediation:
                lines.append("Remediation Tips")
                lines.append("-" * 16)
                lines.append("")
                
                remediation_tips = self._get_remediation_tips()
                
                for check_name, result in results.get('vulnerabilities', {}).items():
                    if result.get('vulnerable', False):
                        lines.append(f"{check_name}:")
                        tip = remediation_tips.get(check_name.lower(), "No specific remediation tips available.")
                        lines.append(f"{tip}")
                        lines.append("")
            
            # Write to file
            with open(output_file, 'w') as f:
                f.write("\n".join(lines))
            
            return True
            
        except Exception as e:
            print(f"Error generating text report: {str(e)}")
            return False
    
    def _get_remediation_tips(self):
        """Get remediation tips for common vulnerabilities
        
        Returns:
            dict: Mapping of vulnerability types to remediation tips
        """
        return {
            'xss': "Implement proper input validation and output encoding. Always use context-appropriate encoding when reflecting user input in HTML, JavaScript, CSS, or URLs. Consider using Content-Security-Policy headers to mitigate the impact of XSS vulnerabilities.",
            
            'sqli': "Use parameterized queries or prepared statements for all database operations. Never concatenate user input directly into SQL queries. Apply the principle of least privilege to database accounts used by the application.",
            
            'csrf': "Implement anti-CSRF tokens in all forms and state-changing requests. These tokens should be unique per user session and verified on the server side for each request. Consider using the SameSite cookie attribute to limit cross-site requests.",
            
            'security_headers': "Implement recommended security headers: Content-Security-Policy, X-XSS-Protection, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and Referrer-Policy. Configure them appropriately for your application's requirements.",
            
            'open_redirect': "Validate and sanitize all redirect URLs. Use a whitelist of allowed destinations or implement indirect redirects through a server-side mapping to prevent attackers from specifying arbitrary URLs.",
            
            'ssl_tls': "Keep SSL/TLS certificates up to date and use secure protocols (TLS 1.2+ only) and strong cipher suites. Disable older protocols and weak ciphers. Implement HSTS to enforce HTTPS usage.",
            
            'directory_listing': "Disable directory listing in your web server configuration. Add index files to directories that should be accessible or use web server configuration to block directory listing completely.",
            
            'file_inclusion': "Implement strict input validation and use whitelisting for file inclusion. Avoid using user input directly in file paths. Consider using indirect references to files through a secure mapping mechanism.",
            
            'insecure_cookies': "Set the Secure, HttpOnly, and SameSite attributes on cookies containing sensitive information or session identifiers. The Secure attribute ensures cookies are only sent over HTTPS connections, HttpOnly prevents JavaScript access, and SameSite prevents cross-site request attacks.",
            
            'clickjacking': "Use the X-Frame-Options header with 'DENY' or 'SAMEORIGIN' values to prevent your pages from being loaded in frames or iframes. You can also use Content-Security-Policy with the frame-ancestors directive for more control."
        }
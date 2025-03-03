# core/scanner.py
import importlib
import os
import pkgutil
from concurrent.futures import ThreadPoolExecutor
import checks  # Import the checks package

class VulnerabilityScanner:
    def __init__(self):
        # Dynamically load all available vulnerability checks
        self.checks = self._load_checks()
        self.results = {}
        self.scan_active = False
        
    def _load_checks(self):
        """Dynamically load all vulnerability check modules"""
        checks_dict = {}
        # Find all modules in the checks package
        for _, name, _ in pkgutil.iter_modules(checks.__path__):
            # Import the module
            module = importlib.import_module(f'checks.{name}')
            # Get the main check class (assumed to be named Check)
            if hasattr(module, 'Check'):
                check_class = getattr(module, 'Check')
                checks_dict[name] = check_class()
        return checks_dict
    
    def scan(self, target_url, selected_checks=None, max_workers=5, progress_callback=None):
        """Run the selected vulnerability checks against the target URL"""
        self.scan_active = True
        self.results = {
            'target': target_url,
            'vulnerabilities': {}
        }
        
        # Determine which checks to run
        checks_to_run = {}
        if selected_checks:
            for check_name in selected_checks:
                if check_name in self.checks:
                    checks_to_run[check_name] = self.checks[check_name]
        else:
            # Run all checks if none specified
            checks_to_run = self.checks
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_check = {
                executor.submit(check.run, target_url): name
                for name, check in checks_to_run.items()
            }
            
            completed = 0
            total = len(future_to_check)
            
            for future in future_to_check:
                if not self.scan_active:
                    break
                
                name = future_to_check[future]
                try:
                    result = future.result()
                    self.results['vulnerabilities'][name] = result
                    
                    completed += 1
                    if progress_callback:
                        progress_callback(completed / total * 100, name, result)
                        
                except Exception as e:
                    # Handle check failure
                    self.results['vulnerabilities'][name] = {
                        'error': str(e),
                        'vulnerable': False
                    }
        
        self.scan_active = False
        return self.results
    
    def stop_scan(self):
        """Stop an ongoing scan"""
        self.scan_active = False
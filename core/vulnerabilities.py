# core/vulnerabilities.py
class VulnerabilityCheck:
    """Base class for all vulnerability checks"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.description = "Base vulnerability check"
    
    def run(self, target_url):
        """Run this vulnerability check against the target URL
        This method should be overridden by subclasses
        """
        raise NotImplementedError("Subclasses must implement the run method")
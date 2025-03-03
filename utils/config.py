#!/usr/bin/env python3
"""
Configuration utility for the web vulnerability scanner.
Manages loading and saving configuration settings.
"""

import json
import os
import yaml

class ConfigManager:
    """Manages configuration settings for the scanner"""
    
    def __init__(self, config_file=None):
        """Initialize the configuration manager
        
        Args:
            config_file: Path to the configuration file
        """
        self.config_file = config_file
        self.config = {}
        self.default_config = {
            'scanner': {
                'max_workers': 5,
                'timeout': 10,
                'delay': 0.5,
                'user_agent': 'WebVulScanner/1.0',
                'respect_robots': True
            },
            'crawler': {
                'max_depth': 3,
                'max_urls': 100,
                'same_domain_only': True,
                'use_sitemap': True
            },
            'checks': {
                'xss': True,
                'sqli': True,
                'csrf': True,
                'security_headers': True,
                'open_redirect': True,
                'ssl_tls': True
            },
            'reporting': {
                'include_details': True,
                'include_remediation': True,
                'default_format': 'html'
            },
            'proxy': {
                'enabled': False,
                'url': 'http://127.0.0.1:8080'
            }
        }
        
        # Load configuration if config_file is provided
        if config_file and os.path.exists(config_file):
            self.load_config()
        else:
            self.config = self.default_config.copy()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            ext = os.path.splitext(self.config_file)[1].lower()
            
            if ext == '.json':
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
            elif ext in ('.yaml', '.yml'):
                with open(self.config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f)
            else:
                # Default to JSON if extension not recognized
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
            
            # Merge with default config to ensure all required settings exist
            self.config = self.default_config.copy()
            self._update_dict(self.config, loaded_config)
            
            return True
            
        except Exception as e:
            print(f"Error loading configuration: {str(e)}")
            self.config = self.default_config.copy()
            return False
    
    def save_config(self, config_file=None):
        """Save configuration to file
        
        Args:
            config_file: Path to save configuration to (defaults to self.config_file)
        """
        file_path = config_file or self.config_file
        if not file_path:
            return False
        
        try:
            ext = os.path.splitext(file_path)[1].lower()
            
            # Create directory if it doesn't exist
            directory = os.path.dirname(file_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            
            if ext in ('.yaml', '.yml'):
                with open(file_path, 'w') as f:
                    yaml.dump(self.config, f, default_flow_style=False)
            else:
                # Default to JSON
                with open(file_path, 'w') as f:
                    json.dump(self.config, f, indent=4)
            
            return True
            
        except Exception as e:
            print(f"Error saving configuration: {str(e)}")
            return False
    
    def get(self, section, key=None, default=None):
        """Get a configuration value
        
        Args:
            section: Configuration section
            key: Configuration key (if None, returns the entire section)
            default: Default value if the key doesn't exist
            
        Returns:
            Configuration value or default
        """
        if section not in self.config:
            return default
        
        if key is None:
            return self.config[section]
        
        return self.config[section].get(key, default)
    
    def set(self, section, key, value):
        """Set a configuration value
        
        Args:
            section: Configuration section
            key: Configuration key
            value: Value to set
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
    
    def reset(self):
        """Reset configuration to defaults"""
        self.config = self.default_config.copy()
    
    def _update_dict(self, target, source):
        """Recursively update a dictionary with another dictionary
        
        Args:
            target: Target dictionary to update
            source: Source dictionary with new values
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._update_dict(target[key], value)
            else:
                target[key] = value
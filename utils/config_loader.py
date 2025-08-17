#!/usr/bin/env python3
"""
Digital Twin Honeynet - Configuration Loader
Utility for loading configuration from centralized config.yaml
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging


class ConfigLoader:
    """Loads and manages configuration from centralized config file"""
    
    def __init__(self, config_file: str = 'config.yaml'):
        self.config_file = config_file
        self.config = self._load_config()
        self.logger = logging.getLogger(__name__)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing configuration file: {e}")
    
    def get_protocol_config(self, protocol_name: str) -> Dict[str, Any]:
        """Get configuration for a specific protocol"""
        protocols = self.config.get('protocols', {})
        protocol_config = protocols.get(protocol_name, {})
        
        if not protocol_config:
            raise ValueError(f"Protocol '{protocol_name}' not found in configuration")
        
        if not protocol_config.get('enabled', False):
            raise ValueError(f"Protocol '{protocol_name}' is not enabled")
        
        return protocol_config
    
    def get_banner_config(self, protocol_name: str) -> Dict[str, Any]:
        """Get banner configuration for a protocol"""
        protocol_config = self.get_protocol_config(protocol_name)
        return protocol_config.get('banner', {})
    
    def get_response_timing_config(self, protocol_name: str) -> Dict[str, Any]:
        """Get response timing configuration for a protocol"""
        protocol_config = self.get_protocol_config(protocol_name)
        return protocol_config.get('response_timing', {})
    
    def get_network_fingerprinting_config(self) -> Dict[str, Any]:
        """Get network fingerprinting configuration"""
        return self.config.get('network_fingerprinting', {})
    
    def get_access_control_config(self) -> Dict[str, Any]:
        """Get access control configuration"""
        return self.config.get('access_control', {})
    
    def get_whitelist_config(self) -> Dict[str, Any]:
        """Get whitelist configuration"""
        access_control = self.get_access_control_config()
        return access_control.get('whitelist', {})
    
    def get_blacklist_config(self) -> Dict[str, Any]:
        """Get blacklist configuration"""
        access_control = self.get_access_control_config()
        return access_control.get('blacklist', {})
    
    def get_attack_patterns_config(self) -> Dict[str, Any]:
        """Get attack patterns configuration"""
        return self.config.get('attack_patterns', {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.config.get('logging', {})
    
    def get_performance_config(self) -> Dict[str, Any]:
        """Get performance configuration"""
        return self.config.get('performance', {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration"""
        return self.config.get('security', {})
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration"""
        return self.config.get('monitoring', {})
    
    def get_system_config(self) -> Dict[str, Any]:
        """Get system configuration"""
        return self.config.get('system', {})
    
    def is_ip_whitelisted(self, ip_address: str) -> bool:
        """Check if an IP address is whitelisted"""
        whitelist_config = self.get_whitelist_config()
        
        if not whitelist_config.get('enabled', False):
            return False
        
        whitelisted_ips = whitelist_config.get('ips', [])
        
        try:
            from ipaddress import ip_address, ip_network
            client_ip = ip_address(ip_address)
            
            for whitelisted_ip in whitelisted_ips:
                try:
                    # Try as network
                    network = ip_network(whitelisted_ip)
                    if client_ip in network:
                        return True
                except ValueError:
                    # Try as single IP
                    try:
                        whitelisted = ip_address(whitelisted_ip)
                        if client_ip == whitelisted:
                            return True
                    except ValueError:
                        continue
            
            return False
        except ValueError:
            self.logger.warning(f"Invalid IP address: {ip_address}")
            return False
    
    def is_ip_blacklisted(self, ip_address: str) -> bool:
        """Check if an IP address is blacklisted"""
        blacklist_config = self.get_blacklist_config()
        
        if not blacklist_config.get('enabled', False):
            return False
        
        blacklisted_ips = blacklist_config.get('ips', [])
        
        try:
            from ipaddress import ip_address
            client_ip = ip_address(ip_address)
            
            for blacklisted_ip in blacklisted_ips:
                try:
                    blacklisted = ip_address(blacklisted_ip)
                    if client_ip == blacklisted:
                        return True
                except ValueError:
                    continue
            
            return False
        except ValueError:
            self.logger.warning(f"Invalid IP address: {ip_address}")
            return False
    
    def is_user_agent_whitelisted(self, user_agent: str) -> bool:
        """Check if a user agent is whitelisted"""
        whitelist_config = self.get_whitelist_config()
        
        if not whitelist_config.get('enabled', False):
            return False
        
        whitelisted_user_agents = whitelist_config.get('user_agents', [])
        
        for whitelisted_ua in whitelisted_user_agents:
            if whitelisted_ua.lower() in user_agent.lower():
                return True
        
        return False
    
    def is_user_agent_blacklisted(self, user_agent: str) -> bool:
        """Check if a user agent is blacklisted"""
        blacklist_config = self.get_blacklist_config()
        
        if not blacklist_config.get('enabled', False):
            return False
        
        blacklisted_user_agents = blacklist_config.get('user_agents', [])
        
        for blacklisted_ua in blacklisted_user_agents:
            if blacklisted_ua.lower() in user_agent.lower():
                return True
        
        return False
    
    def is_pattern_whitelisted(self, pattern: str) -> bool:
        """Check if a pattern is whitelisted"""
        whitelist_config = self.get_whitelist_config()
        
        if not whitelist_config.get('enabled', False):
            return False
        
        whitelisted_patterns = whitelist_config.get('patterns', [])
        
        for whitelisted_pattern in whitelisted_patterns:
            if whitelisted_pattern.lower() in pattern.lower():
                return True
        
        return False
    
    def is_pattern_blacklisted(self, pattern: str) -> bool:
        """Check if a pattern is blacklisted"""
        blacklist_config = self.get_blacklist_config()
        
        if not blacklist_config.get('enabled', False):
            return False
        
        blacklisted_patterns = blacklist_config.get('patterns', [])
        
        for blacklisted_pattern in blacklisted_patterns:
            if blacklisted_pattern.lower() in pattern.lower():
                return True
        
        return False
    
    def detect_attack_patterns(self, content: str) -> List[str]:
        """Detect attack patterns in content"""
        attack_patterns = self.get_attack_patterns_config()
        detected_attacks = []
        
        content_lower = content.lower()
        
        # Check SQL injection patterns
        sql_patterns = attack_patterns.get('sql_injection', [])
        for pattern in sql_patterns:
            if pattern.lower() in content_lower:
                detected_attacks.append(f"SQL Injection: {pattern}")
        
        # Check XSS patterns
        xss_patterns = attack_patterns.get('xss', [])
        for pattern in xss_patterns:
            if pattern.lower() in content_lower:
                detected_attacks.append(f"XSS: {pattern}")
        
        # Check path traversal patterns
        path_traversal_patterns = attack_patterns.get('path_traversal', [])
        for pattern in path_traversal_patterns:
            if pattern.lower() in content_lower:
                detected_attacks.append(f"Path Traversal: {pattern}")
        
        # Check file inclusion patterns
        file_inclusion_patterns = attack_patterns.get('file_inclusion', [])
        for pattern in file_inclusion_patterns:
            if pattern.lower() in content_lower:
                detected_attacks.append(f"File Inclusion: {pattern}")
        
        # Check command injection patterns
        command_injection_patterns = attack_patterns.get('command_injection', [])
        for pattern in command_injection_patterns:
            if pattern.lower() in content_lower:
                detected_attacks.append(f"Command Injection: {pattern}")
        
        return detected_attacks
    
    def get_randomized_network_params(self) -> Dict[str, Any]:
        """Get randomized network parameters for stealth"""
        network_config = self.get_network_fingerprinting_config()
        
        if not network_config.get('enabled', False):
            # Return production fingerprint
            return network_config.get('production_fingerprint', {})
        
        tcp_config = network_config.get('tcp_randomization', {})
        if not tcp_config.get('enabled', False):
            # Return production fingerprint
            return network_config.get('production_fingerprint', {})
        
        import random
        
        # Randomize window size
        window_config = tcp_config.get('window_size', {})
        base_window = window_config.get('base', 65535)
        variation = window_config.get('variation', 0.1)
        min_window = window_config.get('min', 4096)
        max_window = window_config.get('max', 131072)
        
        window_variation = random.uniform(-variation, variation)
        window_size = int(base_window * (1 + window_variation))
        window_size = max(min_window, min(max_window, window_size))
        
        # Randomize TTL
        ttl_config = tcp_config.get('ttl', {})
        base_ttl = ttl_config.get('base', 64)
        variation = ttl_config.get('variation', 0.15)
        min_ttl = ttl_config.get('min', 32)
        max_ttl = ttl_config.get('max', 128)
        
        ttl_variation = random.uniform(-variation, variation)
        ttl = int(base_ttl * (1 + ttl_variation))
        ttl = max(min_ttl, min(max_ttl, ttl))
        
        # Randomize MSS
        mss_config = tcp_config.get('mss', {})
        base_mss = mss_config.get('base', 1460)
        variation = mss_config.get('variation', 0.05)
        min_mss = mss_config.get('min', 536)
        max_mss = mss_config.get('max', 1460)
        
        mss_variation = random.uniform(-variation, variation)
        mss = int(base_mss * (1 + mss_variation))
        mss = max(min_mss, min(max_mss, mss))
        
        # Randomize timing
        timing_config = tcp_config.get('timing', {})
        base_delay = timing_config.get('base_response_delay', 0.05)
        jitter_range = timing_config.get('jitter_range', [0.02, 0.05])
        min_delay = timing_config.get('min_delay', 0.01)
        max_delay = timing_config.get('max_delay', 0.15)
        
        if isinstance(jitter_range, list):
            jitter = random.uniform(jitter_range[0], jitter_range[1])
        else:
            jitter = random.uniform(-jitter_range, jitter_range)
        
        response_delay = base_delay + jitter
        response_delay = max(min_delay, min(max_delay, response_delay))
        
        return {
            'window_size': window_size,
            'ttl': ttl,
            'mss': mss,
            'response_delay': response_delay
        }
    
    def get_response_delay(self, protocol_name: str, connection_id: Optional[str] = None) -> float:
        """Get response delay for a protocol with optional connection variation"""
        timing_config = self.get_response_timing_config(protocol_name)
        
        if not timing_config.get('enabled', False):
            return 0.0
        
        import random
        
        base_delay = timing_config.get('base_delay', 0.1)
        jitter_range = timing_config.get('jitter_range', 0.05)
        min_delay = timing_config.get('min_delay', 0.05)
        max_delay = timing_config.get('max_delay', 0.3)
        
        # Add jitter
        jitter = random.uniform(-jitter_range, jitter_range)
        delay = base_delay + jitter
        
        # Add connection variation if enabled
        if timing_config.get('connection_variation', False) and connection_id:
            # Use connection_id hash for consistent variation per connection
            import hashlib
            hash_value = int(hashlib.md5(connection_id.encode()).hexdigest()[:8], 16)
            connection_variation = (hash_value % 1000) / 10000  # 0-0.1 variation
            delay += connection_variation
        
        # Ensure delay is within bounds
        delay = max(min_delay, min(max_delay, delay))
        
        return delay
    
    def get_random_banner(self, protocol_name: str) -> str:
        """Get a random banner for a protocol"""
        banner_config = self.get_banner_config(protocol_name)
        
        if not banner_config.get('randomization_enabled', False):
            # Return default banner
            if protocol_name == 'http':
                return banner_config.get('server', 'nginx/1.18.0 (Ubuntu)')
            elif protocol_name == 'ssh':
                return banner_config.get('server', 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5')
            elif protocol_name == 'rdp':
                return banner_config.get('server_name', 'Windows Server 2019')
            elif protocol_name == 'smb':
                return banner_config.get('server_name', 'Windows Server 2019')
            else:
                return banner_config.get('server', 'Unknown')
        
        # Return random banner from alternatives
        alternative_banners = banner_config.get('alternative_banners', [])
        if alternative_banners:
            import random
            return random.choice(alternative_banners)
        else:
            # Fall back to default
            if protocol_name == 'http':
                return banner_config.get('server', 'nginx/1.18.0 (Ubuntu)')
            elif protocol_name == 'ssh':
                return banner_config.get('server', 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5')
            elif protocol_name == 'rdp':
                return banner_config.get('server_name', 'Windows Server 2019')
            elif protocol_name == 'smb':
                return banner_config.get('server_name', 'Windows Server 2019')
            else:
                return banner_config.get('server', 'Unknown')
    
    def setup_logging(self, service_name: str) -> logging.Logger:
        """Setup logging for a service based on configuration"""
        logging_config = self.get_logging_config()
        
        if not logging_config.get('enabled', True):
            return logging.getLogger(service_name)
        
        logger = logging.getLogger(service_name)
        logger.setLevel(getattr(logging, logging_config.get('level', 'INFO')))
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # File handler
        log_file = logging_config.get('log_file', f'logs/{service_name}.log')
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        return logger


# Global config loader instance
_config_loader = None


def get_config_loader(config_file: str = 'config.yaml') -> ConfigLoader:
    """Get global config loader instance"""
    global _config_loader
    if _config_loader is None:
        _config_loader = ConfigLoader(config_file)
    return _config_loader


def get_protocol_config(protocol_name: str, config_file: str = 'config.yaml') -> Dict[str, Any]:
    """Get configuration for a specific protocol"""
    loader = get_config_loader(config_file)
    return loader.get_protocol_config(protocol_name)


def get_banner_config(protocol_name: str, config_file: str = 'config.yaml') -> Dict[str, Any]:
    """Get banner configuration for a protocol"""
    loader = get_config_loader(config_file)
    return loader.get_banner_config(protocol_name)


def get_response_timing_config(protocol_name: str, config_file: str = 'config.yaml') -> Dict[str, Any]:
    """Get response timing configuration for a protocol"""
    loader = get_config_loader(config_file)
    return loader.get_response_timing_config(protocol_name)


def get_network_fingerprinting_config(config_file: str = 'config.yaml') -> Dict[str, Any]:
    """Get network fingerprinting configuration"""
    loader = get_config_loader(config_file)
    return loader.get_network_fingerprinting_config()


def get_access_control_config(config_file: str = 'config.yaml') -> Dict[str, Any]:
    """Get access control configuration"""
    loader = get_config_loader(config_file)
    return loader.get_access_control_config()


def is_ip_whitelisted(ip_address: str, config_file: str = 'config.yaml') -> bool:
    """Check if an IP address is whitelisted"""
    loader = get_config_loader(config_file)
    return loader.is_ip_whitelisted(ip_address)


def is_ip_blacklisted(ip_address: str, config_file: str = 'config.yaml') -> bool:
    """Check if an IP address is blacklisted"""
    loader = get_config_loader(config_file)
    return loader.is_ip_blacklisted(ip_address)


def detect_attack_patterns(content: str, config_file: str = 'config.yaml') -> List[str]:
    """Detect attack patterns in content"""
    loader = get_config_loader(config_file)
    return loader.detect_attack_patterns(content)


def get_randomized_network_params(config_file: str = 'config.yaml') -> Dict[str, Any]:
    """Get randomized network parameters for stealth"""
    loader = get_config_loader(config_file)
    return loader.get_randomized_network_params()


def get_response_delay(protocol_name: str, connection_id: Optional[str] = None, config_file: str = 'config.yaml') -> float:
    """Get response delay for a protocol"""
    loader = get_config_loader(config_file)
    return loader.get_response_delay(protocol_name, connection_id)


def get_random_banner(protocol_name: str, config_file: str = 'config.yaml') -> str:
    """Get a random banner for a protocol"""
    loader = get_config_loader(config_file)
    return loader.get_random_banner(protocol_name)


def setup_logging(service_name: str, config_file: str = 'config.yaml') -> logging.Logger:
    """Setup logging for a service"""
    loader = get_config_loader(config_file)
    return loader.setup_logging(service_name)

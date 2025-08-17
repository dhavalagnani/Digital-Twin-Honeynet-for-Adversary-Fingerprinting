#!/usr/bin/env python3
"""
Digital Twin Honeynet - HTTP Fingerprint Fetcher
Fetches and stores real server's HTTP fingerprint for honeypot mimicry
"""
import requests
import time
import logging
import json
import yaml
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, asdict
import socket
import ssl
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

@dataclass
class HTTPFingerprint:
    """HTTP fingerprint data structure"""
    hostname: str
    port: int
    scheme: str
    headers: Dict[str, str]
    response_times: List[float]
    status_codes: List[int]
    content_types: List[str]
    server_technologies: List[str]
    security_headers: Dict[str, str]
    timestamp: str

class HTTPFingerprintFetcher:
    """Fetches HTTP fingerprint from real servers"""
    
    def __init__(self, config_path: str = "honeypot/http_fingerprint_config.yaml"):
        """Initialize HTTP fingerprint fetcher"""
        self.config_path = config_path
        self.config = self._load_config()
        self.fingerprints = {}
        
    def _load_config(self) -> Dict[str, Any]:
        """Load HTTP fingerprint fetcher configuration"""
        default_config = {
            'target_servers': [
                {
                    'hostname': 'production-server',
                    'port': 80,
                    'scheme': 'http',
                    'timeout': 10
                }
            ],
            'fetch_settings': {
                'max_attempts': 3,
                'delay_between_attempts': 1,
                'connection_timeout': 10,
                'request_timeout': 30
            },
            'output': {
                'fingerprint_file': 'honeypot/production_http_fingerprint.json',
                'config_file': 'honeypot/http_fingerprint_config.yaml',
                'log_file': 'honeypot/http_fingerprint.log'
            },
            'test_paths': [
                '/',
                '/index.html',
                '/admin',
                '/login',
                '/api/health',
                '/robots.txt',
                '/favicon.ico'
            ]
        }
        
        if Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except Exception as e:
                logger.error(f"Error loading config: {e}")
                return default_config
        else:
            # Create default config file
            self._save_config(default_config)
            return default_config
    
    def _save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def fetch_server_headers(self, hostname: str, port: int, scheme: str = 'http', timeout: int = 10) -> Optional[Dict[str, str]]:
        """Fetch HTTP headers from server"""
        try:
            url = f"{scheme}://{hostname}:{port}"
            logger.info(f"Fetching headers from {url}")
            
            # Use requests to get headers
            response = requests.head(url, timeout=timeout, allow_redirects=False)
            
            headers = dict(response.headers)
            logger.info(f"Headers fetched: {list(headers.keys())}")
            
            return headers
            
        except Exception as e:
            logger.error(f"Error fetching headers from {hostname}:{port}: {e}")
            return None
    
    def measure_response_times(self, hostname: str, port: int, scheme: str = 'http', 
                             paths: List[str] = None, num_tests: int = 5) -> List[float]:
        """Measure response times for different paths"""
        if paths is None:
            paths = self.config['test_paths']
        
        response_times = []
        
        for path in paths:
            for i in range(num_tests):
                try:
                    url = f"{scheme}://{hostname}:{port}{path}"
                    start_time = time.time()
                    
                    response = requests.get(url, timeout=10, allow_redirects=False)
                    response_time = time.time() - start_time
                    
                    response_times.append(response_time)
                    
                    # Small delay between tests
                    time.sleep(0.5)
                    
                except Exception as e:
                    logger.warning(f"Response time test failed for {path}: {e}")
        
        return response_times
    
    def detect_server_technologies(self, headers: Dict[str, str]) -> List[str]:
        """Detect server technologies from headers"""
        technologies = []
        
        # Check Server header
        if 'Server' in headers:
            technologies.append(f"Server: {headers['Server']}")
        
        # Check X-Powered-By header
        if 'X-Powered-By' in headers:
            technologies.append(f"Powered-By: {headers['X-Powered-By']}")
        
        # Check for common technology indicators
        tech_indicators = {
            'X-AspNet-Version': 'ASP.NET',
            'X-AspNetMvc-Version': 'ASP.NET MVC',
            'X-Runtime': 'Ruby on Rails',
            'X-Version': 'Custom Framework',
            'CF-RAY': 'Cloudflare',
            'X-Amz-Cf-Id': 'AWS CloudFront',
            'X-Cache': 'CDN/Proxy',
            'X-Frame-Options': 'Security Headers',
            'X-Content-Type-Options': 'Security Headers',
            'Strict-Transport-Security': 'HTTPS Enforcement'
        }
        
        for header, tech in tech_indicators.items():
            if header in headers:
                technologies.append(tech)
        
        return technologies
    
    def extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract security-related headers"""
        security_headers = {}
        
        security_header_names = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-Permitted-Cross-Domain-Policies'
        ]
        
        for header in security_header_names:
            if header in headers:
                security_headers[header] = headers[header]
        
        return security_headers
    
    def get_status_codes(self, hostname: str, port: int, scheme: str = 'http', 
                        paths: List[str] = None) -> List[int]:
        """Get status codes for different paths"""
        if paths is None:
            paths = self.config['test_paths']
        
        status_codes = []
        
        for path in paths:
            try:
                url = f"{scheme}://{hostname}:{port}{path}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                status_codes.append(response.status_code)
                
            except Exception as e:
                logger.warning(f"Status code test failed for {path}: {e}")
                status_codes.append(0)  # Connection failed
        
        return status_codes
    
    def get_content_types(self, hostname: str, port: int, scheme: str = 'http', 
                         paths: List[str] = None) -> List[str]:
        """Get content types for different paths"""
        if paths is None:
            paths = self.config['test_paths']
        
        content_types = []
        
        for path in paths:
            try:
                url = f"{scheme}://{hostname}:{port}{path}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                content_type = response.headers.get('Content-Type', '')
                if content_type:
                    content_types.append(content_type)
                
            except Exception as e:
                logger.warning(f"Content type test failed for {path}: {e}")
        
        return content_types
    
    def fetch_server_fingerprint(self, server_config: Dict[str, Any]) -> Optional[HTTPFingerprint]:
        """Fetch complete HTTP fingerprint from server"""
        hostname = server_config['hostname']
        port = server_config['port']
        scheme = server_config.get('scheme', 'http')
        timeout = server_config.get('timeout', 10)
        
        logger.info(f"Fetching HTTP fingerprint from {hostname}:{port}")
        
        # Fetch headers
        headers = self.fetch_server_headers(hostname, port, scheme, timeout)
        if not headers:
            logger.error(f"Failed to fetch headers from {hostname}")
            return None
        
        # Measure response times
        response_times = self.measure_response_times(hostname, port, scheme)
        
        # Get status codes
        status_codes = self.get_status_codes(hostname, port, scheme)
        
        # Get content types
        content_types = self.get_content_types(hostname, port, scheme)
        
        # Detect technologies
        technologies = self.detect_server_technologies(headers)
        
        # Extract security headers
        security_headers = self.extract_security_headers(headers)
        
        # Create fingerprint
        fingerprint = HTTPFingerprint(
            hostname=hostname,
            port=port,
            scheme=scheme,
            headers=headers,
            response_times=response_times,
            status_codes=status_codes,
            content_types=content_types,
            server_technologies=technologies,
            security_headers=security_headers,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )
        
        logger.info(f"HTTP fingerprint collected for {hostname}")
        return fingerprint
    
    def fetch_all_fingerprints(self) -> Dict[str, HTTPFingerprint]:
        """Fetch fingerprints from all configured servers"""
        fingerprints = {}
        
        for server_config in self.config['target_servers']:
            hostname = server_config['hostname']
            fingerprint = self.fetch_server_fingerprint(server_config)
            if fingerprint:
                fingerprints[hostname] = fingerprint
        
        return fingerprints
    
    def save_fingerprints(self, fingerprints: Dict[str, HTTPFingerprint]) -> None:
        """Save fingerprints to JSON file"""
        output_file = self.config['output']['fingerprint_file']
        
        # Convert to serializable format
        data = {}
        for hostname, fingerprint in fingerprints.items():
            data[hostname] = asdict(fingerprint)
        
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"HTTP fingerprints saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving fingerprints: {e}")
    
    def update_http_config(self, fingerprints: Dict[str, HTTPFingerprint]) -> None:
        """Update HTTP honeypot configuration with production server fingerprints"""
        if not fingerprints:
            logger.warning("No fingerprints available for config update")
            return
        
        # Use the first fingerprint as primary
        primary_hostname = list(fingerprints.keys())[0]
        primary_fp = fingerprints[primary_hostname]
        
        logger.info(f"Updating HTTP config with fingerprint from {primary_hostname}")
        
        # Read current HTTP config
        http_config_path = "honeypot/http_config.yaml"
        if not Path(http_config_path).exists():
            logger.error(f"HTTP config file not found: {http_config_path}")
            return
        
        try:
            with open(http_config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Update headers section
            if 'headers' in config:
                if 'Server' in primary_fp.headers:
                    config['headers']['server'] = primary_fp.headers['Server']
                if 'X-Powered-By' in primary_fp.headers:
                    config['headers']['x_powered_by'] = primary_fp.headers['X-Powered-By']
                if 'Content-Type' in primary_fp.headers:
                    config['headers']['content_type'] = primary_fp.headers['Content-Type']
            
            # Update response timing based on measured times
            if 'response_timing' in config and primary_fp.response_times:
                avg_response_time = sum(primary_fp.response_times) / len(primary_fp.response_times)
                config['response_timing']['base_delay'] = avg_response_time
            
            # Add detected technologies
            if primary_fp.server_technologies:
                config['headers']['detected_technologies'] = primary_fp.server_technologies
            
            # Add security headers
            if primary_fp.security_headers:
                config['headers']['security_headers'] = primary_fp.security_headers
            
            # Write updated config
            with open(http_config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            logger.info(f"HTTP config updated with production server fingerprint")
            
        except Exception as e:
            logger.error(f"Error updating HTTP config: {e}")
    
    def run_fingerprint_collection(self) -> bool:
        """Run complete HTTP fingerprint collection process"""
        logger.info("Starting HTTP fingerprint collection process")
        
        try:
            # Fetch all fingerprints
            fingerprints = self.fetch_all_fingerprints()
            
            if not fingerprints:
                logger.error("No fingerprints collected")
                return False
            
            # Save fingerprints
            self.save_fingerprints(fingerprints)
            
            # Update HTTP config
            self.update_http_config(fingerprints)
            
            logger.info("HTTP fingerprint collection completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error during fingerprint collection: {e}")
            return False

def main():
    """Main function for HTTP fingerprint fetcher"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("Digital Twin Honeynet - HTTP Fingerprint Fetcher")
    print("=" * 55)
    
    fetcher = HTTPFingerprintFetcher()
    
    # Run fingerprint collection
    success = fetcher.run_fingerprint_collection()
    
    if success:
        print("\n✅ HTTP fingerprint collection completed successfully!")
        print("   Production server HTTP fingerprints have been saved and config updated.")
    else:
        print("\n❌ HTTP fingerprint collection failed!")
        print("   Please check the logs for details.")
    
    return 0 if success else 1

if __name__ == '__main__':
    exit(main())

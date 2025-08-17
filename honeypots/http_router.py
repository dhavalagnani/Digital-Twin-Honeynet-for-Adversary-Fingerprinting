#!/usr/bin/env python3
"""
Digital Twin Honeynet - HTTP Router/Reverse Proxy
Routes legitimate HTTP traffic to production server, suspicious traffic to honeypot
"""
import logging
import yaml
import time
import threading
from typing import Dict, Any, Optional, List
from pathlib import Path
from flask import Flask, request, Response, redirect
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
from urllib.parse import urljoin, urlparse
import ipaddress

logger = logging.getLogger(__name__)

class HTTPRouter:
    """HTTP router for traffic separation between honeypot and production"""
    
    def __init__(self, config_path: str = "honeypot/router_config.yaml"):
        """Initialize HTTP router"""
        self.config_path = config_path
        self.config = self._load_config()
        self.app = Flask(__name__)
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_proto=1, x_host=1)
        
        # Setup routes
        self._setup_routes()
        
        logger.info("HTTP router initialized successfully")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load router configuration"""
        default_config = {
            'router': {
                'host': '0.0.0.0',
                'port': 80,
                'debug': False,
                'threaded': True
            },
            'honeypot': {
                'host': 'localhost',
                'port': 8080,
                'scheme': 'http'
            },
            'production': {
                'host': '192.168.1.100',
                'port': 80,
                'scheme': 'http'
            },
            'whitelist': {
                'enabled': True,
                'ips': ['127.0.0.1', '192.168.1.0/24', '10.0.0.0/8'],
                'user_agents': ['legitimate-bot', 'monitoring-agent', 'health-check'],
                'paths': ['/health', '/status', '/ping', '/favicon.ico']
            },
            'blacklist': {
                'enabled': True,
                'ips': [],
                'user_agents': ['sqlmap', 'nikto', 'nmap', 'dirb', 'gobuster'],
                'patterns': ['admin', 'wp-admin', 'phpmyadmin', 'config']
            },
            'logging': {
                'enabled': True,
                'log_file': 'honeypot/router.log',
                'level': 'INFO'
            }
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
    
    def _setup_routes(self) -> None:
        """Setup Flask routes"""
        
        @self.app.before_request
        def before_request():
            """Log and analyze incoming requests"""
            self._log_request(request)
        
        @self.app.route('/', defaults={'path': ''})
        @self.app.route('/<path:path>')
        def route_request(path):
            """Route request to appropriate destination"""
            return self._route_request(request, path)
    
    def _log_request(self, request) -> None:
        """Log incoming request"""
        logger.info(f"Router: {request.method} {request.path} from {request.remote_addr}")
    
    def _is_whitelisted(self, request) -> bool:
        """Check if request is whitelisted"""
        whitelist_config = self.config['whitelist']
        if not whitelist_config['enabled']:
            return False
        
        client_ip = request.remote_addr
        
        # Check IP whitelist
        for whitelisted_ip in whitelist_config['ips']:
            if self._ip_in_network(client_ip, whitelisted_ip):
                logger.info(f"IP {client_ip} whitelisted")
                return True
        
        # Check User-Agent whitelist
        user_agent = request.headers.get('User-Agent', '')
        for whitelisted_ua in whitelist_config['user_agents']:
            if whitelisted_ua.lower() in user_agent.lower():
                logger.info(f"User-Agent {user_agent} whitelisted")
                return True
        
        # Check path whitelist
        for whitelisted_path in whitelist_config['paths']:
            if whitelisted_path in request.path:
                logger.info(f"Path {request.path} whitelisted")
                return True
        
        return False
    
    def _is_blacklisted(self, request) -> bool:
        """Check if request is blacklisted"""
        blacklist_config = self.config['blacklist']
        if not blacklist_config['enabled']:
            return False
        
        client_ip = request.remote_addr
        
        # Check IP blacklist
        for blacklisted_ip in blacklist_config['ips']:
            if self._ip_in_network(client_ip, blacklisted_ip):
                logger.warning(f"IP {client_ip} blacklisted")
                return True
        
        # Check User-Agent blacklist
        user_agent = request.headers.get('User-Agent', '')
        for blacklisted_ua in blacklist_config['user_agents']:
            if blacklisted_ua.lower() in user_agent.lower():
                logger.warning(f"User-Agent {user_agent} blacklisted")
                return True
        
        # Check pattern blacklist
        for blacklisted_pattern in blacklist_config['patterns']:
            if blacklisted_pattern.lower() in request.path.lower():
                logger.warning(f"Path {request.path} matches blacklist pattern {blacklisted_pattern}")
                return True
        
        return False
    
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network range"""
        try:
            if '/' in network:
                # CIDR notation
                return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
            else:
                # Single IP
                return ip == network
        except Exception:
            return False
    
    def _route_request(self, request, path: str):
        """Route request to appropriate destination"""
        # Check blacklist first
        if self._is_blacklisted(request):
            logger.warning(f"Request from {request.remote_addr} blacklisted, sending to honeypot")
            return self._forward_to_honeypot(request)
        
        # Check whitelist
        if self._is_whitelisted(request):
            logger.info(f"Request from {request.remote_addr} whitelisted, sending to production")
            return self._forward_to_production(request)
        
        # Default: send to honeypot for analysis
        logger.info(f"Request from {request.remote_addr} sent to honeypot for analysis")
        return self._forward_to_honeypot(request)
    
    def _forward_to_production(self, request):
        """Forward request to production server"""
        production_config = self.config['production']
        
        # Build production URL
        production_url = f"{production_config['scheme']}://{production_config['host']}:{production_config['port']}{request.full_path}"
        
        try:
            # Forward the request
            if request.method == 'GET':
                response = requests.get(production_url, headers=dict(request.headers), timeout=30)
            elif request.method == 'POST':
                response = requests.post(production_url, data=request.get_data(), headers=dict(request.headers), timeout=30)
            elif request.method == 'PUT':
                response = requests.put(production_url, data=request.get_data(), headers=dict(request.headers), timeout=30)
            elif request.method == 'DELETE':
                response = requests.delete(production_url, headers=dict(request.headers), timeout=30)
            else:
                response = requests.request(request.method, production_url, data=request.get_data(), headers=dict(request.headers), timeout=30)
            
            # Create response
            flask_response = Response(
                response.content,
                status=response.status_code,
                headers=dict(response.headers)
            )
            
            logger.info(f"Request forwarded to production: {response.status_code}")
            return flask_response
            
        except Exception as e:
            logger.error(f"Error forwarding to production: {e}")
            return Response(
                'Service temporarily unavailable',
                status=503,
                headers={'Content-Type': 'text/plain'}
            )
    
    def _forward_to_honeypot(self, request):
        """Forward request to honeypot"""
        honeypot_config = self.config['honeypot']
        
        # Build honeypot URL
        honeypot_url = f"{honeypot_config['scheme']}://{honeypot_config['host']}:{honeypot_config['port']}{request.full_path}"
        
        try:
            # Forward the request
            if request.method == 'GET':
                response = requests.get(honeypot_url, headers=dict(request.headers), timeout=30)
            elif request.method == 'POST':
                response = requests.post(honeypot_url, data=request.get_data(), headers=dict(request.headers), timeout=30)
            elif request.method == 'PUT':
                response = requests.put(honeypot_url, data=request.get_data(), headers=dict(request.headers), timeout=30)
            elif request.method == 'DELETE':
                response = requests.delete(honeypot_url, headers=dict(request.headers), timeout=30)
            else:
                response = requests.request(request.method, honeypot_url, data=request.get_data(), headers=dict(request.headers), timeout=30)
            
            # Create response
            flask_response = Response(
                response.content,
                status=response.status_code,
                headers=dict(response.headers)
            )
            
            logger.info(f"Request forwarded to honeypot: {response.status_code}")
            return flask_response
            
        except Exception as e:
            logger.error(f"Error forwarding to honeypot: {e}")
            return Response(
                'Service temporarily unavailable',
                status=503,
                headers={'Content-Type': 'text/plain'}
            )
    
    def run(self, host: str = None, port: int = None, debug: bool = None):
        """Run the HTTP router"""
        router_config = self.config['router']
        
        host = host or router_config['host']
        port = port or router_config['port']
        debug = debug if debug is not None else router_config['debug']
        
        logger.info(f"Starting HTTP router on {host}:{port}")
        
        self.app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=router_config['threaded']
        )

def main():
    """Main function for HTTP router"""
    logging.basicConfig(level=logging.INFO)
    
    print("Digital Twin Honeynet - HTTP Router")
    print("=" * 35)
    
    router = HTTPRouter()
    router.run()

if __name__ == '__main__':
    main()

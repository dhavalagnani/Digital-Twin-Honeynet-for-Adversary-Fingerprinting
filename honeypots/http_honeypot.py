#!/usr/bin/env python3
"""
Digital Twin Honeynet - HTTP Honeypot
Lightweight Flask-based HTTP honeypot for detecting web-based attacks
"""
import json
import time
import logging
import threading
import random
import socket
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import configparser
from flask import Flask, request, Response, jsonify, render_template_string
from werkzeug.middleware.proxy_fix import ProxyFix
import yaml

logger = logging.getLogger(__name__)

@dataclass
class HTTPRequest:
    """HTTP request data structure for logging"""
    timestamp: str
    method: str
    path: str
    query_params: Dict[str, str]
    headers: Dict[str, str]
    payload: str
    client_ip: str
    user_agent: str
    content_type: str
    content_length: int
    request_id: str

@dataclass
class HTTPResponse:
    """HTTP response data structure for logging"""
    timestamp: str
    status_code: int
    headers: Dict[str, str]
    payload: str
    response_time: float
    request_id: str

class HTTPHoneypot:
    """Lightweight HTTP honeypot for detecting web-based attacks"""
    
    def __init__(self, config_path: str = "honeypot/http_config.yaml"):
        """Initialize HTTP honeypot with configuration"""
        self.config_path = config_path
        self.config = self._load_config()
        self.app = Flask(__name__)
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_proto=1, x_host=1)
        self.request_counter = 0
        self._lock = threading.Lock()
        
        # Setup logging
        self._setup_logging()
        
        # Setup routes
        self._setup_routes()
        
        # Load production server fingerprint
        self.production_fingerprint = self._load_production_fingerprint()
        
        logger.info("HTTP honeypot initialized successfully")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load HTTP honeypot configuration"""
        default_config = {
            'server': {
                'host': '0.0.0.0',
                'port': 8080,
                'debug': False,
                'threaded': True
            },
            'production_server': {
                'host': 'production-server',
                'port': 80,
                'scheme': 'http'
            },
            'whitelist': {
                'enabled': True,
                'ips': ['127.0.0.1', '192.168.1.0/24', '10.0.0.0/8'],
                'user_agents': ['legitimate-bot', 'monitoring-agent']
            },
            'response_timing': {
                'enabled': True,
                'base_delay': 0.1,
                'jitter_range': 0.05,
                'min_delay': 0.05,
                'max_delay': 0.3
            },
            'headers': {
                'server': 'nginx/1.18.0 (Ubuntu)',
                'x_powered_by': 'PHP/7.4.3',
                'content_type': 'text/html; charset=UTF-8',
                'date_format': '%a, %d %b %Y %H:%M:%S GMT'
            },
            'logging': {
                'enabled': True,
                'log_file': 'honeypot/http_honeypot.log',
                'json_log_file': 'honeypot/http_honeypot.json',
                'level': 'INFO'
            },
            'templates': {
                'default_page': 'index.html',
                'error_404': '404.html',
                'error_500': '500.html'
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
    
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        log_config = self.config['logging']
        if log_config['enabled']:
            logging.basicConfig(
                level=getattr(logging, log_config['level']),
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_config['log_file']),
                    logging.StreamHandler()
                ]
            )
    
    def _load_production_fingerprint(self) -> Dict[str, Any]:
        """Load production server HTTP fingerprint"""
        fingerprint_file = "honeypot/production_http_fingerprint.json"
        if Path(fingerprint_file).exists():
            try:
                with open(fingerprint_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading HTTP fingerprint: {e}")
        
        # Return default fingerprint
        return {
            'headers': {
                'Server': 'nginx/1.18.0 (Ubuntu)',
                'X-Powered-By': 'PHP/7.4.3',
                'Content-Type': 'text/html; charset=UTF-8'
            },
            'response_times': [0.1, 0.15, 0.2, 0.25, 0.3],
            'status_codes': [200, 404, 500],
            'content_types': [
                'text/html; charset=UTF-8',
                'application/json',
                'text/plain'
            ]
        }
    
    def _setup_routes(self) -> None:
        """Setup Flask routes"""
        
        @self.app.before_request
        def before_request():
            """Log incoming requests"""
            self._log_request(request)
        
        @self.app.after_request
        def after_request(response):
            """Log outgoing responses"""
            self._log_response(response)
            return response
        
        @self.app.route('/', defaults={'path': ''})
        @self.app.route('/<path:path>')
        def catch_all(path):
            """Catch all routes and handle appropriately"""
            return self._handle_request(request, path)
        
        @self.app.errorhandler(404)
        def not_found(error):
            """Handle 404 errors"""
            return self._handle_404(request)
        
        @self.app.errorhandler(500)
        def internal_error(error):
            """Handle 500 errors"""
            return self._handle_500(request)
    
    def _is_whitelisted(self, request) -> bool:
        """Check if request is from whitelisted source"""
        whitelist_config = self.config['whitelist']
        if not whitelist_config['enabled']:
            return False
        
        client_ip = request.remote_addr
        
        # Check IP whitelist
        for whitelisted_ip in whitelist_config['ips']:
            if self._ip_in_network(client_ip, whitelisted_ip):
                return True
        
        # Check User-Agent whitelist
        user_agent = request.headers.get('User-Agent', '')
        for whitelisted_ua in whitelist_config['user_agents']:
            if whitelisted_ua.lower() in user_agent.lower():
                return True
        
        return False
    
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network range"""
        try:
            if '/' in network:
                # CIDR notation
                import ipaddress
                return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
            else:
                # Single IP
                return ip == network
        except Exception:
            return False
    
    def _get_response_delay(self, request_id: str) -> float:
        """Calculate randomized response delay"""
        timing_config = self.config['response_timing']
        if not timing_config['enabled']:
            return 0.0
        
        # Use request ID for consistent delay per request
        random.seed(hash(request_id))
        
        base_delay = timing_config['base_delay']
        jitter = random.uniform(-timing_config['jitter_range'], timing_config['jitter_range'])
        delay = base_delay + jitter
        
        # Clamp to min/max bounds
        delay = max(timing_config['min_delay'], min(timing_config['max_delay'], delay))
        
        return delay
    
    def _get_production_headers(self) -> Dict[str, str]:
        """Get production server-like headers"""
        headers = self.production_fingerprint['headers'].copy()
        
        # Add current date
        headers['Date'] = datetime.now(timezone.utc).strftime(
            self.config['headers']['date_format']
        )
        
        # Add common headers
        headers.update({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block'
        })
        
        return headers
    
    def _log_request(self, request) -> None:
        """Log incoming HTTP request"""
        with self._lock:
            self.request_counter += 1
            request_id = f"http_{self.request_counter}_{int(time.time())}"
            request.request_id = request_id
        
        # Extract request data
        http_request = HTTPRequest(
            timestamp=datetime.now().isoformat(),
            method=request.method,
            path=request.path,
            query_params=dict(request.args),
            headers=dict(request.headers),
            payload=request.get_data(as_text=True),
            client_ip=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            content_type=request.headers.get('Content-Type', ''),
            content_length=request.content_length or 0,
            request_id=request_id
        )
        
        # Log to JSON file
        self._log_to_json('http_request', asdict(http_request))
        
        logger.info(f"HTTP Request: {request.method} {request.path} from {request.remote_addr}")
    
    def _log_response(self, response) -> None:
        """Log outgoing HTTP response"""
        if hasattr(request, 'request_id'):
            request_id = request.request_id
        else:
            request_id = f"unknown_{int(time.time())}"
        
        # Extract response data
        http_response = HTTPResponse(
            timestamp=datetime.now().isoformat(),
            status_code=response.status_code,
            headers=dict(response.headers),
            payload=response.get_data(as_text=True) if response.is_json else '',
            response_time=0.0,  # Will be calculated by timing middleware
            request_id=request_id
        )
        
        # Log to JSON file
        self._log_to_json('http_response', asdict(http_response))
        
        logger.info(f"HTTP Response: {response.status_code} for {request_id}")
    
    def _log_to_json(self, event_type: str, data: Dict[str, Any]) -> None:
        """Log event to JSON file"""
        log_config = self.config['logging']
        if not log_config['enabled']:
            return
        
        json_log_file = log_config['json_log_file']
        log_entry = {
            'event_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        
        try:
            with open(json_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Error writing to JSON log: {e}")
    
    def _handle_request(self, request, path: str):
        """Handle incoming HTTP request"""
        # Check if request should be whitelisted
        if self._is_whitelisted(request):
            logger.info(f"Whitelisted request from {request.remote_addr}, forwarding to production")
            return self._forward_to_production(request)
        
        # Apply response delay
        delay = self._get_response_delay(request.request_id)
        if delay > 0:
            time.sleep(delay)
        
        # Determine response based on path and method
        if request.method == 'GET':
            return self._handle_get_request(request, path)
        elif request.method == 'POST':
            return self._handle_post_request(request, path)
        else:
            return self._handle_other_methods(request, path)
    
    def _handle_get_request(self, request, path: str):
        """Handle GET requests"""
        # Common attack patterns
        if any(pattern in path.lower() for pattern in ['admin', 'wp-admin', 'phpmyadmin', 'config']):
            return self._generate_admin_page(request)
        elif any(pattern in path.lower() for pattern in ['.php', '.asp', '.jsp']):
            return self._generate_script_response(request)
        elif any(pattern in path.lower() for pattern in ['backup', '.bak', '.sql']):
            return self._generate_backup_response(request)
        else:
            return self._generate_default_page(request)
    
    def _handle_post_request(self, request, path: str):
        """Handle POST requests"""
        # Check for common attack payloads
        payload = request.get_data(as_text=True).lower()
        
        if any(pattern in payload for pattern in ['union select', 'drop table', 'insert into']):
            return self._generate_sql_error_response(request)
        elif any(pattern in payload for pattern in ['<script', 'javascript:', 'onload=']):
            return self._generate_xss_response(request)
        elif any(pattern in payload for pattern in ['../', '..\\', 'etc/passwd']):
            return self._generate_path_traversal_response(request)
        else:
            return self._generate_form_response(request)
    
    def _handle_other_methods(self, request, path: str):
        """Handle other HTTP methods"""
        return Response(
            'Method Not Allowed',
            status=405,
            headers=self._get_production_headers()
        )
    
    def _generate_default_page(self, request):
        """Generate default homepage"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Welcome - Production Server</title>
            <meta charset="UTF-8">
        </head>
        <body>
            <h1>Welcome to Production Server</h1>
            <p>This is a production web server.</p>
            <p>Current time: {timestamp}</p>
        </body>
        </html>
        """.format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        return Response(
            html_content,
            status=200,
            headers=self._get_production_headers()
        )
    
    def _generate_admin_page(self, request):
        """Generate admin login page"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Login</title>
            <meta charset="UTF-8">
        </head>
        <body>
            <h2>Administrator Login</h2>
            <form method="POST" action="/admin/login">
                <p>Username: <input type="text" name="username"></p>
                <p>Password: <input type="password" name="password"></p>
                <p><input type="submit" value="Login"></p>
            </form>
        </body>
        </html>
        """
        
        return Response(
            html_content,
            status=200,
            headers=self._get_production_headers()
        )
    
    def _generate_script_response(self, request):
        """Generate response for script requests"""
        return Response(
            '<?php echo "Script execution disabled"; ?>',
            status=403,
            headers=self._get_production_headers()
        )
    
    def _generate_backup_response(self, request):
        """Generate response for backup file requests"""
        return Response(
            'Backup files not found',
            status=404,
            headers=self._get_production_headers()
        )
    
    def _generate_sql_error_response(self, request):
        """Generate SQL error response"""
        return Response(
            'Database connection error',
            status=500,
            headers=self._get_production_headers()
        )
    
    def _generate_xss_response(self, request):
        """Generate XSS response"""
        return Response(
            'Invalid input detected',
            status=400,
            headers=self._get_production_headers()
        )
    
    def _generate_path_traversal_response(self, request):
        """Generate path traversal response"""
        return Response(
            'Access denied',
            status=403,
            headers=self._get_production_headers()
        )
    
    def _generate_form_response(self, request):
        """Generate form submission response"""
        return Response(
            'Form submitted successfully',
            status=200,
            headers=self._get_production_headers()
        )
    
    def _handle_404(self, request):
        """Handle 404 errors"""
        return Response(
            'Page not found',
            status=404,
            headers=self._get_production_headers()
        )
    
    def _handle_500(self, request):
        """Handle 500 errors"""
        return Response(
            'Internal server error',
            status=500,
            headers=self._get_production_headers()
        )
    
    def _forward_to_production(self, request):
        """Forward request to production server"""
        # This would implement actual forwarding logic
        # For now, return a placeholder response
        return Response(
            'Request forwarded to production server',
            status=200,
            headers=self._get_production_headers()
        )
    
    def run(self, host: str = None, port: int = None, debug: bool = None):
        """Run the HTTP honeypot"""
        server_config = self.config['server']
        
        host = host or server_config['host']
        port = port or server_config['port']
        debug = debug if debug is not None else server_config['debug']
        
        logger.info(f"Starting HTTP honeypot on {host}:{port}")
        
        self.app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=server_config['threaded']
        )

def main():
    """Main function for HTTP honeypot"""
    logging.basicConfig(level=logging.INFO)
    
    print("Digital Twin Honeynet - HTTP Honeypot")
    print("=" * 40)
    
    honeypot = HTTPHoneypot()
    honeypot.run()

if __name__ == '__main__':
    main()

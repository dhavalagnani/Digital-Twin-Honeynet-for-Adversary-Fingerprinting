#!/usr/bin/env python3
"""
Digital Twin Honeynet - Network Router
Routes traffic between honeypots and production services based on centralized configuration
"""

import socket
import threading
import time
import logging
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
import json
import hashlib
from datetime import datetime

# Import configuration utilities
try:
    from utils.config_loader import get_config_loader, is_ip_whitelisted, is_ip_blacklisted, detect_attack_patterns
except ImportError:
    # Fallback for direct execution
    import sys
    sys.path.append('..')
    from utils.config_loader import get_config_loader, is_ip_whitelisted, is_ip_blacklisted, detect_attack_patterns


class NetworkRouter:
    """Routes network traffic based on centralized configuration"""
    
    def __init__(self, config_file: str = 'config.yaml'):
        self.config_loader = get_config_loader(config_file)
        self.logger = self.config_loader.setup_logging('network_router')
        
        # Load configuration
        self.config = self.config_loader.config
        self.protocols_config = self.config.get('protocols', {})
        self.access_control_config = self.config_loader.get_access_control_config()
        self.attack_patterns_config = self.config_loader.get_attack_patterns_config()
        
        # Routing statistics
        self.stats = {
            'total_requests': 0,
            'honeypot_routes': 0,
            'production_routes': 0,
            'blocked_requests': 0,
            'whitelisted_requests': 0,
            'blacklisted_requests': 0,
            'attack_detections': 0,
            'protocol_stats': {}
        }
        
        # Connection tracking
        self.connections = {}
        self.connection_lock = threading.Lock()
        
        # Rate limiting
        self.rate_limits = {}
        self.rate_limit_lock = threading.Lock()
        
        self.logger.info("Network router initialized")
    
    def route_request(self, client_ip: str, protocol: str, request_data: str, 
                     user_agent: str = "", headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Route a request based on configuration rules
        
        Returns:
            Dict with routing decision and metadata
        """
        self.stats['total_requests'] += 1
        
        # Initialize routing decision
        routing_decision = {
            'route': 'honeypot',  # Default route
            'reason': 'default',
            'protocol': protocol,
            'client_ip': client_ip,
            'timestamp': datetime.now().isoformat(),
            'attack_detected': False,
            'attacks': [],
            'whitelisted': False,
            'blacklisted': False,
            'rate_limited': False
        }
        
        # Check if IP is blacklisted
        if is_ip_blacklisted(client_ip):
            routing_decision['route'] = 'blocked'
            routing_decision['reason'] = 'blacklisted_ip'
            routing_decision['blacklisted'] = True
            self.stats['blacklisted_requests'] += 1
            self.logger.warning(f"Request blocked from blacklisted IP: {client_ip}")
            return routing_decision
        
        # Check if IP is whitelisted
        if is_ip_whitelisted(client_ip):
            routing_decision['route'] = 'production'
            routing_decision['reason'] = 'whitelisted_ip'
            routing_decision['whitelisted'] = True
            self.stats['whitelisted_requests'] += 1
            self.logger.info(f"Request routed to production from whitelisted IP: {client_ip}")
            return routing_decision
        
        # Check user agent blacklist
        if user_agent and self.config_loader.is_user_agent_blacklisted(user_agent):
            routing_decision['route'] = 'blocked'
            routing_decision['reason'] = 'blacklisted_user_agent'
            routing_decision['blacklisted'] = True
            self.stats['blacklisted_requests'] += 1
            self.logger.warning(f"Request blocked from blacklisted user agent: {user_agent}")
            return routing_decision
        
        # Check user agent whitelist
        if user_agent and self.config_loader.is_user_agent_whitelisted(user_agent):
            routing_decision['route'] = 'production'
            routing_decision['reason'] = 'whitelisted_user_agent'
            routing_decision['whitelisted'] = True
            self.stats['whitelisted_requests'] += 1
            self.logger.info(f"Request routed to production from whitelisted user agent: {user_agent}")
            return routing_decision
        
        # Check for attack patterns
        attacks = detect_attack_patterns(request_data)
        if attacks:
            routing_decision['attack_detected'] = True
            routing_decision['attacks'] = attacks
            routing_decision['route'] = 'honeypot'
            routing_decision['reason'] = 'attack_detected'
            self.stats['attack_detections'] += 1
            self.logger.warning(f"Attack detected from {client_ip}: {attacks}")
        
        # Check rate limiting
        if self._is_rate_limited(client_ip):
            routing_decision['route'] = 'blocked'
            routing_decision['reason'] = 'rate_limited'
            routing_decision['rate_limited'] = True
            self.stats['blocked_requests'] += 1
            self.logger.warning(f"Request blocked due to rate limiting: {client_ip}")
            return routing_decision
        
        # Check pattern-based routing
        if self._should_route_to_production(request_data, headers):
            routing_decision['route'] = 'production'
            routing_decision['reason'] = 'legitimate_pattern'
            self.stats['production_routes'] += 1
        else:
            routing_decision['route'] = 'honeypot'
            routing_decision['reason'] = 'suspicious_pattern'
            self.stats['honeypot_routes'] += 1
        
        # Update protocol statistics
        if protocol not in self.stats['protocol_stats']:
            self.stats['protocol_stats'][protocol] = {
                'total': 0,
                'honeypot': 0,
                'production': 0,
                'blocked': 0,
                'attacks': 0
            }
        
        self.stats['protocol_stats'][protocol]['total'] += 1
        
        if routing_decision['route'] == 'honeypot':
            self.stats['protocol_stats'][protocol]['honeypot'] += 1
        elif routing_decision['route'] == 'production':
            self.stats['protocol_stats'][protocol]['production'] += 1
        elif routing_decision['route'] == 'blocked':
            self.stats['protocol_stats'][protocol]['blocked'] += 1
        
        if routing_decision['attack_detected']:
            self.stats['protocol_stats'][protocol]['attacks'] += 1
        
        # Log routing decision
        self.logger.info(f"Routed {protocol} request from {client_ip} to {routing_decision['route']}: {routing_decision['reason']}")
        
        return routing_decision
    
    def _should_route_to_production(self, request_data: str, headers: Dict[str, str] = None) -> bool:
        """Determine if request should be routed to production based on patterns"""
        
        # Check for whitelisted patterns
        if self.config_loader.is_pattern_whitelisted(request_data):
            return True
        
        # Check for blacklisted patterns
        if self.config_loader.is_pattern_blacklisted(request_data):
            return False
        
        # Check headers for suspicious patterns
        if headers:
            for header_name, header_value in headers.items():
                if self.config_loader.is_pattern_blacklisted(header_value):
                    return False
        
        # Default to honeypot for suspicious requests
        return False
    
    def _is_rate_limited(self, client_ip: str) -> bool:
        """Check if client is rate limited"""
        rate_limit_config = self.config.get('performance', {}).get('rate_limiting', {})
        
        if not rate_limit_config.get('enabled', False):
            return False
        
        requests_per_minute = rate_limit_config.get('requests_per_minute', 100)
        burst_size = rate_limit_config.get('burst_size', 20)
        window = rate_limit_config.get('window', 60)
        
        current_time = time.time()
        
        with self.rate_limit_lock:
            if client_ip not in self.rate_limits:
                self.rate_limits[client_ip] = {
                    'requests': [],
                    'last_burst': current_time
                }
            
            client_limits = self.rate_limits[client_ip]
            
            # Clean old requests
            client_limits['requests'] = [
                req_time for req_time in client_limits['requests']
                if current_time - req_time < window
            ]
            
            # Check burst limit
            if len(client_limits['requests']) >= burst_size:
                return True
            
            # Check rate limit
            if len(client_limits['requests']) >= requests_per_minute:
                return True
            
            # Add current request
            client_limits['requests'].append(current_time)
            
            return False
    
    def get_production_endpoint(self, protocol: str) -> Optional[Tuple[str, int]]:
        """Get production endpoint for a protocol"""
        protocol_config = self.protocols_config.get(protocol, {})
        
        if not protocol_config.get('enabled', False):
            return None
        
        production_host = protocol_config.get('production_server', {}).get('host', 'production-server')
        production_port = protocol_config.get('production_port')
        
        if not production_port:
            return None
        
        return (production_host, production_port)
    
    def get_honeypot_endpoint(self, protocol: str) -> Optional[Tuple[str, int]]:
        """Get honeypot endpoint for a protocol"""
        protocol_config = self.protocols_config.get(protocol, {})
        
        if not protocol_config.get('enabled', False):
            return None
        
        honeypot_host = 'localhost'  # Honeypot runs locally
        honeypot_port = protocol_config.get('honeypot_port')
        
        if not honeypot_port:
            return None
        
        return (honeypot_host, honeypot_port)
    
    def track_connection(self, connection_id: str, client_ip: str, protocol: str, 
                        routing_decision: Dict[str, Any]):
        """Track connection for analysis"""
        with self.connection_lock:
            self.connections[connection_id] = {
                'client_ip': client_ip,
                'protocol': protocol,
                'routing_decision': routing_decision,
                'start_time': time.time(),
                'last_activity': time.time(),
                'requests': 0,
                'bytes_sent': 0,
                'bytes_received': 0
            }
    
    def update_connection(self, connection_id: str, bytes_sent: int = 0, 
                         bytes_received: int = 0):
        """Update connection statistics"""
        with self.connection_lock:
            if connection_id in self.connections:
                self.connections[connection_id]['last_activity'] = time.time()
                self.connections[connection_id]['requests'] += 1
                self.connections[connection_id]['bytes_sent'] += bytes_sent
                self.connections[connection_id]['bytes_received'] += bytes_received
    
    def close_connection(self, connection_id: str):
        """Close and remove connection tracking"""
        with self.connection_lock:
            if connection_id in self.connections:
                del self.connections[connection_id]
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        with self.connection_lock:
            active_connections = len(self.connections)
            
            # Calculate total bytes
            total_bytes_sent = sum(conn['bytes_sent'] for conn in self.connections.values())
            total_bytes_received = sum(conn['bytes_received'] for conn in self.connections.values())
            
            # Group by protocol
            protocol_connections = {}
            for conn in self.connections.values():
                protocol = conn['protocol']
                if protocol not in protocol_connections:
                    protocol_connections[protocol] = 0
                protocol_connections[protocol] += 1
            
            return {
                'active_connections': active_connections,
                'total_bytes_sent': total_bytes_sent,
                'total_bytes_received': total_bytes_received,
                'protocol_connections': protocol_connections,
                'connections': list(self.connections.keys())
            }
    
    def get_routing_stats(self) -> Dict[str, Any]:
        """Get routing statistics"""
        return {
            'total_requests': self.stats['total_requests'],
            'honeypot_routes': self.stats['honeypot_routes'],
            'production_routes': self.stats['production_routes'],
            'blocked_requests': self.stats['blocked_requests'],
            'whitelisted_requests': self.stats['whitelisted_requests'],
            'blacklisted_requests': self.stats['blacklisted_requests'],
            'attack_detections': self.stats['attack_detections'],
            'protocol_stats': self.stats['protocol_stats'],
            'connection_stats': self.get_connection_stats()
        }
    
    def reset_stats(self):
        """Reset routing statistics"""
        self.stats = {
            'total_requests': 0,
            'honeypot_routes': 0,
            'production_routes': 0,
            'blocked_requests': 0,
            'whitelisted_requests': 0,
            'blacklisted_requests': 0,
            'attack_detections': 0,
            'protocol_stats': {}
        }
        
        with self.connection_lock:
            self.connections.clear()
        
        with self.rate_limit_lock:
            self.rate_limits.clear()
        
        self.logger.info("Routing statistics reset")
    
    def export_stats(self, filename: str = None) -> str:
        """Export routing statistics to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"logs/routing_stats_{timestamp}.json"
        
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        
        stats_data = {
            'timestamp': datetime.now().isoformat(),
            'routing_stats': self.get_routing_stats(),
            'configuration': {
                'protocols': self.protocols_config,
                'access_control': self.access_control_config,
                'attack_patterns': self.attack_patterns_config
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(stats_data, f, indent=2)
        
        self.logger.info(f"Routing statistics exported to {filename}")
        return filename


class HTTPRouter(NetworkRouter):
    """HTTP-specific router with additional HTTP-specific logic"""
    
    def __init__(self, config_file: str = 'config.yaml'):
        super().__init__(config_file)
        self.logger = self.config_loader.setup_logging('http_router')
    
    def route_http_request(self, client_ip: str, method: str, path: str, 
                          headers: Dict[str, str], body: str = "") -> Dict[str, Any]:
        """Route HTTP request with HTTP-specific logic"""
        
        # Combine request data for analysis
        request_data = f"{method} {path} {body}"
        
        # Get user agent
        user_agent = headers.get('User-Agent', '')
        
        # Route the request
        routing_decision = self.route_request(
            client_ip=client_ip,
            protocol='http',
            request_data=request_data,
            user_agent=user_agent,
            headers=headers
        )
        
        # Add HTTP-specific information
        routing_decision['http_method'] = method
        routing_decision['http_path'] = path
        routing_decision['http_headers'] = headers
        
        return routing_decision
    
    def should_route_to_production_http(self, method: str, path: str, 
                                      headers: Dict[str, str]) -> bool:
        """HTTP-specific routing logic"""
        
        # Check for health check endpoints
        health_paths = ['/health', '/status', '/ping', '/favicon.ico']
        if path in health_paths:
            return True
        
        # Check for legitimate monitoring tools
        user_agent = headers.get('User-Agent', '').lower()
        monitoring_agents = ['uptime-robot', 'pingdom', 'newrelic', 'datadog', 'prometheus']
        if any(agent in user_agent for agent in monitoring_agents):
            return True
        
        # Check for suspicious patterns
        suspicious_patterns = ['admin', 'wp-admin', 'phpmyadmin', 'config', 'backup']
        if any(pattern in path.lower() for pattern in suspicious_patterns):
            return False
        
        # Default to honeypot for unknown requests
        return False


class TCPRouter(NetworkRouter):
    """TCP-specific router for non-HTTP protocols"""
    
    def __init__(self, config_file: str = 'config.yaml'):
        super().__init__(config_file)
        self.logger = self.config_loader.setup_logging('tcp_router')
    
    def route_tcp_connection(self, client_ip: str, protocol: str, 
                           initial_data: bytes = b"") -> Dict[str, Any]:
        """Route TCP connection with protocol-specific logic"""
        
        # Convert initial data to string for analysis
        request_data = initial_data.decode('utf-8', errors='ignore')
        
        # Route the connection
        routing_decision = self.route_request(
            client_ip=client_ip,
            protocol=protocol,
            request_data=request_data
        )
        
        # Add TCP-specific information
        routing_decision['initial_data'] = initial_data.hex() if initial_data else ""
        
        return routing_decision


# Global router instances
_http_router = None
_tcp_router = None


def get_http_router(config_file: str = 'config.yaml') -> HTTPRouter:
    """Get global HTTP router instance"""
    global _http_router
    if _http_router is None:
        _http_router = HTTPRouter(config_file)
    return _http_router


def get_tcp_router(config_file: str = 'config.yaml') -> TCPRouter:
    """Get global TCP router instance"""
    global _tcp_router
    if _tcp_router is None:
        _tcp_router = TCPRouter(config_file)
    return _tcp_router


def route_http_request(client_ip: str, method: str, path: str, 
                      headers: Dict[str, str], body: str = "", 
                      config_file: str = 'config.yaml') -> Dict[str, Any]:
    """Route HTTP request using global router"""
    router = get_http_router(config_file)
    return router.route_http_request(client_ip, method, path, headers, body)


def route_tcp_connection(client_ip: str, protocol: str, initial_data: bytes = b"",
                        config_file: str = 'config.yaml') -> Dict[str, Any]:
    """Route TCP connection using global router"""
    router = get_tcp_router(config_file)
    return router.route_tcp_connection(client_ip, protocol, initial_data)


def get_routing_stats(config_file: str = 'config.yaml') -> Dict[str, Any]:
    """Get routing statistics from global router"""
    router = get_http_router(config_file)
    return router.get_routing_stats()


if __name__ == '__main__':
    # Test the router
    router = NetworkRouter()
    
    # Test routing decisions
    test_cases = [
        {
            'client_ip': '192.168.1.100',
            'protocol': 'http',
            'request_data': 'GET /health HTTP/1.1',
            'user_agent': 'uptime-robot'
        },
        {
            'client_ip': '10.0.0.1',
            'protocol': 'http',
            'request_data': 'GET /admin HTTP/1.1',
            'user_agent': 'sqlmap'
        },
        {
            'client_ip': '172.16.0.1',
            'protocol': 'ssh',
            'request_data': 'SSH-2.0-OpenSSH_8.2p1',
            'user_agent': ''
        }
    ]
    
    for test_case in test_cases:
        decision = router.route_request(**test_case)
        print(f"Routing decision: {decision}")
    
    # Print statistics
    stats = router.get_routing_stats()
    print(f"\nRouting statistics: {stats}")

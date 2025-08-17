#!/usr/bin/env python3
"""
Digital Twin Honeynet - Central Controller
Manages all honeypot services based on centralized configuration
"""

import yaml
import subprocess
import time
import sys
import os
import signal
import socket
import threading
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import psutil


@dataclass
class ServiceStatus:
    """Service status information"""
    name: str
    pid: Optional[int]
    status: str  # running, stopped, starting, stopping, error
    port: Optional[int]
    health_check_url: Optional[str]
    last_check: Optional[float]
    error_message: Optional[str] = None


class ConfigurationValidator:
    """Validates honeynet configuration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.errors = []
        self.warnings = []
    
    def validate(self) -> bool:
        """Run all validation checks"""
        self.errors.clear()
        self.warnings.clear()
        
        self._validate_required_files()
        self._validate_required_directories()
        self._validate_port_configuration()
        self._validate_network_configuration()
        self._validate_protocol_configuration()
        self._validate_access_control()
        
        if self.errors:
            print("Configuration validation failed:")
            for error in self.errors:
                print(f"  ERROR: {error}")
        
        if self.warnings:
            print("Configuration warnings:")
            for warning in self.warnings:
                print(f"  WARNING: {warning}")
        
        return len(self.errors) == 0
    
    def _validate_required_files(self):
        """Validate that required files exist"""
        required_files = self.config.get('validation', {}).get('required_files', [])
        for file_path in required_files:
            if not Path(file_path).exists():
                self.errors.append(f"Required file not found: {file_path}")
    
    def _validate_required_directories(self):
        """Validate that required directories exist"""
        required_dirs = self.config.get('validation', {}).get('required_directories', [])
        for dir_path in required_dirs:
            if not Path(dir_path).exists():
                self.errors.append(f"Required directory not found: {dir_path}")
    
    def _validate_port_configuration(self):
        """Validate port configuration"""
        protocols = self.config.get('protocols', {})
        used_ports = set()
        
        for protocol_name, protocol_config in protocols.items():
            if not protocol_config.get('enabled', False):
                continue
            
            ports = protocol_config.get('ports', [])
            for port in ports:
                if port in used_ports:
                    self.errors.append(f"Port {port} is used by multiple protocols")
                used_ports.add(port)
                
                # Check if port is in reserved range
                reserved_ports = self.config.get('validation', {}).get('port_validation', {}).get('reserved_ports', [])
                if port in reserved_ports:
                    self.warnings.append(f"Port {port} is in reserved ports list")
                
                # Check if port is in allowed range
                allowed_ranges = self.config.get('validation', {}).get('port_validation', {}).get('allowed_ranges', [])
                port_allowed = False
                for min_port, max_port in allowed_ranges:
                    if min_port <= port <= max_port:
                        port_allowed = True
                        break
                
                if not port_allowed:
                    self.warnings.append(f"Port {port} is outside allowed ranges")
    
    def _validate_network_configuration(self):
        """Validate network configuration"""
        network_config = self.config.get('system', {}).get('network', {})
        
        # Validate subnet
        subnet = network_config.get('subnet')
        if subnet:
            try:
                ipaddress.ip_network(subnet)
            except ValueError:
                self.errors.append(f"Invalid subnet: {subnet}")
        
        # Validate gateway
        gateway = network_config.get('gateway')
        if gateway:
            try:
                ipaddress.ip_address(gateway)
            except ValueError:
                self.errors.append(f"Invalid gateway: {gateway}")
        
        # Validate DNS servers
        dns_servers = network_config.get('dns_servers', [])
        for dns in dns_servers:
            try:
                ipaddress.ip_address(dns)
            except ValueError:
                self.errors.append(f"Invalid DNS server: {dns}")
    
    def _validate_protocol_configuration(self):
        """Validate protocol-specific configuration"""
        protocols = self.config.get('protocols', {})
        
        for protocol_name, protocol_config in protocols.items():
            if not protocol_config.get('enabled', False):
                continue
            
            # Validate banner configuration
            banner_config = protocol_config.get('banner', {})
            if not banner_config:
                self.warnings.append(f"No banner configuration for {protocol_name}")
            
            # Validate response timing
            timing_config = protocol_config.get('response_timing', {})
            if timing_config.get('enabled', False):
                base_delay = timing_config.get('base_delay', 0)
                jitter_range = timing_config.get('jitter_range', 0)
                min_delay = timing_config.get('min_delay', 0)
                max_delay = timing_config.get('max_delay', 0)
                
                if min_delay > max_delay:
                    self.errors.append(f"Invalid timing configuration for {protocol_name}: min_delay > max_delay")
                
                if base_delay < 0 or jitter_range < 0:
                    self.errors.append(f"Invalid timing configuration for {protocol_name}: negative values")
    
    def _validate_access_control(self):
        """Validate access control configuration"""
        access_control = self.config.get('access_control', {})
        
        # Validate whitelist IPs
        whitelist = access_control.get('whitelist', {})
        if whitelist.get('enabled', False):
            ips = whitelist.get('ips', [])
            for ip in ips:
                try:
                    ipaddress.ip_network(ip)
                except ValueError:
                    self.errors.append(f"Invalid whitelist IP/network: {ip}")
        
        # Validate blacklist IPs
        blacklist = access_control.get('blacklist', {})
        if blacklist.get('enabled', False):
            ips = blacklist.get('ips', [])
            for ip in ips:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    self.errors.append(f"Invalid blacklist IP: {ip}")


class ServiceManager:
    """Manages honeypot services"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.services: Dict[str, ServiceStatus] = {}
        self.processes: Dict[str, subprocess.Popen] = {}
        self.running = False
        self.logger = self._setup_logging()
        
        # Service startup scripts mapping
        self.service_scripts = {
            'http-honeypot': 'honeypot/http_honeypot.py',
            'http-router': 'honeypot/http_router.py',
            'rdp-honeypot': 'honeypot/rdp_honeypot.py',
            'smb-honeypot': 'honeypot/smb_honeypot.py',
            'log-monitor': 'cowrie_log_monitor.py',
            'api-backend': 'fastapi_backend/main.py'
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        log_config = self.config.get('logging', {})
        logger = logging.getLogger('honeynet_controller')
        logger.setLevel(getattr(logging, log_config.get('level', 'INFO')))
        
        # Create handlers
        if not logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
            
            # File handler
            if log_config.get('enabled', True):
                log_file = log_config.get('log_file', 'logs/honeynet_controller.log')
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(logging.DEBUG)
                file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                file_handler.setFormatter(file_formatter)
                logger.addHandler(file_handler)
        
        return logger
    
    def start_services(self) -> bool:
        """Start all enabled services"""
        self.logger.info("Starting honeynet services...")
        self.running = True
        
        # Get startup order
        startup_order = self.config.get('services', {}).get('startup_order', [])
        
        # Start services in order
        for service_name in startup_order:
            if not self._should_start_service(service_name):
                continue
            
            self.logger.info(f"Starting service: {service_name}")
            if not self._start_service(service_name):
                self.logger.error(f"Failed to start service: {service_name}")
                return False
            
            # Wait for service to be ready
            if not self._wait_for_service_ready(service_name):
                self.logger.error(f"Service {service_name} failed to become ready")
                return False
        
        self.logger.info("All services started successfully")
        return True
    
    def _should_start_service(self, service_name: str) -> bool:
        """Check if service should be started based on configuration"""
        # Check if it's a protocol service
        if service_name in ['http-honeypot', 'rdp-honeypot', 'smb-honeypot']:
            protocol_name = service_name.split('-')[0]
            return self.config.get('protocols', {}).get(protocol_name, {}).get('enabled', False)
        
        # Always start infrastructure services
        infrastructure_services = ['database', 'redis', 'log-monitor', 'http-router', 'api-backend', 'haproxy']
        return service_name in infrastructure_services
    
    def _start_service(self, service_name: str) -> bool:
        """Start a specific service"""
        try:
            if service_name in self.service_scripts:
                script_path = self.service_scripts[service_name]
                if not Path(script_path).exists():
                    self.logger.error(f"Service script not found: {script_path}")
                    return False
                
                # Start the service
                process = subprocess.Popen([
                    sys.executable, script_path
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self.processes[service_name] = process
                
                # Update service status
                self.services[service_name] = ServiceStatus(
                    name=service_name,
                    pid=process.pid,
                    status='starting',
                    port=self._get_service_port(service_name),
                    health_check_url=self._get_health_check_url(service_name),
                    last_check=time.time()
                )
                
                self.logger.info(f"Started {service_name} with PID {process.pid}")
                return True
            
            else:
                self.logger.warning(f"No startup script defined for service: {service_name}")
                return True  # Assume external service (Docker, etc.)
        
        except Exception as e:
            self.logger.error(f"Failed to start {service_name}: {e}")
            return False
    
    def _get_service_port(self, service_name: str) -> Optional[int]:
        """Get the port for a service"""
        if service_name == 'http-honeypot':
            return self.config.get('protocols', {}).get('http', {}).get('honeypot_port')
        elif service_name == 'rdp-honeypot':
            return self.config.get('protocols', {}).get('rdp', {}).get('honeypot_port')
        elif service_name == 'smb-honeypot':
            return self.config.get('protocols', {}).get('smb', {}).get('honeypot_port')
        elif service_name == 'http-router':
            return self.config.get('protocols', {}).get('http', {}).get('router_port')
        elif service_name == 'api-backend':
            return 8000  # Default FastAPI port
        return None
    
    def _get_health_check_url(self, service_name: str) -> Optional[str]:
        """Get health check URL for a service"""
        health_checks = self.config.get('services', {}).get('health_checks', {})
        return health_checks.get(service_name)
    
    def _wait_for_service_ready(self, service_name: str, timeout: int = 30) -> bool:
        """Wait for service to become ready"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self._check_service_health(service_name):
                self.services[service_name].status = 'running'
                self.logger.info(f"Service {service_name} is ready")
                return True
            
            time.sleep(1)
        
        self.services[service_name].status = 'error'
        self.services[service_name].error_message = 'Service failed to become ready within timeout'
        return False
    
    def _check_service_health(self, service_name: str) -> bool:
        """Check if a service is healthy"""
        service_status = self.services.get(service_name)
        if not service_status:
            return False
        
        # Check if process is still running
        if service_name in self.processes:
            process = self.processes[service_name]
            if process.poll() is not None:
                return False
        
        # Check health check URL if available
        if service_status.health_check_url:
            return self._check_health_url(service_status.health_check_url)
        
        # Check port if available
        if service_status.port:
            return self._check_port(service_status.port)
        
        return True
    
    def _check_health_url(self, url: str) -> bool:
        """Check health check URL"""
        try:
            import requests
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def _check_port(self, port: int) -> bool:
        """Check if port is listening"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except:
            return False
    
    def stop_services(self):
        """Stop all services"""
        self.logger.info("Stopping honeynet services...")
        self.running = False
        
        # Stop services in reverse order
        startup_order = self.config.get('services', {}).get('startup_order', [])
        for service_name in reversed(startup_order):
            if service_name in self.processes:
                self.logger.info(f"Stopping service: {service_name}")
                self._stop_service(service_name)
        
        self.logger.info("All services stopped")
    
    def _stop_service(self, service_name: str):
        """Stop a specific service"""
        if service_name in self.processes:
            process = self.processes[service_name]
            
            # Update status
            if service_name in self.services:
                self.services[service_name].status = 'stopping'
            
            try:
                # Try graceful shutdown
                process.terminate()
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Force kill if needed
                process.kill()
                process.wait()
            except Exception as e:
                self.logger.error(f"Error stopping {service_name}: {e}")
            
            # Update status
            if service_name in self.services:
                self.services[service_name].status = 'stopped'
                self.services[service_name].pid = None
            
            del self.processes[service_name]
    
    def get_service_status(self) -> Dict[str, ServiceStatus]:
        """Get status of all services"""
        # Update status for running services
        for service_name in list(self.services.keys()):
            if self.services[service_name].status == 'running':
                if not self._check_service_health(service_name):
                    self.services[service_name].status = 'error'
                    self.services[service_name].error_message = 'Service health check failed'
        
        return self.services.copy()
    
    def restart_service(self, service_name: str) -> bool:
        """Restart a specific service"""
        self.logger.info(f"Restarting service: {service_name}")
        
        # Stop service
        if service_name in self.processes:
            self._stop_service(service_name)
        
        # Start service
        return self._start_service(service_name)


class HoneynetController:
    """Main honeynet controller"""
    
    def __init__(self, config_file: str = 'config.yaml'):
        self.config_file = config_file
        self.config = self._load_config()
        self.validator = ConfigurationValidator(self.config)
        self.service_manager = ServiceManager(self.config)
        self.logger = self.service_manager.logger
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            print(f"Configuration file not found: {self.config_file}")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"Error parsing configuration file: {e}")
            sys.exit(1)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def validate_configuration(self) -> bool:
        """Validate the configuration"""
        self.logger.info("Validating configuration...")
        return self.validator.validate()
    
    def start(self) -> bool:
        """Start the honeynet"""
        self.logger.info("Starting Digital Twin Honeynet...")
        
        # Validate configuration
        if not self.validate_configuration():
            self.logger.error("Configuration validation failed")
            return False
        
        # Start services
        if not self.service_manager.start_services():
            self.logger.error("Failed to start services")
            return False
        
        self.logger.info("Honeynet started successfully")
        return True
    
    def stop(self):
        """Stop the honeynet"""
        self.logger.info("Stopping honeynet...")
        self.service_manager.stop_services()
        self.logger.info("Honeynet stopped")
    
    def status(self) -> Dict[str, Any]:
        """Get honeynet status"""
        service_status = self.service_manager.get_service_status()
        
        # Count services by status
        status_counts = {}
        for status in service_status.values():
            status_counts[status.status] = status_counts.get(status.status, 0) + 1
        
        return {
            'system': {
                'name': self.config.get('system', {}).get('name', 'Unknown'),
                'version': self.config.get('system', {}).get('version', 'Unknown'),
                'environment': self.config.get('system', {}).get('environment', 'Unknown'),
                'running': self.service_manager.running
            },
            'services': {
                'total': len(service_status),
                'status_counts': status_counts,
                'details': {name: {
                    'status': status.status,
                    'pid': status.pid,
                    'port': status.port,
                    'error': status.error_message
                } for name, status in service_status.items()}
            },
            'protocols': {
                name: {
                    'enabled': config.get('enabled', False),
                    'ports': config.get('ports', [])
                } for name, config in self.config.get('protocols', {}).items()
            }
        }
    
    def restart(self) -> bool:
        """Restart the honeynet"""
        self.logger.info("Restarting honeynet...")
        self.stop()
        time.sleep(2)  # Wait for services to fully stop
        return self.start()
    
    def restart_service(self, service_name: str) -> bool:
        """Restart a specific service"""
        return self.service_manager.restart_service(service_name)
    
    def run(self):
        """Run the honeynet controller"""
        if not self.start():
            sys.exit(1)
        
        try:
            # Keep running and monitor services
            while self.service_manager.running:
                time.sleep(10)  # Check every 10 seconds
                
                # Log status periodically
                status = self.status()
                running_services = status['services']['status_counts'].get('running', 0)
                total_services = status['services']['total']
                
                if running_services < total_services:
                    self.logger.warning(f"Some services are not running: {running_services}/{total_services}")
                
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        finally:
            self.stop()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Digital Twin Honeynet Controller')
    parser.add_argument('--config', '-c', default='config.yaml', help='Configuration file path')
    parser.add_argument('--action', '-a', choices=['start', 'stop', 'restart', 'status', 'validate'], 
                       default='start', help='Action to perform')
    parser.add_argument('--service', '-s', help='Service name for restart action')
    
    args = parser.parse_args()
    
    controller = HoneynetController(args.config)
    
    if args.action == 'validate':
        if controller.validate_configuration():
            print("Configuration is valid")
            sys.exit(0)
        else:
            print("Configuration validation failed")
            sys.exit(1)
    
    elif args.action == 'status':
        status = controller.status()
        print(json.dumps(status, indent=2))
    
    elif args.action == 'restart':
        if args.service:
            if controller.service_manager.restart_service(args.service):
                print(f"Service {args.service} restarted successfully")
            else:
                print(f"Failed to restart service {args.service}")
                sys.exit(1)
        else:
            if controller.restart():
                print("Honeynet restarted successfully")
            else:
                print("Failed to restart honeynet")
                sys.exit(1)
    
    elif args.action == 'stop':
        controller.stop()
        print("Honeynet stopped")
    
    elif args.action == 'start':
        controller.run()


if __name__ == '__main__':
    main()

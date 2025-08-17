#!/usr/bin/env python3
"""
Digital Twin Honeynet - Native Service Controller
Manages native systemd services instead of Docker containers
"""

import subprocess
import logging
import argparse
import sys
import os
import time
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import yaml

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils'))

try:
    from utils.config_loader import get_config_loader
except ImportError:
    print("Error: Could not import config_loader. Make sure utils/config_loader.py is accessible.")
    sys.exit(1)


class NativeServiceManager:
    """Manages native systemd services for the honeynet"""

    def __init__(self, config_file: str = 'config.yaml'):
        self.config_loader = get_config_loader(config_file)
        self.config = self.config_loader.config
        self.logger = self._setup_logging()
        
        # Service definitions
        self.services = {
            'database': {
                'name': 'postgresql',
                'description': 'PostgreSQL Database',
                'dependencies': []
            },
            'cache': {
                'name': 'redis-server',
                'description': 'Redis Cache',
                'dependencies': []
            },
            'http-honeypot': {
                'name': 'nginx',
                'description': 'HTTP Honeypot (nginx)',
                'dependencies': ['database', 'cache']
            },
            'ssh-honeypot': {
                'name': 'cowrie',
                'description': 'SSH Honeypot (Cowrie)',
                'dependencies': ['database', 'cache']
            },
            'rdp-honeypot': {
                'name': 'rdp-honeypot',
                'description': 'RDP Honeypot',
                'dependencies': ['database', 'cache']
            },
            'smb-honeypot': {
                'name': 'smb-honeypot',
                'description': 'SMB Honeypot',
                'dependencies': ['database', 'cache']
            },
            'api-backend': {
                'name': 'honeynet-api',
                'description': 'API Backend (FastAPI)',
                'dependencies': ['database', 'cache']
            },
            'load-balancer': {
                'name': 'haproxy',
                'description': 'Load Balancer (HAProxy)',
                'dependencies': ['http-honeypot', 'api-backend']
            },
            'monitor': {
                'name': 'honeynet-monitor',
                'description': 'Log Monitor',
                'dependencies': ['database', 'cache']
            }
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the native service manager"""
        logger = logging.getLogger('native_service_manager')
        logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # File handler
        file_handler = logging.FileHandler('logs/native_controller.log')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        return logger

    def run_command(self, command: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Run a system command and return results"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'stdout': '',
                'stderr': f'Command timed out after {timeout} seconds',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1
            }

    def check_service_status(self, service_name: str) -> Dict[str, Any]:
        """Check the status of a systemd service"""
        result = self.run_command(['systemctl', 'is-active', service_name])
        
        if result['success']:
            status = result['stdout'].strip()
            return {
                'name': service_name,
                'status': status,
                'running': status == 'active',
                'enabled': self.is_service_enabled(service_name)
            }
        else:
            return {
                'name': service_name,
                'status': 'unknown',
                'running': False,
                'enabled': False,
                'error': result['stderr']
            }

    def is_service_enabled(self, service_name: str) -> bool:
        """Check if a service is enabled to start on boot"""
        result = self.run_command(['systemctl', 'is-enabled', service_name])
        return result['success'] and result['stdout'].strip() == 'enabled'

    def start_service(self, service_name: str) -> Dict[str, Any]:
        """Start a systemd service"""
        self.logger.info(f"Starting service: {service_name}")
        result = self.run_command(['systemctl', 'start', service_name])
        
        if result['success']:
            self.logger.info(f"Service {service_name} started successfully")
        else:
            self.logger.error(f"Failed to start service {service_name}: {result['stderr']}")
        
        return result

    def stop_service(self, service_name: str) -> Dict[str, Any]:
        """Stop a systemd service"""
        self.logger.info(f"Stopping service: {service_name}")
        result = self.run_command(['systemctl', 'stop', service_name])
        
        if result['success']:
            self.logger.info(f"Service {service_name} stopped successfully")
        else:
            self.logger.error(f"Failed to stop service {service_name}: {result['stderr']}")
        
        return result

    def restart_service(self, service_name: str) -> Dict[str, Any]:
        """Restart a systemd service"""
        self.logger.info(f"Restarting service: {service_name}")
        result = self.run_command(['systemctl', 'restart', service_name])
        
        if result['success']:
            self.logger.info(f"Service {service_name} restarted successfully")
        else:
            self.logger.error(f"Failed to restart service {service_name}: {result['stderr']}")
        
        return result

    def enable_service(self, service_name: str) -> Dict[str, Any]:
        """Enable a systemd service to start on boot"""
        self.logger.info(f"Enabling service: {service_name}")
        result = self.run_command(['systemctl', 'enable', service_name])
        
        if result['success']:
            self.logger.info(f"Service {service_name} enabled successfully")
        else:
            self.logger.error(f"Failed to enable service {service_name}: {result['stderr']}")
        
        return result

    def disable_service(self, service_name: str) -> Dict[str, Any]:
        """Disable a systemd service from starting on boot"""
        self.logger.info(f"Disabling service: {service_name}")
        result = self.run_command(['systemctl', 'disable', service_name])
        
        if result['success']:
            self.logger.info(f"Service {service_name} disabled successfully")
        else:
            self.logger.error(f"Failed to disable service {service_name}: {result['stderr']}")
        
        return result

    def get_enabled_services(self) -> List[str]:
        """Get list of services that should be enabled based on configuration"""
        enabled_services = []
        protocols_config = self.config.get('protocols', {})
        
        # Always enable core services
        enabled_services.extend(['database', 'cache', 'monitor'])
        
        # Enable protocol-specific services
        for protocol, config in protocols_config.items():
            if config.get('enabled', False):
                if protocol == 'http':
                    enabled_services.append('http-honeypot')
                elif protocol == 'ssh':
                    enabled_services.append('ssh-honeypot')
                elif protocol == 'rdp':
                    enabled_services.append('rdp-honeypot')
                elif protocol == 'smb':
                    enabled_services.append('smb-honeypot')
        
        # Always enable API and load balancer if any services are enabled
        if len(enabled_services) > 3:  # More than just core services
            enabled_services.extend(['api-backend', 'load-balancer'])
        
        return list(set(enabled_services))  # Remove duplicates

    def start_services(self) -> Dict[str, Any]:
        """Start all enabled services in dependency order"""
        self.logger.info("Starting honeynet services...")
        
        enabled_services = self.get_enabled_services()
        results = {}
        
        # Sort services by dependencies
        started_services = set()
        
        while len(started_services) < len(enabled_services):
            progress = False
            
            for service_key in enabled_services:
                if service_key in started_services:
                    continue
                
                service_info = self.services[service_key]
                dependencies_met = all(dep in started_services for dep in service_info['dependencies'])
                
                if dependencies_met:
                    service_name = service_info['name']
                    result = self.start_service(service_name)
                    results[service_key] = result
                    
                    if result['success']:
                        started_services.add(service_key)
                        progress = True
                        
                        # Wait a moment for service to fully start
                        time.sleep(2)
                    else:
                        self.logger.error(f"Failed to start {service_key}, skipping dependent services")
                        break
            
            if not progress:
                self.logger.error("Circular dependency detected or service failed to start")
                break
        
        # Check final status
        final_status = self.get_services_status()
        
        return {
            'started_services': list(started_services),
            'failed_services': [s for s in enabled_services if s not in started_services],
            'results': results,
            'final_status': final_status
        }

    def stop_services(self) -> Dict[str, Any]:
        """Stop all honeynet services in reverse dependency order"""
        self.logger.info("Stopping honeynet services...")
        
        enabled_services = self.get_enabled_services()
        results = {}
        
        # Stop in reverse order (dependencies last)
        for service_key in reversed(enabled_services):
            service_info = self.services[service_key]
            service_name = service_info['name']
            
            result = self.stop_service(service_name)
            results[service_key] = result
            
            if result['success']:
                time.sleep(1)  # Brief pause between stops
        
        return {
            'stopped_services': enabled_services,
            'results': results
        }

    def restart_services(self) -> Dict[str, Any]:
        """Restart all honeynet services"""
        self.logger.info("Restarting honeynet services...")
        
        # Stop all services
        stop_result = self.stop_services()
        
        # Wait a moment
        time.sleep(5)
        
        # Start all services
        start_result = self.start_services()
        
        return {
            'stop_result': stop_result,
            'start_result': start_result
        }

    def get_services_status(self) -> Dict[str, Any]:
        """Get status of all honeynet services"""
        enabled_services = self.get_enabled_services()
        status = {}
        
        for service_key in enabled_services:
            service_info = self.services[service_key]
            service_name = service_info['name']
            
            status[service_key] = {
                'name': service_name,
                'description': service_info['description'],
                **self.check_service_status(service_name)
            }
        
        return status

    def validate_services(self) -> Dict[str, Any]:
        """Validate that all required services are available"""
        self.logger.info("Validating honeynet services...")
        
        validation_results = {}
        all_services = list(self.services.keys())
        
        for service_key in all_services:
            service_info = self.services[service_key]
            service_name = service_info['name']
            
            # Check if service file exists
            service_file = f"/etc/systemd/system/{service_name}.service"
            service_exists = Path(service_file).exists()
            
            # Check if service is available in systemd
            result = self.run_command(['systemctl', 'list-unit-files', service_name])
            available = result['success'] and service_name in result['stdout']
            
            validation_results[service_key] = {
                'name': service_name,
                'description': service_info['description'],
                'service_file_exists': service_exists,
                'systemd_available': available,
                'valid': service_exists and available
            }
        
        return validation_results

    def configure_services(self) -> Dict[str, Any]:
        """Configure services based on the configuration file"""
        self.logger.info("Configuring honeynet services...")
        
        config_results = {}
        
        # Configure nginx for HTTP honeypot
        if self.config.get('protocols', {}).get('http', {}).get('enabled', False):
            config_results['nginx'] = self._configure_nginx()
        
        # Configure HAProxy
        config_results['haproxy'] = self._configure_haproxy()
        
        # Configure PostgreSQL
        config_results['postgresql'] = self._configure_postgresql()
        
        # Configure Redis
        config_results['redis'] = self._configure_redis()
        
        return config_results

    def _configure_nginx(self) -> Dict[str, Any]:
        """Configure nginx for HTTP honeypot"""
        try:
            # Get HTTP configuration
            http_config = self.config.get('protocols', {}).get('http', {})
            banner_config = http_config.get('banner', {})
            
            # Create nginx configuration
            nginx_config = f"""
server {{
    listen 8080;
    server_name _;
    
    access_log /var/log/honeynet/http-honeypot.log;
    error_log /var/log/honeynet/http-honeypot-error.log;
    
    location / {{
        return 200 "{banner_config.get('server', 'nginx/1.18.0 (Ubuntu)')}";
        add_header Server "{banner_config.get('server', 'nginx/1.18.0 (Ubuntu)')}";
    }}
    
    location /admin {{
        return 403 "Access Denied";
    }}
    
    location /phpmyadmin {{
        return 404 "Not Found";
    }}
}}
"""
            
            # Write configuration
            with open('/etc/nginx/sites-available/honeypot', 'w') as f:
                f.write(nginx_config)
            
            # Enable site
            subprocess.run(['ln', '-sf', '/etc/nginx/sites-available/honeypot', '/etc/nginx/sites-enabled/'])
            
            # Test configuration
            result = self.run_command(['nginx', '-t'])
            
            if result['success']:
                self.run_command(['systemctl', 'reload', 'nginx'])
                return {'success': True, 'message': 'Nginx configured successfully'}
            else:
                return {'success': False, 'error': result['stderr']}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _configure_haproxy(self) -> Dict[str, Any]:
        """Configure HAProxy for load balancing"""
        try:
            # Get access control configuration
            access_control = self.config.get('access_control', {})
            whitelist_ips = access_control.get('whitelist_ips', [])
            blacklist_ips = access_control.get('blacklist_ips', [])
            
            # Create whitelist file
            with open('/etc/haproxy/whitelist.txt', 'w') as f:
                for ip in whitelist_ips:
                    f.write(f"{ip}\n")
            
            # Create blacklist file
            with open('/etc/haproxy/blacklist.txt', 'w') as f:
                for ip in blacklist_ips:
                    f.write(f"{ip}\n")
            
            # Test configuration
            result = self.run_command(['haproxy', '-c', '-f', '/etc/haproxy/haproxy.cfg'])
            
            if result['success']:
                self.run_command(['systemctl', 'reload', 'haproxy'])
                return {'success': True, 'message': 'HAProxy configured successfully'}
            else:
                return {'success': False, 'error': result['stderr']}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _configure_postgresql(self) -> Dict[str, Any]:
        """Configure PostgreSQL database"""
        try:
            # Get database configuration
            db_config = self.config.get('database', {})
            
            # Create database and user if they don't exist
            commands = [
                f"CREATE USER honeynet WITH PASSWORD '{db_config.get('password', 'honeynet_password')}';",
                f"CREATE DATABASE {db_config.get('name', 'honeynet_db')} OWNER honeynet;",
                f"GRANT ALL PRIVILEGES ON DATABASE {db_config.get('name', 'honeynet_db')} TO honeynet;"
            ]
            
            for cmd in commands:
                result = self.run_command(['sudo', '-u', 'postgres', 'psql', '-c', cmd])
                if not result['success'] and 'already exists' not in result['stderr']:
                    return {'success': False, 'error': result['stderr']}
            
            return {'success': True, 'message': 'PostgreSQL configured successfully'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _configure_redis(self) -> Dict[str, Any]:
        """Configure Redis cache"""
        try:
            # Get Redis configuration
            redis_config = self.config.get('redis', {})
            
            # Update Redis configuration
            redis_conf = '/etc/redis/redis.conf'
            
            # Read current config
            with open(redis_conf, 'r') as f:
                lines = f.readlines()
            
            # Update bind address
            new_lines = []
            for line in lines:
                if line.startswith('bind '):
                    new_lines.append(f"bind 127.0.0.1 {redis_config.get('bind_network', '172.20.0.0/16')}\n")
                else:
                    new_lines.append(line)
            
            # Write updated config
            with open(redis_conf, 'w') as f:
                f.writelines(new_lines)
            
            # Restart Redis
            result = self.run_command(['systemctl', 'restart', 'redis-server'])
            
            if result['success']:
                return {'success': True, 'message': 'Redis configured successfully'}
            else:
                return {'success': False, 'error': result['stderr']}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Digital Twin Honeynet - Native Service Controller')
    parser.add_argument('--action', '-a', required=True, 
                       choices=['start', 'stop', 'restart', 'status', 'validate', 'configure'],
                       help='Action to perform')
    parser.add_argument('--config', '-c', default='config.yaml', help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup manager
    manager = NativeServiceManager(args.config)
    
    if args.verbose:
        manager.logger.setLevel(logging.DEBUG)
    
    try:
        if args.action == 'start':
            result = manager.start_services()
            print(f"Started services: {result['started_services']}")
            if result['failed_services']:
                print(f"Failed services: {result['failed_services']}")
                sys.exit(1)
            else:
                print("All services started successfully")
                
        elif args.action == 'stop':
            result = manager.stop_services()
            print(f"Stopped services: {result['stopped_services']}")
            
        elif args.action == 'restart':
            result = manager.restart_services()
            print("Services restarted successfully")
            
        elif args.action == 'status':
            status = manager.get_services_status()
            print("\nHoneynet Service Status:")
            print("=" * 50)
            for service_key, service_status in status.items():
                status_icon = "✓" if service_status['running'] else "✗"
                print(f"{status_icon} {service_status['description']}: {service_status['status']}")
                
        elif args.action == 'validate':
            validation = manager.validate_services()
            print("\nService Validation Results:")
            print("=" * 50)
            for service_key, service_validation in validation.items():
                status_icon = "✓" if service_validation['valid'] else "✗"
                print(f"{status_icon} {service_validation['description']}")
                if not service_validation['valid']:
                    print(f"    Service file exists: {service_validation['service_file_exists']}")
                    print(f"    Systemd available: {service_validation['systemd_available']}")
                    
        elif args.action == 'configure':
            result = manager.configure_services()
            print("\nService Configuration Results:")
            print("=" * 50)
            for service_key, config_result in result.items():
                status_icon = "✓" if config_result['success'] else "✗"
                print(f"{status_icon} {service_key}: {config_result.get('message', config_result.get('error', 'Unknown'))}")
                
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nOperation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

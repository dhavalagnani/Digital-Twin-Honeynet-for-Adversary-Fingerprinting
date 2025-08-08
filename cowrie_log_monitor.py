#!/usr/bin/env python3
"""
Digital Twin Honeynet - Cowrie Log Monitor
Monitors Cowrie honeypot logs in real-time and blocks malicious IPs
"""

import os
import json
import time
import logging
import requests
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict, deque
import re

# Load environment variables from .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system environment variables

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/cowrie_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CowrieLogHandler(FileSystemEventHandler):
    """Handles file system events for Cowrie logs"""
    
    def __init__(self, log_monitor):
        self.log_monitor = log_monitor
        self.last_position = 0
        
    def on_modified(self, event):
        """Called when log file is modified"""
        if not event.is_directory and event.src_path.endswith(('.json', '.log')):
            self.log_monitor.process_log_file(event.src_path)
            
    def on_created(self, event):
        """Called when new log file is created"""
        if not event.is_directory and event.src_path.endswith(('.json', '.log')):
            logger.info(f"New log file detected: {event.src_path}")
            self.log_monitor.process_log_file(event.src_path)

class CowrieLogMonitor:
    """Monitors Cowrie logs and blocks malicious IPs"""
    
    def __init__(self):
        # Configuration from environment variables
        self.cowrie_log_path = os.getenv('COWRIE_LOG_PATH', 'honeypot/logs/cowrie.json')
        self.fastapi_url = os.getenv('FASTAPI_URL', 'http://localhost:8000')
        self.fastapi_port = os.getenv('FASTAPI_PORT', '8000')
        self.api_endpoint = f"{self.fastapi_url}/api/block"
        
        # Malicious patterns to detect
        self.malicious_patterns = {
            'brute_force': {
                'keywords': ['login.failed', 'authentication failed'],
                'threshold': 5,
                'window': 60  # seconds
            },
            'suspicious_commands': [
                'wget', 'curl', 'nc ', 'netcat', 'telnet', 'ssh-keygen',
                'rm -rf', 'dd if=', 'mkfs', 'fdisk', 'shutdown', 'reboot'
            ],
            'reverse_shells': [
                'bash -i >&', 'nc -e', 'python -c', 'perl -e',
                'ruby -rsocket', 'php -r', 'java -cp'
            ],
            'data_exfiltration': [
                'cat /etc/passwd', 'cat /etc/shadow', 'cat /proc/version',
                'uname -a', 'whoami', 'id', 'ps aux', 'netstat'
            ],
            'file_operations': [
                'wget http://', 'curl -O', 'scp', 'rsync'
            ]
        }
        
        # IP tracking for brute force detection
        self.ip_attempts = defaultdict(lambda: deque(maxlen=100))
        self.blocked_ips = set()
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'malicious_events': 0,
            'blocked_ips': 0,
            'brute_force_detected': 0,
            'suspicious_commands': 0,
            'reverse_shells': 0,
            'data_exfiltration': 0
        }
        
        # Observer for file watching
        self.observer = None
        self.handler = None
        self.running = False
        
        logger.info(f"Cowrie log monitor initialized")
        logger.info(f"Monitoring: {self.cowrie_log_path}")
        logger.info(f"API endpoint: {self.api_endpoint}")
        
    def start_monitoring(self):
        """Start monitoring Cowrie logs"""
        try:
            self.running = True
            
            # Create observer for file system events
            self.observer = Observer()
            self.handler = CowrieLogHandler(self)
            
            # Monitor log directory
            log_dir = Path(self.cowrie_log_path).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            self.observer.schedule(self.handler, str(log_dir), recursive=False)
            self.observer.start()
            
            logger.info(f"Started monitoring log directory: {log_dir}")
            
            # Process existing log file
            self.process_existing_logs()
            
            # Keep running
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, stopping...")
            self.stop_monitoring()
        except Exception as e:
            logger.error(f"Error in monitoring: {e}")
            self.stop_monitoring()
            
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
            
        logger.info("Cowrie log monitoring stopped")
        
    def process_existing_logs(self):
        """Process existing log file"""
        if Path(self.cowrie_log_path).exists():
            logger.info("Processing existing log file...")
            self.process_log_file(self.cowrie_log_path)
            
    def process_log_file(self, file_path: str):
        """Process a log file for malicious activity"""
        try:
            if not Path(file_path).exists():
                return
                
            with open(file_path, 'r') as f:
                # Read new lines
                f.seek(0, 2)  # Go to end of file
                current_size = f.tell()
                
                if current_size < self.handler.last_position:
                    # File was truncated, reset position
                    self.handler.last_position = 0
                    
                f.seek(self.handler.last_position)
                
                for line in f:
                    line = line.strip()
                    if line:
                        self.process_log_line(line)
                        
                self.handler.last_position = current_size
                
        except Exception as e:
            logger.error(f"Error processing log file {file_path}: {e}")
            
    def process_log_line(self, line: str):
        """Process a single log line"""
        try:
            # Parse JSON log entry
            log_entry = json.loads(line)
            
            # Update statistics
            self.stats['total_events'] += 1
            
            # Extract key information
            event_id = log_entry.get('eventid', '')
            src_ip = log_entry.get('src_ip', '')
            timestamp = log_entry.get('timestamp', '')
            message = log_entry.get('message', '')
            
            # Check for malicious activity
            malicious_type = self.detect_malicious_activity(log_entry)
            
            if malicious_type:
                self.stats['malicious_events'] += 1
                logger.warning(f"Malicious activity detected: {malicious_type} from {src_ip}")
                
                # Block the IP
                if src_ip and src_ip not in self.blocked_ips:
                    self.block_malicious_ip(src_ip, malicious_type, log_entry)
                    
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in log line: {line[:100]}...")
        except Exception as e:
            logger.error(f"Error processing log line: {e}")
            
    def detect_malicious_activity(self, log_entry: Dict[str, Any]) -> Optional[str]:
        """Detect malicious activity in log entry"""
        try:
            event_id = log_entry.get('eventid', '')
            src_ip = log_entry.get('src_ip', '')
            message = log_entry.get('message', '')
            input_data = log_entry.get('input', '')
            
            # Check for brute force attacks
            if self.detect_brute_force(log_entry):
                return 'brute_force'
                
            # Check for suspicious commands
            if self.detect_suspicious_commands(input_data):
                return 'suspicious_command'
                
            # Check for reverse shells
            if self.detect_reverse_shell(input_data):
                return 'reverse_shell'
                
            # Check for data exfiltration
            if self.detect_data_exfiltration(input_data):
                return 'data_exfiltration'
                
            # Check for file operations
            if self.detect_file_operations(input_data):
                return 'file_operation'
                
            return None
            
        except Exception as e:
            logger.error(f"Error detecting malicious activity: {e}")
            return None
            
    def detect_brute_force(self, log_entry: Dict[str, Any]) -> bool:
        """Detect brute force attacks"""
        try:
            event_id = log_entry.get('eventid', '')
            src_ip = log_entry.get('src_ip', '')
            timestamp = log_entry.get('timestamp', '')
            
            if event_id == 'cowrie.login.failed' and src_ip:
                # Add to tracking
                self.ip_attempts[src_ip].append(datetime.now())
                
                # Check threshold
                now = datetime.now()
                window_start = now - timedelta(seconds=self.malicious_patterns['brute_force']['window'])
                
                recent_attempts = sum(1 for attempt in self.ip_attempts[src_ip] 
                                    if attempt >= window_start)
                
                if recent_attempts >= self.malicious_patterns['brute_force']['threshold']:
                    self.stats['brute_force_detected'] += 1
                    logger.warning(f"Brute force detected: {src_ip} - {recent_attempts} attempts")
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error detecting brute force: {e}")
            return False
            
    def detect_suspicious_commands(self, input_data: str) -> bool:
        """Detect suspicious commands"""
        if not input_data:
            return False
            
        input_lower = input_data.lower()
        
        for command in self.malicious_patterns['suspicious_commands']:
            if command in input_lower:
                self.stats['suspicious_commands'] += 1
                logger.warning(f"Suspicious command detected: {input_data}")
                return True
                
        return False
        
    def detect_reverse_shell(self, input_data: str) -> bool:
        """Detect reverse shell attempts"""
        if not input_data:
            return False
            
        input_lower = input_data.lower()
        
        for pattern in self.malicious_patterns['reverse_shells']:
            if pattern in input_lower:
                self.stats['reverse_shells'] += 1
                logger.warning(f"Reverse shell detected: {input_data}")
                return True
                
        return False
        
    def detect_data_exfiltration(self, input_data: str) -> bool:
        """Detect data exfiltration attempts"""
        if not input_data:
            return False
            
        input_lower = input_data.lower()
        
        for pattern in self.malicious_patterns['data_exfiltration']:
            if pattern in input_lower:
                self.stats['data_exfiltration'] += 1
                logger.warning(f"Data exfiltration detected: {input_data}")
                return True
                
        return False
        
    def detect_file_operations(self, input_data: str) -> bool:
        """Detect suspicious file operations"""
        if not input_data:
            return False
            
        input_lower = input_data.lower()
        
        for pattern in self.malicious_patterns['file_operations']:
            if pattern in input_lower:
                logger.warning(f"Suspicious file operation detected: {input_data}")
                return True
                
        return False
        
    def block_malicious_ip(self, ip_address: str, malicious_type: str, log_entry: Dict[str, Any]):
        """Block a malicious IP via FastAPI"""
        try:
            if ip_address in self.blocked_ips:
                logger.info(f"IP {ip_address} already blocked")
                return
                
            # Prepare block request
            block_data = {
                'ip': ip_address,
                'reason': f'Cowrie detected {malicious_type}',
                'source': 'cowrie_log_monitor',
                'timestamp': datetime.now().isoformat(),
                'log_entry': log_entry
            }
            
            # Send block request to FastAPI
            response = requests.post(
                self.api_endpoint,
                json=block_data,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    self.blocked_ips.add(ip_address)
                    self.stats['blocked_ips'] += 1
                    logger.info(f"Successfully blocked IP {ip_address} for {malicious_type}")
                else:
                    logger.error(f"Failed to block IP {ip_address}: {result.get('error', 'Unknown error')}")
            else:
                logger.error(f"Failed to block IP {ip_address}: HTTP {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending block request for {ip_address}: {e}")
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            'monitor_stats': self.stats.copy(),
            'blocked_ips_count': len(self.blocked_ips),
            'blocked_ips_list': list(self.blocked_ips),
            'monitoring_path': self.cowrie_log_path,
            'api_endpoint': self.api_endpoint
        }
        
    def test_api_connectivity(self) -> bool:
        """Test connectivity to FastAPI server"""
        try:
            response = requests.get(f"{self.fastapi_url}/health", timeout=5)
            if response.status_code == 200:
                logger.info("✓ FastAPI connectivity test passed")
                return True
            else:
                logger.error(f"✗ FastAPI connectivity test failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"✗ FastAPI connectivity test failed: {e}")
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Cowrie Log Monitor')
    parser.add_argument('--log-path', help='Path to Cowrie log file')
    parser.add_argument('--api-url', help='FastAPI server URL')
    parser.add_argument('--api-port', help='FastAPI server port')
    parser.add_argument('--test', action='store_true', help='Test API connectivity only')
    parser.add_argument('--stats', action='store_true', help='Show statistics and exit')
    
    args = parser.parse_args()
    
    # Override environment variables with command line arguments
    if args.log_path:
        os.environ['COWRIE_LOG_PATH'] = args.log_path
    if args.api_url:
        os.environ['FASTAPI_URL'] = args.api_url
    if args.api_port:
        os.environ['FASTAPI_PORT'] = args.api_port
    
    # Create monitor
    monitor = CowrieLogMonitor()
    
    # Test connectivity if requested
    if args.test:
        if monitor.test_api_connectivity():
            print("✓ API connectivity test passed")
            exit(0)
        else:
            print("✗ API connectivity test failed")
            exit(1)
    
    # Show statistics if requested
    if args.stats:
        stats = monitor.get_statistics()
        print("Cowrie Log Monitor Statistics:")
        print(json.dumps(stats, indent=2))
        exit(0)
    
    # Start monitoring
    print("Starting Cowrie Log Monitor...")
    print(f"Monitoring: {monitor.cowrie_log_path}")
    print(f"API endpoint: {monitor.api_endpoint}")
    print("Press Ctrl+C to stop")
    
    monitor.start_monitoring()

if __name__ == "__main__":
    main() 
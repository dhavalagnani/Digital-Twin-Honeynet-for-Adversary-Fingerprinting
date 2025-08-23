#!/usr/bin/env python3
"""
Digital Twin Honeynet - Log Forwarder
Comprehensive log collection and forwarding system
"""

import json
import logging
import time
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import queue
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LogNormalizer:
    """Normalizes logs from different sources into unified JSON schema"""
    
    def __init__(self):
        self.session_cache = {}
        self.ip_reputation = {}
        
    def normalize_cowrie_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Normalize Cowrie SSH honeypot logs"""
        try:
            data = json.loads(log_line)
            
            # Extract key information
            event_type = data.get('eventid', 'unknown')
            timestamp = data.get('timestamp', datetime.now().isoformat())
            src_ip = data.get('src_ip', 'unknown')
            session = data.get('session', 'unknown')
            username = data.get('username', 'unknown')
            
            # Determine action based on event type
            action = self._map_cowrie_event_to_action(event_type, data)
            
            # Determine result
            result = self._determine_result(event_type, data)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(event_type, data)
            
            return {
                'timestamp': timestamp,
                'source': 'cowrie_ssh',
                'actor': {
                    'ip': src_ip,
                    'username': username,
                    'session': session
                },
                'action': action,
                'result': result,
                'threat_score': threat_score,
                'raw_data': data,
                'event_type': event_type,
                'normalized': True
            }
            
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse Cowrie log line: {log_line}")
            return None
        except Exception as e:
            logger.error(f"Error normalizing Cowrie log: {e}")
            return None
    
    def normalize_auditd_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Normalize auditd logs"""
        try:
            # Parse auditd log format
            # Example: type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="sudo" a1="ls" a2="-la"
            match = re.match(r'type=(\w+) msg=audit\(([\d.]+):(\d+)\):(.*)', log_line)
            if not match:
                return None
                
            event_type = match.group(1)
            timestamp = float(match.group(2))
            audit_id = match.group(3)
            details = match.group(4)
            
            # Extract additional information
            actor_info = self._extract_auditd_actor(details)
            action_info = self._extract_auditd_action(event_type, details)
            
            return {
                'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                'source': 'auditd',
                'actor': actor_info,
                'action': action_info,
                'result': 'success',  # auditd logs successful events
                'threat_score': self._calculate_auditd_threat_score(event_type, details),
                'raw_data': log_line,
                'event_type': event_type,
                'audit_id': audit_id,
                'normalized': True
            }
            
        except Exception as e:
            logger.error(f"Error normalizing auditd log: {e}")
            return None
    
    def normalize_haproxy_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Normalize HAProxy logs"""
        try:
            # HAProxy log format: client_ip:port [timestamp] frontend backend/server status_code bytes
            parts = log_line.split()
            if len(parts) < 8:
                return None
                
            client_ip = parts[0].split(':')[0]
            timestamp_str = f"{parts[1]} {parts[2]}"
            frontend = parts[3]
            backend = parts[4]
            status_code = parts[5]
            bytes_transferred = parts[6]
            
            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str, '[%d/%b/%Y:%H:%M:%S %z]').isoformat()
            
            # Determine action and result
            action = f"http_request_{frontend}"
            result = 'success' if status_code.startswith('2') else 'failed'
            
            return {
                'timestamp': timestamp,
                'source': 'haproxy',
                'actor': {
                    'ip': client_ip,
                    'user_agent': self._extract_user_agent(log_line)
                },
                'action': action,
                'result': result,
                'threat_score': self._calculate_haproxy_threat_score(status_code, log_line),
                'raw_data': log_line,
                'event_type': 'http_request',
                'status_code': status_code,
                'bytes_transferred': bytes_transferred,
                'normalized': True
            }
            
        except Exception as e:
            logger.error(f"Error normalizing HAProxy log: {e}")
            return None
    
    def normalize_nftables_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Normalize nftables logs"""
        try:
            # nftables log format varies, but typically includes action and IP
            if 'DROP' in log_line or 'ACCEPT' in log_line:
                action = 'DROP' if 'DROP' in log_line else 'ACCEPT'
                ip_match = re.search(r'SRC=([\d.]+)', log_line)
                src_ip = ip_match.group(1) if ip_match else 'unknown'
                
                return {
                    'timestamp': datetime.now().isoformat(),
                    'source': 'nftables',
                    'actor': {'ip': src_ip},
                    'action': f'firewall_{action.lower()}',
                    'result': 'blocked' if action == 'DROP' else 'allowed',
                    'threat_score': 50 if action == 'DROP' else 0,
                    'raw_data': log_line,
                    'event_type': 'firewall_rule',
                    'normalized': True
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error normalizing nftables log: {e}")
            return None
    
    def _map_cowrie_event_to_action(self, event_type: str, data: Dict[str, Any]) -> str:
        """Map Cowrie event types to normalized actions"""
        action_mapping = {
            'cowrie.login.success': 'ssh_login',
            'cowrie.login.failed': 'ssh_login_failed',
            'cowrie.command.input': 'command_execution',
            'cowrie.session.connect': 'session_start',
            'cowrie.session.closed': 'session_end',
            'cowrie.direct-tcpip.request': 'port_forward',
            'cowrie.direct-tcpip.data': 'data_transfer',
            'cowrie.client.fingerprint': 'client_fingerprint',
            'cowrie.log.closed': 'log_closed'
        }
        return action_mapping.get(event_type, 'unknown_action')
    
    def _determine_result(self, event_type: str, data: Dict[str, Any]) -> str:
        """Determine the result of an action"""
        if 'success' in event_type:
            return 'success'
        elif 'failed' in event_type:
            return 'failed'
        elif 'closed' in event_type:
            return 'closed'
        else:
            return 'unknown'
    
    def _calculate_threat_score(self, event_type: str, data: Dict[str, Any]) -> int:
        """Calculate threat score for Cowrie events"""
        base_scores = {
            'cowrie.login.failed': 10,
            'cowrie.command.input': 5,
            'cowrie.direct-tcpip.request': 20,
            'cowrie.client.fingerprint': 2
        }
        
        score = base_scores.get(event_type, 0)
        
        # Add score for suspicious commands
        if event_type == 'cowrie.command.input':
            command = data.get('input', '').lower()
            suspicious_commands = ['rm -rf', 'dd', 'mkfs', 'nmap', 'netcat', 'nc']
            if any(cmd in command for cmd in suspicious_commands):
                score += 30
        
        return min(score, 100)
    
    def _extract_auditd_actor(self, details: str) -> Dict[str, Any]:
        """Extract actor information from auditd details"""
        # Extract user ID if available
        uid_match = re.search(r'uid=(\d+)', details)
        uid = uid_match.group(1) if uid_match else 'unknown'
        
        return {
            'uid': uid,
            'type': 'system_user'
        }
    
    def _extract_auditd_action(self, event_type: str, details: str) -> str:
        """Extract action information from auditd details"""
        if event_type == 'EXECVE':
            # Extract command from execve details
            cmd_match = re.search(r'a0="([^"]+)"', details)
            if cmd_match:
                return f"execve_{cmd_match.group(1)}"
        elif event_type == 'USER_CMD':
            return 'user_command'
        
        return f"auditd_{event_type.lower()}"
    
    def _calculate_auditd_threat_score(self, event_type: str, details: str) -> int:
        """Calculate threat score for auditd events"""
        score = 0
        
        if event_type == 'EXECVE':
            # Check for dangerous commands
            dangerous_cmds = ['sudo', 'su', 'passwd', 'chmod', 'chown']
            if any(cmd in details for cmd in dangerous_cmds):
                score += 20
        
        return min(score, 100)
    
    def _extract_user_agent(self, log_line: str) -> str:
        """Extract User-Agent from HAProxy log"""
        ua_match = re.search(r'"([^"]*)"', log_line)
        return ua_match.group(1) if ua_match else 'unknown'
    
    def _calculate_haproxy_threat_score(self, status_code: str, log_line: str) -> int:
        """Calculate threat score for HAProxy events"""
        score = 0
        
        # High status codes indicate potential attacks
        if status_code.startswith('4') or status_code.startswith('5'):
            score += 10
        
        # Check for suspicious user agents
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'dirb', 'gobuster']
        if any(agent in log_line.lower() for agent in suspicious_agents):
            score += 30
        
        return min(score, 100)

class LogForwarder:
    """Main log forwarding system"""
    
    def __init__(self, api_url: str = 'http://localhost:8000'):
        self.api_url = api_url
        self.normalizer = LogNormalizer()
        self.log_queue = queue.Queue()
        self.running = False
        self.observers = []
        
        # Log file paths
        self.log_paths = {
            'cowrie': 'honeypot/logs/cowrie.json',
            'auditd': '/var/log/audit/audit.log',
            'haproxy': '/var/log/haproxy.log',
            'nftables': '/var/log/nftables.log'
        }
        
        # Ensure log directories exist
        Path('logs').mkdir(exist_ok=True)
        
    def start(self):
        """Start the log forwarder"""
        logger.info("Starting log forwarder...")
        self.running = True
        
        # Start log processors
        self._start_log_processors()
        
        # Start forwarder thread
        forwarder_thread = threading.Thread(target=self._forward_logs)
        forwarder_thread.daemon = True
        forwarder_thread.start()
        
        logger.info("Log forwarder started successfully")
    
    def stop(self):
        """Stop the log forwarder"""
        logger.info("Stopping log forwarder...")
        self.running = False
        
        # Stop all observers
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        logger.info("Log forwarder stopped")
    
    def _start_log_processors(self):
        """Start file watchers for each log source"""
        for log_name, log_path in self.log_paths.items():
            if Path(log_path).exists():
                self._start_file_watcher(log_path, log_name)
            else:
                logger.warning(f"Log file not found: {log_path}")
    
    def _start_file_watcher(self, log_path: str, log_type: str):
        """Start watching a specific log file"""
        event_handler = LogFileHandler(self, log_type)
        observer = Observer()
        observer.schedule(event_handler, str(Path(log_path).parent), recursive=False)
        observer.start()
        self.observers.append(observer)
        
        logger.info(f"Started watching {log_path} for {log_type} logs")
    
    def _forward_logs(self):
        """Forward logs to the API backend"""
        while self.running:
            try:
                # Get log from queue
                log_entry = self.log_queue.get(timeout=1)
                
                # Send to API
                self._send_to_api(log_entry)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error forwarding log: {e}")
    
    def _send_to_api(self, log_entry: Dict[str, Any]):
        """Send normalized log to API backend"""
        try:
            response = requests.post(
                f"{self.api_url}/api/logs",
                json=log_entry,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.debug(f"Successfully forwarded log: {log_entry.get('event_type')}")
            else:
                logger.warning(f"Failed to forward log: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending log to API: {e}")
    
    def process_log_line(self, log_line: str, log_type: str):
        """Process a single log line"""
        try:
            # Normalize based on log type
            if log_type == 'cowrie':
                normalized = self.normalizer.normalize_cowrie_log(log_line)
            elif log_type == 'auditd':
                normalized = self.normalizer.normalize_auditd_log(log_line)
            elif log_type == 'haproxy':
                normalized = self.normalizer.normalize_haproxy_log(log_line)
            elif log_type == 'nftables':
                normalized = self.normalizer.normalize_nftables_log(log_line)
            else:
                logger.warning(f"Unknown log type: {log_type}")
                return
            
            if normalized:
                # Add to queue for forwarding
                self.log_queue.put(normalized)
                
        except Exception as e:
            logger.error(f"Error processing {log_type} log line: {e}")

class LogFileHandler(FileSystemEventHandler):
    """File system event handler for log files"""
    
    def __init__(self, forwarder: LogForwarder, log_type: str):
        self.forwarder = forwarder
        self.log_type = log_type
        self.last_position = 0
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        
        try:
            # Read new lines from the file
            with open(event.src_path, 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                # Process each new line
                for line in new_lines:
                    line = line.strip()
                    if line:
                        self.forwarder.process_log_line(line, self.log_type)
                        
        except Exception as e:
            logger.error(f"Error reading log file {event.src_path}: {e}")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Digital Twin Honeynet Log Forwarder')
    parser.add_argument('--api-url', default='http://localhost:8000', help='API backend URL')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create and start log forwarder
    forwarder = LogForwarder(args.api_url)
    
    try:
        forwarder.start()
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        forwarder.stop()

if __name__ == "__main__":
    main()

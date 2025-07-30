#!/usr/bin/env python3
"""
Digital Twin Honeynet - Log Parser
Extracts IPs, TTPs, and behavioral patterns from Cowrie logs
"""

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
import ipaddress

logger = logging.getLogger(__name__)

class LogParser:
    """Parses Cowrie logs and extracts security-relevant information"""
    
    def __init__(self):
        # Statistics tracking
        self.stats = {
            'total_logs_processed': 0,
            'unique_ips': 0,
            'login_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'file_downloads': 0,
            'commands_executed': 0,
            'sessions_tracked': 0
        }
        
        # IP tracking
        self.ip_activity = defaultdict(lambda: {
            'first_seen': None,
            'last_seen': None,
            'login_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'commands': [],
            'downloads': [],
            'sessions': set(),
            'geolocation': None,
            'threat_score': 0
        })
        
        # Session tracking
        self.session_data = defaultdict(lambda: {
            'start_time': None,
            'end_time': None,
            'ip_address': None,
            'username': None,
            'commands': [],
            'downloads': [],
            'duration': 0
        })
        
        # TTP tracking
        self.ttps_detected = defaultdict(int)
        
        # Recent logs for dashboard
        self.recent_logs = deque(maxlen=1000)
        
        # Behavioral patterns
        self.behavioral_patterns = {
            'brute_force': [],
            'port_scanning': [],
            'file_operations': [],
            'command_execution': [],
            'data_exfiltration': []
        }
        
        logger.info("Log parser initialized")
        
    def parse_log_entry(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse a single log entry"""
        try:
            # Parse JSON log entry
            log_entry = json.loads(log_line)
            
            # Extract basic information
            event_id = log_entry.get('eventid', '')
            timestamp = log_entry.get('timestamp', '')
            src_ip = log_entry.get('src_ip', '')
            session = log_entry.get('session', '')
            
            # Parse timestamp
            parsed_timestamp = self.parse_timestamp(timestamp)
            
            # Create parsed entry
            parsed_entry = {
                'event_id': event_id,
                'timestamp': parsed_timestamp,
                'src_ip': src_ip,
                'session': session,
                'raw_entry': log_entry,
                'parsed_data': {}
            }
            
            # Parse based on event type
            if event_id == 'cowrie.login.failed':
                parsed_entry['parsed_data'] = self.parse_login_failed(log_entry)
            elif event_id == 'cowrie.login.success':
                parsed_entry['parsed_data'] = self.parse_login_success(log_entry)
            elif event_id == 'cowrie.session.connect':
                parsed_entry['parsed_data'] = self.parse_session_connect(log_entry)
            elif event_id == 'cowrie.session.file_download':
                parsed_entry['parsed_data'] = self.parse_file_download(log_entry)
            elif event_id == 'cowrie.command.input':
                parsed_entry['parsed_data'] = self.parse_command_input(log_entry)
            elif event_id == 'cowrie.session.closed':
                parsed_entry['parsed_data'] = self.parse_session_closed(log_entry)
            else:
                parsed_entry['parsed_data'] = self.parse_generic_event(log_entry)
                
            # Update statistics
            self.update_statistics(parsed_entry)
            
            # Track IP activity
            self.track_ip_activity(parsed_entry)
            
            # Track session data
            self.track_session_data(parsed_entry)
            
            # Detect TTPs
            self.detect_ttps(parsed_entry)
            
            # Add to recent logs
            self.recent_logs.append(parsed_entry)
            
            return parsed_entry
            
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in log line: {log_line[:100]}...")
            return None
        except Exception as e:
            logger.error(f"Error parsing log entry: {e}")
            return None
            
    def parse_timestamp(self, timestamp: str) -> datetime:
        """Parse timestamp string to datetime object"""
        try:
            # Handle different timestamp formats
            if timestamp.endswith('Z'):
                timestamp = timestamp.replace('Z', '+00:00')
            return datetime.fromisoformat(timestamp)
        except Exception:
            return datetime.now()
            
    def parse_login_failed(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse failed login event"""
        return {
            'event_type': 'login_failed',
            'username': log_entry.get('username', ''),
            'password': log_entry.get('password', ''),
            'reason': log_entry.get('reason', ''),
            'threat_indicators': self.analyze_login_threat(log_entry)
        }
        
    def parse_login_success(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse successful login event"""
        return {
            'event_type': 'login_success',
            'username': log_entry.get('username', ''),
            'password': log_entry.get('password', ''),
            'threat_indicators': self.analyze_login_threat(log_entry)
        }
        
    def parse_session_connect(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse session connection event"""
        return {
            'event_type': 'session_connect',
            'src_port': log_entry.get('src_port', ''),
            'dst_port': log_entry.get('dst_port', ''),
            'protocol': log_entry.get('protocol', 'ssh')
        }
        
    def parse_file_download(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse file download event"""
        return {
            'event_type': 'file_download',
            'filename': log_entry.get('filename', ''),
            'url': log_entry.get('url', ''),
            'size': log_entry.get('size', 0),
            'threat_indicators': self.analyze_file_threat(log_entry)
        }
        
    def parse_command_input(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse command input event"""
        command = log_entry.get('input', '')
        return {
            'event_type': 'command_input',
            'command': command,
            'threat_indicators': self.analyze_command_threat(command)
        }
        
    def parse_session_closed(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse session closed event"""
        return {
            'event_type': 'session_closed',
            'duration': log_entry.get('duration', 0),
            'reason': log_entry.get('reason', '')
        }
        
    def parse_generic_event(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse generic event"""
        return {
            'event_type': 'generic',
            'message': log_entry.get('message', ''),
            'data': log_entry
        }
        
    def analyze_login_threat(self, log_entry: Dict[str, Any]) -> List[str]:
        """Analyze login event for threat indicators"""
        indicators = []
        username = log_entry.get('username', '').lower()
        password = log_entry.get('password', '').lower()
        
        # Common attack usernames
        attack_usernames = ['admin', 'root', 'test', 'guest', 'user', 'ubuntu', 'centos']
        if username in attack_usernames:
            indicators.append('suspicious_username')
            
        # Common weak passwords
        weak_passwords = ['password', '123456', 'admin', 'root', 'test', 'guest']
        if password in weak_passwords:
            indicators.append('weak_password')
            
        # Empty or null credentials
        if not username or not password:
            indicators.append('empty_credentials')
            
        # Very long credentials (potential overflow attempts)
        if len(username) > 50 or len(password) > 100:
            indicators.append('credential_overflow')
            
        return indicators
        
    def analyze_file_threat(self, log_entry: Dict[str, Any]) -> List[str]:
        """Analyze file download for threat indicators"""
        indicators = []
        filename = log_entry.get('filename', '').lower()
        url = log_entry.get('url', '').lower()
        
        # Suspicious file extensions
        suspicious_extensions = ['.sh', '.py', '.pl', '.exe', '.bat', '.cmd']
        if any(ext in filename for ext in suspicious_extensions):
            indicators.append('suspicious_file_type')
            
        # Suspicious URLs
        suspicious_domains = ['pastebin.com', 'githubusercontent.com', 'raw.githubusercontent.com']
        if any(domain in url for domain in suspicious_domains):
            indicators.append('suspicious_source')
            
        # Large file downloads
        size = log_entry.get('size', 0)
        if size > 10 * 1024 * 1024:  # 10MB
            indicators.append('large_file_download')
            
        return indicators
        
    def analyze_command_threat(self, command: str) -> List[str]:
        """Analyze command for threat indicators"""
        indicators = []
        command_lower = command.lower()
        
        # Dangerous commands
        dangerous_commands = [
            'rm -rf', 'dd if=', 'mkfs', 'fdisk', 'shutdown', 'reboot',
            'wget', 'curl', 'nc ', 'netcat', 'telnet', 'ssh-keygen'
        ]
        
        for dangerous_cmd in dangerous_commands:
            if dangerous_cmd in command_lower:
                indicators.append('dangerous_command')
                break
                
        # Data exfiltration patterns
        exfiltration_patterns = [
            'cat /etc/passwd', 'cat /etc/shadow', 'cat /proc/version',
            'uname -a', 'whoami', 'id', 'ps aux', 'netstat'
        ]
        
        for pattern in exfiltration_patterns:
            if pattern in command_lower:
                indicators.append('data_exfiltration')
                break
                
        # Network reconnaissance
        recon_patterns = [
            'nmap', 'ping', 'traceroute', 'dig', 'nslookup', 'host'
        ]
        
        for pattern in recon_patterns:
            if pattern in command_lower:
                indicators.append('network_reconnaissance')
                break
                
        return indicators
        
    def update_statistics(self, parsed_entry: Dict[str, Any]):
        """Update parser statistics"""
        self.stats['total_logs_processed'] += 1
        
        event_type = parsed_entry['parsed_data'].get('event_type', '')
        
        if event_type == 'login_failed':
            self.stats['failed_logins'] += 1
            self.stats['login_attempts'] += 1
        elif event_type == 'login_success':
            self.stats['successful_logins'] += 1
            self.stats['login_attempts'] += 1
        elif event_type == 'file_download':
            self.stats['file_downloads'] += 1
        elif event_type == 'command_input':
            self.stats['commands_executed'] += 1
            
    def track_ip_activity(self, parsed_entry: Dict[str, Any]):
        """Track activity per IP address"""
        src_ip = parsed_entry['src_ip']
        timestamp = parsed_entry['timestamp']
        
        if src_ip not in self.ip_activity:
            self.ip_activity[src_ip]['first_seen'] = timestamp
            self.stats['unique_ips'] += 1
            
        self.ip_activity[src_ip]['last_seen'] = timestamp
        
        # Track specific activity types
        event_type = parsed_entry['parsed_data'].get('event_type', '')
        
        if event_type == 'login_failed':
            self.ip_activity[src_ip]['failed_logins'] += 1
            self.ip_activity[src_ip]['login_attempts'] += 1
        elif event_type == 'login_success':
            self.ip_activity[src_ip]['successful_logins'] += 1
            self.ip_activity[src_ip]['login_attempts'] += 1
        elif event_type == 'command_input':
            command = parsed_entry['parsed_data'].get('command', '')
            self.ip_activity[src_ip]['commands'].append({
                'timestamp': timestamp,
                'command': command
            })
        elif event_type == 'file_download':
            download_info = {
                'timestamp': timestamp,
                'filename': parsed_entry['parsed_data'].get('filename', ''),
                'url': parsed_entry['parsed_data'].get('url', '')
            }
            self.ip_activity[src_ip]['downloads'].append(download_info)
            
        # Add session tracking
        session = parsed_entry['session']
        if session:
            self.ip_activity[src_ip]['sessions'].add(session)
            
        # Calculate threat score
        self.calculate_threat_score(src_ip)
        
    def track_session_data(self, parsed_entry: Dict[str, Any]):
        """Track session-specific data"""
        session = parsed_entry['session']
        timestamp = parsed_entry['timestamp']
        
        if not session:
            return
            
        if session not in self.session_data:
            self.session_data[session]['start_time'] = timestamp
            self.session_data[session]['ip_address'] = parsed_entry['src_ip']
            self.stats['sessions_tracked'] += 1
            
        # Track session end
        event_type = parsed_entry['parsed_data'].get('event_type', '')
        if event_type == 'session_closed':
            self.session_data[session]['end_time'] = timestamp
            duration = parsed_entry['parsed_data'].get('duration', 0)
            self.session_data[session]['duration'] = duration
            
        # Track commands in session
        if event_type == 'command_input':
            command = parsed_entry['parsed_data'].get('command', '')
            self.session_data[session]['commands'].append({
                'timestamp': timestamp,
                'command': command
            })
            
        # Track downloads in session
        if event_type == 'file_download':
            download_info = {
                'timestamp': timestamp,
                'filename': parsed_entry['parsed_data'].get('filename', ''),
                'url': parsed_entry['parsed_data'].get('url', '')
            }
            self.session_data[session]['downloads'].append(download_info)
            
    def detect_ttps(self, parsed_entry: Dict[str, Any]):
        """Detect Tactics, Techniques, and Procedures (TTPs)"""
        indicators = parsed_entry['parsed_data'].get('threat_indicators', [])
        
        for indicator in indicators:
            self.ttps_detected[indicator] += 1
            
        # Detect behavioral patterns
        event_type = parsed_entry['parsed_data'].get('event_type', '')
        src_ip = parsed_entry['src_ip']
        
        if event_type == 'login_failed':
            # Check for brute force patterns
            if self.is_brute_force_pattern(src_ip):
                self.behavioral_patterns['brute_force'].append({
                    'ip': src_ip,
                    'timestamp': parsed_entry['timestamp'],
                    'pattern': 'rapid_failed_logins'
                })
                
        elif event_type == 'command_input':
            command = parsed_entry['parsed_data'].get('command', '')
            if self.is_reconnaissance_command(command):
                self.behavioral_patterns['port_scanning'].append({
                    'ip': src_ip,
                    'timestamp': parsed_entry['timestamp'],
                    'command': command
                })
                
        elif event_type == 'file_download':
            self.behavioral_patterns['file_operations'].append({
                'ip': src_ip,
                'timestamp': parsed_entry['timestamp'],
                'filename': parsed_entry['parsed_data'].get('filename', '')
            })
            
    def is_brute_force_pattern(self, src_ip: str) -> bool:
        """Check if IP shows brute force patterns"""
        if src_ip not in self.ip_activity:
            return False
            
        activity = self.ip_activity[src_ip]
        failed_attempts = activity['failed_logins']
        
        # Consider brute force if more than 5 failed attempts
        return failed_attempts > 5
        
    def is_reconnaissance_command(self, command: str) -> bool:
        """Check if command is reconnaissance-related"""
        recon_commands = ['nmap', 'ping', 'traceroute', 'netstat', 'ss']
        return any(cmd in command.lower() for cmd in recon_commands)
        
    def calculate_threat_score(self, src_ip: str):
        """Calculate threat score for an IP"""
        if src_ip not in self.ip_activity:
            return
            
        activity = self.ip_activity[src_ip]
        score = 0
        
        # Failed login attempts
        score += activity['failed_logins'] * 10
        
        # Dangerous commands
        dangerous_commands = len([
            cmd for cmd in activity['commands']
            if any(dc in cmd['command'].lower() for dc in ['rm -rf', 'dd', 'mkfs'])
        ])
        score += dangerous_commands * 50
        
        # Suspicious downloads
        suspicious_downloads = len([
            dl for dl in activity['downloads']
            if any(ext in dl['filename'].lower() for ext in ['.sh', '.py', '.exe'])
        ])
        score += suspicious_downloads * 30
        
        # Multiple sessions
        if len(activity['sessions']) > 3:
            score += 20
            
        activity['threat_score'] = min(score, 100)  # Cap at 100
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get parser statistics"""
        return {
            'parser_stats': self.stats.copy(),
            'unique_ips': len(self.ip_activity),
            'active_sessions': len([s for s in self.session_data.values() if not s['end_time']]),
            'ttps_detected': dict(self.ttps_detected),
            'behavioral_patterns': {
                pattern: len(events) for pattern, events in self.behavioral_patterns.items()
            }
        }
        
    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent parsed logs"""
        return list(self.recent_logs)[-limit:]
        
    def get_ip_activity(self, src_ip: str) -> Optional[Dict[str, Any]]:
        """Get activity for specific IP"""
        return self.ip_activity.get(src_ip)
        
    def get_high_threat_ips(self, threshold: int = 50) -> List[Tuple[str, int]]:
        """Get IPs with high threat scores"""
        high_threat = [
            (ip, activity['threat_score'])
            for ip, activity in self.ip_activity.items()
            if activity['threat_score'] >= threshold
        ]
        return sorted(high_threat, key=lambda x: x[1], reverse=True)
        
    def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get summary for specific session"""
        return self.session_data.get(session_id) 
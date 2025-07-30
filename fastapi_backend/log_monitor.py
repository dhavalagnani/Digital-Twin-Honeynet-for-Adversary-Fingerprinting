#!/usr/bin/env python3
"""
Digital Twin Honeynet - Log Monitor
Watches Cowrie logs in real-time and processes security events
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading

from parser import LogParser
from firewall import FirewallManager
from config import BEHAVIOR_RULES, SYSTEM_CONFIG

logger = logging.getLogger(__name__)

class CowrieLogHandler(FileSystemEventHandler):
    """Handles file system events for Cowrie logs"""
    
    def __init__(self, log_monitor):
        self.log_monitor = log_monitor
        self.last_position = 0
        
    def on_modified(self, event):
        """Called when log file is modified"""
        if not event.is_directory and event.src_path.endswith('.json'):
            asyncio.create_task(self.log_monitor.process_log_file(event.src_path))
            
    def on_created(self, event):
        """Called when new log file is created"""
        if not event.is_directory and event.src_path.endswith('.json'):
            logger.info(f"New log file detected: {event.src_path}")
            asyncio.create_task(self.log_monitor.process_log_file(event.src_path))

class LogMonitor:
    """Monitors Cowrie logs and processes security events"""
    
    def __init__(self):
        self.observer = None
        self.handler = None
        self.running = False
        self.start_time = None
        
        # Initialize components
        self.parser = LogParser()
        self.firewall = FirewallManager()
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'processed_events': 0,
            'blocked_ips': 0,
            'redirected_requests': 0,
            'alerts_generated': 0,
            'last_event_time': None
        }
        
        # Event tracking
        self.ip_events = {}  # Track events per IP
        self.session_tracking = {}  # Track user sessions
        
        # Alert thresholds
        self.alert_thresholds = {
            'brute_force_attempts': BEHAVIOR_RULES.get('brute_force_threshold', 5),
            'brute_force_window': BEHAVIOR_RULES.get('brute_force_window', 60),
            'suspicious_patterns': BEHAVIOR_RULES.get('suspicious_patterns', []),
            'legitimate_delay_min': BEHAVIOR_RULES.get('legitimate_delay_min', 1.0),
            'legitimate_delay_max': BEHAVIOR_RULES.get('legitimate_delay_max', 5.0)
        }
        
        logger.info("Log monitor initialized")
        
    async def start_monitoring(self):
        """Start monitoring log files"""
        try:
            self.start_time = datetime.now()
            self.running = True
            
            # Create observer for file system events
            self.observer = Observer()
            self.handler = CowrieLogHandler(self)
            
            # Monitor honeypot log directory
            log_path = Path("honeypot/logs")
            log_path.mkdir(parents=True, exist_ok=True)
            
            self.observer.schedule(self.handler, str(log_path), recursive=False)
            self.observer.start()
            
            logger.info(f"Started monitoring log directory: {log_path}")
            
            # Process existing log files
            await self.process_existing_logs()
            
        except Exception as e:
            logger.error(f"Error starting log monitor: {e}")
            raise
            
    async def stop_monitoring(self):
        """Stop monitoring log files"""
        try:
            self.running = False
            
            if self.observer:
                self.observer.stop()
                self.observer.join()
                
            logger.info("Log monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error stopping log monitor: {e}")
            
    async def process_existing_logs(self):
        """Process existing log files on startup"""
        try:
            log_path = Path("honeypot/logs")
            
            for log_file in log_path.glob("*.json"):
                await self.process_log_file(str(log_file))
                
            logger.info("Processed existing log files")
            
        except Exception as e:
            logger.error(f"Error processing existing logs: {e}")
            
    async def process_log_file(self, file_path: str):
        """Process a log file for security events"""
        try:
            if not Path(file_path).exists():
                return
                
            with open(file_path, 'r') as f:
                # Read new lines since last position
                f.seek(0, 2)  # Go to end of file
                current_size = f.tell()
                
                if current_size < self.handler.last_position:
                    # File was truncated, reset position
                    self.handler.last_position = 0
                    
                f.seek(self.handler.last_position)
                
                for line in f:
                    line = line.strip()
                    if line:
                        await self.process_log_line(line)
                        
                self.handler.last_position = current_size
                
        except Exception as e:
            logger.error(f"Error processing log file {file_path}: {e}")
            
    async def process_log_line(self, line: str):
        """Process a single log line"""
        try:
            # Parse log entry
            log_entry = json.loads(line)
            
            # Update statistics
            self.stats['total_events'] += 1
            self.stats['last_event_time'] = datetime.now().isoformat()
            
            # Extract key information
            event_id = log_entry.get('eventid', '')
            src_ip = log_entry.get('src_ip', '')
            timestamp = log_entry.get('timestamp', '')
            username = log_entry.get('username', '')
            password = log_entry.get('password', '')
            session = log_entry.get('session', '')
            
            # Classify event
            classification = await self.classify_event(log_entry)
            
            # Take action based on classification
            await self.handle_event(log_entry, classification)
            
            # Update processed events count
            self.stats['processed_events'] += 1
            
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in log line: {line[:100]}...")
        except Exception as e:
            logger.error(f"Error processing log line: {e}")
            
    async def classify_event(self, log_entry: Dict[str, Any]) -> str:
        """Classify event as legitimate, suspicious, or malicious"""
        try:
            event_id = log_entry.get('eventid', '')
            src_ip = log_entry.get('src_ip', '')
            username = log_entry.get('username', '')
            timestamp = log_entry.get('timestamp', '')
            
            # Check if IP is in whitelist
            if self.is_whitelisted_ip(src_ip):
                return 'legitimate'
                
            # Check for brute force patterns
            if await self.detect_brute_force(src_ip, timestamp):
                return 'malicious'
                
            # Check for suspicious patterns
            if self.detect_suspicious_patterns(username, password):
                return 'suspicious'
                
            # Check timing patterns
            if await self.detect_timing_anomalies(src_ip, timestamp):
                return 'suspicious'
                
            # Default to legitimate
            return 'legitimate'
            
        except Exception as e:
            logger.error(f"Error classifying event: {e}")
            return 'suspicious'  # Default to suspicious on error
            
    async def handle_event(self, log_entry: Dict[str, Any], classification: str):
        """Handle event based on classification"""
        try:
            src_ip = log_entry.get('src_ip', '')
            event_id = log_entry.get('eventid', '')
            
            if classification == 'malicious':
                # Block IP immediately
                reason = f"Malicious activity detected: {event_id}"
                success = self.firewall.block_ip(src_ip, reason)
                
                if success:
                    self.stats['blocked_ips'] += 1
                    logger.warning(f"Blocked malicious IP {src_ip}: {reason}")
                    
                    # Generate alert
                    await self.generate_alert('high', src_ip, reason)
                    
            elif classification == 'suspicious':
                # Monitor closely but don't block yet
                reason = f"Suspicious activity detected: {event_id}"
                logger.info(f"Suspicious activity from {src_ip}: {reason}")
                
                # Generate soft alert
                await self.generate_alert('medium', src_ip, reason)
                
            elif classification == 'legitimate':
                # Redirect to production
                reason = f"Legitimate traffic: {event_id}"
                success = await self.redirect_to_production(src_ip, log_entry)
                
                if success:
                    self.stats['redirected_requests'] += 1
                    logger.info(f"Redirected legitimate traffic from {src_ip}")
                    
        except Exception as e:
            logger.error(f"Error handling event: {e}")
            
    async def detect_brute_force(self, src_ip: str, timestamp: str) -> bool:
        """Detect brute force attacks"""
        try:
            now = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            window_start = now - timedelta(seconds=self.alert_thresholds['brute_force_window'])
            
            # Get events for this IP in the time window
            if src_ip not in self.ip_events:
                self.ip_events[src_ip] = []
                
            # Add current event
            self.ip_events[src_ip].append({
                'timestamp': now,
                'type': 'login_attempt'
            })
            
            # Remove old events outside window
            self.ip_events[src_ip] = [
                event for event in self.ip_events[src_ip]
                if event['timestamp'] >= window_start
            ]
            
            # Check if threshold exceeded
            failed_attempts = len([
                event for event in self.ip_events[src_ip]
                if event['type'] == 'login_attempt'
            ])
            
            return failed_attempts >= self.alert_thresholds['brute_force_attempts']
            
        except Exception as e:
            logger.error(f"Error detecting brute force: {e}")
            return False
            
    def detect_suspicious_patterns(self, username: str, password: str) -> bool:
        """Detect suspicious username/password patterns"""
        try:
            suspicious_usernames = self.alert_thresholds['suspicious_patterns']
            
            # Check for suspicious usernames
            if username.lower() in [u.lower() for u in suspicious_usernames]:
                return True
                
            # Check for common attack patterns
            attack_patterns = ['admin', 'root', 'test', 'guest', 'user']
            if username.lower() in attack_patterns:
                return True
                
            # Check for weak passwords
            weak_passwords = ['password', '123456', 'admin', 'root', 'test']
            if password.lower() in weak_passwords:
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error detecting suspicious patterns: {e}")
            return False
            
    async def detect_timing_anomalies(self, src_ip: str, timestamp: str) -> bool:
        """Detect timing anomalies in requests"""
        try:
            now = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            if src_ip not in self.ip_events:
                return False
                
            recent_events = self.ip_events[src_ip][-3:]  # Last 3 events
            
            if len(recent_events) < 2:
                return False
                
            # Check for rapid-fire requests
            for i in range(1, len(recent_events)):
                time_diff = (now - recent_events[i-1]['timestamp']).total_seconds()
                
                if time_diff < self.alert_thresholds['legitimate_delay_min']:
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error detecting timing anomalies: {e}")
            return False
            
    def is_whitelisted_ip(self, src_ip: str) -> bool:
        """Check if IP is in whitelist"""
        try:
            whitelist = BEHAVIOR_RULES.get('redirect_whitelist', [])
            
            for network in whitelist:
                if self.ip_in_network(src_ip, network):
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error checking whitelist: {e}")
            return False
            
    def ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network range"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
        except Exception:
            return False
            
    async def redirect_to_production(self, src_ip: str, log_entry: Dict[str, Any]) -> bool:
        """Redirect legitimate traffic to production server"""
        try:
            # This would integrate with HAProxy or similar
            # For now, we just log the redirect
            logger.info(f"Redirecting {src_ip} to production server")
            
            # In a real implementation, this would:
            # 1. Update HAProxy configuration
            # 2. Add IP to whitelist
            # 3. Configure routing rules
            
            return True
            
        except Exception as e:
            logger.error(f"Error redirecting to production: {e}")
            return False
            
    async def generate_alert(self, severity: str, src_ip: str, reason: str):
        """Generate security alert"""
        try:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'severity': severity,
                'source_ip': src_ip,
                'reason': reason,
                'action_taken': 'blocked' if severity == 'high' else 'monitored'
            }
            
            # Log alert
            logger.warning(f"SECURITY ALERT: {severity.upper()} - {src_ip} - {reason}")
            
            # Store alert
            self.stats['alerts_generated'] += 1
            
            # In a real implementation, this would:
            # 1. Send email/SMS notifications
            # 2. Update dashboard
            # 3. Store in database
            
        except Exception as e:
            logger.error(f"Error generating alert: {e}")
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        return {
            'monitor_stats': self.stats.copy(),
            'uptime': self.get_uptime(),
            'active_sessions': len(self.session_tracking),
            'tracked_ips': len(self.ip_events)
        }
        
    def get_uptime(self) -> Dict[str, int]:
        """Get system uptime"""
        if not self.start_time:
            return {'seconds': 0, 'minutes': 0, 'hours': 0}
            
        uptime = datetime.now() - self.start_time
        total_seconds = int(uptime.total_seconds())
        
        return {
            'seconds': total_seconds % 60,
            'minutes': (total_seconds // 60) % 60,
            'hours': total_seconds // 3600
        } 
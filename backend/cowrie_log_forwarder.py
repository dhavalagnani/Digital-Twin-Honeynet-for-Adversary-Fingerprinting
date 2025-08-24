#!/usr/bin/env python3
"""
Digital Twin Honeynet - Cowrie Log Forwarder
Lightweight background service that tails cowrie.json and forwards to dashboard WebSocket
"""

import json
import logging
import time
import threading
import asyncio
import websockets
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import queue
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/cowrie_forwarder.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CowrieLogNormalizer:
    """Normalizes Cowrie logs into dashboard-compatible JSON format"""
    
    def __init__(self):
        self.session_cache = {}
        
    def normalize_log_entry(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Normalize a single Cowrie log entry"""
        try:
            # Parse JSON log entry
            data = json.loads(log_line)
            
            # Extract key information
            event_type = data.get('eventid', 'unknown')
            timestamp = data.get('timestamp', datetime.now().isoformat())
            src_ip = data.get('src_ip', 'unknown')
            session = data.get('session', 'unknown')
            username = data.get('username', 'unknown')
            
            # Map event types to user-friendly actions
            action = self._map_event_to_action(event_type, data)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(event_type, data)
            
            # Create normalized entry
            normalized = {
                'timestamp': timestamp,
                'source': 'cowrie_ssh',
                'actor': {
                    'ip': src_ip,
                    'username': username,
                    'session': session
                },
                'action': action,
                'result': self._determine_result(event_type),
                'threat_score': threat_score,
                'raw_data': data,
                'event_type': event_type,
                'normalized': True,
                'dashboard_type': 'cowrie_log'
            }
            
            # Add session tracking
            if session:
                self._update_session_cache(session, normalized)
            
            return normalized
            
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in log line: {log_line[:100]}...")
            return None
        except Exception as e:
            logger.error(f"Error normalizing log entry: {e}")
            return None
    
    def _map_event_to_action(self, event_type: str, data: Dict[str, Any]) -> str:
        """Map Cowrie event types to user-friendly actions"""
        action_mapping = {
            'cowrie.login.success': 'SSH Login Success',
            'cowrie.login.failed': 'SSH Login Failed',
            'cowrie.command.input': 'Command Execution',
            'cowrie.session.connect': 'Session Started',
            'cowrie.session.closed': 'Session Ended',
            'cowrie.direct-tcpip.request': 'Port Forward Request',
            'cowrie.direct-tcpip.data': 'Data Transfer',
            'cowrie.client.fingerprint': 'Client Fingerprint',
            'cowrie.log.closed': 'Log Closed'
        }
        
        action = action_mapping.get(event_type, 'Unknown Action')
        
        # Add command details for command execution
        if event_type == 'cowrie.command.input':
            command = data.get('input', '').strip()
            if command:
                action = f"Command: {command[:50]}{'...' if len(command) > 50 else ''}"
        
        return action
    
    def _determine_result(self, event_type: str) -> str:
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
            suspicious_commands = [
                'rm -rf', 'dd', 'mkfs', 'nmap', 'netcat', 'nc', 'wget', 'curl',
                'bash -i', 'python -c', 'perl -e', 'cat /etc/passwd', 'uname -a'
            ]
            if any(cmd in command for cmd in suspicious_commands):
                score += 30
        
        return min(score, 100)
    
    def _update_session_cache(self, session: str, log_entry: Dict[str, Any]):
        """Update session cache for tracking"""
        if session not in self.session_cache:
            self.session_cache[session] = {
                'start_time': log_entry['timestamp'],
                'ip': log_entry['actor']['ip'],
                'username': log_entry['actor']['username'],
                'commands': []
            }
        
        # Add command to session if it's a command execution
        if log_entry['event_type'] == 'cowrie.command.input':
            command = log_entry['raw_data'].get('input', '').strip()
            if command:
                self.session_cache[session]['commands'].append({
                    'command': command,
                    'timestamp': log_entry['timestamp']
                })

class CowrieLogForwarder:
    """Main log forwarding service"""
    
    def __init__(self, log_path: str = 'honeypot/logs/cowrie.json', 
                 websocket_url: str = 'ws://localhost:8000/ws'):
        self.log_path = Path(log_path)
        self.websocket_url = websocket_url
        self.normalizer = CowrieLogNormalizer()
        self.running = False
        self.last_position = 0
        self.log_queue = queue.Queue()
        self.websocket = None
        
        # Statistics
        self.stats = {
            'total_logs_processed': 0,
            'logs_forwarded': 0,
            'errors': 0,
            'last_activity': None
        }
        
        # Ensure log directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Cowrie log forwarder initialized")
        logger.info(f"Log file: {self.log_path}")
        logger.info(f"WebSocket URL: {self.websocket_url}")
    
    def start(self):
        """Start the log forwarder service"""
        logger.info("Starting Cowrie log forwarder...")
        self.running = True
        
        # Start WebSocket connection
        self._start_websocket_connection()
        
        # Start log processing thread
        log_thread = threading.Thread(target=self._process_log_file, daemon=True)
        log_thread.start()
        
        # Start forwarding thread
        forward_thread = threading.Thread(target=self._forward_logs, daemon=True)
        forward_thread.start()
        
        logger.info("Cowrie log forwarder started successfully")
    
    def stop(self):
        """Stop the log forwarder service"""
        logger.info("Stopping Cowrie log forwarder...")
        self.running = False
        
        if self.websocket:
            asyncio.run(self._close_websocket())
        
        logger.info("Cowrie log forwarder stopped")
    
    def _start_websocket_connection(self):
        """Start WebSocket connection to dashboard"""
        try:
            # Run WebSocket connection in a separate thread
            ws_thread = threading.Thread(target=self._websocket_worker, daemon=True)
            ws_thread.start()
        except Exception as e:
            logger.error(f"Error starting WebSocket connection: {e}")
    
    def _websocket_worker(self):
        """WebSocket worker thread"""
        while self.running:
            try:
                asyncio.run(self._connect_websocket())
            except Exception as e:
                logger.error(f"WebSocket connection error: {e}")
                time.sleep(5)  # Wait before reconnecting
    
    async def _connect_websocket(self):
        """Connect to WebSocket endpoint"""
        try:
            self.websocket = await websockets.connect(self.websocket_url)
            logger.info("Connected to dashboard WebSocket")
            
            # Keep connection alive
            while self.running and self.websocket:
                try:
                    await self.websocket.ping()
                    await asyncio.sleep(30)  # Ping every 30 seconds
                except:
                    break
                    
        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            self.websocket = None
    
    async def _close_websocket(self):
        """Close WebSocket connection"""
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
    
    def _process_log_file(self):
        """Process the Cowrie log file"""
        while self.running:
            try:
                if not self.log_path.exists():
                    logger.warning(f"Log file not found: {self.log_path}")
                    time.sleep(5)
                    continue
                
                # Read new lines from the file
                with open(self.log_path, 'r', encoding='utf-8') as f:
                    # Go to last known position
                    f.seek(self.last_position)
                    
                    # Read new lines
                    new_lines = f.readlines()
                    self.last_position = f.tell()
                    
                    # Process each new line
                    for line in new_lines:
                        line = line.strip()
                        if line:
                            self._process_log_line(line)
                
                # Wait before next check
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error processing log file: {e}")
                time.sleep(5)
    
    def _process_log_line(self, line: str):
        """Process a single log line"""
        try:
            # Normalize the log entry
            normalized = self.normalizer.normalize_log_entry(line)
            
            if normalized:
                # Add to queue for forwarding
                self.log_queue.put(normalized)
                self.stats['total_logs_processed'] += 1
                self.stats['last_activity'] = datetime.now().isoformat()
                
                logger.debug(f"Processed log: {normalized['event_type']} from {normalized['actor']['ip']}")
            
        except Exception as e:
            logger.error(f"Error processing log line: {e}")
            self.stats['errors'] += 1
    
    def _forward_logs(self):
        """Forward logs to WebSocket"""
        while self.running:
            try:
                # Get log from queue
                log_entry = self.log_queue.get(timeout=1)
                
                # Forward to WebSocket
                asyncio.run(self._send_to_websocket(log_entry))
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error forwarding log: {e}")
                self.stats['errors'] += 1
    
    async def _send_to_websocket(self, log_entry: Dict[str, Any]):
        """Send log entry to WebSocket"""
        if not self.websocket:
            logger.warning("WebSocket not connected, skipping log forward")
            return
        
        try:
            # Create message for dashboard
            message = {
                'type': 'cowrie_log',
                'log': log_entry,
                'timestamp': datetime.now().isoformat()
            }
            
            # Send to WebSocket
            await self.websocket.send(json.dumps(message))
            self.stats['logs_forwarded'] += 1
            
            logger.debug(f"Forwarded log: {log_entry['event_type']}")
            
        except Exception as e:
            logger.error(f"Error sending to WebSocket: {e}")
            self.stats['errors'] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get service statistics"""
        return {
            'service_stats': self.stats.copy(),
            'log_file': str(self.log_path),
            'websocket_url': self.websocket_url,
            'websocket_connected': self.websocket is not None,
            'session_count': len(self.normalizer.session_cache)
        }

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Cowrie Log Forwarder')
    parser.add_argument('--log-path', default='honeypot/logs/cowrie.json', 
                       help='Path to Cowrie log file')
    parser.add_argument('--websocket-url', default='ws://localhost:8000/ws',
                       help='Dashboard WebSocket URL')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--stats', action='store_true', help='Show statistics and exit')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create forwarder
    forwarder = CowrieLogForwarder(args.log_path, args.websocket_url)
    
    # Show statistics if requested
    if args.stats:
        stats = forwarder.get_statistics()
        print("Cowrie Log Forwarder Statistics:")
        print(json.dumps(stats, indent=2))
        return
    
    try:
        # Start the service
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

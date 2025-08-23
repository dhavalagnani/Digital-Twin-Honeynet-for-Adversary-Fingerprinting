#!/usr/bin/env python3
"""
Digital Twin Honeynet - Attack Simulator 1
TC1: Legitimate Access Testing (No False Positives)
"""

import time
import random
import requests
import json
import logging
import argparse
from datetime import datetime
import paramiko
import socket
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LegitimateAccessSimulator:
    """Simulates legitimate user access patterns"""

    def __init__(self, target_host='localhost', target_port=22, api_url='http://localhost:8000'):
        self.target_host = target_host
        self.target_port = target_port
        self.api_url = api_url

        # Legitimate user credentials
        self.legitimate_users = [
            {'username': 'admin', 'password': 'admin123'},
            {'username': 'user1', 'password': 'secure_password_2024'},
            {'username': 'developer', 'password': 'dev_pass_123'},
            {'username': 'operator', 'password': 'op_secure_456'}
        ]

        # Legitimate behavior patterns
        self.behavior_patterns = {
            'normal_delay': (2.0, 5.0),      # Normal delay between attempts
            'session_duration': (30, 300),    # Session duration in seconds
            'command_delay': (1.0, 3.0),     # Delay between commands
            'typing_speed': (0.1, 0.5)       # Realistic typing delays
        }

        logger.info(f"Legitimate access simulator initialized for {target_host}:{target_port}")

    def simulate_legitimate_login(self, username, password):
        """Simulate a legitimate login attempt via SSH"""
        logger.info(f"Simulating legitimate login: {username} -> {self.target_host}:{self.target_port}")

        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            session.connect(
                hostname=self.target_host,
                port=self.target_port,
                username=username,
                password=password,
                timeout=5,
                look_for_keys=False,
                allow_agent=False
            )
            logger.info(f"SSH login successful: {username}")
            login_success = True
        except paramiko.AuthenticationException:
            logger.warning(f"SSH login failed (auth): {username}")
            login_success = False
        except paramiko.SSHException as e:
            logger.error(f"SSH exception: {e}")
            login_success = False
        except Exception as e:
            logger.error(f"SSH connection error: {e}")
            login_success = False
        finally:
            session.close()

        # Log the attempt regardless of success/failure
        log_entry = {
            'eventid': 'cowrie.login.success' if login_success else 'cowrie.login.failed',
            'timestamp': datetime.now().isoformat(),
            'src_ip': self.get_legitimate_ip(),
            'username': username,
            'password': password,
            'session': f'legitimate_{random.randint(1000, 9999)}',
            'message': f"{'Successful' if login_success else 'Failed'} login: {username}"
        }
        self.write_log_entry(log_entry)

        # Simulate realistic delay
        time.sleep(random.uniform(*self.behavior_patterns['normal_delay']))

        return login_success

    def simulate_legitimate_session(self, username):
        """Simulate a legitimate user session"""
        logger.info(f"Simulating legitimate session for {username}")

        session_id = f'legitimate_session_{random.randint(1000, 9999)}'
        session_duration = random.randint(*self.behavior_patterns['session_duration'])

        # Session start
        start_log = {
            'eventid': 'cowrie.session.connect',
            'timestamp': datetime.now().isoformat(),
            'src_ip': self.get_legitimate_ip(),
            'session': session_id,
            'message': f'Session started for {username}'
        }
        self.write_log_entry(start_log)

        # Simulate legitimate commands
        legitimate_commands = [
            'ls -la',
            'pwd',
            'whoami',
            'date',
            'uptime',
            'df -h',
            'ps aux | head -10',
            'netstat -tuln | head -5'
        ]

        for command in random.sample(legitimate_commands, random.randint(3, 6)):
            time.sleep(random.uniform(*self.behavior_patterns['typing_speed']))

            command_log = {
                'eventid': 'cowrie.command.input',
                'timestamp': datetime.now().isoformat(),
                'src_ip': self.get_legitimate_ip(),
                'session': session_id,
                'input': command,
                'message': f'Command executed: {command}'
            }
            self.write_log_entry(command_log)

            time.sleep(random.uniform(*self.behavior_patterns['command_delay']))

        # Session end
        end_log = {
            'eventid': 'cowrie.session.closed',
            'timestamp': datetime.now().isoformat(),
            'src_ip': self.get_legitimate_ip(),
            'session': session_id,
            'duration': session_duration,
            'message': f'Session ended for {username}'
        }
        self.write_log_entry(end_log)

        logger.info(f"Legitimate session completed for {username}")

    def simulate_legitimate_file_operations(self, username):
        """Simulate legitimate file operations"""
        logger.info(f"Simulating legitimate file operations for {username}")

        session_id = f'legitimate_file_{random.randint(1000, 9999)}'

        file_operations = [
            {'operation': 'read', 'file': '/etc/passwd'},
            {'operation': 'read', 'file': '/proc/version'},
            {'operation': 'list', 'file': '/home'},
            {'operation': 'read', 'file': '/etc/hostname'}
        ]

        for op in file_operations:
            time.sleep(random.uniform(1.0, 3.0))

            if op['operation'] == 'read':
                log_entry = {
                    'eventid': 'cowrie.command.input',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': self.get_legitimate_ip(),
                    'session': session_id,
                    'input': f'cat {op["file"]}',
                    'message': f'File read: {op["file"]}'
                }
            else:
                log_entry = {
                    'eventid': 'cowrie.command.input',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': self.get_legitimate_ip(),
                    'session': session_id,
                    'input': f'ls -la {op["file"]}',
                    'message': f'File list: {op["file"]}'
                }

            self.write_log_entry(log_entry)

        logger.info(f"Legitimate file operations completed for {username}")

    def get_legitimate_ip(self):
        """Get a legitimate IP address from whitelisted ranges"""
        legitimate_ranges = [
            '192.168.1.100',
            '192.168.1.101',
            '192.168.1.102',
            '10.0.0.50',
            '10.0.0.51',
            '172.16.0.10',
            '172.16.0.11'
        ]
        return random.choice(legitimate_ranges)

    def write_log_entry(self, log_entry):
        """Write log entry to Cowrie log file"""
        try:
            Path('honeypot/logs').mkdir(parents=True, exist_ok=True)

            with open('honeypot/logs/cowrie.json', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')

        except Exception as e:
            logger.error(f"Error writing log entry: {e}")

    def test_api_connectivity(self):
        """Test connectivity to the security API"""
        try:
            response = requests.get(f"{self.api_url}/health", timeout=5)
            if response.status_code == 200:
                logger.info("✓ API connectivity test passed")
                return True
            else:
                logger.error(f"✗ API connectivity test failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"✗ API connectivity test failed: {e}")
            return False

    def get_system_status(self):
        """Get current system status"""
        try:
            response = requests.get(f"{self.api_url}/status", timeout=5)
            if response.status_code == 200:
                status = response.json()
                logger.info("System Status:")
                logger.info(f"  - Total requests: {status.get('stats', {}).get('total_requests', 0)}")
                logger.info(f"  - Blocked IPs: {status.get('stats', {}).get('blocked_ips', 0)}")
                logger.info(f"  - Redirected requests: {status.get('stats', {}).get('redirected_requests', 0)}")
                return status
            else:
                logger.error(f"Failed to get status: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return None

    def run_legitimate_access_test(self):
        """Run comprehensive legitimate access test"""
        logger.info("=" * 60)
        logger.info("🧪 TC1: Legitimate Access Testing")
        logger.info("=" * 60)

        if not self.test_api_connectivity():
            logger.error("Cannot connect to API. Make sure the honeynet system is running.")
            return

        logger.info("Initial system status:")
        initial_status = self.get_system_status()

        for i, user in enumerate(self.legitimate_users):
            logger.info(f"\n--- Legitimate User {i+1}: {user['username']} ---")

            # Simulate login
            self.simulate_legitimate_login(user['username'], user['password'])
            time.sleep(2)

            # Simulate session
            self.simulate_legitimate_session(user['username'])
            time.sleep(3)

            # Simulate file operations
            self.simulate_legitimate_file_operations(user['username'])
            time.sleep(2)

        logger.info("\nFinal system status:")
        final_status = self.get_system_status()

        if initial_status and final_status:
            initial_blocked = initial_status.get('stats', {}).get('blocked_ips', 0)
            final_blocked = final_status.get('stats', {}).get('blocked_ips', 0)

            if final_blocked == initial_blocked:
                logger.info("✅ SUCCESS: No false positives detected!")
                logger.info("✅ All legitimate traffic was properly classified")
            else:
                logger.warning("⚠️  WARNING: Potential false positives detected!")
                logger.warning(f"   Blocked IPs increased from {initial_blocked} to {final_blocked}")

        logger.info("\n✅ Legitimate access testing completed!")

def main():
    parser = argparse.ArgumentParser(description='TC1: Legitimate Access Simulator')
    parser.add_argument('--target', default='localhost', help='Target host (default: localhost)')
    parser.add_argument('--port', type=int, default=22, help='Target port (default: 22)')
    parser.add_argument('--api-url', default='http://localhost:8000', help='API URL (default: http://localhost:8000)')
    parser.add_argument('--users', type=int, default=4, help='Number of legitimate users to simulate (default: 4)')
    parser.add_argument('--delay', type=float, default=2.0, help='Delay between users (default: 2.0s)')

    args = parser.parse_args()

    simulator = LegitimateAccessSimulator(args.target, args.port, args.api_url)
    simulator.run_legitimate_access_test()

    logger.info("Legitimate access simulation completed!")

if __name__ == "__main__":
    main()

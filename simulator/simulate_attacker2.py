#!/usr/bin/env python3
"""
Digital Twin Honeynet - Attack Simulator 2
TC2: Boundary Value Analysis (Slight Deviations)
"""

import time
import random
import requests
import json
import logging
import argparse
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BoundaryValueSimulator:
    """Simulates boundary value scenarios for testing"""
    
    def __init__(self, target_host='localhost', target_port=22, api_url='http://localhost:8000'):
        self.target_host = target_host
        self.target_port = target_port
        self.api_url = api_url
        
        # Boundary test scenarios
        self.boundary_scenarios = {
            'brute_force_threshold': {
                'name': 'Brute Force Threshold Boundary',
                'attempts': 4,  # Just below threshold of 5
                'delay': 1.5,   # Slightly faster than normal
                'expected': 'allow_but_log'
            },
            'timing_boundary': {
                'name': 'Timing Boundary',
                'attempts': 3,
                'delay': 0.8,   # Just above suspicious threshold
                'expected': 'allow_but_log'
            },
            'username_boundary': {
                'name': 'Username Boundary',
                'attempts': 2,
                'delay': 2.0,
                'username': 'admin_test',  # Similar to suspicious but not exact
                'expected': 'allow_but_log'
            },
            'password_boundary': {
                'name': 'Password Boundary',
                'attempts': 2,
                'delay': 2.5,
                'password': 'admin1234',  # Similar to weak password
                'expected': 'allow_but_log'
            }
        }
        
        logger.info(f"Boundary value simulator initialized for {target_host}:{target_port}")
        
    def simulate_boundary_brute_force(self, scenario_name):
        """Simulate boundary brute force scenario"""
        scenario = self.boundary_scenarios[scenario_name]
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_test_ip()
        
        for i in range(scenario['attempts']):
            # Create failed login attempt
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': scenario.get('username', 'admin'),
                'password': scenario.get('password', f'wrong_pass_{i}'),
                'session': f'bva_{scenario_name}_{i:02d}',
                'message': f'Failed login attempt {i+1}/{scenario["attempts"]}'
            }
            
            self.write_log_entry(log_entry)
            logger.info(f"  Attempt {i+1}/{scenario['attempts']}: {scenario.get('username', 'admin')}")
            
            # Wait according to scenario delay
            time.sleep(scenario['delay'])
            
        logger.info(f"  Expected result: {scenario['expected']}")
        
    def simulate_boundary_timing(self):
        """Simulate boundary timing scenarios"""
        logger.info("Testing: Timing Boundary Scenarios")
        
        timing_scenarios = [
            {'delay': 0.6, 'description': 'Just above suspicious threshold'},
            {'delay': 0.9, 'description': 'Near legitimate minimum'},
            {'delay': 4.8, 'description': 'Near legitimate maximum'},
            {'delay': 5.2, 'description': 'Just above legitimate maximum'}
        ]
        
        for scenario in timing_scenarios:
            src_ip = self.get_test_ip()
            
            for i in range(3):  # 3 attempts per scenario
                log_entry = {
                    'eventid': 'cowrie.login.failed',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'username': f'user_{i}',
                    'password': f'pass_{i}',
                    'session': f'timing_bva_{i:02d}',
                    'message': f'Timing test: {scenario["description"]}'
                }
                
                self.write_log_entry(log_entry)
                time.sleep(scenario['delay'])
                
            logger.info(f"  Timing scenario: {scenario['description']} ({scenario['delay']}s delay)")
            
    def simulate_boundary_credentials(self):
        """Simulate boundary credential scenarios"""
        logger.info("Testing: Credential Boundary Scenarios")
        
        credential_scenarios = [
            {'username': 'admin1', 'password': 'admin123', 'description': 'Similar to admin'},
            {'username': 'root_user', 'password': 'root123', 'description': 'Similar to root'},
            {'username': 'test_user', 'password': 'test123', 'description': 'Similar to test'},
            {'username': 'guest_user', 'password': 'guest123', 'description': 'Similar to guest'}
        ]
        
        for scenario in credential_scenarios:
            src_ip = self.get_test_ip()
            
            for i in range(2):  # 2 attempts per scenario
                log_entry = {
                    'eventid': 'cowrie.login.failed',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'username': scenario['username'],
                    'password': scenario['password'],
                    'session': f'cred_bva_{i:02d}',
                    'message': f'Credential test: {scenario["description"]}'
                }
                
                self.write_log_entry(log_entry)
                time.sleep(2.0)  # Normal delay
                
            logger.info(f"  Credential scenario: {scenario['description']}")
            
    def simulate_boundary_network(self):
        """Simulate boundary network scenarios"""
        logger.info("Testing: Network Boundary Scenarios")
        
        network_scenarios = [
            {'ip': '192.168.1.254', 'description': 'Edge of local network'},
            {'ip': '10.0.0.1', 'description': 'Edge of private network A'},
            {'ip': '172.16.0.1', 'description': 'Edge of private network B'},
            {'ip': '192.168.2.1', 'description': 'Outside whitelist'}
        ]
        
        for scenario in network_scenarios:
            for i in range(2):  # 2 attempts per scenario
                log_entry = {
                    'eventid': 'cowrie.login.failed',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': scenario['ip'],
                    'username': 'test_user',
                    'password': 'test_pass',
                    'session': f'net_bva_{i:02d}',
                    'message': f'Network test: {scenario["description"]}'
                }
                
                self.write_log_entry(log_entry)
                time.sleep(2.5)  # Normal delay
                
            logger.info(f"  Network scenario: {scenario['description']} ({scenario['ip']})")
            
    def simulate_boundary_session(self):
        """Simulate boundary session scenarios"""
        logger.info("Testing: Session Boundary Scenarios")
        
        session_scenarios = [
            {'duration': 25, 'description': 'Short session'},
            {'duration': 295, 'description': 'Long session'},
            {'commands': 2, 'description': 'Few commands'},
            {'commands': 8, 'description': 'Many commands'}
        ]
        
        for scenario in session_scenarios:
            src_ip = self.get_test_ip()
            session_id = f'session_bva_{random.randint(1000, 9999)}'
            
            # Session start
            start_log = {
                'eventid': 'cowrie.session.connect',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'session': session_id,
                'message': f'Session start: {scenario["description"]}'
            }
            self.write_log_entry(start_log)
            
            # Commands
            commands = ['ls', 'pwd', 'whoami', 'date', 'uptime', 'ps', 'netstat', 'df']
            num_commands = scenario.get('commands', 3)
            
            for i in range(num_commands):
                command_log = {
                    'eventid': 'cowrie.command.input',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'session': session_id,
                    'input': commands[i],
                    'message': f'Command {i+1}/{num_commands}'
                }
                self.write_log_entry(command_log)
                time.sleep(1.0)
                
            # Session end
            end_log = {
                'eventid': 'cowrie.session.closed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'session': session_id,
                'duration': scenario.get('duration', 60),
                'message': f'Session end: {scenario["description"]}'
            }
            self.write_log_entry(end_log)
            
            logger.info(f"  Session scenario: {scenario['description']}")
            
    def get_test_ip(self):
        """Get a test IP address"""
        test_ips = [
            '192.168.1.200',
            '10.0.0.100',
            '172.16.0.50',
            '203.0.113.10'
        ]
        return random.choice(test_ips)
        
    def write_log_entry(self, log_entry):
        """Write log entry to Cowrie log file"""
        try:
            # Ensure logs directory exists
            Path('honeypot/logs').mkdir(parents=True, exist_ok=True)
            
            # Write to Cowrie-style JSON log
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
                logger.info(f"  - Alerts: {status.get('stats', {}).get('alerts', 0)}")
                return status
            else:
                logger.error(f"Failed to get status: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return None
            
    def run_boundary_value_test(self):
        """Run comprehensive boundary value analysis test"""
        logger.info("=" * 60)
        logger.info("🧪 TC2: Boundary Value Analysis Testing")
        logger.info("=" * 60)
        
        # Test API connectivity first
        if not self.test_api_connectivity():
            logger.error("Cannot connect to API. Make sure the honeynet system is running.")
            return
            
        # Get initial status
        logger.info("Initial system status:")
        initial_status = self.get_system_status()
        
        # Run boundary value tests
        logger.info("\n--- Boundary Value Test Scenarios ---")
        
        # Test brute force boundaries
        self.simulate_boundary_brute_force('brute_force_threshold')
        time.sleep(3)
        
        # Test timing boundaries
        self.simulate_boundary_timing()
        time.sleep(3)
        
        # Test credential boundaries
        self.simulate_boundary_credentials()
        time.sleep(3)
        
        # Test network boundaries
        self.simulate_boundary_network()
        time.sleep(3)
        
        # Test session boundaries
        self.simulate_boundary_session()
        time.sleep(3)
        
        # Get final status
        logger.info("\nFinal system status:")
        final_status = self.get_system_status()
        
        # Analyze results
        if initial_status and final_status:
            initial_blocked = initial_status.get('stats', {}).get('blocked_ips', 0)
            final_blocked = final_status.get('stats', {}).get('blocked_ips', 0)
            alerts_generated = final_status.get('stats', {}).get('alerts', 0)
            
            logger.info("\n--- Boundary Value Analysis Results ---")
            logger.info(f"Initial blocked IPs: {initial_blocked}")
            logger.info(f"Final blocked IPs: {final_blocked}")
            logger.info(f"Alerts generated: {alerts_generated}")
            
            if final_blocked == initial_blocked:
                logger.info("✅ SUCCESS: No false positives in boundary tests!")
                logger.info("✅ System correctly handled boundary conditions")
            else:
                logger.warning("⚠️  WARNING: Potential false positives in boundary tests!")
                logger.warning(f"   Blocked IPs increased from {initial_blocked} to {final_blocked}")
                
            if alerts_generated > 0:
                logger.info("✅ SUCCESS: System generated appropriate alerts for boundary conditions")
            else:
                logger.info("ℹ️  INFO: No alerts generated (may be expected for boundary tests)")
                
        logger.info("\n✅ Boundary value analysis testing completed!")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='TC2: Boundary Value Analysis Simulator')
    parser.add_argument('--target', default='localhost', help='Target host (default: localhost)')
    parser.add_argument('--port', type=int, default=22, help='Target port (default: 22)')
    parser.add_argument('--api-url', default='http://localhost:8000', help='API URL (default: http://localhost:8000)')
    parser.add_argument('--scenario', choices=['all', 'brute_force', 'timing', 'credentials', 'network', 'session'], 
                       default='all', help='Specific scenario to test (default: all)')
    parser.add_argument('--delay', type=float, default=2.0, help='Delay between scenarios (default: 2.0s)')
    
    args = parser.parse_args()
    
    # Create simulator
    simulator = BoundaryValueSimulator(args.target, args.port, args.api_url)
    
    # Run test
    simulator.run_boundary_value_test()
    
    logger.info("Boundary value analysis simulation completed!")

if __name__ == "__main__":
    main() 
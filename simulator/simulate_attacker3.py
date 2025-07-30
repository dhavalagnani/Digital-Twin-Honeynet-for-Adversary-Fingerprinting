#!/usr/bin/env python3
"""
Digital Twin Honeynet - Attack Simulator 3
TC3: Timing Anomaly Testing (Anomalous Timing Patterns)
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

class TimingAnomalySimulator:
    """Simulates timing anomalies for testing"""
    
    def __init__(self, target_host='localhost', target_port=22, api_url='http://localhost:8000'):
        self.target_host = target_host
        self.target_port = target_port
        self.api_url = api_url
        
        # Timing anomaly scenarios
        self.timing_scenarios = {
            'rapid_fire': {
                'name': 'Rapid Fire Attacks',
                'delay': 0.1,
                'burst_size': 5,
                'description': 'Very fast consecutive attempts'
            },
            'burst_attacks': {
                'name': 'Burst Attack Pattern',
                'delay': 0.3,
                'burst_size': 3,
                'burst_count': 4,
                'burst_interval': 10,
                'description': 'Bursts of rapid attempts with pauses'
            },
            'irregular_timing': {
                'name': 'Irregular Timing Pattern',
                'delays': [0.1, 2.5, 0.2, 3.0, 0.1, 1.8],
                'description': 'Irregular timing between attempts'
            },
            'slow_then_fast': {
                'name': 'Slow Then Fast Pattern',
                'slow_delay': 5.0,
                'fast_delay': 0.1,
                'slow_attempts': 2,
                'fast_attempts': 4,
                'description': 'Slow attempts followed by rapid attempts'
            },
            'oscillating_timing': {
                'name': 'Oscillating Timing',
                'min_delay': 0.2,
                'max_delay': 1.0,
                'oscillations': 6,
                'description': 'Oscillating between fast and slow'
            }
        }
        
        logger.info(f"Timing anomaly simulator initialized for {target_host}:{target_port}")
        
    def simulate_rapid_fire_attack(self):
        """Simulate rapid fire attack pattern"""
        scenario = self.timing_scenarios['rapid_fire']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_test_ip()
        
        for i in range(scenario['burst_size']):
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': f'user_{i}',
                'password': f'pass_{i}',
                'session': f'rapid_fire_{i:02d}',
                'message': f'Rapid fire attempt {i+1}/{scenario["burst_size"]}'
            }
            
            self.write_log_entry(log_entry)
            logger.info(f"  Rapid attempt {i+1}/{scenario['burst_size']} (delay: {scenario['delay']}s)")
            
            time.sleep(scenario['delay'])
            
        logger.info(f"  Expected: Soft alert for timing anomaly")
        
    def simulate_burst_attack_pattern(self):
        """Simulate burst attack pattern"""
        scenario = self.timing_scenarios['burst_attacks']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_test_ip()
        
        for burst in range(scenario['burst_count']):
            logger.info(f"  Burst {burst+1}/{scenario['burst_count']}")
            
            # Rapid attempts in burst
            for i in range(scenario['burst_size']):
                log_entry = {
                    'eventid': 'cowrie.login.failed',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'username': f'burst_user_{burst}_{i}',
                    'password': f'burst_pass_{burst}_{i}',
                    'session': f'burst_{burst}_{i:02d}',
                    'message': f'Burst {burst+1}, attempt {i+1}'
                }
                
                self.write_log_entry(log_entry)
                time.sleep(scenario['delay'])
                
            # Pause between bursts
            if burst < scenario['burst_count'] - 1:
                logger.info(f"  Pausing {scenario['burst_interval']}s between bursts")
                time.sleep(scenario['burst_interval'])
                
        logger.info(f"  Expected: Soft alert for burst pattern")
        
    def simulate_irregular_timing(self):
        """Simulate irregular timing pattern"""
        scenario = self.timing_scenarios['irregular_timing']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_test_ip()
        
        for i, delay in enumerate(scenario['delays']):
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': f'irregular_user_{i}',
                'password': f'irregular_pass_{i}',
                'session': f'irregular_{i:02d}',
                'message': f'Irregular timing attempt {i+1} (delay: {delay}s)'
            }
            
            self.write_log_entry(log_entry)
            logger.info(f"  Attempt {i+1} with {delay}s delay")
            
            time.sleep(delay)
            
        logger.info(f"  Expected: Soft alert for irregular timing")
        
    def simulate_slow_then_fast_pattern(self):
        """Simulate slow then fast pattern"""
        scenario = self.timing_scenarios['slow_then_fast']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_test_ip()
        
        # Slow attempts first
        logger.info(f"  Phase 1: Slow attempts ({scenario['slow_attempts']} attempts, {scenario['slow_delay']}s delay)")
        for i in range(scenario['slow_attempts']):
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': f'slow_user_{i}',
                'password': f'slow_pass_{i}',
                'session': f'slow_{i:02d}',
                'message': f'Slow attempt {i+1}'
            }
            
            self.write_log_entry(log_entry)
            time.sleep(scenario['slow_delay'])
            
        # Fast attempts second
        logger.info(f"  Phase 2: Fast attempts ({scenario['fast_attempts']} attempts, {scenario['fast_delay']}s delay)")
        for i in range(scenario['fast_attempts']):
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': f'fast_user_{i}',
                'password': f'fast_pass_{i}',
                'session': f'fast_{i:02d}',
                'message': f'Fast attempt {i+1}'
            }
            
            self.write_log_entry(log_entry)
            time.sleep(scenario['fast_delay'])
            
        logger.info(f"  Expected: Soft alert for timing pattern change")
        
    def simulate_oscillating_timing(self):
        """Simulate oscillating timing pattern"""
        scenario = self.timing_scenarios['oscillating_timing']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_test_ip()
        
        for i in range(scenario['oscillations']):
            # Oscillate between min and max delay
            if i % 2 == 0:
                delay = scenario['min_delay']
                phase = 'fast'
            else:
                delay = scenario['max_delay']
                phase = 'slow'
                
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': f'oscillate_user_{i}',
                'password': f'oscillate_pass_{i}',
                'session': f'oscillate_{i:02d}',
                'message': f'Oscillating attempt {i+1} ({phase}: {delay}s)'
            }
            
            self.write_log_entry(log_entry)
            logger.info(f"  Attempt {i+1} ({phase} phase, {delay}s delay)")
            
            time.sleep(delay)
            
        logger.info(f"  Expected: Soft alert for oscillating pattern")
        
    def simulate_timing_with_commands(self):
        """Simulate timing anomalies with command execution"""
        logger.info("Testing: Timing Anomalies with Commands")
        
        src_ip = self.get_test_ip()
        session_id = f'timing_cmd_{random.randint(1000, 9999)}'
        
        # Session start
        start_log = {
            'eventid': 'cowrie.session.connect',
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'session': session_id,
            'message': 'Timing anomaly session start'
        }
        self.write_log_entry(start_log)
        
        # Rapid command execution
        commands = ['whoami', 'pwd', 'ls', 'ps', 'netstat']
        for i, command in enumerate(commands):
            command_log = {
                'eventid': 'cowrie.command.input',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'session': session_id,
                'input': command,
                'message': f'Rapid command {i+1}: {command}'
            }
            self.write_log_entry(command_log)
            
            # Very fast command execution
            time.sleep(0.1)
            
        # Session end
        end_log = {
            'eventid': 'cowrie.session.closed',
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'session': session_id,
            'duration': 5,
            'message': 'Timing anomaly session end'
        }
        self.write_log_entry(end_log)
        
        logger.info("  Expected: Soft alert for rapid command execution")
        
    def simulate_mixed_timing_patterns(self):
        """Simulate mixed timing patterns from multiple IPs"""
        logger.info("Testing: Mixed Timing Patterns (Multiple IPs)")
        
        test_ips = [
            '192.168.1.100',
            '10.0.0.50',
            '172.16.0.25',
            '203.0.113.10'
        ]
        
        # Simulate different timing patterns from different IPs
        for i, ip in enumerate(test_ips):
            pattern_type = i % 4  # 4 different patterns
            
            if pattern_type == 0:
                # Rapid fire from this IP
                for j in range(3):
                    log_entry = {
                        'eventid': 'cowrie.login.failed',
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': ip,
                        'username': f'mixed_user_{i}_{j}',
                        'password': f'mixed_pass_{i}_{j}',
                        'session': f'mixed_{i}_{j:02d}',
                        'message': f'Mixed pattern: rapid fire from {ip}'
                    }
                    self.write_log_entry(log_entry)
                    time.sleep(0.2)
                    
            elif pattern_type == 1:
                # Slow attempts from this IP
                for j in range(2):
                    log_entry = {
                        'eventid': 'cowrie.login.failed',
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': ip,
                        'username': f'mixed_user_{i}_{j}',
                        'password': f'mixed_pass_{i}_{j}',
                        'session': f'mixed_{i}_{j:02d}',
                        'message': f'Mixed pattern: slow attempts from {ip}'
                    }
                    self.write_log_entry(log_entry)
                    time.sleep(4.0)
                    
            elif pattern_type == 2:
                # Burst pattern from this IP
                for j in range(4):
                    log_entry = {
                        'eventid': 'cowrie.login.failed',
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': ip,
                        'username': f'mixed_user_{i}_{j}',
                        'password': f'mixed_pass_{i}_{j}',
                        'session': f'mixed_{i}_{j:02d}',
                        'message': f'Mixed pattern: burst from {ip}'
                    }
                    self.write_log_entry(log_entry)
                    time.sleep(0.3)
                    
            else:
                # Irregular pattern from this IP
                delays = [0.1, 2.0, 0.5, 3.0]
                for j, delay in enumerate(delays):
                    log_entry = {
                        'eventid': 'cowrie.login.failed',
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': ip,
                        'username': f'mixed_user_{i}_{j}',
                        'password': f'mixed_pass_{i}_{j}',
                        'session': f'mixed_{i}_{j:02d}',
                        'message': f'Mixed pattern: irregular from {ip}'
                    }
                    self.write_log_entry(log_entry)
                    time.sleep(delay)
                    
            logger.info(f"  Mixed pattern {pattern_type+1} from {ip}")
            
        logger.info("  Expected: Multiple soft alerts for different timing patterns")
        
    def get_test_ip(self):
        """Get a test IP address"""
        test_ips = [
            '192.168.1.200',
            '10.0.0.100',
            '172.16.0.50',
            '203.0.113.10',
            '198.51.100.20'
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
            
    def run_timing_anomaly_test(self):
        """Run comprehensive timing anomaly test"""
        logger.info("=" * 60)
        logger.info("🧪 TC3: Timing Anomaly Testing")
        logger.info("=" * 60)
        
        # Test API connectivity first
        if not self.test_api_connectivity():
            logger.error("Cannot connect to API. Make sure the honeynet system is running.")
            return
            
        # Get initial status
        logger.info("Initial system status:")
        initial_status = self.get_system_status()
        
        # Run timing anomaly tests
        logger.info("\n--- Timing Anomaly Test Scenarios ---")
        
        # Test rapid fire attacks
        self.simulate_rapid_fire_attack()
        time.sleep(5)
        
        # Test burst attack patterns
        self.simulate_burst_attack_pattern()
        time.sleep(5)
        
        # Test irregular timing
        self.simulate_irregular_timing()
        time.sleep(5)
        
        # Test slow then fast pattern
        self.simulate_slow_then_fast_pattern()
        time.sleep(5)
        
        # Test oscillating timing
        self.simulate_oscillating_timing()
        time.sleep(5)
        
        # Test timing with commands
        self.simulate_timing_with_commands()
        time.sleep(5)
        
        # Test mixed timing patterns
        self.simulate_mixed_timing_patterns()
        time.sleep(5)
        
        # Get final status
        logger.info("\nFinal system status:")
        final_status = self.get_system_status()
        
        # Analyze results
        if initial_status and final_status:
            initial_alerts = initial_status.get('stats', {}).get('alerts', 0)
            final_alerts = final_status.get('stats', {}).get('alerts', 0)
            alerts_generated = final_alerts - initial_alerts
            
            logger.info("\n--- Timing Anomaly Analysis Results ---")
            logger.info(f"Initial alerts: {initial_alerts}")
            logger.info(f"Final alerts: {final_alerts}")
            logger.info(f"Alerts generated: {alerts_generated}")
            
            if alerts_generated > 0:
                logger.info("✅ SUCCESS: System detected timing anomalies!")
                logger.info("✅ Soft alerts generated for anomalous timing patterns")
            else:
                logger.warning("⚠️  WARNING: No alerts generated for timing anomalies")
                logger.warning("   System may not be detecting timing-based threats")
                
        logger.info("\n✅ Timing anomaly testing completed!")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='TC3: Timing Anomaly Simulator')
    parser.add_argument('--target', default='localhost', help='Target host (default: localhost)')
    parser.add_argument('--port', type=int, default=22, help='Target port (default: 22)')
    parser.add_argument('--api-url', default='http://localhost:8000', help='API URL (default: http://localhost:8000)')
    parser.add_argument('--scenario', choices=['all', 'rapid_fire', 'burst', 'irregular', 'slow_fast', 'oscillating', 'commands', 'mixed'], 
                       default='all', help='Specific scenario to test (default: all)')
    parser.add_argument('--delay', type=float, default=5.0, help='Delay between scenarios (default: 5.0s)')
    
    args = parser.parse_args()
    
    # Create simulator
    simulator = TimingAnomalySimulator(args.target, args.port, args.api_url)
    
    # Run test
    simulator.run_timing_anomaly_test()
    
    logger.info("Timing anomaly simulation completed!")

if __name__ == "__main__":
    main() 
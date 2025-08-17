#!/usr/bin/env python3
"""
Digital Twin Honeynet - Banner Fetcher
Fetches and stores real server's SSH banner and error patterns for honeypot matching
"""
import socket
import time
import logging
import json
import yaml
from typing import Dict, Any, Optional, List
from pathlib import Path
import paramiko
import threading
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class ServerFingerprint:
    """Server fingerprint data structure"""
    hostname: str
    port: int
    ssh_banner: str
    auth_failure_messages: List[str]
    auth_success_messages: List[str]
    welcome_messages: List[str]
    prompt_styles: List[str]
    error_messages: List[str]
    disconnect_messages: List[str]
    timestamp: str
    connection_delays: List[float]

class BannerFetcher:
    """Fetches SSH banner and response patterns from real servers"""
    
    def __init__(self, config_path: str = "honeypot/banner_config.yaml"):
        """Initialize banner fetcher"""
        self.config_path = config_path
        self.config = self._load_config()
        self.fingerprints = {}
        
    def _load_config(self) -> Dict[str, Any]:
        """Load banner fetcher configuration"""
        default_config = {
            'target_servers': [
                {
                    'hostname': 'production-server',
                    'port': 22,
                    'username': 'admin',
                    'password': 'admin123',
                    'timeout': 10
                }
            ],
            'fetch_settings': {
                'max_attempts': 3,
                'delay_between_attempts': 2,
                'connection_timeout': 10,
                'auth_timeout': 30
            },
            'output': {
                'fingerprint_file': 'honeypot/production_fingerprints.json',
                'config_file': 'honeypot/banner_config.yaml',
                'log_file': 'honeypot/banner_fetch.log'
            }
        }
        
        if Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except Exception as e:
                logger.error(f"Error loading config: {e}")
                return default_config
        else:
            # Create default config file
            self._save_config(default_config)
            return default_config
    
    def _save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def fetch_server_banner(self, hostname: str, port: int = 22, timeout: int = 10) -> Optional[str]:
        """Fetch SSH banner from server using raw socket connection"""
        try:
            logger.info(f"Fetching banner from {hostname}:{port}")
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to server
            start_time = time.time()
            sock.connect((hostname, port))
            connect_time = time.time() - start_time
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            logger.info(f"Banner fetched: {banner} (connect time: {connect_time:.3f}s)")
            return banner
            
        except Exception as e:
            logger.error(f"Error fetching banner from {hostname}:{port}: {e}")
            return None
    
    def test_authentication_messages(self, hostname: str, port: int, username: str, 
                                   password: str, timeout: int = 30) -> Dict[str, List[str]]:
        """Test authentication and collect error messages"""
        messages = {
            'auth_failure_messages': [],
            'auth_success_messages': [],
            'welcome_messages': [],
            'prompt_styles': [],
            'error_messages': [],
            'disconnect_messages': []
        }
        
        try:
            logger.info(f"Testing authentication messages from {hostname}:{port}")
            
            # Test with invalid credentials first
            for invalid_pass in ['wrong_password', 'invalid', 'test123']:
                try:
                    transport = paramiko.Transport((hostname, port))
                    transport.connect(username=username, password=invalid_pass)
                    transport.close()
                except paramiko.AuthenticationException as e:
                    error_msg = str(e)
                    if error_msg not in messages['auth_failure_messages']:
                        messages['auth_failure_messages'].append(error_msg)
                except Exception as e:
                    error_msg = str(e)
                    if error_msg not in messages['error_messages']:
                        messages['error_messages'].append(error_msg)
            
            # Test with valid credentials
            try:
                transport = paramiko.Transport((hostname, port))
                transport.connect(username=username, password=password)
                
                # Get channel for interactive session
                channel = transport.open_session()
                channel.get_pty()
                channel.invoke_shell()
                
                # Wait for welcome message
                time.sleep(1)
                output = channel.recv(1024).decode('utf-8', errors='ignore')
                if output.strip():
                    messages['welcome_messages'].append(output.strip())
                
                # Send a command to get prompt
                channel.send('echo $PS1\n')
                time.sleep(0.5)
                output = channel.recv(1024).decode('utf-8', errors='ignore')
                if output.strip():
                    messages['prompt_styles'].append(output.strip())
                
                # Test command not found
                channel.send('invalid_command\n')
                time.sleep(0.5)
                output = channel.recv(1024).decode('utf-8', errors='ignore')
                if output.strip():
                    messages['error_messages'].append(output.strip())
                
                channel.close()
                transport.close()
                
            except Exception as e:
                error_msg = str(e)
                if error_msg not in messages['error_messages']:
                    messages['error_messages'].append(error_msg)
                    
        except Exception as e:
            logger.error(f"Error testing authentication messages: {e}")
        
        return messages
    
    def measure_connection_delays(self, hostname: str, port: int, num_tests: int = 5) -> List[float]:
        """Measure connection delays to the server"""
        delays = []
        
        for i in range(num_tests):
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((hostname, port))
                connect_time = time.time() - start_time
                delays.append(connect_time)
                sock.close()
                
                # Small delay between tests
                time.sleep(0.5)
                
            except Exception as e:
                logger.warning(f"Connection test {i+1} failed: {e}")
        
        return delays
    
    def fetch_server_fingerprint(self, server_config: Dict[str, Any]) -> Optional[ServerFingerprint]:
        """Fetch complete server fingerprint"""
        hostname = server_config['hostname']
        port = server_config['port']
        username = server_config.get('username', 'admin')
        password = server_config.get('password', 'admin123')
        timeout = server_config.get('timeout', 10)
        
        logger.info(f"Fetching fingerprint from {hostname}:{port}")
        
        # Fetch banner
        banner = self.fetch_server_banner(hostname, port, timeout)
        if not banner:
            logger.error(f"Failed to fetch banner from {hostname}")
            return None
        
        # Test authentication messages
        messages = self.test_authentication_messages(hostname, port, username, password, timeout)
        
        # Measure connection delays
        delays = self.measure_connection_delays(hostname, port)
        
        # Create fingerprint
        fingerprint = ServerFingerprint(
            hostname=hostname,
            port=port,
            ssh_banner=banner,
            auth_failure_messages=messages['auth_failure_messages'],
            auth_success_messages=messages['auth_success_messages'],
            welcome_messages=messages['welcome_messages'],
            prompt_styles=messages['prompt_styles'],
            error_messages=messages['error_messages'],
            disconnect_messages=messages['disconnect_messages'],
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            connection_delays=delays
        )
        
        logger.info(f"Fingerprint collected for {hostname}")
        return fingerprint
    
    def fetch_all_fingerprints(self) -> Dict[str, ServerFingerprint]:
        """Fetch fingerprints from all configured servers"""
        fingerprints = {}
        
        for server_config in self.config['target_servers']:
            hostname = server_config['hostname']
            fingerprint = self.fetch_server_fingerprint(server_config)
            if fingerprint:
                fingerprints[hostname] = fingerprint
        
        return fingerprints
    
    def save_fingerprints(self, fingerprints: Dict[str, ServerFingerprint]) -> None:
        """Save fingerprints to JSON file"""
        output_file = self.config['output']['fingerprint_file']
        
        # Convert to serializable format
        data = {}
        for hostname, fingerprint in fingerprints.items():
            data[hostname] = asdict(fingerprint)
        
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Fingerprints saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving fingerprints: {e}")
    
    def update_cowrie_config(self, fingerprints: Dict[str, ServerFingerprint]) -> None:
        """Update Cowrie configuration with production server fingerprints"""
        if not fingerprints:
            logger.warning("No fingerprints available for config update")
            return
        
        # Use the first fingerprint as primary
        primary_hostname = list(fingerprints.keys())[0]
        primary_fp = fingerprints[primary_hostname]
        
        logger.info(f"Updating Cowrie config with fingerprint from {primary_hostname}")
        
        # Read current Cowrie config
        cowrie_config_path = "honeypot/cowrie.cfg"
        if not Path(cowrie_config_path).exists():
            logger.error(f"Cowrie config file not found: {cowrie_config_path}")
            return
        
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(cowrie_config_path)
            
            # Update SSH version
            if 'ssh' in config:
                config.set('ssh', 'version', primary_fp.ssh_banner)
            
            # Update banner section
            if 'banner' in config:
                config.set('banner', 'production_banner', primary_fp.ssh_banner)
            
            # Update auth messages
            if 'auth_messages' in config and primary_fp.auth_failure_messages:
                config.set('auth_messages', 'auth_failure_msg', 
                          primary_fp.auth_failure_messages[0])
            
            # Update session responses
            if 'session_responses' in config and primary_fp.welcome_messages:
                config.set('session_responses', 'welcome_msg', 
                          primary_fp.welcome_messages[0])
            
            # Update banner timing based on measured delays
            if 'banner_timing' in config and primary_fp.connection_delays:
                avg_delay = sum(primary_fp.connection_delays) / len(primary_fp.connection_delays)
                config.set('banner_timing', 'base_delay', str(avg_delay))
            
            # Write updated config
            with open(cowrie_config_path, 'w') as f:
                config.write(f)
            
            logger.info(f"Cowrie config updated with production server fingerprint")
            
        except Exception as e:
            logger.error(f"Error updating Cowrie config: {e}")
    
    def run_fingerprint_collection(self) -> bool:
        """Run complete fingerprint collection process"""
        logger.info("Starting fingerprint collection process")
        
        try:
            # Fetch all fingerprints
            fingerprints = self.fetch_all_fingerprints()
            
            if not fingerprints:
                logger.error("No fingerprints collected")
                return False
            
            # Save fingerprints
            self.save_fingerprints(fingerprints)
            
            # Update Cowrie config
            self.update_cowrie_config(fingerprints)
            
            logger.info("Fingerprint collection completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error during fingerprint collection: {e}")
            return False

def main():
    """Main function for banner fetcher"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("Digital Twin Honeynet - Banner Fetcher")
    print("=" * 50)
    
    fetcher = BannerFetcher()
    
    # Run fingerprint collection
    success = fetcher.run_fingerprint_collection()
    
    if success:
        print("\n✅ Fingerprint collection completed successfully!")
        print("   Production server fingerprints have been saved and Cowrie config updated.")
    else:
        print("\n❌ Fingerprint collection failed!")
        print("   Please check the logs for details.")
    
    return 0 if success else 1

if __name__ == '__main__':
    exit(main())

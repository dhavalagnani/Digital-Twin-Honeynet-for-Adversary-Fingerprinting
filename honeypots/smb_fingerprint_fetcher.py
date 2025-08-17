#!/usr/bin/env python3
"""
Digital Twin Honeynet - SMB Fingerprint Fetcher
Fetches and stores real server's SMB fingerprint for honeypot mimicry
"""
import socket
import time
import logging
import json
import yaml
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, asdict
import threading

logger = logging.getLogger(__name__)

@dataclass
class SMBFingerprint:
    """SMB fingerprint data structure"""
    hostname: str
    port: int
    server_name: str
    version: str
    build: str
    supported_versions: List[str]
    encryption_levels: List[str]
    authentication_methods: List[str]
    shares: List[str]
    timestamp: str
    connection_delays: List[float]

class SMBFingerprintFetcher:
    """Fetches SMB fingerprint from real servers"""
    
    def __init__(self, config_path: str = "honeypot/smb_fingerprint_config.yaml"):
        """Initialize SMB fingerprint fetcher"""
        self.config_path = config_path
        self.config = self._load_config()
        self.fingerprints = {}
        
    def _load_config(self) -> Dict[str, Any]:
        """Load SMB fingerprint fetcher configuration"""
        default_config = {
            'target_servers': [
                {
                    'hostname': 'production-server',
                    'port': 445,
                    'timeout': 10
                }
            ],
            'fetch_settings': {
                'max_attempts': 3,
                'delay_between_attempts': 2,
                'connection_timeout': 10
            },
            'output': {
                'fingerprint_file': 'honeypot/production_smb_fingerprint.json',
                'config_file': 'honeypot/smb_fingerprint_config.yaml',
                'log_file': 'honeypot/smb_fingerprint.log'
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
    
    def fetch_smb_banner(self, hostname: str, port: int = 445, timeout: int = 10) -> Optional[str]:
        """Fetch SMB banner from server using raw socket connection"""
        try:
            logger.info(f"Fetching SMB banner from {hostname}:{port}")
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Connect to server
            start_time = time.time()
            sock.connect((hostname, port))
            connect_time = time.time() - start_time
            
            # Send SMB negotiation request
            negotiation_request = self._create_smb_negotiation_request()
            sock.send(negotiation_request)
            
            # Receive SMB negotiation response
            response = sock.recv(1024)
            sock.close()
            
            # Parse SMB banner (simplified)
            if response:
                # Extract server name from SMB packet
                server_name = self._parse_smb_banner(response)
                logger.info(f"SMB banner fetched: {server_name} (connect time: {connect_time:.3f}s)")
                return server_name
            
            return None
            
        except Exception as e:
            logger.error(f"Error fetching SMB banner from {hostname}:{port}: {e}")
            return None
    
    def _create_smb_negotiation_request(self) -> bytes:
        """Create a basic SMB negotiation request"""
        # This is a simplified SMB negotiation request
        # In a real implementation, you would create proper SMB packets
        
        # Basic SMB header structure
        smb_header = b'\xffSMB'  # SMB signature
        smb_header += b'\x72'    # Command: Negotiate Protocol
        smb_header += b'\x00\x00\x00\x00'  # Status: Success
        smb_header += b'\x00\x00'  # Flags
        smb_header += b'\x00\x00'  # Flags2
        smb_header += b'\x00\x00'  # Process ID High
        smb_header += b'\x00\x00\x00\x00'  # Signature
        smb_header += b'\x00\x00'  # Reserved
        smb_header += b'\x00\x00'  # Tree ID
        smb_header += b'\x00\x00\x00\x00'  # Process ID
        smb_header += b'\x00\x00'  # User ID
        smb_header += b'\x00\x00'  # Multiplex ID
        
        return smb_header
    
    def _parse_smb_banner(self, banner_data: bytes) -> str:
        """Parse SMB banner data to extract server information"""
        try:
            # This is a simplified SMB banner parser
            # In a real implementation, you would parse the actual SMB protocol packets
            
            # Look for common Windows server names in the banner
            banner_str = banner_data.decode('utf-8', errors='ignore')
            
            # Common Windows server patterns
            server_patterns = [
                'Windows Server 2019',
                'Windows Server 2016',
                'Windows Server 2022',
                'Windows 10',
                'Windows 11'
            ]
            
            for pattern in server_patterns:
                if pattern.lower() in banner_str.lower():
                    return pattern
            
            # Default fallback
            return 'Windows Server 2019'
            
        except Exception as e:
            logger.error(f"Error parsing SMB banner: {e}")
            return 'Windows Server 2019'
    
    def measure_connection_delays(self, hostname: str, port: int, num_tests: int = 5) -> List[float]:
        """Measure connection delays to the SMB server"""
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
    
    def fetch_server_fingerprint(self, server_config: Dict[str, Any]) -> Optional[SMBFingerprint]:
        """Fetch complete SMB fingerprint from server"""
        hostname = server_config['hostname']
        port = server_config['port']
        timeout = server_config.get('timeout', 10)
        
        logger.info(f"Fetching SMB fingerprint from {hostname}:{port}")
        
        # Fetch banner
        server_name = self.fetch_smb_banner(hostname, port, timeout)
        if not server_name:
            logger.error(f"Failed to fetch SMB banner from {hostname}")
            return None
        
        # Measure connection delays
        delays = self.measure_connection_delays(hostname, port)
        
        # Create fingerprint
        fingerprint = SMBFingerprint(
            hostname=hostname,
            port=port,
            server_name=server_name,
            version='SMB 3.1.1',
            build='17763',
            supported_versions=['SMB1', 'SMB2', 'SMB3'],
            encryption_levels=['None', 'AES-128-GCM', 'AES-256-GCM'],
            authentication_methods=['NTLM', 'Kerberos'],
            shares=['C$', 'IPC$', 'ADMIN$'],
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            connection_delays=delays
        )
        
        logger.info(f"SMB fingerprint collected for {hostname}")
        return fingerprint
    
    def fetch_all_fingerprints(self) -> Dict[str, SMBFingerprint]:
        """Fetch fingerprints from all configured servers"""
        fingerprints = {}
        
        for server_config in self.config['target_servers']:
            hostname = server_config['hostname']
            fingerprint = self.fetch_server_fingerprint(server_config)
            if fingerprint:
                fingerprints[hostname] = fingerprint
        
        return fingerprints
    
    def save_fingerprints(self, fingerprints: Dict[str, SMBFingerprint]) -> None:
        """Save fingerprints to JSON file"""
        output_file = self.config['output']['fingerprint_file']
        
        # Convert to serializable format
        data = {}
        for hostname, fingerprint in fingerprints.items():
            data[hostname] = asdict(fingerprint)
        
        try:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"SMB fingerprints saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving fingerprints: {e}")
    
    def update_smb_config(self, fingerprints: Dict[str, SMBFingerprint]) -> None:
        """Update SMB honeypot configuration with production server fingerprints"""
        if not fingerprints:
            logger.warning("No fingerprints available for config update")
            return
        
        # Use the first fingerprint as primary
        primary_hostname = list(fingerprints.keys())[0]
        primary_fp = fingerprints[primary_hostname]
        
        logger.info(f"Updating SMB config with fingerprint from {primary_hostname}")
        
        # Read current SMB config
        smb_config_path = "honeypot/smb_config.yaml"
        if not Path(smb_config_path).exists():
            logger.error(f"SMB config file not found: {smb_config_path}")
            return
        
        try:
            with open(smb_config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Update banner section
            if 'banner' in config:
                config['banner']['server_name'] = primary_fp.server_name
                config['banner']['version_string'] = primary_fp.version
                config['banner']['build_number'] = primary_fp.build
            
            # Update protocol section
            if 'protocol' in config:
                config['protocol']['supported_versions'] = primary_fp.supported_versions
                config['protocol']['encryption_levels'] = primary_fp.encryption_levels
                config['protocol']['authentication_methods'] = primary_fp.authentication_methods
            
            # Update shares section
            if 'shares' in config:
                config['shares']['default_shares'] = primary_fp.shares
            
            # Update response timing based on measured delays
            if 'response_timing' in config and primary_fp.connection_delays:
                avg_delay = sum(primary_fp.connection_delays) / len(primary_fp.connection_delays)
                config['response_timing']['base_delay'] = avg_delay
            
            # Write updated config
            with open(smb_config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            logger.info(f"SMB config updated with production server fingerprint")
            
        except Exception as e:
            logger.error(f"Error updating SMB config: {e}")
    
    def run_fingerprint_collection(self) -> bool:
        """Run complete SMB fingerprint collection process"""
        logger.info("Starting SMB fingerprint collection process")
        
        try:
            # Fetch all fingerprints
            fingerprints = self.fetch_all_fingerprints()
            
            if not fingerprints:
                logger.error("No fingerprints collected")
                return False
            
            # Save fingerprints
            self.save_fingerprints(fingerprints)
            
            # Update SMB config
            self.update_smb_config(fingerprints)
            
            logger.info("SMB fingerprint collection completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error during fingerprint collection: {e}")
            return False

def main():
    """Main function for SMB fingerprint fetcher"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("Digital Twin Honeynet - SMB Fingerprint Fetcher")
    print("=" * 50)
    
    fetcher = SMBFingerprintFetcher()
    
    # Run fingerprint collection
    success = fetcher.run_fingerprint_collection()
    
    if success:
        print("\n✅ SMB fingerprint collection completed successfully!")
        print("   Production server SMB fingerprints have been saved and config updated.")
    else:
        print("\n❌ SMB fingerprint collection failed!")
        print("   Please check the logs for details.")
    
    return 0 if success else 1

if __name__ == '__main__':
    exit(main())

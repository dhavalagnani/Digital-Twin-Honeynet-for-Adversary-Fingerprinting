#!/usr/bin/env python3
"""
Digital Twin Honeynet - RDP Honeypot
Minimal RDP service emulation using RDPY for capturing scans and handshake attempts
"""
import json
import time
import logging
import threading
import random
import socket
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import configparser
import yaml

# RDPY imports
try:
    from rdpy.core import rss
    from rdpy.core import rdp
    from rdpy.protocol import rdp as rdp_protocol
    from rdpy.core import log
    RDPY_AVAILABLE = True
except ImportError:
    RDPY_AVAILABLE = False
    print("Warning: RDPY not available. Install with: pip install rdpy")

logger = logging.getLogger(__name__)

@dataclass
class RDPRequest:
    """RDP request data structure for logging"""
    timestamp: str
    client_ip: str
    client_port: int
    protocol_version: str
    requested_features: List[str]
    client_info: Dict[str, Any]
    request_id: str

@dataclass
class RDPResponse:
    """RDP response data structure for logging"""
    timestamp: str
    server_version: str
    supported_features: List[str]
    response_time: float
    request_id: str

class RDPHoneypot:
    """Minimal RDP honeypot for capturing handshake attempts and scans"""
    
    def __init__(self, config_path: str = "honeypot/rdp_config.yaml"):
        """Initialize RDP honeypot with configuration"""
        self.config_path = config_path
        self.config = self._load_config()
        self.request_counter = 0
        self._lock = threading.Lock()
        
        # Setup logging
        self._setup_logging()
        
        # Load production server fingerprint
        self.production_fingerprint = self._load_production_fingerprint()
        
        logger.info("RDP honeypot initialized successfully")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load RDP honeypot configuration"""
        default_config = {
            'server': {
                'host': '0.0.0.0',
                'port': 3389,
                'max_connections': 50,
                'timeout': 30
            },
            'production_server': {
                'host': 'production-server',
                'port': 3389,
                'version': 'RDP 8.1',
                'build': '17763'
            },
            'banner': {
                'server_name': 'Windows Server 2019',
                'version_string': 'RDP 8.1',
                'build_number': '17763',
                'randomization_enabled': False,
                'alternative_banners': [
                    'Windows Server 2016',
                    'Windows Server 2022',
                    'Windows 10 Pro'
                ]
            },
            'protocol': {
                'supported_protocols': ['RDP', 'SSL/TLS'],
                'encryption_levels': ['Low', 'Medium', 'High'],
                'authentication_methods': ['NTLM', 'Kerberos'],
                'credssp_enabled': True
            },
            'response_timing': {
                'enabled': True,
                'base_delay': 0.1,
                'jitter_range': 0.05,
                'min_delay': 0.05,
                'max_delay': 0.3
            },
            'logging': {
                'enabled': True,
                'log_file': 'honeypot/rdp_honeypot.log',
                'json_log_file': 'honeypot/rdp_honeypot.json',
                'level': 'INFO'
            },
            'security': {
                'max_request_size': 1048576,  # 1MB
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_minute': 100,
                    'burst_size': 20
                }
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
    
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        log_config = self.config['logging']
        if log_config['enabled']:
            logging.basicConfig(
                level=getattr(logging, log_config['level']),
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_config['log_file']),
                    logging.StreamHandler()
                ]
            )
    
    def _load_production_fingerprint(self) -> Dict[str, Any]:
        """Load production server RDP fingerprint"""
        fingerprint_file = "honeypot/production_rdp_fingerprint.json"
        if Path(fingerprint_file).exists():
            try:
                with open(fingerprint_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading RDP fingerprint: {e}")
        
        # Return default fingerprint
        return {
            'server_name': 'Windows Server 2019',
            'version': 'RDP 8.1',
            'build': '17763',
            'supported_protocols': ['RDP', 'SSL/TLS'],
            'encryption_levels': ['Low', 'Medium', 'High'],
            'authentication_methods': ['NTLM', 'Kerberos']
        }
    
    def _get_response_delay(self, request_id: str) -> float:
        """Calculate randomized response delay"""
        timing_config = self.config['response_timing']
        if not timing_config['enabled']:
            return 0.0
        
        # Use request ID for consistent delay per request
        random.seed(hash(request_id))
        
        base_delay = timing_config['base_delay']
        jitter = random.uniform(-timing_config['jitter_range'], timing_config['jitter_range'])
        delay = base_delay + jitter
        
        # Clamp to min/max bounds
        delay = max(timing_config['min_delay'], min(timing_config['max_delay'], delay))
        
        return delay
    
    def _log_request(self, client_ip: str, client_port: int, protocol_version: str, 
                    requested_features: List[str], client_info: Dict[str, Any]) -> str:
        """Log incoming RDP request"""
        with self._lock:
            self.request_counter += 1
            request_id = f"rdp_{self.request_counter}_{int(time.time())}"
        
        # Extract request data
        rdp_request = RDPRequest(
            timestamp=datetime.now().isoformat(),
            client_ip=client_ip,
            client_port=client_port,
            protocol_version=protocol_version,
            requested_features=requested_features,
            client_info=client_info,
            request_id=request_id
        )
        
        # Log to JSON file
        self._log_to_json('rdp_request', asdict(rdp_request))
        
        logger.info(f"RDP Request: {protocol_version} from {client_ip}:{client_port}")
        return request_id
    
    def _log_response(self, request_id: str, server_version: str, 
                     supported_features: List[str], response_time: float) -> None:
        """Log outgoing RDP response"""
        # Extract response data
        rdp_response = RDPResponse(
            timestamp=datetime.now().isoformat(),
            server_version=server_version,
            supported_features=supported_features,
            response_time=response_time,
            request_id=request_id
        )
        
        # Log to JSON file
        self._log_to_json('rdp_response', asdict(rdp_response))
        
        logger.info(f"RDP Response: {server_version} for {request_id}")
    
    def _log_to_json(self, event_type: str, data: Dict[str, Any]) -> None:
        """Log event to JSON file"""
        log_config = self.config['logging']
        if not log_config['enabled']:
            return
        
        json_log_file = log_config['json_log_file']
        log_entry = {
            'event_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        
        try:
            with open(json_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Error writing to JSON log: {e}")
    
    def _get_server_banner(self) -> str:
        """Get server banner (production or randomized)"""
        banner_config = self.config['banner']
        
        if not banner_config['randomization_enabled']:
            return banner_config['server_name']
        
        # Return random banner from alternatives
        alternatives = banner_config['alternative_banners']
        if alternatives:
            return random.choice(alternatives)
        
        return banner_config['server_name']
    
    def _handle_rdp_connection(self, client_socket: socket.socket, client_address: Tuple[str, int]) -> None:
        """Handle individual RDP connection"""
        client_ip, client_port = client_address
        start_time = time.time()
        
        try:
            # Log connection attempt
            request_id = self._log_request(
                client_ip=client_ip,
                client_port=client_port,
                protocol_version="RDP",
                requested_features=["Connection Request"],
                client_info={"address": f"{client_ip}:{client_port}"}
            )
            
            # Apply response delay
            delay = self._get_response_delay(request_id)
            if delay > 0:
                time.sleep(delay)
            
            # Send RDP connection response
            server_banner = self._get_server_banner()
            response_data = self._generate_rdp_response(server_banner)
            
            # Send response
            client_socket.send(response_data)
            
            # Log response
            response_time = time.time() - start_time
            self._log_response(
                request_id=request_id,
                server_version=server_banner,
                supported_features=self.config['protocol']['supported_protocols'],
                response_time=response_time
            )
            
            # Close connection after brief delay
            time.sleep(0.1)
            
        except Exception as e:
            logger.error(f"Error handling RDP connection from {client_ip}:{client_port}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _generate_rdp_response(self, server_banner: str) -> bytes:
        """Generate RDP protocol response"""
        # This is a simplified RDP response
        # In a real implementation, you would use RDPY to generate proper RDP packets
        
        response = {
            'protocol': 'RDP',
            'version': '8.1',
            'server_name': server_banner,
            'build': self.config['banner']['build_number'],
            'supported_features': self.config['protocol']['supported_protocols'],
            'encryption_levels': self.config['protocol']['encryption_levels'],
            'authentication_methods': self.config['protocol']['authentication_methods']
        }
        
        # Convert to bytes (simplified)
        response_str = json.dumps(response)
        return response_str.encode('utf-8')
    
    def run(self, host: str = None, port: int = None):
        """Run the RDP honeypot"""
        server_config = self.config['server']
        
        host = host or server_config['host']
        port = port or server_config['port']
        
        logger.info(f"Starting RDP honeypot on {host}:{port}")
        
        try:
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen(server_config['max_connections'])
            
            logger.info(f"RDP honeypot listening on {host}:{port}")
            
            while True:
                try:
                    client_socket, client_address = server_socket.accept()
                    
                    # Handle connection in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_rdp_connection,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    logger.info("RDP honeypot shutting down...")
                    break
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
            
        except Exception as e:
            logger.error(f"Error starting RDP honeypot: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass

def main():
    """Main function for RDP honeypot"""
    if not RDPY_AVAILABLE:
        print("RDPY not available. Install with: pip install rdpy")
        print("Running in simulation mode...")
    
    logging.basicConfig(level=logging.INFO)
    
    print("Digital Twin Honeynet - RDP Honeypot")
    print("=" * 40)
    
    honeypot = RDPHoneypot()
    honeypot.run()

if __name__ == '__main__':
    main()

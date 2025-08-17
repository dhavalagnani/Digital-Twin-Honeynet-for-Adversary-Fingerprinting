#!/usr/bin/env python3
"""
Digital Twin Honeynet - Firewall Manager
Integrates with nftables and ipset for IP blocking and traffic management
"""

import subprocess
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import ipaddress

logger = logging.getLogger(__name__)

class FirewallManager:
    """Manages firewall rules using nftables and ipset"""
    
    def __init__(self):
        # Configuration
        self.table_name = 'honeynet'
        self.chain_name = 'blocked_ips'
        self.set_name = 'blocked_ips'
        
        # Statistics
        self.stats = {
            'total_blocked_ips': 0,
            'active_blocks': 0,
            'rules_created': 0,
            'rules_removed': 0,
            'last_cleanup': None
        }
        
        # Track blocked IPs
        self.blocked_ips = {}  # ip -> {timestamp, reason, rule_handle}
        
        # Configuration file
        self.config_file = Path('firewall/firewall_config.json')
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Log file
        self.log_file = Path('logs/firewall_actions.log')
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info("Firewall manager initialized")
        
    def initialize(self):
        """Initialize firewall tables and sets"""
        try:
            # Check if nftables is available
            if not self.check_nftables():
                logger.error("nftables not available")
                return False
                
            # Create honeynet table
            self.create_table()
            
            # Create blocked IPs chain
            self.create_chain()
            
            # Create ipset for blocked IPs
            self.create_ipset()
            
            # Load existing configuration
            self.load_configuration()
            
            logger.info("Firewall initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing firewall: {e}")
            return False
            
    def check_nftables(self) -> bool:
        """Check if nftables is available"""
        try:
            result = subprocess.run(['nft', '--version'], 
                                  capture_output=True, text=True, check=True)
            logger.info(f"nftables version: {result.stdout.strip()}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("nftables not found or not working")
            return False
            
    def create_table(self):
        """Create honeynet table if it doesn't exist"""
        try:
            # Check if table exists
            result = subprocess.run(
                ['nft', 'list', 'tables', 'ip', self.table_name],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                # Create table
                subprocess.run(['nft', 'add', 'table', 'ip', self.table_name], check=True)
                logger.info(f"Created nftables table: {self.table_name}")
            else:
                logger.info(f"Table {self.table_name} already exists")
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Error creating table: {e}")
            raise
            
    def create_chain(self):
        """Create blocked IPs chain if it doesn't exist"""
        try:
            # Check if chain exists
            result = subprocess.run(
                ['nft', 'list', 'chain', 'ip', self.table_name, self.chain_name],
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                # Create chain
                subprocess.run([
                    'nft', 'add', 'chain', 'ip', self.table_name, self.chain_name
                ], check=True)
                
                # Add default policy (return)
                subprocess.run([
                    'nft', 'add', 'rule', 'ip', self.table_name, self.chain_name, 'counter', 'return'
                ], check=True)
                
                logger.info(f"Created chain: {self.chain_name}")
            else:
                logger.info(f"Chain {self.chain_name} already exists")
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Error creating chain: {e}")
            raise
            
    def create_ipset(self):
        """Create ipset for blocked IPs"""
        try:
            # Check if ipset is available
            result = subprocess.run(['ipset', '--version'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                # Create ipset if it doesn't exist
                result = subprocess.run(
                    ['ipset', 'list', self.set_name],
                    capture_output=True, text=True
                )
                
                if result.returncode != 0:
                    # Create ipset
                    subprocess.run([
                        'ipset', 'create', self.set_name, 'hash:ip', 'timeout', '3600'
                    ], check=True)
                    logger.info(f"Created ipset: {self.set_name}")
                else:
                    logger.info(f"ipset {self.set_name} already exists")
            else:
                logger.warning("ipset not available, using nftables only")
                
        except subprocess.CalledProcessError as e:
            logger.warning(f"Error creating ipset: {e}")
            
    def block_ip(self, ip_address: str, reason: str = "Security threat") -> bool:
        """Block an IP address"""
        try:
            # Validate IP address
            if not self.is_valid_ip(ip_address):
                logger.error(f"Invalid IP address: {ip_address}")
                return False
                
            # Check if already blocked
            if ip_address in self.blocked_ips:
                logger.info(f"IP {ip_address} already blocked")
                return True
                
            # Add to ipset (if available)
            if self.add_to_ipset(ip_address):
                logger.info(f"Added {ip_address} to ipset")
                
            # Create nftables rule
            rule_handle = self.create_block_rule(ip_address, reason)
            
            if rule_handle:
                # Track blocked IP
                self.blocked_ips[ip_address] = {
                    'timestamp': datetime.now().isoformat(),
                    'reason': reason,
                    'rule_handle': rule_handle
                }
                
                # Update statistics
                self.stats['total_blocked_ips'] += 1
                self.stats['active_blocks'] += 1
                self.stats['rules_created'] += 1
                
                # Log action
                self.log_action('block', ip_address, reason)
                
                logger.info(f"Successfully blocked IP {ip_address}: {reason}")
                return True
            else:
                logger.error(f"Failed to create block rule for {ip_address}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
            
    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        try:
            # Validate IP address
            if not self.is_valid_ip(ip_address):
                logger.error(f"Invalid IP address: {ip_address}")
                return False
                
            # Check if IP is blocked
            if ip_address not in self.blocked_ips:
                logger.info(f"IP {ip_address} is not blocked")
                return True
                
            # Remove from ipset
            self.remove_from_ipset(ip_address)
            
            # Remove nftables rule
            rule_handle = self.blocked_ips[ip_address]['rule_handle']
            success = self.remove_block_rule(rule_handle)
            
            if success:
                # Remove from tracking
                del self.blocked_ips[ip_address]
                
                # Update statistics
                self.stats['active_blocks'] -= 1
                self.stats['rules_removed'] += 1
                
                # Log action
                self.log_action('unblock', ip_address, 'Manual unblock')
                
                logger.info(f"Successfully unblocked IP {ip_address}")
                return True
            else:
                logger.error(f"Failed to remove block rule for {ip_address}")
                return False
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
            
    def add_to_ipset(self, ip_address: str) -> bool:
        """Add IP to ipset"""
        try:
            subprocess.run([
                'ipset', 'add', self.set_name, ip_address
            ], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
            
    def remove_from_ipset(self, ip_address: str) -> bool:
        """Remove IP from ipset"""
        try:
            subprocess.run([
                'ipset', 'del', self.set_name, ip_address
            ], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
            
    def create_block_rule(self, ip_address: str, reason: str) -> Optional[str]:
        """Create nftables block rule"""
        try:
            # Create rule with comment
            comment = f"Blocked by honeynet: {reason}"
            
            result = subprocess.run([
                'nft', 'add', 'rule', 'ip', self.table_name, self.chain_name,
                'ip', 'saddr', ip_address, 'counter', 'drop', 'comment', comment
            ], capture_output=True, text=True, check=True)
            
            # Extract rule handle
            rule_handle = self.extract_rule_handle(ip_address)
            return rule_handle
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error creating block rule: {e}")
            return None
            
    def remove_block_rule(self, rule_handle: str) -> bool:
        """Remove nftables block rule"""
        try:
            subprocess.run([
                'nft', 'delete', 'rule', 'ip', self.table_name, self.chain_name,
                'handle', rule_handle
            ], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Error removing block rule: {e}")
            return False
            
    def extract_rule_handle(self, ip_address: str) -> Optional[str]:
        """Extract rule handle for an IP address"""
        try:
            result = subprocess.run([
                'nft', 'list', 'ruleset'
            ], capture_output=True, text=True, check=True)
            
            # Parse rules to find handle
            lines = result.stdout.split('\n')
            for line in lines:
                if f'ip saddr {ip_address}' in line and 'drop' in line:
                    # Extract handle
                    if 'handle' in line:
                        handle_match = line.split('handle')[1].split()[0]
                        return handle_match
                        
            return None
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error extracting rule handle: {e}")
            return None
            
    def is_valid_ip(self, ip_address: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
            
    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IP addresses"""
        return list(self.blocked_ips.keys())
        
    def get_block_info(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get information about a blocked IP"""
        return self.blocked_ips.get(ip_address)
        
    def cleanup_expired_blocks(self, max_age_hours: int = 24):
        """Clean up expired IP blocks"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            expired_ips = []
            
            for ip_address, info in self.blocked_ips.items():
                block_time = datetime.fromisoformat(info['timestamp'])
                if block_time < cutoff_time:
                    expired_ips.append(ip_address)
                    
            for ip_address in expired_ips:
                self.unblock_ip(ip_address)
                logger.info(f"Cleaned up expired block for {ip_address}")
                
            self.stats['last_cleanup'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"Error cleaning up expired blocks: {e}")
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get firewall statistics"""
        return {
            'firewall_stats': self.stats.copy(),
            'blocked_ips_count': len(self.blocked_ips),
            'blocked_ips_list': list(self.blocked_ips.keys()),
            'table_name': self.table_name,
            'chain_name': self.chain_name,
            'set_name': self.set_name
        }
        
    def log_action(self, action: str, ip_address: str, reason: str):
        """Log firewall action"""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'ip_address': ip_address,
                'reason': reason,
                'source': 'firewall_manager'
            }
            
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Error logging action: {e}")
            
    def save_configuration(self):
        """Save current configuration to file"""
        try:
            config = {
                'blocked_ips': self.blocked_ips,
                'stats': self.stats,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
                
            logger.info("Configuration saved")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            
    def load_configuration(self):
        """Load configuration from file"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    
                # Restore blocked IPs
                for ip_address, info in config.get('blocked_ips', {}).items():
                    if self.is_valid_ip(ip_address):
                        # Recreate block rule
                        rule_handle = self.create_block_rule(ip_address, info['reason'])
                        if rule_handle:
                            self.blocked_ips[ip_address] = {
                                'timestamp': info['timestamp'],
                                'reason': info['reason'],
                                'rule_handle': rule_handle
                            }
                            
                # Restore statistics
                self.stats.update(config.get('stats', {}))
                
                logger.info("Configuration loaded")
                
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            
    def get_rules_summary(self) -> Dict[str, Any]:
        """Get summary of current firewall rules"""
        try:
            result = subprocess.run([
                'nft', 'list', 'ruleset'
            ], capture_output=True, text=True, check=True)
            
            # Parse rules
            rules = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'ip saddr' in line and 'drop' in line:
                    # Extract IP and comment
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'saddr':
                            ip = parts[i + 1]
                            break
                    else:
                        ip = 'unknown'
                        
                    comment = 'No comment'
                    if 'comment' in line:
                        comment_start = line.find('comment') + 8
                        comment = line[comment_start:].strip('"')
                        
                    rules.append({
                        'ip': ip,
                        'action': 'drop',
                        'comment': comment
                    })
                    
            return {
                'total_rules': len(rules),
                'rules': rules
            }
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting rules summary: {e}")
            return {'total_rules': 0, 'rules': []}
            
    def test_connectivity(self) -> bool:
        """Test firewall connectivity and functionality"""
        try:
            # Test nftables
            result = subprocess.run(['nft', 'list', 'tables'], 
                                  capture_output=True, text=True, check=True)
            
            # Test ipset (if available)
            try:
                result = subprocess.run(['ipset', 'list'], 
                                      capture_output=True, text=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.warning("ipset not available for testing")
                
            logger.info("Firewall connectivity test passed")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Firewall connectivity test failed: {e}")
            return False 
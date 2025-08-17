#!/usr/bin/env python3
"""
Honeynet Log Parser and Visualizer
Parses honeypot logs and provides attack summaries and statistics.
"""

import os
import re
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LogParser:
    def __init__(self, log_dir: str = "/var/log/honeynet"):
        self.log_dir = log_dir
        self.attack_data = defaultdict(list)
        self.stats = defaultdict(int)
        
    def parse_cowrie_log(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse Cowrie SSH honeypot logs"""
        attacks = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        # Parse JSON log entries
                        if line.strip().startswith('{'):
                            data = json.loads(line.strip())
                            
                            attack = {
                                'timestamp': data.get('timestamp', ''),
                                'src_ip': data.get('src_ip', ''),
                                'dst_service': 'ssh',
                                'attack_type': 'ssh_connection',
                                'payload': data.get('message', ''),
                                'user_agent': data.get('session', ''),
                                'port': 2222
                            }
                            
                            # Determine attack type based on message
                            message = data.get('message', '').lower()
                            if 'login attempt' in message:
                                attack['attack_type'] = 'ssh_brute_force'
                            elif 'command' in message:
                                attack['attack_type'] = 'ssh_command_execution'
                            elif 'download' in message:
                                attack['attack_type'] = 'ssh_file_download'
                            
                            attacks.append(attack)
                            
                    except json.JSONDecodeError:
                        # Skip non-JSON lines
                        continue
                        
        except FileNotFoundError:
            logger.warning(f"Log file not found: {log_file}")
        except Exception as e:
            logger.error(f"Error parsing Cowrie log: {e}")
            
        return attacks
    
    def parse_http_log(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse HTTP honeypot logs"""
        attacks = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Parse nginx access log format
                    match = re.match(r'(\S+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+)', line)
                    if match:
                        src_ip, timestamp, request, status, size = match.groups()
                        
                        # Parse request line
                        req_parts = request.split()
                        if len(req_parts) >= 2:
                            method, path = req_parts[0], req_parts[1]
                            
                            attack = {
                                'timestamp': timestamp,
                                'src_ip': src_ip,
                                'dst_service': 'http',
                                'attack_type': 'http_request',
                                'payload': path,
                                'user_agent': '',
                                'port': 8080,
                                'method': method,
                                'status': int(status)
                            }
                            
                            # Determine attack type based on path and method
                            path_lower = path.lower()
                            if any(pattern in path_lower for pattern in ['admin', 'wp-admin', 'phpmyadmin']):
                                attack['attack_type'] = 'http_directory_traversal'
                            elif any(pattern in path_lower for pattern in ['../', '..\\', '%2e%2e']):
                                attack['attack_type'] = 'http_path_traversal'
                            elif any(pattern in path_lower for pattern in ['union', 'select', 'drop', 'insert']):
                                attack['attack_type'] = 'http_sql_injection'
                            elif any(pattern in path_lower for pattern in ['<script', 'javascript:', 'onerror']):
                                attack['attack_type'] = 'http_xss'
                            
                            attacks.append(attack)
                            
        except FileNotFoundError:
            logger.warning(f"Log file not found: {log_file}")
        except Exception as e:
            logger.error(f"Error parsing HTTP log: {e}")
            
        return attacks
    
    def parse_rdp_log(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse RDP honeypot logs"""
        attacks = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Parse RDP log entries
                    match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\S+) - (.+)', line)
                    if match:
                        timestamp, src_ip, message = match.groups()
                        
                        attack = {
                            'timestamp': timestamp,
                            'src_ip': src_ip,
                            'dst_service': 'rdp',
                            'attack_type': 'rdp_connection',
                            'payload': message,
                            'user_agent': '',
                            'port': 3389
                        }
                        
                        # Determine attack type based on message
                        message_lower = message.lower()
                        if 'login attempt' in message_lower:
                            attack['attack_type'] = 'rdp_brute_force'
                        elif 'authentication failed' in message_lower:
                            attack['attack_type'] = 'rdp_auth_failure'
                        
                        attacks.append(attack)
                        
        except FileNotFoundError:
            logger.warning(f"Log file not found: {log_file}")
        except Exception as e:
            logger.error(f"Error parsing RDP log: {e}")
            
        return attacks
    
    def parse_smb_log(self, log_file: str) -> List[Dict[str, Any]]:
        """Parse SMB honeypot logs"""
        attacks = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Parse SMB log entries
                    match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\S+) - (.+)', line)
                    if match:
                        timestamp, src_ip, message = match.groups()
                        
                        attack = {
                            'timestamp': timestamp,
                            'src_ip': src_ip,
                            'dst_service': 'smb',
                            'attack_type': 'smb_connection',
                            'payload': message,
                            'user_agent': '',
                            'port': 445
                        }
                        
                        # Determine attack type based on message
                        message_lower = message.lower()
                        if 'share enumeration' in message_lower:
                            attack['attack_type'] = 'smb_share_enumeration'
                        elif 'authentication failed' in message_lower:
                            attack['attack_type'] = 'smb_auth_failure'
                        elif 'file access' in message_lower:
                            attack['attack_type'] = 'smb_file_access'
                        
                        attacks.append(attack)
                        
        except FileNotFoundError:
            logger.warning(f"Log file not found: {log_file}")
        except Exception as e:
            logger.error(f"Error parsing SMB log: {e}")
            
        return attacks
    
    def parse_all_logs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Parse all honeypot logs"""
        log_files = {
            'ssh': os.path.join(self.log_dir, 'cowrie.log'),
            'http': os.path.join(self.log_dir, 'http-honeypot.log'),
            'rdp': os.path.join(self.log_dir, 'rdp-honeypot.log'),
            'smb': os.path.join(self.log_dir, 'smb-honeypot.log')
        }
        
        all_attacks = {}
        
        # Parse each log file
        if os.path.exists(log_files['ssh']):
            all_attacks['ssh'] = self.parse_cowrie_log(log_files['ssh'])
            
        if os.path.exists(log_files['http']):
            all_attacks['http'] = self.parse_http_log(log_files['http'])
            
        if os.path.exists(log_files['rdp']):
            all_attacks['rdp'] = self.parse_rdp_log(log_files['rdp'])
            
        if os.path.exists(log_files['smb']):
            all_attacks['smb'] = self.parse_smb_log(log_files['smb'])
        
        return all_attacks
    
    def generate_statistics(self, attacks: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Generate attack statistics"""
        stats = {
            'total_attacks': 0,
            'unique_ips': set(),
            'service_breakdown': defaultdict(int),
            'attack_type_breakdown': defaultdict(int),
            'top_attackers': Counter(),
            'recent_attacks': [],
            'hourly_breakdown': defaultdict(int)
        }
        
        # Process all attacks
        for service, service_attacks in attacks.items():
            for attack in service_attacks:
                stats['total_attacks'] += 1
                stats['unique_ips'].add(attack['src_ip'])
                stats['service_breakdown'][service] += 1
                stats['attack_type_breakdown'][attack['attack_type']] += 1
                stats['top_attackers'][attack['src_ip']] += 1
                
                # Add to recent attacks (last 24 hours)
                try:
                    if 'timestamp' in attack and attack['timestamp']:
                        if isinstance(attack['timestamp'], str):
                            # Parse timestamp
                            if 'T' in attack['timestamp']:
                                # ISO format
                                dt = datetime.fromisoformat(attack['timestamp'].replace('Z', '+00:00'))
                            else:
                                # Standard format
                                dt = datetime.strptime(attack['timestamp'], '%Y-%m-%d %H:%M:%S')
                            
                            if dt > datetime.now() - timedelta(hours=24):
                                stats['recent_attacks'].append(attack)
                                stats['hourly_breakdown'][dt.hour] += 1
                except:
                    pass
        
        # Convert sets to counts
        stats['unique_ips'] = len(stats['unique_ips'])
        stats['service_breakdown'] = dict(stats['service_breakdown'])
        stats['attack_type_breakdown'] = dict(stats['attack_type_breakdown'])
        stats['top_attackers'] = dict(stats['top_attackers'].most_common(10))
        stats['hourly_breakdown'] = dict(stats['hourly_breakdown'])
        
        return stats
    
    def print_summary(self, stats: Dict[str, Any]):
        """Print attack summary"""
        print("\n" + "="*60)
        print("HONEYNET ATTACK SUMMARY")
        print("="*60)
        
        print(f"\n📊 Overall Statistics:")
        print(f"   Total Attacks: {stats['total_attacks']}")
        print(f"   Unique Attackers: {stats['unique_ips']}")
        print(f"   Recent Attacks (24h): {len(stats['recent_attacks'])}")
        
        print(f"\n🎯 Service Breakdown:")
        for service, count in stats['service_breakdown'].items():
            percentage = (count / stats['total_attacks'] * 100) if stats['total_attacks'] > 0 else 0
            print(f"   {service.upper()}: {count} ({percentage:.1f}%)")
        
        print(f"\n⚔️ Attack Type Breakdown:")
        for attack_type, count in stats['attack_type_breakdown'].items():
            percentage = (count / stats['total_attacks'] * 100) if stats['total_attacks'] > 0 else 0
            print(f"   {attack_type}: {count} ({percentage:.1f}%)")
        
        print(f"\n🔝 Top Attackers:")
        for ip, count in list(stats['top_attackers'].items())[:5]:
            print(f"   {ip}: {count} attacks")
        
        print(f"\n⏰ Hourly Activity (24h):")
        for hour in range(24):
            count = stats['hourly_breakdown'].get(hour, 0)
            if count > 0:
                print(f"   {hour:02d}:00 - {hour:02d}:59: {count} attacks")
        
        print("="*60)
    
    def print_recent_attacks(self, attacks: Dict[str, List[Dict[str, Any]]], limit: int = 10):
        """Print recent attacks"""
        print(f"\n🕒 Recent Attacks (Last 24 hours, showing {limit}):")
        print("-" * 80)
        
        all_recent = []
        for service, service_attacks in attacks.items():
            for attack in service_attacks:
                if 'timestamp' in attack and attack['timestamp']:
                    try:
                        if isinstance(attack['timestamp'], str):
                            if 'T' in attack['timestamp']:
                                dt = datetime.fromisoformat(attack['timestamp'].replace('Z', '+00:00'))
                            else:
                                dt = datetime.strptime(attack['timestamp'], '%Y-%m-%d %H:%M:%S')
                            
                            if dt > datetime.now() - timedelta(hours=24):
                                all_recent.append((dt, attack))
                    except:
                        pass
        
        # Sort by timestamp and show most recent
        all_recent.sort(key=lambda x: x[0], reverse=True)
        
        for dt, attack in all_recent[:limit]:
            print(f"{dt.strftime('%Y-%m-%d %H:%M:%S')} | "
                  f"{attack['src_ip']:15} | "
                  f"{attack['dst_service']:4} | "
                  f"{attack['attack_type']:20} | "
                  f"{attack['payload'][:30]}...")
        
        print("-" * 80)
    
    def export_to_json(self, attacks: Dict[str, List[Dict[str, Any]]], output_file: str):
        """Export attack data to JSON"""
        try:
            with open(output_file, 'w') as f:
                json.dump(attacks, f, indent=2, default=str)
            print(f"\n✅ Attack data exported to: {output_file}")
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")


def main():
    parser = argparse.ArgumentParser(description="Honeynet Log Parser and Visualizer")
    parser.add_argument("--log-dir", default="/var/log/honeynet", 
                       help="Directory containing honeypot logs")
    parser.add_argument("--output", help="Export attack data to JSON file")
    parser.add_argument("--recent-only", action="store_true", 
                       help="Show only recent attacks (24h)")
    parser.add_argument("--limit", type=int, default=10, 
                       help="Limit number of recent attacks to show")
    
    args = parser.parse_args()
    
    # Create log parser
    parser = LogParser(args.log_dir)
    
    # Parse all logs
    print("🔍 Parsing honeypot logs...")
    attacks = parser.parse_all_logs()
    
    if not any(attacks.values()):
        print("❌ No log files found or no attacks detected.")
        return
    
    # Generate statistics
    stats = parser.generate_statistics(attacks)
    
    # Print summary
    parser.print_summary(stats)
    
    # Print recent attacks
    if args.recent_only or stats['recent_attacks']:
        parser.print_recent_attacks(attacks, args.limit)
    
    # Export to JSON if requested
    if args.output:
        parser.export_to_json(attacks, args.output)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Simple Attacker Simulation Script for Honeynet Demo
This script simulates various types of attacks for testing and demonstration purposes.
"""

import requests
import socket
import time
import random
import argparse
from typing import List, Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackerSimulator:
    def __init__(self, target_host: str = "localhost"):
        self.target_host = target_host
        self.attack_results = []

    def simulate_http_attack(self, attack_type: str = "sql_injection"):
        """Simulate HTTP-based attacks"""
        logger.info(f"Simulating HTTP {attack_type} attack...")
        
        attacks = {
            "sql_injection": [
                "' OR 1=1 --",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM users --",
                "admin'--",
                "1' OR '1'='1"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd"
            ],
            "directory_traversal": [
                "/admin",
                "/wp-admin",
                "/phpmyadmin",
                "/config",
                "/backup",
                "/.git",
                "/.env"
            ]
        }
        
        payloads = attacks.get(attack_type, attacks["sql_injection"])
        
        for payload in payloads:
            try:
                # Test on main port (HAProxy)
                response = requests.get(
                    f"http://{self.target_host}:80/search?q={payload}",
                    timeout=5,
                    headers={"User-Agent": "sqlmap/1.0"}
                )
                
                # Test on honeypot port
                response2 = requests.get(
                    f"http://{self.target_host}:8080/search?q={payload}",
                    timeout=5,
                    headers={"User-Agent": "sqlmap/1.0"}
                )
                
                self.attack_results.append({
                    "type": f"http_{attack_type}",
                    "payload": payload,
                    "main_port_status": response.status_code,
                    "honeypot_port_status": response2.status_code,
                    "timestamp": time.time()
                })
                
                logger.info(f"HTTP {attack_type}: {payload} -> Main: {response.status_code}, Honeypot: {response2.status_code}")
                time.sleep(0.5)  # Small delay between requests
                
            except Exception as e:
                logger.error(f"HTTP attack failed: {e}")

    def simulate_ssh_attack(self):
        """Simulate SSH brute force attacks"""
        logger.info("Simulating SSH brute force attack...")
        
        common_credentials = [
            ("admin", "admin"),
            ("root", "password"),
            ("root", "123456"),
            ("admin", "password"),
            ("user", "user"),
            ("test", "test"),
            ("guest", "guest"),
            ("administrator", "admin"),
            ("root", "root"),
            ("admin", "123456")
        ]
        
        for username, password in common_credentials:
            try:
                # This is a simulation - we don't actually connect
                # In a real scenario, you'd use paramiko or similar
                logger.info(f"SSH attempt: {username}:{password}")
                
                self.attack_results.append({
                    "type": "ssh_brute_force",
                    "username": username,
                    "password": password,
                    "timestamp": time.time()
                })
                
                time.sleep(0.2)  # Small delay
                
            except Exception as e:
                logger.error(f"SSH attack failed: {e}")

    def simulate_port_scan(self):
        """Simulate port scanning"""
        logger.info("Simulating port scan...")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 445, 139]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_host, port))
                sock.close()
                
                status = "open" if result == 0 else "closed"
                logger.info(f"Port {port}: {status}")
                
                self.attack_results.append({
                    "type": "port_scan",
                    "port": port,
                    "status": status,
                    "timestamp": time.time()
                })
                
            except Exception as e:
                logger.error(f"Port scan failed for port {port}: {e}")

    def simulate_rdp_attack(self):
        """Simulate RDP connection attempts"""
        logger.info("Simulating RDP attack...")
        
        # Simulate RDP connection attempts
        rdp_payloads = [
            "mstsc /v:target /u:admin /p:password",
            "xfreerdp /v:target /u:administrator /p:admin123",
            "rdesktop -u admin -p password target",
            "mstsc /v:target /u:root /p:root"
        ]
        
        for payload in rdp_payloads:
            logger.info(f"RDP attempt: {payload}")
            
            self.attack_results.append({
                "type": "rdp_connection",
                "payload": payload,
                "timestamp": time.time()
            })
            
            time.sleep(0.3)

    def simulate_smb_attack(self):
        """Simulate SMB attacks"""
        logger.info("Simulating SMB attack...")
        
        smb_attempts = [
            "smbclient //target/ipc$ -U admin%password",
            "smbclient //target/c$ -U administrator%admin123",
            "smbclient //target/share -U guest%",
            "smbclient //target/admin$ -U root%root"
        ]
        
        for attempt in smb_attempts:
            logger.info(f"SMB attempt: {attempt}")
            
            self.attack_results.append({
                "type": "smb_connection",
                "payload": attempt,
                "timestamp": time.time()
            })
            
            time.sleep(0.3)

    def run_all_attacks(self):
        """Run all attack simulations"""
        logger.info("Starting comprehensive attack simulation...")
        
        # HTTP attacks
        self.simulate_http_attack("sql_injection")
        self.simulate_http_attack("xss")
        self.simulate_http_attack("path_traversal")
        self.simulate_http_attack("directory_traversal")
        
        # Other attacks
        self.simulate_ssh_attack()
        self.simulate_port_scan()
        self.simulate_rdp_attack()
        self.simulate_smb_attack()
        
        logger.info("Attack simulation completed!")
        return self.attack_results

    def print_summary(self):
        """Print attack simulation summary"""
        print("\n" + "="*50)
        print("ATTACK SIMULATION SUMMARY")
        print("="*50)
        
        attack_types = {}
        for result in self.attack_results:
            attack_type = result["type"]
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        for attack_type, count in attack_types.items():
            print(f"{attack_type}: {count} attempts")
        
        print(f"\nTotal attacks simulated: {len(self.attack_results)}")
        print("="*50)


def main():
    parser = argparse.ArgumentParser(description="Honeynet Attacker Simulator")
    parser.add_argument("--target", default="localhost", help="Target host (default: localhost)")
    parser.add_argument("--attack-type", choices=["http", "ssh", "port-scan", "rdp", "smb", "all"], 
                       default="all", help="Type of attack to simulate")
    parser.add_argument("--http-type", choices=["sql_injection", "xss", "path_traversal", "directory_traversal"],
                       default="sql_injection", help="HTTP attack type")
    
    args = parser.parse_args()
    
    simulator = AttackerSimulator(args.target)
    
    if args.attack_type == "all":
        results = simulator.run_all_attacks()
    elif args.attack_type == "http":
        simulator.simulate_http_attack(args.http_type)
    elif args.attack_type == "ssh":
        simulator.simulate_ssh_attack()
    elif args.attack_type == "port-scan":
        simulator.simulate_port_scan()
    elif args.attack_type == "rdp":
        simulator.simulate_rdp_attack()
    elif args.attack_type == "smb":
        simulator.simulate_smb_attack()
    
    simulator.print_summary()


if __name__ == "__main__":
    main()

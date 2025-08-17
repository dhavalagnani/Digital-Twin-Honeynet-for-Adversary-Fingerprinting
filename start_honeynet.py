#!/usr/bin/env python3
"""
Digital Twin Honeynet - Startup Script
Starts all honeypot services (SSH, HTTP, RDP, and SMB)
"""
import subprocess
import time
import sys
import os
from pathlib import Path

def start_services():
    """Start all honeypot services"""
    print("Starting Digital Twin Honeynet...")
    
    # Start HTTP honeypot
    print("Starting HTTP honeypot...")
    http_honeypot = subprocess.Popen([
        sys.executable, "honeypot/http_honeypot.py"
    ])
    
    # Start HTTP router
    print("Starting HTTP router...")
    http_router = subprocess.Popen([
        sys.executable, "honeypot/http_router.py"
    ])
    
    # Start RDP honeypot
    print("Starting RDP honeypot...")
    rdp_honeypot = subprocess.Popen([
        sys.executable, "honeypot/rdp_honeypot.py"
    ])
    
    # Start SMB honeypot
    print("Starting SMB honeypot...")
    smb_honeypot = subprocess.Popen([
        sys.executable, "honeypot/smb_honeypot.py"
    ])
    
    # Start log monitor
    print("Starting log monitor...")
    log_monitor = subprocess.Popen([
        sys.executable, "cowrie_log_monitor.py"
    ])
    
    print("All services started!")
    print("HTTP Honeypot: http://localhost:8080")
    print("HTTP Router: http://localhost:80")
    print("SSH Honeypot: localhost:2222")
    print("RDP Honeypot: localhost:3389")
    print("SMB Honeypot: localhost:445")
    
    try:
        # Keep running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down services...")
        http_honeypot.terminate()
        http_router.terminate()
        rdp_honeypot.terminate()
        smb_honeypot.terminate()
        log_monitor.terminate()
        print("Services stopped")

if __name__ == '__main__':
    start_services()

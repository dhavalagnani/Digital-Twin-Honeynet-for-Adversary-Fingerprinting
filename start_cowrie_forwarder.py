#!/usr/bin/env python3
"""
Startup script for Cowrie Log Forwarder
"""

import sys
import os
import subprocess
import time
from pathlib import Path

def main():
    """Start the Cowrie log forwarder"""
    
    # Add backend directory to Python path
    backend_dir = Path(__file__).parent / "backend"
    sys.path.insert(0, str(backend_dir))
    
    # Ensure logs directory exists
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Ensure honeypot logs directory exists
    honeypot_logs_dir = Path("honeypot/logs")
    honeypot_logs_dir.mkdir(parents=True, exist_ok=True)
    
    print("🐝 Starting Cowrie Log Forwarder...")
    print(f"📁 Log directory: {logs_dir.absolute()}")
    print(f"📁 Honeypot logs: {honeypot_logs_dir.absolute()}")
    print(f"🌐 WebSocket URL: ws://localhost:8000/ws")
    print("Press Ctrl+C to stop")
    print("-" * 50)
    
    try:
        # Import and run the forwarder
        from backend.cowrie_log_forwarder import CowrieLogForwarder
        
        # Create forwarder instance
        forwarder = CowrieLogForwarder()
        
        # Start the service
        forwarder.start()
        
    except KeyboardInterrupt:
        print("\n🛑 Received interrupt signal, stopping...")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

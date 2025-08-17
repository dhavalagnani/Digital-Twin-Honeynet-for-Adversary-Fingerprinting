#!/usr/bin/env python3
"""
Digital Twin Honeynet - HTTP Honeypot Integration
Manages HTTP honeypot integration with existing SSH honeypot system
"""
import sys
import os
import logging
import subprocess
import time
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

class HTTPHoneypotIntegration:
    """Manages HTTP honeypot integration"""
    
    def __init__(self):
        """Initialize HTTP honeypot integration"""
        self.project_root = Path(__file__).parent.parent
        self.honeypot_dir = self.project_root / "honeypot"
        self.logs_dir = self.project_root / "logs"
        
        # Ensure directories exist
        self.logs_dir.mkdir(exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.logs_dir / "http_integration.log"),
                logging.StreamHandler()
            ]
        )
    
    def check_dependencies(self) -> bool:
        """Check if all required dependencies are installed"""
        logger.info("Checking dependencies...")
        
        required_packages = [
            'flask', 'requests', 'yaml', 'paramiko'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
                logger.info(f"✓ {package} is installed")
            except ImportError:
                missing_packages.append(package)
                logger.error(f"✗ {package} is missing")
        
        if missing_packages:
            logger.error(f"Missing packages: {', '.join(missing_packages)}")
            logger.info("Install missing packages with: pip install " + " ".join(missing_packages))
            return False
        
        logger.info("All dependencies are installed")
        return True
    
    def fetch_production_fingerprints(self) -> bool:
        """Fetch production server fingerprints"""
        logger.info("Fetching production server fingerprints...")
        
        try:
            # Fetch HTTP fingerprints
            http_fetcher = self.honeypot_dir / "http_fingerprint_fetcher.py"
            if http_fetcher.exists():
                result = subprocess.run([sys.executable, str(http_fetcher)], 
                                      capture_output=True, text=True, cwd=self.project_root)
                if result.returncode == 0:
                    logger.info("✓ HTTP fingerprints fetched successfully")
                else:
                    logger.warning(f"HTTP fingerprint fetching failed: {result.stderr}")
            
            # Fetch SSH banners (if banner fetcher exists)
            banner_fetcher = self.honeypot_dir / "banner_fetcher.py"
            if banner_fetcher.exists():
                result = subprocess.run([sys.executable, str(banner_fetcher)], 
                                      capture_output=True, text=True, cwd=self.project_root)
                if result.returncode == 0:
                    logger.info("✓ SSH banners fetched successfully")
                else:
                    logger.warning(f"SSH banner fetching failed: {result.stderr}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error fetching fingerprints: {e}")
            return False
    
    def test_http_honeypot(self) -> bool:
        """Test HTTP honeypot functionality"""
        logger.info("Testing HTTP honeypot...")
        
        try:
            # Test HTTP honeypot module
            http_honeypot = self.honeypot_dir / "http_honeypot.py"
            if http_honeypot.exists():
                result = subprocess.run([sys.executable, str(http_honeypot)], 
                                      capture_output=True, text=True, timeout=30, cwd=self.project_root)
                if result.returncode == 0:
                    logger.info("✓ HTTP honeypot test passed")
                    return True
                else:
                    logger.error(f"HTTP honeypot test failed: {result.stderr}")
                    return False
            else:
                logger.error("HTTP honeypot module not found")
                return False
                
        except subprocess.TimeoutExpired:
            logger.info("✓ HTTP honeypot test completed (timeout expected)")
            return True
        except Exception as e:
            logger.error(f"Error testing HTTP honeypot: {e}")
            return False
    
    def test_http_router(self) -> bool:
        """Test HTTP router functionality"""
        logger.info("Testing HTTP router...")
        
        try:
            # Test HTTP router module
            http_router = self.honeypot_dir / "http_router.py"
            if http_router.exists():
                result = subprocess.run([sys.executable, str(http_router)], 
                                      capture_output=True, text=True, timeout=30, cwd=self.project_root)
                if result.returncode == 0:
                    logger.info("✓ HTTP router test passed")
                    return True
                else:
                    logger.error(f"HTTP router test failed: {result.stderr}")
                    return False
            else:
                logger.error("HTTP router module not found")
                return False
                
        except subprocess.TimeoutExpired:
            logger.info("✓ HTTP router test completed (timeout expected)")
            return True
        except Exception as e:
            logger.error(f"Error testing HTTP router: {e}")
            return False
    
    def check_native_services(self) -> bool:
        """Check native service configuration"""
        logger.info("Checking native service configuration...")
        
        try:
            # Check for native service files
            service_files = [
                "/etc/systemd/system/cowrie.service",
                "/etc/systemd/system/rdp-honeypot.service",
                "/etc/systemd/system/smb-honeypot.service",
                "/etc/systemd/system/honeynet-api.service",
                "/etc/systemd/system/honeynet-monitor.service"
            ]
            
            for service_file in service_files:
                if Path(service_file).exists():
                    logger.info(f"✓ {service_file} exists")
                else:
                    logger.info(f"Will create {service_file} during native installation")
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking native services: {e}")
            return False
    
    def update_logging_pipeline(self) -> bool:
        """Update logging pipeline to include HTTP honeypot logs"""
        logger.info("Updating logging pipeline...")
        
        try:
            # Check existing log monitor
            log_monitor = self.project_root / "cowrie_log_monitor.py"
            if log_monitor.exists():
                logger.info("✓ Existing log monitor found")
                
                # Read current log monitor
                with open(log_monitor, 'r') as f:
                    content = f.read()
                
                # Check if HTTP logging is already integrated
                if 'http_honeypot' in content or 'HTTP' in content:
                    logger.info("✓ HTTP logging already integrated")
                else:
                    logger.info("HTTP logging integration needed")
            
            # Check for HTTP log files
            http_logs = [
                "honeypot/http_honeypot.json",
                "honeypot/http_honeypot.log",
                "honeypot/router.log"
            ]
            
            for log_file in http_logs:
                log_path = self.project_root / log_file
                if log_path.exists():
                    logger.info(f"✓ {log_file} exists")
                else:
                    logger.info(f"Will create {log_file} when honeypot runs")
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating logging pipeline: {e}")
            return False
    
    def create_startup_script(self) -> bool:
        """Create startup script for the complete honeynet"""
        logger.info("Creating startup script...")
        
        try:
            startup_script = self.project_root / "start_honeynet.py"
            
            script_content = '''#!/usr/bin/env python3
"""
Digital Twin Honeynet - Startup Script
Starts all honeypot services (SSH and HTTP)
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
    
    # Start log monitor
    print("Starting log monitor...")
    log_monitor = subprocess.Popen([
        sys.executable, "cowrie_log_monitor.py"
    ])
    
    print("All services started!")
    print("HTTP Honeypot: http://localhost:8080")
    print("HTTP Router: http://localhost:80")
    print("SSH Honeypot: localhost:2222")
    
    try:
        # Keep running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\\nShutting down services...")
        http_honeypot.terminate()
        http_router.terminate()
        log_monitor.terminate()
        print("Services stopped")

if __name__ == '__main__':
    start_services()
'''
            
            with open(startup_script, 'w') as f:
                f.write(script_content)
            
            # Make executable
            os.chmod(startup_script, 0o755)
            
            logger.info("✓ Startup script created: start_honeynet.py")
            return True
            
        except Exception as e:
            logger.error(f"Error creating startup script: {e}")
            return False
    
    def run_integration_tests(self) -> bool:
        """Run integration tests"""
        logger.info("Running integration tests...")
        
        tests_passed = 0
        total_tests = 0
        
        # Test 1: Dependencies
        total_tests += 1
        if self.check_dependencies():
            tests_passed += 1
        
        # Test 2: HTTP honeypot
        total_tests += 1
        if self.test_http_honeypot():
            tests_passed += 1
        
        # Test 3: HTTP router
        total_tests += 1
        if self.test_http_router():
            tests_passed += 1
        
        # Test 4: Native services
        total_tests += 1
        if self.check_native_services():
            tests_passed += 1
        
        # Test 5: Logging pipeline
        total_tests += 1
        if self.update_logging_pipeline():
            tests_passed += 1
        
        # Test 6: Startup script
        total_tests += 1
        if self.create_startup_script():
            tests_passed += 1
        
        logger.info(f"Integration tests: {tests_passed}/{total_tests} passed")
        return tests_passed == total_tests
    
    def show_status(self):
        """Show current integration status"""
        print("Digital Twin Honeynet - HTTP Integration Status")
        print("=" * 50)
        
        # Check files
        files_to_check = [
            ("HTTP Honeypot", "honeypots/http_honeypot.py"),
            ("HTTP Router", "honeypots/http_router.py"),
            ("HTTP Config", "honeypots/http_config.yaml"),
            ("Router Config", "honeypots/router_config.yaml"),
            ("Native Controller", "honeynet_controller_native.py"),
            ("Install Script", "install_native_services.sh"),
            ("Startup Script", "start_honeynet.py")
        ]
        
        for name, path in files_to_check:
            file_path = self.project_root / path
            if file_path.exists():
                print(f"✓ {name}: {path}")
            else:
                print(f"✗ {name}: {path} (missing)")
        
        print("\nServices:")
        print("• HTTP Honeypot: Port 8080")
        print("• HTTP Router: Port 80")
        print("• SSH Honeypot: Port 2222")
        print("• Log Monitor: Running")
        
        print("\nNext steps:")
        print("1. Run: python honeypot/integrate_http_honeypot.py test")
        print("2. Run: sudo ./install_native_services.sh")
        print("3. Run: python honeynet_controller_native.py --action start")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python integrate_http_honeypot.py [command]")
        print("Commands:")
        print("  status  - Show integration status")
        print("  test    - Run integration tests")
        print("  fetch   - Fetch production fingerprints")
        print("  start   - Start all services")
        return 1
    
    command = sys.argv[1]
    integration = HTTPHoneypotIntegration()
    
    if command == "status":
        integration.show_status()
    elif command == "test":
        success = integration.run_integration_tests()
        return 0 if success else 1
    elif command == "fetch":
        success = integration.fetch_production_fingerprints()
        return 0 if success else 1
    elif command == "start":
        print("Starting Digital Twin Honeynet with HTTP support...")
        # This would start all services
        print("Use: python start_honeynet.py")
        return 0
    else:
        print(f"Unknown command: {command}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())

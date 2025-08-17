#!/usr/bin/env python3
"""
Digital Twin Honeynet - Cowrie Integration Script
Provides easy commands to integrate TCP/IP stack randomization with Cowrie
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from tcp_randomizer import get_tcp_randomizer
from network_layer import get_network_manager
from cowrie_integration import get_cowrie_integration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_cowrie_installation():
    """Check if Cowrie is installed and accessible"""
    cowrie_paths = [
        Path.cwd() / 'cowrie',
        Path.cwd() / 'cowrie' / 'bin' / 'cowrie',
        Path('/opt/cowrie'),
        Path('/usr/local/cowrie'),
        Path.home() / 'cowrie'
    ]
    
    for path in cowrie_paths:
        if path.exists():
            logger.info(f"Found Cowrie installation at: {path}")
            return path
    
    logger.warning("Cowrie installation not found in common locations")
    return None


def generate_integration_files():
    """Generate integration files for Cowrie"""
    try:
        integration = get_cowrie_integration()
        
        # Generate patch file
        patch_success = integration.generate_cowrie_patch("cowrie_patch.py")
        
        # Generate integration script
        integration_script = '''#!/usr/bin/env python3
"""
Cowrie Integration Script - Auto-generated
Apply this script to integrate TCP/IP stack randomization with Cowrie
"""

import sys
import os
from pathlib import Path

# Add the honeypot directory to Python path
honeypot_dir = Path(__file__).parent / 'honeypot'
sys.path.insert(0, str(honeypot_dir))

# Import and apply patches
from cowrie_patch import apply_patches

def integrate_with_cowrie():
    """Integrate TCP/IP randomization with Cowrie"""
    try:
        # This will be called from Cowrie's main file
        # The actual SSH server class will be passed here
        print("TCP/IP stack randomization integration ready")
        print("Apply patches in Cowrie's main server file")
        return True
    except Exception as e:
        print(f"Integration failed: {e}")
        return False

if __name__ == "__main__":
    integrate_with_cowrie()
'''
        
        with open("cowrie_integration_script.py", "w") as f:
            f.write(integration_script)
        
        # Generate README for integration
        readme_content = '''# Cowrie Integration Guide

This directory contains files for integrating TCP/IP stack randomization with Cowrie.

## Files Generated:
- `cowrie_patch.py` - Patch file for Cowrie SSH server
- `cowrie_integration_script.py` - Integration script
- `tcp_config.yaml` - Configuration file (copy from honeypot/)

## Integration Steps:

### Step 1: Copy Configuration
```bash
cp honeypot/tcp_config.yaml .
```

### Step 2: Modify Cowrie's Main File
Add the following to Cowrie's main server file (usually `bin/cowrie`):

```python
# Add at the top of the file
import sys
from pathlib import Path

# Add honeypot directory to path
honeypot_dir = Path(__file__).parent.parent / 'honeypot'
sys.path.insert(0, str(honeypot_dir))

# Import and apply patches
from cowrie_patch import apply_patches

# Apply patches before starting the server
# (Add this before the server starts)
```

### Step 3: Apply Patches
In Cowrie's SSH server class, apply the patches:

```python
# Find the SSH server class and apply patches
apply_patches(YourSSHServerClass)
```

### Step 4: Restart Cowrie
```bash
# Stop Cowrie
systemctl stop cowrie

# Start Cowrie with randomization
systemctl start cowrie
```

## Verification:
Check that randomization is working:
```bash
python honeypot/tcp_randomizer.py
```

## Troubleshooting:
- Check logs: `tail -f logs/cowrie.log`
- Test configuration: `python -c "from honeypot.tcp_randomizer import get_tcp_randomizer; print(get_tcp_randomizer().is_enabled())"`
'''
        
        with open("COWRIE_INTEGRATION_README.md", "w") as f:
            f.write(readme_content)
        
        logger.info("Generated integration files:")
        logger.info("  - cowrie_patch.py")
        logger.info("  - cowrie_integration_script.py")
        logger.info("  - COWRIE_INTEGRATION_README.md")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate integration files: {e}")
        return False


def test_randomization():
    """Test the TCP/IP stack randomization"""
    try:
        logger.info("Testing TCP/IP stack randomization...")
        
        # Test randomizer
        randomizer = get_tcp_randomizer()
        logger.info(f"Randomizer enabled: {randomizer.is_enabled()}")
        
        # Test network manager
        manager = get_network_manager()
        logger.info(f"Network manager active: {manager is not None}")
        
        # Test integration
        integration = get_cowrie_integration()
        logger.info(f"Integration ready: {integration is not None}")
        
        # Test parameter generation
        params = randomizer.get_randomized_params()
        logger.info(f"Sample parameters:")
        logger.info(f"  Window Size: {params.window_size}")
        logger.info(f"  TTL: {params.ttl}")
        logger.info(f"  MSS: {params.mss}")
        logger.info(f"  Response Delay: {params.response_delay:.3f}s")
        
        logger.info("✓ TCP/IP stack randomization test passed")
        return True
        
    except Exception as e:
        logger.error(f"✗ TCP/IP stack randomization test failed: {e}")
        return False


def show_status():
    """Show current integration status"""
    try:
        logger.info("TCP/IP Stack Randomization Status")
        logger.info("=" * 40)
        
        # Check randomizer
        randomizer = get_tcp_randomizer()
        logger.info(f"Randomizer: {'✓ Enabled' if randomizer.is_enabled() else '✗ Disabled'}")
        
        # Check network manager
        manager = get_network_manager()
        logger.info(f"Network Manager: {'✓ Active' if manager else '✗ Inactive'}")
        
        # Check integration
        integration = get_cowrie_integration()
        status = integration.get_integration_status()
        logger.info(f"Integration: {'✓ Ready' if status['randomizer_enabled'] else '✗ Not Ready'}")
        
        # Check Cowrie installation
        cowrie_path = check_cowrie_installation()
        logger.info(f"Cowrie Installation: {'✓ Found' if cowrie_path else '✗ Not Found'}")
        
        # Show configuration
        config_path = Path("honeypot/tcp_config.yaml")
        logger.info(f"Configuration: {'✓ Loaded' if config_path.exists() else '✗ Missing'}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to show status: {e}")
        return False


def enable_randomization():
    """Enable TCP/IP stack randomization"""
    try:
        randomizer = get_tcp_randomizer()
        manager = get_network_manager()
        integration = get_cowrie_integration()
        
        randomizer.enable()
        manager.enable_randomization()
        integration.enable_integration()
        
        logger.info("✓ TCP/IP stack randomization enabled")
        return True
        
    except Exception as e:
        logger.error(f"✗ Failed to enable randomization: {e}")
        return False


def disable_randomization():
    """Disable TCP/IP stack randomization"""
    try:
        randomizer = get_tcp_randomizer()
        manager = get_network_manager()
        integration = get_cowrie_integration()
        
        randomizer.disable()
        manager.disable_randomization()
        integration.disable_integration()
        
        logger.info("✓ TCP/IP stack randomization disabled")
        return True
        
    except Exception as e:
        logger.error(f"✗ Failed to disable randomization: {e}")
        return False


def reload_config():
    """Reload configuration"""
    try:
        randomizer = get_tcp_randomizer()
        manager = get_network_manager()
        integration = get_cowrie_integration()
        
        randomizer.reload_config()
        manager.reload_config()
        integration.reload_configuration()
        
        logger.info("✓ Configuration reloaded")
        return True
        
    except Exception as e:
        logger.error(f"✗ Failed to reload configuration: {e}")
        return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Digital Twin Honeynet - Cowrie Integration Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s status                    # Show integration status
  %(prog)s test                      # Test randomization
  %(prog)s generate                  # Generate integration files
  %(prog)s enable                    # Enable randomization
  %(prog)s disable                   # Disable randomization
  %(prog)s reload                    # Reload configuration
        """
    )
    
    parser.add_argument(
        'command',
        choices=['status', 'test', 'generate', 'enable', 'disable', 'reload'],
        help='Command to execute'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Execute command
    success = False
    
    if args.command == 'status':
        success = show_status()
    elif args.command == 'test':
        success = test_randomization()
    elif args.command == 'generate':
        success = generate_integration_files()
    elif args.command == 'enable':
        success = enable_randomization()
    elif args.command == 'disable':
        success = disable_randomization()
    elif args.command == 'reload':
        success = reload_config()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Digital Twin Honeynet - Cowrie Integration Patch
This file contains patches for integrating TCP/IP stack randomization with Cowrie

To apply this patch:
1. Copy this file to your Cowrie installation directory
2. Import and apply the patches in Cowrie's main server file
3. Restart Cowrie to enable randomization
"""

import sys
import os
import logging
from pathlib import Path

# Add the honeypot directory to Python path
honeypot_dir = Path(__file__).parent
sys.path.insert(0, str(honeypot_dir))

from tcp_randomizer import get_tcp_randomizer
from network_layer import get_network_manager

logger = logging.getLogger(__name__)

class CowrieRandomizationPatches:
    """Patches for integrating TCP/IP randomization with Cowrie"""
    
    def __init__(self):
        self.randomizer = get_tcp_randomizer()
        self.network_manager = get_network_manager()
        self._original_methods = {}
    
    def patch_ssh_server(self, ssh_server_class):
        """
        Patch SSH server class with randomization
        
        Args:
            ssh_server_class: The SSH server class to patch
        """
        # Store original methods
        self._original_methods['handle'] = ssh_server_class.handle
        self._original_methods['handle_auth'] = ssh_server_class.handle_auth
        self._original_methods['handle_session'] = ssh_server_class.handle_session
        
        # Apply patches
        ssh_server_class.handle = self._patched_handle
        ssh_server_class.handle_auth = self._patched_handle_auth
        ssh_server_class.handle_session = self._patched_handle_session
        
        logger.info("Applied randomization patches to SSH server")
    
    def _patched_handle(self, *args, **kwargs):
        """Patched handle method with randomization"""
        # Apply connection randomization
        if self.randomizer.is_enabled():
            self.randomizer.apply_delay()
        
        # Call original method
        return self._original_methods['handle'](*args, **kwargs)
    
    def _patched_handle_auth(self, *args, **kwargs):
        """Patched authentication handler with randomization"""
        # Apply authentication randomization
        if self.randomizer.is_enabled():
            self.randomizer.apply_delay()
        
        # Call original method
        return self._original_methods['handle_auth'](*args, **kwargs)
    
    def _patched_handle_session(self, *args, **kwargs):
        """Patched session handler with randomization"""
        # Apply session randomization
        if self.randomizer.is_enabled():
            self.randomizer.apply_delay()
        
        # Call original method
        return self._original_methods['handle_session'](*args, **kwargs)
    
    def unpatch_ssh_server(self, ssh_server_class):
        """
        Remove patches from SSH server class
        
        Args:
            ssh_server_class: The SSH server class to unpatch
        """
        # Restore original methods
        for method_name, original_method in self._original_methods.items():
            setattr(ssh_server_class, method_name, original_method)
        
        logger.info("Removed randomization patches from SSH server")

# Global patch instance
_patches = None

def get_patches():
    """Get or create global patch instance"""
    global _patches
    if _patches is None:
        _patches = CowrieRandomizationPatches()
    return _patches

def apply_patches(ssh_server_class):
    """Apply patches to SSH server class"""
    patches = get_patches()
    patches.patch_ssh_server(ssh_server_class)

def remove_patches(ssh_server_class):
    """Remove patches from SSH server class"""
    patches = get_patches()
    patches.unpatch_ssh_server(ssh_server_class)

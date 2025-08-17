#!/usr/bin/env python3
"""
Digital Twin Honeynet - Cowrie Integration Module
Provides integration hooks for TCP/IP stack randomization with Cowrie
"""

import os
import sys
import logging
import importlib
from typing import Optional, Dict, Any
from pathlib import Path

from tcp_randomizer import TCPStackRandomizer, get_tcp_randomizer
from network_layer import NetworkLayerManager, get_network_manager

logger = logging.getLogger(__name__)


class CowrieIntegration:
    """
    Integration layer for TCP/IP stack randomization with Cowrie
    
    This class provides methods to integrate the randomization
    functionality with Cowrie's SSH server implementation.
    """
    
    def __init__(self, config_path: str = "honeypot/tcp_config.yaml"):
        """
        Initialize Cowrie integration
        
        Args:
            config_path: Path to TCP configuration file
        """
        self.config_path = config_path
        self.randomizer = get_tcp_randomizer(config_path)
        self.network_manager = get_network_manager(config_path)
        self._patched_modules = set()
        self._original_socket = None
        
        logger.info("Cowrie integration initialized")
    
    def patch_cowrie_socket(self) -> bool:
        """
        Patch Cowrie's socket usage with randomized sockets
        
        Returns:
            True if patching was successful, False otherwise
        """
        try:
            # Store original socket
            import socket
            self._original_socket = socket.socket
            
            # Replace socket.socket with our randomized version
            from .network_layer import create_randomized_socket
            
            def patched_socket(family=socket.AF_INET, type=socket.SOCK_STREAM, 
                             proto=0, fileno=None):
                return create_randomized_socket(family, type, proto, fileno)
            
            # Apply the patch
            socket.socket = patched_socket
            self._patched_modules.add('socket')
            
            logger.info("Successfully patched socket.socket with randomized version")
            return True
            
        except Exception as e:
            logger.error(f"Failed to patch Cowrie socket: {e}")
            return False
    
    def unpatch_cowrie_socket(self) -> bool:
        """
        Restore original socket implementation
        
        Returns:
            True if unpatching was successful, False otherwise
        """
        try:
            if self._original_socket and 'socket' in self._patched_modules:
                import socket
                socket.socket = self._original_socket
                self._patched_modules.remove('socket')
                logger.info("Restored original socket implementation")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to unpatch Cowrie socket: {e}")
            return False
    
    def patch_cowrie_ssh_server(self) -> bool:
        """
        Patch Cowrie's SSH server with randomization hooks
        
        Returns:
            True if patching was successful, False otherwise
        """
        try:
            # This would require access to Cowrie's source code
            # For now, we'll provide a template for manual integration
            
            logger.info("SSH server patching requires manual integration")
            logger.info("Use the provided hooks in Cowrie's SSH server code")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to patch Cowrie SSH server: {e}")
            return False
    
    def create_ssh_server_hooks(self) -> Dict[str, Any]:
        """
        Create hooks for integration with Cowrie's SSH server
        
        Returns:
            Dictionary containing hook functions and patches
        """
        hooks = {
            'connection_hook': self._connection_hook,
            'authentication_hook': self._authentication_hook,
            'session_hook': self._session_hook,
            'data_transfer_hook': self._data_transfer_hook,
            'disconnect_hook': self._disconnect_hook
        }
        
        return hooks
    
    def _connection_hook(self, client_address: tuple, connection_id: str) -> None:
        """
        Hook called when a new SSH connection is established
        
        Args:
            client_address: Client address tuple (host, port)
            connection_id: Unique connection identifier
        """
        if self.randomizer.is_enabled():
            # Apply connection randomization
            self.randomizer.apply_delay()
            
            # Get randomized parameters for this connection
            params = self.randomizer.get_randomized_params()
            
            logger.info(f"Applied randomization to connection {connection_id} from {client_address}")
            logger.debug(f"Connection parameters: {params}")
    
    def _authentication_hook(self, username: str, password: str, 
                           success: bool, connection_id: str) -> None:
        """
        Hook called during SSH authentication
        
        Args:
            username: Username attempting authentication
            password: Password used (may be empty for key-based auth)
            success: Whether authentication was successful
            connection_id: Unique connection identifier
        """
        if self.randomizer.is_enabled():
            # Apply authentication response delay
            self.randomizer.apply_delay()
            
            logger.debug(f"Applied authentication randomization for {username} (success: {success})")
    
    def _session_hook(self, session_id: str, command: str, 
                     connection_id: str) -> None:
        """
        Hook called when a new SSH session is created
        
        Args:
            session_id: Unique session identifier
            command: Command being executed
            connection_id: Unique connection identifier
        """
        if self.randomizer.is_enabled():
            # Apply session creation delay
            self.randomizer.apply_delay()
            
            logger.debug(f"Applied session randomization for session {session_id}")
    
    def _data_transfer_hook(self, data_size: int, direction: str, 
                           connection_id: str) -> None:
        """
        Hook called during data transfer
        
        Args:
            data_size: Size of data being transferred
            direction: 'in' or 'out'
            connection_id: Unique connection identifier
        """
        if self.randomizer.is_enabled():
            # Apply data transfer delay
            self.randomizer.apply_delay()
            
            logger.debug(f"Applied data transfer randomization ({direction}, {data_size} bytes)")
    
    def _disconnect_hook(self, connection_id: str, reason: str) -> None:
        """
        Hook called when SSH connection is disconnected
        
        Args:
            connection_id: Unique connection identifier
            reason: Reason for disconnection
        """
        if self.randomizer.is_enabled():
            # Apply disconnect delay
            self.randomizer.apply_delay()
            
            # Remove from connection tracking
            self.network_manager.remove_connection(connection_id)
            
            logger.debug(f"Applied disconnect randomization for {connection_id} (reason: {reason})")
    
    def generate_cowrie_patch(self, output_path: str = "honeypot/cowrie_patch.py") -> bool:
        """
        Generate a patch file for Cowrie integration
        
        Args:
            output_path: Path to save the patch file
            
        Returns:
            True if patch generation was successful, False otherwise
        """
        try:
            patch_content = self._generate_patch_content()
            
            with open(output_path, 'w') as f:
                f.write(patch_content)
            
            logger.info(f"Generated Cowrie patch file: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate Cowrie patch: {e}")
            return False
    
    def _generate_patch_content(self) -> str:
        """Generate the content for the Cowrie patch file"""
        return '''#!/usr/bin/env python3
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
'''
    
    def get_integration_status(self) -> Dict[str, Any]:
        """
        Get current integration status
        
        Returns:
            Dictionary with integration status information
        """
        status = {
            'randomizer_enabled': self.randomizer.is_enabled(),
            'network_manager_active': self.network_manager is not None,
            'patched_modules': list(self._patched_modules),
            'config_path': self.config_path,
            'connection_stats': self.network_manager.get_connection_stats()
        }
        
        return status
    
    def enable_integration(self) -> bool:
        """Enable TCP/IP stack randomization integration"""
        try:
            self.randomizer.enable()
            self.network_manager.enable_randomization()
            logger.info("TCP/IP stack randomization integration enabled")
            return True
        except Exception as e:
            logger.error(f"Failed to enable integration: {e}")
            return False
    
    def disable_integration(self) -> bool:
        """Disable TCP/IP stack randomization integration"""
        try:
            self.randomizer.disable()
            self.network_manager.disable_randomization()
            logger.info("TCP/IP stack randomization integration disabled")
            return True
        except Exception as e:
            logger.error(f"Failed to disable integration: {e}")
            return False
    
    def reload_configuration(self) -> bool:
        """Reload configuration for all components"""
        try:
            self.randomizer.reload_config()
            self.network_manager.reload_config()
            logger.info("Configuration reloaded for all components")
            return True
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            return False


# Global integration instance
_integration = None

def get_cowrie_integration(config_path: str = "honeypot/tcp_config.yaml") -> CowrieIntegration:
    """
    Get or create global Cowrie integration instance
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        CowrieIntegration instance
    """
    global _integration
    if _integration is None:
        _integration = CowrieIntegration(config_path)
    return _integration


def apply_cowrie_patches() -> bool:
    """Apply patches to Cowrie's network handling"""
    integration = get_cowrie_integration()
    return integration.patch_cowrie_socket()


def remove_cowrie_patches() -> bool:
    """Remove patches from Cowrie's network handling"""
    integration = get_cowrie_integration()
    return integration.unpatch_cowrie_socket()


if __name__ == "__main__":
    # Test the integration
    logging.basicConfig(level=logging.DEBUG)
    
    print("Testing Cowrie Integration")
    print("=" * 40)
    
    # Test integration creation
    integration = get_cowrie_integration()
    print(f"Integration created: {integration}")
    
    # Test status
    status = integration.get_integration_status()
    print(f"Integration status: {status}")
    
    # Test patch generation
    success = integration.generate_cowrie_patch()
    print(f"Patch generation: {'Success' if success else 'Failed'}")
    
    # Test hooks
    hooks = integration.create_ssh_server_hooks()
    print(f"Available hooks: {list(hooks.keys())}")

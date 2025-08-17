#!/usr/bin/env python3
"""
Digital Twin Honeynet - Network Layer Integration
Provides TCP socket wrappers with randomized behavior for Cowrie integration
"""

import socket
import time
import logging
import threading
from typing import Optional, Tuple, Any
from contextlib import contextmanager

from tcp_randomizer import TCPStackRandomizer, NetworkParams, get_tcp_randomizer

logger = logging.getLogger(__name__)


class RandomizedTCPSocket:
    """
    TCP socket wrapper with randomized network behavior
    
    This class wraps standard TCP sockets and applies randomized
    timing and network parameters to reduce fingerprinting risk.
    """
    
    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, 
                 proto=0, fileno=None, randomizer: Optional[TCPStackRandomizer] = None):
        """
        Initialize randomized TCP socket
        
        Args:
            family: Socket family (default: AF_INET)
            type: Socket type (default: SOCK_STREAM)
            proto: Protocol (default: 0)
            fileno: File descriptor (default: None)
            randomizer: TCP randomizer instance (default: None)
        """
        self._socket = socket.socket(family, type, proto, fileno)
        self.randomizer = randomizer or get_tcp_randomizer()
        self._local_params: Optional[NetworkParams] = None
        self._remote_params: Optional[NetworkParams] = None
        self._connection_time: Optional[float] = None
        
        logger.debug("Randomized TCP socket initialized")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def bind(self, address: Tuple[str, int]) -> None:
        """Bind socket to address with randomized parameters"""
        if self.randomizer.is_enabled():
            # Apply delay before binding
            self.randomizer.apply_delay()
        
        self._socket.bind(address)
        logger.debug(f"Socket bound to {address}")
    
    def listen(self, backlog: int = 5) -> None:
        """Start listening with randomized parameters"""
        if self.randomizer.is_enabled():
            # Apply delay before listening
            self.randomizer.apply_delay()
        
        self._socket.listen(backlog)
        logger.debug(f"Socket listening with backlog {backlog}")
    
    def accept(self) -> Tuple['RandomizedTCPSocket', Tuple[str, int]]:
        """
        Accept connection with randomized timing
        
        Returns:
            Tuple of (client_socket, client_address)
        """
        if self.randomizer.is_enabled():
            # Apply delay before accepting
            self.randomizer.apply_delay()
        
        client_socket, client_address = self._socket.accept()
        
        # Create randomized wrapper for client socket
        randomized_client = RandomizedTCPSocket(fileno=client_socket.fileno())
        randomized_client._socket = client_socket
        randomized_client._connection_time = time.time()
        
        # Get randomized parameters for this connection
        randomized_client._local_params = self.randomizer.get_randomized_params()
        
        logger.debug(f"Accepted connection from {client_address}")
        logger.debug(f"Connection parameters: {randomized_client._local_params}")
        
        return randomized_client, client_address
    
    def connect(self, address: Tuple[str, int]) -> None:
        """
        Connect to remote address with randomized timing
        
        Args:
            address: Remote address tuple (host, port)
        """
        if self.randomizer.is_enabled():
            # Apply delay before connecting
            self.randomizer.apply_delay()
        
        self._socket.connect(address)
        self._connection_time = time.time()
        
        # Get randomized parameters for this connection
        self._local_params = self.randomizer.get_randomized_params()
        
        logger.debug(f"Connected to {address}")
        logger.debug(f"Connection parameters: {self._local_params}")
    
    def send(self, data: bytes, flags: int = 0) -> int:
        """
        Send data with randomized timing
        
        Args:
            data: Data to send
            flags: Socket flags
            
        Returns:
            Number of bytes sent
        """
        if self.randomizer.is_enabled():
            # Apply delay before sending
            self.randomizer.apply_delay()
        
        return self._socket.send(data, flags)
    
    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        """
        Receive data with randomized timing
        
        Args:
            bufsize: Buffer size
            flags: Socket flags
            
        Returns:
            Received data
        """
        if self.randomizer.is_enabled():
            # Apply delay before receiving
            self.randomizer.apply_delay()
        
        return self._socket.recv(bufsize, flags)
    
    def sendall(self, data: bytes, flags: int = 0) -> None:
        """
        Send all data with randomized timing
        
        Args:
            data: Data to send
            flags: Socket flags
        """
        if self.randomizer.is_enabled():
            # Apply delay before sending
            self.randomizer.apply_delay()
        
        self._socket.sendall(data, flags)
    
    def close(self) -> None:
        """Close socket with randomized timing"""
        if self.randomizer.is_enabled():
            # Apply delay before closing
            self.randomizer.apply_delay()
        
        self._socket.close()
        logger.debug("Socket closed")
    
    def shutdown(self, how: int) -> None:
        """
        Shutdown socket with randomized timing
        
        Args:
            how: Shutdown mode
        """
        if self.randomizer.is_enabled():
            # Apply delay before shutdown
            self.randomizer.apply_delay()
        
        self._socket.shutdown(how)
        logger.debug(f"Socket shutdown with mode {how}")
    
    def settimeout(self, timeout: Optional[float]) -> None:
        """Set socket timeout"""
        self._socket.settimeout(timeout)
    
    def gettimeout(self) -> Optional[float]:
        """Get socket timeout"""
        return self._socket.gettimeout()
    
    def setsockopt(self, level: int, optname: int, value: Any) -> None:
        """Set socket option with randomized parameters if applicable"""
        if self.randomizer.is_enabled():
            # Apply randomized network parameters for specific options
            if level == socket.SOL_TCP and optname == socket.TCP_NODELAY:
                # Apply delay before setting TCP_NODELAY
                self.randomizer.apply_delay()
            elif level == socket.IPPROTO_TCP and optname == socket.TCP_WINDOW_CLAMP:
                # Use randomized window size
                if self._local_params:
                    value = self._local_params.window_size
                    logger.debug(f"Setting randomized window size: {value}")
        
        self._socket.setsockopt(level, optname, value)
    
    def getsockopt(self, level: int, optname: int, buflen: int = 0) -> Any:
        """Get socket option"""
        return self._socket.getsockopt(level, optname, buflen)
    
    def fileno(self) -> int:
        """Get file descriptor"""
        return self._socket.fileno()
    
    def getpeername(self) -> Tuple[str, int]:
        """Get peer address"""
        return self._socket.getpeername()
    
    def getsockname(self) -> Tuple[str, int]:
        """Get socket address"""
        return self._socket.getsockname()
    
    def get_connection_params(self) -> Optional[NetworkParams]:
        """Get connection parameters"""
        return self._local_params
    
    def get_connection_time(self) -> Optional[float]:
        """Get connection establishment time"""
        return self._connection_time


class NetworkLayerManager:
    """
    Manager for network layer randomization
    
    Provides centralized control over TCP/IP stack randomization
    and integration with Cowrie's network handling.
    """
    
    def __init__(self, config_path: str = "honeypot/tcp_config.yaml"):
        """
        Initialize network layer manager
        
        Args:
            config_path: Path to TCP configuration file
        """
        self.randomizer = TCPStackRandomizer(config_path)
        self._lock = threading.Lock()
        self._active_connections = {}
        
        logger.info("Network layer manager initialized")
    
    def create_socket(self, family=socket.AF_INET, type=socket.SOCK_STREAM, 
                     proto=0, fileno=None) -> RandomizedTCPSocket:
        """
        Create a new randomized TCP socket
        
        Args:
            family: Socket family
            type: Socket type
            proto: Protocol
            fileno: File descriptor
            
        Returns:
            RandomizedTCPSocket instance
        """
        return RandomizedTCPSocket(family, type, proto, fileno, self.randomizer)
    
    def apply_connection_randomization(self, sock: RandomizedTCPSocket, 
                                     connection_id: str) -> None:
        """
        Apply randomization to a specific connection
        
        Args:
            sock: Randomized socket
            connection_id: Unique connection identifier
        """
        with self._lock:
            self._active_connections[connection_id] = {
                'socket': sock,
                'params': sock.get_connection_params(),
                'start_time': sock.get_connection_time()
            }
        
        logger.debug(f"Applied randomization to connection {connection_id}")
    
    def get_connection_stats(self) -> dict:
        """
        Get statistics about active connections
        
        Returns:
            Dictionary with connection statistics
        """
        with self._lock:
            stats = {
                'total_connections': len(self._active_connections),
                'randomizer_enabled': self.randomizer.is_enabled(),
                'connections': {}
            }
            
            for conn_id, conn_data in self._active_connections.items():
                stats['connections'][conn_id] = {
                    'params': conn_data['params'],
                    'start_time': conn_data['start_time'],
                    'duration': time.time() - conn_data['start_time'] if conn_data['start_time'] else 0
                }
        
        return stats
    
    def remove_connection(self, connection_id: str) -> None:
        """
        Remove connection from tracking
        
        Args:
            connection_id: Connection identifier to remove
        """
        with self._lock:
            if connection_id in self._active_connections:
                del self._active_connections[connection_id]
                logger.debug(f"Removed connection {connection_id} from tracking")
    
    def enable_randomization(self) -> None:
        """Enable TCP/IP stack randomization"""
        self.randomizer.enable()
        logger.info("Network layer randomization enabled")
    
    def disable_randomization(self) -> None:
        """Disable TCP/IP stack randomization"""
        self.randomizer.disable()
        logger.info("Network layer randomization disabled")
    
    def reload_config(self) -> None:
        """Reload configuration"""
        self.randomizer.reload_config()
        logger.info("Network layer configuration reloaded")


# Global network layer manager instance
_network_manager = None

def get_network_manager(config_path: str = "honeypot/tcp_config.yaml") -> NetworkLayerManager:
    """
    Get or create global network layer manager
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        NetworkLayerManager instance
    """
    global _network_manager
    if _network_manager is None:
        _network_manager = NetworkLayerManager(config_path)
    return _network_manager


def create_randomized_socket(family=socket.AF_INET, type=socket.SOCK_STREAM, 
                           proto=0, fileno=None) -> RandomizedTCPSocket:
    """
    Create a randomized TCP socket
    
    Args:
        family: Socket family
        type: Socket type
        proto: Protocol
        fileno: File descriptor
        
    Returns:
        RandomizedTCPSocket instance
    """
    manager = get_network_manager()
    return manager.create_socket(family, type, proto, fileno)


@contextmanager
def randomized_socket_context(family=socket.AF_INET, type=socket.SOCK_STREAM, 
                            proto=0, fileno=None):
    """
    Context manager for randomized TCP socket
    
    Args:
        family: Socket family
        type: Socket type
        proto: Protocol
        fileno: File descriptor
        
    Yields:
        RandomizedTCPSocket instance
    """
    sock = create_randomized_socket(family, type, proto, fileno)
    try:
        yield sock
    finally:
        sock.close()


if __name__ == "__main__":
    # Test the network layer
    logging.basicConfig(level=logging.DEBUG)
    
    print("Testing Network Layer Integration")
    print("=" * 40)
    
    # Test socket creation
    manager = get_network_manager()
    print(f"Randomizer enabled: {manager.randomizer.is_enabled()}")
    
    # Test socket creation
    with randomized_socket_context() as sock:
        print("Created randomized socket")
        params = sock.get_connection_params()
        print(f"Socket parameters: {params}")
    
    # Test connection stats
    stats = manager.get_connection_stats()
    print(f"Connection stats: {stats}")

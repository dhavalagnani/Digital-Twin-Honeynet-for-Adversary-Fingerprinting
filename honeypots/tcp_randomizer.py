#!/usr/bin/env python3
"""
Digital Twin Honeynet - TCP/IP Stack Behavior Randomizer
Implements configurable network parameter variations to reduce fingerprinting risk
"""

import yaml
import random
import time
import socket
import struct
import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class NetworkParams:
    """Network parameters for TCP/IP stack randomization"""
    window_size: int
    ttl: int
    mss: int
    response_delay: float
    jitter_range: Tuple[float, float]


class TCPStackRandomizer:
    """
    TCP/IP stack behavior randomizer for honeypot fingerprinting protection
    
    This module provides configurable variations in:
    - TCP handshake response timing (with jitter)
    - Window size variations
    - TTL (Time To Live) variations  
    - MSS (Maximum Segment Size) variations
    """
    
    def __init__(self, config_path: str = "honeypot/tcp_config.yaml"):
        """
        Initialize the TCP stack randomizer
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.enabled = self.config.get('enabled', True)
        
        if self.enabled:
            logger.info("TCP/IP stack randomizer initialized")
            logger.info(f"Configuration loaded from: {config_path}")
        else:
            logger.info("TCP/IP stack randomizer disabled")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        default_config = {
            'enabled': True,
            'timing': {
                'base_response_delay': 0.05,  # 50ms base delay
                'jitter_range': [0.02, 0.05],  # ±20-50ms jitter
                'min_delay': 0.01,  # 10ms minimum
                'max_delay': 0.15   # 150ms maximum
            },
            'network_params': {
                'window_size': {
                    'base': 65535,
                    'variation': 0.1,  # ±10% variation
                    'min': 4096,
                    'max': 131072
                },
                'ttl': {
                    'base': 64,
                    'variation': 0.15,  # ±15% variation
                    'min': 32,
                    'max': 128
                },
                'mss': {
                    'base': 1460,
                    'variation': 0.05,  # ±5% variation
                    'min': 536,
                    'max': 1460
                }
            },
            'production_fingerprint': {
                'window_size': 65535,
                'ttl': 64,
                'mss': 1460,
                'response_delay': 0.03
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Merge with defaults
                    self._merge_configs(default_config, user_config)
                    logger.info("Configuration loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
                logger.info("Using default configuration")
        else:
            logger.info(f"Config file not found: {config_path}")
            logger.info("Creating default configuration file")
            self._save_config(default_config)
        
        return default_config
    
    def _merge_configs(self, default: Dict, user: Dict) -> None:
        """Recursively merge user config with defaults"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_configs(default[key], value)
            else:
                default[key] = value
    
    def _save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to YAML file"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            logger.info(f"Default configuration saved to: {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
    
    def get_randomized_delay(self) -> float:
        """
        Get randomized response delay with jitter
        
        Returns:
            Randomized delay in seconds
        """
        if not self.enabled:
            return 0.0
        
        timing_config = self.config['timing']
        base_delay = timing_config['base_response_delay']
        jitter_min, jitter_max = timing_config['jitter_range']
        
        # Add random jitter
        jitter = random.uniform(-jitter_min, jitter_max)
        delay = base_delay + jitter
        
        # Clamp to min/max bounds
        delay = max(timing_config['min_delay'], 
                   min(timing_config['max_delay'], delay))
        
        logger.debug(f"Randomized delay: {delay:.3f}s (base: {base_delay:.3f}s, jitter: {jitter:.3f}s)")
        return delay
    
    def get_randomized_window_size(self) -> int:
        """
        Get randomized TCP window size
        
        Returns:
            Randomized window size
        """
        if not self.enabled:
            return self.config['production_fingerprint']['window_size']
        
        window_config = self.config['network_params']['window_size']
        base_size = window_config['base']
        variation = window_config['variation']
        
        # Calculate variation range
        variation_amount = int(base_size * variation)
        window_size = random.randint(base_size - variation_amount, 
                                   base_size + variation_amount)
        
        # Clamp to min/max bounds
        window_size = max(window_config['min'], 
                         min(window_config['max'], window_size))
        
        # Ensure it's a multiple of 2 for TCP compliance
        window_size = (window_size // 2) * 2
        
        logger.debug(f"Randomized window size: {window_size} (base: {base_size})")
        return window_size
    
    def get_randomized_ttl(self) -> int:
        """
        Get randomized TTL value
        
        Returns:
            Randomized TTL
        """
        if not self.enabled:
            return self.config['production_fingerprint']['ttl']
        
        ttl_config = self.config['network_params']['ttl']
        base_ttl = ttl_config['base']
        variation = ttl_config['variation']
        
        # Calculate variation range
        variation_amount = int(base_ttl * variation)
        ttl = random.randint(base_ttl - variation_amount, 
                           base_ttl + variation_amount)
        
        # Clamp to min/max bounds
        ttl = max(ttl_config['min'], min(ttl_config['max'], ttl))
        
        logger.debug(f"Randomized TTL: {ttl} (base: {base_ttl})")
        return ttl
    
    def get_randomized_mss(self) -> int:
        """
        Get randomized MSS value
        
        Returns:
            Randomized MSS
        """
        if not self.enabled:
            return self.config['production_fingerprint']['mss']
        
        mss_config = self.config['network_params']['mss']
        base_mss = mss_config['base']
        variation = mss_config['variation']
        
        # Calculate variation range
        variation_amount = int(base_mss * variation)
        mss = random.randint(base_mss - variation_amount, 
                           base_mss + variation_amount)
        
        # Clamp to min/max bounds
        mss = max(mss_config['min'], min(mss_config['max'], mss))
        
        # Ensure it's a multiple of 4 for TCP compliance
        mss = (mss // 4) * 4
        
        logger.debug(f"Randomized MSS: {mss} (base: {base_mss})")
        return mss
    
    def get_randomized_params(self) -> NetworkParams:
        """
        Get all randomized network parameters
        
        Returns:
            NetworkParams object with randomized values
        """
        return NetworkParams(
            window_size=self.get_randomized_window_size(),
            ttl=self.get_randomized_ttl(),
            mss=self.get_randomized_mss(),
            response_delay=self.get_randomized_delay(),
            jitter_range=tuple(self.config['timing']['jitter_range'])
        )
    
    def apply_delay(self) -> None:
        """Apply randomized delay to current execution"""
        if self.enabled:
            delay = self.get_randomized_delay()
            if delay > 0:
                time.sleep(delay)
                logger.debug(f"Applied delay: {delay:.3f}s")
    
    def get_production_fingerprint(self) -> NetworkParams:
        """
        Get production server fingerprint parameters
        
        Returns:
            NetworkParams object with production values
        """
        fingerprint = self.config['production_fingerprint']
        return NetworkParams(
            window_size=fingerprint['window_size'],
            ttl=fingerprint['ttl'],
            mss=fingerprint['mss'],
            response_delay=fingerprint['response_delay'],
            jitter_range=(0.0, 0.0)  # No jitter for production
        )
    
    def is_enabled(self) -> bool:
        """Check if randomizer is enabled"""
        return self.enabled
    
    def enable(self) -> None:
        """Enable the randomizer"""
        self.enabled = True
        logger.info("TCP/IP stack randomizer enabled")
    
    def disable(self) -> None:
        """Disable the randomizer"""
        self.enabled = False
        logger.info("TCP/IP stack randomizer disabled")
    
    def reload_config(self) -> None:
        """Reload configuration from file"""
        self.config = self._load_config()
        logger.info("Configuration reloaded")


# Global instance for easy access
_tcp_randomizer = None

def get_tcp_randomizer(config_path: str = "honeypot/tcp_config.yaml") -> TCPStackRandomizer:
    """
    Get or create global TCP randomizer instance
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        TCPStackRandomizer instance
    """
    global _tcp_randomizer
    if _tcp_randomizer is None:
        _tcp_randomizer = TCPStackRandomizer(config_path)
    return _tcp_randomizer


def apply_tcp_randomization() -> None:
    """Apply TCP randomization delay to current execution"""
    randomizer = get_tcp_randomizer()
    randomizer.apply_delay()


def get_randomized_network_params() -> NetworkParams:
    """Get randomized network parameters"""
    randomizer = get_tcp_randomizer()
    return randomizer.get_randomized_params()


if __name__ == "__main__":
    # Test the randomizer
    logging.basicConfig(level=logging.DEBUG)
    
    randomizer = TCPStackRandomizer()
    
    print("Testing TCP/IP Stack Randomizer")
    print("=" * 40)
    
    for i in range(5):
        params = randomizer.get_randomized_params()
        print(f"Test {i+1}:")
        print(f"  Window Size: {params.window_size}")
        print(f"  TTL: {params.ttl}")
        print(f"  MSS: {params.mss}")
        print(f"  Response Delay: {params.response_delay:.3f}s")
        print()
    
    print("Production Fingerprint:")
    prod_params = randomizer.get_production_fingerprint()
    print(f"  Window Size: {prod_params.window_size}")
    print(f"  TTL: {prod_params.ttl}")
    print(f"  MSS: {prod_params.mss}")
    print(f"  Response Delay: {prod_params.response_delay:.3f}s")

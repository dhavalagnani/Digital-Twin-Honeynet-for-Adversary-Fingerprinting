#!/usr/bin/env python3
"""
Unit tests for TCP/IP Stack Behavior Randomizer
Tests all randomization parameters and configuration options
"""

import unittest
import tempfile
import yaml
import time
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the honeypot directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / 'honeypot'))

from tcp_randomizer import TCPStackRandomizer, NetworkParams, get_tcp_randomizer, apply_tcp_randomization, get_randomized_network_params
from network_layer import RandomizedTCPSocket, NetworkLayerManager, get_network_manager


class TestTCPStackRandomizer(unittest.TestCase):
    """Test cases for TCPStackRandomizer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary config file
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, 'test_tcp_config.yaml')
        
        # Test configuration
        self.test_config = {
            'enabled': True,
            'timing': {
                'base_response_delay': 0.05,
                'jitter_range': [0.02, 0.05],
                'min_delay': 0.01,
                'max_delay': 0.15
            },
            'network_params': {
                'window_size': {
                    'base': 65535,
                    'variation': 0.1,
                    'min': 4096,
                    'max': 131072
                },
                'ttl': {
                    'base': 64,
                    'variation': 0.15,
                    'min': 32,
                    'max': 128
                },
                'mss': {
                    'base': 1460,
                    'variation': 0.05,
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
        
        # Write test config
        with open(self.config_path, 'w') as f:
            yaml.dump(self.test_config, f)
        
        # Create randomizer instance
        self.randomizer = TCPStackRandomizer(self.config_path)
    
    def tearDown(self):
        """Clean up test fixtures"""
        # Remove temporary files
        if os.path.exists(self.config_path):
            os.remove(self.config_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)
    
    def test_initialization(self):
        """Test randomizer initialization"""
        self.assertIsNotNone(self.randomizer)
        self.assertTrue(self.randomizer.is_enabled())
        self.assertEqual(self.randomizer.config_path, Path(self.config_path))
    
    def test_config_loading(self):
        """Test configuration loading from YAML"""
        config = self.randomizer.config
        
        # Check timing configuration
        self.assertEqual(config['timing']['base_response_delay'], 0.05)
        self.assertEqual(config['timing']['jitter_range'], [0.02, 0.05])
        self.assertEqual(config['timing']['min_delay'], 0.01)
        self.assertEqual(config['timing']['max_delay'], 0.15)
        
        # Check network parameters
        self.assertEqual(config['network_params']['window_size']['base'], 65535)
        self.assertEqual(config['network_params']['ttl']['base'], 64)
        self.assertEqual(config['network_params']['mss']['base'], 1460)
        
        # Check production fingerprint
        self.assertEqual(config['production_fingerprint']['window_size'], 65535)
        self.assertEqual(config['production_fingerprint']['ttl'], 64)
        self.assertEqual(config['production_fingerprint']['mss'], 1460)
    
    def test_randomized_delay(self):
        """Test randomized delay generation"""
        delays = []
        for _ in range(100):
            delay = self.randomizer.get_randomized_delay()
            delays.append(delay)
            
            # Check bounds
            self.assertGreaterEqual(delay, 0.01)  # min_delay
            self.assertLessEqual(delay, 0.15)     # max_delay
        
        # Check that delays vary (not all the same)
        unique_delays = set(delays)
        self.assertGreater(len(unique_delays), 1)
        
        # Check average is reasonable
        avg_delay = sum(delays) / len(delays)
        self.assertGreater(avg_delay, 0.03)  # Should be above min
        self.assertLess(avg_delay, 0.12)     # Should be below max
    
    def test_randomized_window_size(self):
        """Test randomized window size generation"""
        window_sizes = []
        for _ in range(100):
            window_size = self.randomizer.get_randomized_window_size()
            window_sizes.append(window_size)
            
            # Check bounds
            self.assertGreaterEqual(window_size, 4096)   # min
            self.assertLessEqual(window_size, 131072)    # max
            
            # Check TCP compliance (multiple of 2)
            self.assertEqual(window_size % 2, 0)
        
        # Check that window sizes vary
        unique_sizes = set(window_sizes)
        self.assertGreater(len(unique_sizes), 1)
        
        # Check average is reasonable
        avg_size = sum(window_sizes) / len(window_sizes)
        self.assertGreater(avg_size, 50000)  # Should be above min
        self.assertLess(avg_size, 120000)    # Should be below max
    
    def test_randomized_ttl(self):
        """Test randomized TTL generation"""
        ttls = []
        for _ in range(100):
            ttl = self.randomizer.get_randomized_ttl()
            ttls.append(ttl)
            
            # Check bounds
            self.assertGreaterEqual(ttl, 32)   # min
            self.assertLessEqual(ttl, 128)     # max
        
        # Check that TTLs vary
        unique_ttls = set(ttls)
        self.assertGreater(len(unique_ttls), 1)
        
        # Check average is reasonable
        avg_ttl = sum(ttls) / len(ttls)
        self.assertGreater(avg_ttl, 40)   # Should be above min
        self.assertLess(avg_ttl, 100)     # Should be below max
    
    def test_randomized_mss(self):
        """Test randomized MSS generation"""
        mss_values = []
        for _ in range(100):
            mss = self.randomizer.get_randomized_mss()
            mss_values.append(mss)
            
            # Check bounds
            self.assertGreaterEqual(mss, 536)   # min
            self.assertLessEqual(mss, 1460)     # max
            
            # Check TCP compliance (multiple of 4)
            self.assertEqual(mss % 4, 0)
        
        # Check that MSS values vary
        unique_mss = set(mss_values)
        self.assertGreater(len(unique_mss), 1)
        
        # Check average is reasonable
        avg_mss = sum(mss_values) / len(mss_values)
        self.assertGreater(avg_mss, 800)   # Should be above min
        self.assertLess(avg_mss, 1450)     # Should be below max (adjusted for base value of 1460)
    
    def test_get_randomized_params(self):
        """Test getting all randomized parameters"""
        params = self.randomizer.get_randomized_params()
        
        # Check parameter types
        self.assertIsInstance(params, NetworkParams)
        self.assertIsInstance(params.window_size, int)
        self.assertIsInstance(params.ttl, int)
        self.assertIsInstance(params.mss, int)
        self.assertIsInstance(params.response_delay, float)
        self.assertIsInstance(params.jitter_range, tuple)
        
        # Check bounds
        self.assertGreaterEqual(params.window_size, 4096)
        self.assertLessEqual(params.window_size, 131072)
        self.assertGreaterEqual(params.ttl, 32)
        self.assertLessEqual(params.ttl, 128)
        self.assertGreaterEqual(params.mss, 536)
        self.assertLessEqual(params.mss, 1460)
        self.assertGreaterEqual(params.response_delay, 0.01)
        self.assertLessEqual(params.response_delay, 0.15)
    
    def test_apply_delay(self):
        """Test delay application"""
        start_time = time.time()
        self.randomizer.apply_delay()
        end_time = time.time()
        
        # Check that delay was applied
        elapsed = end_time - start_time
        self.assertGreater(elapsed, 0.01)  # Should have some delay
        self.assertLess(elapsed, 0.2)      # Should not be excessive
    
    def test_disabled_randomizer(self):
        """Test behavior when randomizer is disabled"""
        self.randomizer.disable()
        
        # Check that randomization is disabled
        self.assertFalse(self.randomizer.is_enabled())
        
        # Check that delays are zero when disabled
        delay = self.randomizer.get_randomized_delay()
        self.assertEqual(delay, 0.0)
        
        # Check that parameters match production fingerprint
        window_size = self.randomizer.get_randomized_window_size()
        ttl = self.randomizer.get_randomized_ttl()
        mss = self.randomizer.get_randomized_mss()
        
        self.assertEqual(window_size, 65535)
        self.assertEqual(ttl, 64)
        self.assertEqual(mss, 1460)
    
    def test_enable_disable(self):
        """Test enable/disable functionality"""
        # Start disabled
        self.randomizer.disable()
        self.assertFalse(self.randomizer.is_enabled())
        
        # Enable
        self.randomizer.enable()
        self.assertTrue(self.randomizer.is_enabled())
        
        # Disable again
        self.randomizer.disable()
        self.assertFalse(self.randomizer.is_enabled())
    
    def test_reload_config(self):
        """Test configuration reloading"""
        # Modify config file
        new_config = self.test_config.copy()
        new_config['timing']['base_response_delay'] = 0.1
        
        with open(self.config_path, 'w') as f:
            yaml.dump(new_config, f)
        
        # Reload config
        self.randomizer.reload_config()
        
        # Check that new value is loaded
        self.assertEqual(self.randomizer.config['timing']['base_response_delay'], 0.1)
    
    def test_production_fingerprint(self):
        """Test production fingerprint retrieval"""
        fingerprint = self.randomizer.get_production_fingerprint()
        
        self.assertEqual(fingerprint.window_size, 65535)
        self.assertEqual(fingerprint.ttl, 64)
        self.assertEqual(fingerprint.mss, 1460)
        self.assertEqual(fingerprint.response_delay, 0.03)
        self.assertEqual(fingerprint.jitter_range, (0.0, 0.0))


class TestNetworkLayer(unittest.TestCase):
    """Test cases for NetworkLayerManager and RandomizedTCPSocket"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, 'test_network_config.yaml')
        
        # Create test config
        test_config = {
            'enabled': True,
            'timing': {
                'base_response_delay': 0.01,  # Shorter for testing
                'jitter_range': [0.005, 0.01],
                'min_delay': 0.001,
                'max_delay': 0.05
            },
            'network_params': {
                'window_size': {
                    'base': 65535,
                    'variation': 0.1,
                    'min': 4096,
                    'max': 131072
                },
                'ttl': {
                    'base': 64,
                    'variation': 0.15,
                    'min': 32,
                    'max': 128
                },
                'mss': {
                    'base': 1460,
                    'variation': 0.05,
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
        
        with open(self.config_path, 'w') as f:
            yaml.dump(test_config, f)
        
        self.manager = NetworkLayerManager(self.config_path)
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.config_path):
            os.remove(self.config_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)
    
    def test_manager_initialization(self):
        """Test NetworkLayerManager initialization"""
        self.assertIsNotNone(self.manager)
        self.assertIsNotNone(self.manager.randomizer)
        self.assertTrue(self.manager.randomizer.is_enabled())
    
    def test_socket_creation(self):
        """Test randomized socket creation"""
        socket = self.manager.create_socket()
        
        self.assertIsInstance(socket, RandomizedTCPSocket)
        self.assertIsNotNone(socket.randomizer)
        self.assertTrue(socket.randomizer.is_enabled())
    
    def test_socket_context_manager(self):
        """Test socket context manager"""
        with self.manager.create_socket() as sock:
            self.assertIsInstance(sock, RandomizedTCPSocket)
            # Socket should be closed automatically
    
    def test_connection_tracking(self):
        """Test connection tracking functionality"""
        socket = self.manager.create_socket()
        connection_id = "test_connection_001"
        
        # Apply randomization to connection
        self.manager.apply_connection_randomization(socket, connection_id)
        
        # Check connection stats
        stats = self.manager.get_connection_stats()
        self.assertEqual(stats['total_connections'], 1)
        self.assertTrue(stats['randomizer_enabled'])
        self.assertIn(connection_id, stats['connections'])
        
        # Remove connection
        self.manager.remove_connection(connection_id)
        
        # Check that connection was removed
        stats = self.manager.get_connection_stats()
        self.assertEqual(stats['total_connections'], 0)
    
    def test_enable_disable_randomization(self):
        """Test enabling/disabling randomization"""
        # Start enabled
        self.assertTrue(self.manager.randomizer.is_enabled())
        
        # Disable
        self.manager.disable_randomization()
        self.assertFalse(self.manager.randomizer.is_enabled())
        
        # Enable
        self.manager.enable_randomization()
        self.assertTrue(self.manager.randomizer.is_enabled())
    
    def test_reload_config(self):
        """Test configuration reloading"""
        self.manager.reload_config()
        # Should not raise any exceptions


class TestGlobalFunctions(unittest.TestCase):
    """Test cases for global functions"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, 'test_global_config.yaml')
        
        # Create test config
        test_config = {
            'enabled': True,
            'timing': {
                'base_response_delay': 0.01,
                'jitter_range': [0.005, 0.01],
                'min_delay': 0.001,
                'max_delay': 0.05
            },
            'network_params': {
                'window_size': {
                    'base': 65535,
                    'variation': 0.1,
                    'min': 4096,
                    'max': 131072
                },
                'ttl': {
                    'base': 64,
                    'variation': 0.15,
                    'min': 32,
                    'max': 128
                },
                'mss': {
                    'base': 1460,
                    'variation': 0.05,
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
        
        with open(self.config_path, 'w') as f:
            yaml.dump(test_config, f)
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.config_path):
            os.remove(self.config_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)
    
    def test_get_tcp_randomizer(self):
        """Test get_tcp_randomizer function"""
        randomizer = get_tcp_randomizer(self.config_path)
        self.assertIsInstance(randomizer, TCPStackRandomizer)
        self.assertTrue(randomizer.is_enabled())
    
    def test_get_network_manager(self):
        """Test get_network_manager function"""
        manager = get_network_manager(self.config_path)
        self.assertIsInstance(manager, NetworkLayerManager)
        self.assertTrue(manager.randomizer.is_enabled())
    
    def test_apply_tcp_randomization(self):
        """Test apply_tcp_randomization function"""
        # Should not raise any exceptions
        apply_tcp_randomization()
    
    def test_get_randomized_network_params(self):
        """Test get_randomized_network_params function"""
        params = get_randomized_network_params()
        self.assertIsInstance(params, NetworkParams)
        self.assertIsInstance(params.window_size, int)
        self.assertIsInstance(params.ttl, int)
        self.assertIsInstance(params.mss, int)
        self.assertIsInstance(params.response_delay, float)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
Unit tests for Banner Matcher Module
Tests SSH banner and response matching functionality
"""
import unittest
import tempfile
import yaml
import time
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

# Add the honeypot directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / 'honeypot'))

from banner_matcher import BannerMatcher, BannerConfig, AuthMessages, SessionResponses, get_banner_matcher, apply_banner_matching, get_production_banner, get_randomized_banner_delay

class TestBannerMatcher(unittest.TestCase):
    """Test cases for BannerMatcher class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_cowrie.cfg')
        
        # Create test configuration
        self.test_config = """
[ssh]
enabled = true
port = 2222
version = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
hostname = production-server

[banner]
enabled = true
production_banner = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
alternative_banners = SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.1,SSH-2.0-OpenSSH_8.1p1 Debian-1+deb11u2
rotation_interval = 0

[banner_timing]
enabled = true
base_delay = 0.05
jitter_range = 0.02
min_delay = 0.01
max_delay = 0.15
connection_variation = true

[auth_messages]
enabled = true
auth_failure_msg = Permission denied, please try again.
auth_success_msg = 
invalid_username_msg = Invalid username.
account_locked_msg = Account locked due to too many failed attempts.
max_failed_attempts = 5
lockout_duration = 3600

[session_responses]
enabled = true
welcome_msg = Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)
last_login_format = Last login: {timestamp} from {ip}
prompt_style = {username}@{hostname}:{path}$
default_prompt = admin@production-server:~$
root_prompt = root@production-server:~#
command_not_found = {command}: command not found
permission_denied = Permission denied
"""
        
        with open(self.config_file, 'w') as f:
            f.write(self.test_config)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_banner_matcher_initialization(self):
        """Test banner matcher initialization"""
        matcher = BannerMatcher(self.config_file)
        
        self.assertIsNotNone(matcher)
        self.assertEqual(matcher.banner_config.production_banner, 
                        'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5')
        self.assertTrue(matcher.banner_config.banner_randomization_enabled)
        self.assertEqual(matcher.banner_config.base_delay, 0.05)
    
    def test_get_banner_production_mode(self):
        """Test getting banner in production mode (randomization disabled)"""
        # Create config with randomization disabled
        config_without_randomization = self.test_config.replace(
            'enabled = true', 'enabled = false'
        )
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(config_without_randomization)
            temp_config = f.name
        
        try:
            matcher = BannerMatcher(temp_config)
            banner = matcher.get_banner()
            
            self.assertEqual(banner, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5')
        finally:
            os.unlink(temp_config)
    
    def test_get_banner_randomization_mode(self):
        """Test getting banner in randomization mode"""
        matcher = BannerMatcher(self.config_file)
        
        # Test multiple banner retrievals
        banners = []
        for _ in range(10):
            banner = matcher.get_banner()
            banners.append(banner)
        
        # Should get different banners (randomization enabled)
        unique_banners = set(banners)
        self.assertGreater(len(unique_banners), 1)
        
        # All banners should be from the alternative banners list
        expected_banners = [
            'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
            'SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.1',
            'SSH-2.0-OpenSSH_8.1p1 Debian-1+deb11u2'
        ]
        for banner in unique_banners:
            self.assertIn(banner, expected_banners)
    
    def test_get_banner_delay(self):
        """Test banner delay calculation"""
        matcher = BannerMatcher(self.config_file)
        
        delays = []
        for i in range(10):
            delay = matcher.get_banner_delay(f"conn_{i}")
            delays.append(delay)
        
        # All delays should be within bounds
        for delay in delays:
            self.assertGreaterEqual(delay, 0.01)  # min_delay
            self.assertLessEqual(delay, 0.15)     # max_delay
        
        # Delays should vary (due to jitter)
        unique_delays = set(delays)
        self.assertGreater(len(unique_delays), 1)
    
    def test_auth_messages(self):
        """Test authentication message retrieval"""
        matcher = BannerMatcher(self.config_file)
        
        self.assertEqual(matcher.get_auth_failure_message(), 
                        'Permission denied, please try again.')
        self.assertEqual(matcher.get_invalid_username_message(), 
                        'Invalid username.')
        self.assertEqual(matcher.get_account_locked_message(), 
                        'Account locked due to too many failed attempts.')
    
    def test_session_responses(self):
        """Test session response retrieval"""
        matcher = BannerMatcher(self.config_file)
        
        self.assertEqual(matcher.get_welcome_message(), 
                        'Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)')
        self.assertEqual(matcher.get_prompt(), 
                        'admin@production-server:~$')
        self.assertEqual(matcher.get_prompt(is_root=True), 
                        'root@production-server:~#')
        self.assertEqual(matcher.get_command_not_found_message('test_cmd'), 
                        'test_cmd: command not found')
        self.assertEqual(matcher.get_permission_denied_message(), 
                        'Permission denied')
    
    def test_last_login_message(self):
        """Test last login message formatting"""
        matcher = BannerMatcher(self.config_file)
        
        message = matcher.get_last_login_message('192.168.1.100')
        
        # Should contain IP address
        self.assertIn('192.168.1.100', message)
        # Should contain timestamp format
        self.assertIn('Last login:', message)
    
    def test_reload_config(self):
        """Test configuration reloading"""
        matcher = BannerMatcher(self.config_file)
        
        # Get initial banner
        initial_banner = matcher.get_banner()
        
        # Modify config file
        modified_config = self.test_config.replace(
            'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
            'SSH-2.0-OpenSSH_9.0p1 Ubuntu-6ubuntu1.1'
        )
        
        with open(self.config_file, 'w') as f:
            f.write(modified_config)
        
        # Reload config
        matcher.reload_config()
        
        # Banner should be updated
        new_banner = matcher.get_banner()
        self.assertNotEqual(initial_banner, new_banner)
        self.assertIn('SSH-2.0-OpenSSH_9.0p1', new_banner)

class TestGlobalFunctions(unittest.TestCase):
    """Test cases for global functions"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_cowrie.cfg')
        
        # Create minimal test configuration
        test_config = """
[ssh]
version = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

[banner]
enabled = false
production_banner = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

[banner_timing]
enabled = true
base_delay = 0.05
jitter_range = 0.02
min_delay = 0.01
max_delay = 0.15
"""
        
        with open(self.config_file, 'w') as f:
            f.write(test_config)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_get_banner_matcher(self):
        """Test global banner matcher function"""
        matcher = get_banner_matcher(self.config_file)
        
        self.assertIsNotNone(matcher)
        self.assertIsInstance(matcher, BannerMatcher)
    
    def test_apply_banner_matching(self):
        """Test apply banner matching function"""
        # Should not raise any exceptions
        apply_banner_matching()
    
    def test_get_production_banner(self):
        """Test get production banner function"""
        banner = get_production_banner()
        
        self.assertIsInstance(banner, str)
        self.assertIn('SSH-2.0-OpenSSH', banner)
    
    def test_get_randomized_banner_delay(self):
        """Test get randomized banner delay function"""
        delay = get_randomized_banner_delay("test_connection")
        
        self.assertIsInstance(delay, float)
        self.assertGreater(delay, 0)

class TestBannerConfig(unittest.TestCase):
    """Test cases for BannerConfig dataclass"""
    
    def test_banner_config_creation(self):
        """Test BannerConfig dataclass creation"""
        config = BannerConfig(
            production_banner="SSH-2.0-OpenSSH_8.2p1",
            alternative_banners=["SSH-2.0-OpenSSH_8.4p1"],
            banner_randomization_enabled=True,
            rotation_interval=0,
            base_delay=0.05,
            jitter_range=0.02,
            min_delay=0.01,
            max_delay=0.15,
            connection_variation=True
        )
        
        self.assertEqual(config.production_banner, "SSH-2.0-OpenSSH_8.2p1")
        self.assertTrue(config.banner_randomization_enabled)
        self.assertEqual(config.base_delay, 0.05)

class TestAuthMessages(unittest.TestCase):
    """Test cases for AuthMessages dataclass"""
    
    def test_auth_messages_creation(self):
        """Test AuthMessages dataclass creation"""
        messages = AuthMessages(
            auth_failure_msg="Permission denied",
            auth_success_msg="",
            invalid_username_msg="Invalid username",
            account_locked_msg="Account locked",
            max_failed_attempts=5,
            lockout_duration=3600
        )
        
        self.assertEqual(messages.auth_failure_msg, "Permission denied")
        self.assertEqual(messages.max_failed_attempts, 5)

class TestSessionResponses(unittest.TestCase):
    """Test cases for SessionResponses dataclass"""
    
    def test_session_responses_creation(self):
        """Test SessionResponses dataclass creation"""
        responses = SessionResponses(
            welcome_msg="Welcome",
            last_login_format="Last login: {timestamp}",
            prompt_style="{username}@{hostname}$",
            default_prompt="admin@server:~$",
            root_prompt="root@server:~#",
            command_not_found="{command}: command not found",
            permission_denied="Permission denied"
        )
        
        self.assertEqual(responses.welcome_msg, "Welcome")
        self.assertEqual(responses.default_prompt, "admin@server:~$")

if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)

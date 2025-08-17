#!/usr/bin/env python3
"""
Digital Twin Honeynet - Banner and Response Matcher
Implements configurable SSH banner and response matching to mimic production server
"""
import yaml
import random
import time
import logging
import socket
import threading
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone
import configparser

logger = logging.getLogger(__name__)

@dataclass
class BannerConfig:
    """Configuration for SSH banner and response matching"""
    production_banner: str
    alternative_banners: List[str]
    banner_randomization_enabled: bool
    rotation_interval: int
    base_delay: float
    jitter_range: float
    min_delay: float
    max_delay: float
    connection_variation: bool

@dataclass
class AuthMessages:
    """Authentication message configuration"""
    auth_failure_msg: str
    auth_success_msg: str
    invalid_username_msg: str
    account_locked_msg: str
    max_failed_attempts: int
    lockout_duration: int

@dataclass
class SessionResponses:
    """Session response configuration"""
    welcome_msg: str
    last_login_format: str
    prompt_style: str
    default_prompt: str
    root_prompt: str
    command_not_found: str
    permission_denied: str

class BannerMatcher:
    """Handles SSH banner and response matching for production server mimicry"""
    
    def __init__(self, config_path: str = "honeypot/cowrie.cfg"):
        """Initialize banner matcher with configuration"""
        self.config_path = config_path
        self.config = self._load_config()
        self.banner_config = self._parse_banner_config()
        self.auth_messages = self._parse_auth_messages()
        self.session_responses = self._parse_session_responses()
        self.current_banner = self.banner_config.production_banner
        self.last_banner_rotation = time.time()
        self._lock = threading.Lock()
        
        logger.info("Banner matcher initialized with production server configuration")
    
    def _load_config(self) -> configparser.ConfigParser:
        """Load Cowrie configuration file"""
        config = configparser.ConfigParser()
        if Path(self.config_path).exists():
            config.read(self.config_path)
        else:
            logger.warning(f"Configuration file {self.config_path} not found, using defaults")
        return config
    
    def _parse_banner_config(self) -> BannerConfig:
        """Parse banner configuration from Cowrie config"""
        try:
            banner_section = self.config.get('banner', 'enabled', fallback='false')
            banner_enabled = banner_section.lower() == 'true'
            
            production_banner = self.config.get('ssh', 'version', 
                                              fallback='SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5')
            
            # Parse alternative banners (simplified parsing)
            alt_banners_str = self.config.get('banner', 'alternative_banners', 
                                            fallback='SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.1,SSH-2.0-OpenSSH_8.1p1 Debian-1+deb11u2')
            alternative_banners = [b.strip() for b in alt_banners_str.split(',')]
            
            rotation_interval = self.config.getint('banner', 'rotation_interval', fallback=0)
            
            # Parse timing configuration
            base_delay = self.config.getfloat('banner_timing', 'base_delay', fallback=0.05)
            jitter_range = self.config.getfloat('banner_timing', 'jitter_range', fallback=0.02)
            min_delay = self.config.getfloat('banner_timing', 'min_delay', fallback=0.01)
            max_delay = self.config.getfloat('banner_timing', 'max_delay', fallback=0.15)
            connection_variation = self.config.getboolean('banner_timing', 'connection_variation', fallback=True)
            
            return BannerConfig(
                production_banner=production_banner,
                alternative_banners=alternative_banners,
                banner_randomization_enabled=banner_enabled,
                rotation_interval=rotation_interval,
                base_delay=base_delay,
                jitter_range=jitter_range,
                min_delay=min_delay,
                max_delay=max_delay,
                connection_variation=connection_variation
            )
        except Exception as e:
            logger.error(f"Error parsing banner config: {e}")
            return BannerConfig(
                production_banner='SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
                alternative_banners=['SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.1'],
                banner_randomization_enabled=False,
                rotation_interval=0,
                base_delay=0.05,
                jitter_range=0.02,
                min_delay=0.01,
                max_delay=0.15,
                connection_variation=True
            )
    
    def _parse_auth_messages(self) -> AuthMessages:
        """Parse authentication message configuration"""
        try:
            return AuthMessages(
                auth_failure_msg=self.config.get('auth_messages', 'auth_failure_msg', 
                                               fallback='Permission denied, please try again.'),
                auth_success_msg=self.config.get('auth_messages', 'auth_success_msg', fallback=''),
                invalid_username_msg=self.config.get('auth_messages', 'invalid_username_msg', 
                                                   fallback='Invalid username.'),
                account_locked_msg=self.config.get('auth_messages', 'account_locked_msg', 
                                                 fallback='Account locked due to too many failed attempts.'),
                max_failed_attempts=self.config.getint('auth_messages', 'max_failed_attempts', fallback=5),
                lockout_duration=self.config.getint('auth_messages', 'lockout_duration', fallback=3600)
            )
        except Exception as e:
            logger.error(f"Error parsing auth messages: {e}")
            return AuthMessages(
                auth_failure_msg='Permission denied, please try again.',
                auth_success_msg='',
                invalid_username_msg='Invalid username.',
                account_locked_msg='Account locked due to too many failed attempts.',
                max_failed_attempts=5,
                lockout_duration=3600
            )
    
    def _parse_session_responses(self) -> SessionResponses:
        """Parse session response configuration"""
        try:
            return SessionResponses(
                welcome_msg=self.config.get('session_responses', 'welcome_msg', 
                                          fallback='Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)'),
                last_login_format=self.config.get('session_responses', 'last_login_format', 
                                                fallback='Last login: {timestamp} from {ip}'),
                prompt_style=self.config.get('session_responses', 'prompt_style', 
                                           fallback='{username}@{hostname}:{path}$'),
                default_prompt=self.config.get('session_responses', 'default_prompt', 
                                             fallback='admin@production-server:~$'),
                root_prompt=self.config.get('session_responses', 'root_prompt', 
                                          fallback='root@production-server:~#'),
                command_not_found=self.config.get('session_responses', 'command_not_found', 
                                                fallback='{command}: command not found'),
                permission_denied=self.config.get('session_responses', 'permission_denied', 
                                                fallback='Permission denied')
            )
        except Exception as e:
            logger.error(f"Error parsing session responses: {e}")
            return SessionResponses(
                welcome_msg='Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)',
                last_login_format='Last login: {timestamp} from {ip}',
                prompt_style='{username}@{hostname}:{path}$',
                default_prompt='admin@production-server:~$',
                root_prompt='root@production-server:~#',
                command_not_found='{command}: command not found',
                permission_denied='Permission denied'
            )
    
    def get_banner(self) -> str:
        """Get the current SSH banner (production or randomized)"""
        with self._lock:
            if not self.banner_config.banner_randomization_enabled:
                return self.banner_config.production_banner
            
            # Check if it's time to rotate the banner
            current_time = time.time()
            if (self.banner_config.rotation_interval > 0 and 
                current_time - self.last_banner_rotation > self.banner_config.rotation_interval):
                self._rotate_banner()
                self.last_banner_rotation = current_time
            
            return self.current_banner
    
    def _rotate_banner(self) -> None:
        """Rotate to a new banner from the alternative banners list"""
        if self.banner_config.alternative_banners:
            self.current_banner = random.choice(self.banner_config.alternative_banners)
            logger.debug(f"Rotated banner to: {self.current_banner}")
    
    def get_banner_delay(self, connection_id: Optional[str] = None) -> float:
        """Calculate randomized banner delay for realistic timing"""
        if not self.banner_config.connection_variation:
            base_delay = self.banner_config.base_delay
        else:
            # Add connection-specific variation
            if connection_id:
                random.seed(hash(connection_id))
            base_delay = self.banner_config.base_delay
        
        # Add jitter
        jitter = random.uniform(-self.banner_config.jitter_range, self.banner_config.jitter_range)
        delay = base_delay + jitter
        
        # Clamp to min/max bounds
        delay = max(self.banner_config.min_delay, min(self.banner_config.max_delay, delay))
        
        logger.debug(f"Calculated banner delay: {delay:.3f}s for connection {connection_id}")
        return delay
    
    def get_auth_failure_message(self) -> str:
        """Get authentication failure message"""
        return self.auth_messages.auth_failure_msg
    
    def get_auth_success_message(self) -> str:
        """Get authentication success message"""
        return self.auth_messages.auth_success_msg
    
    def get_invalid_username_message(self) -> str:
        """Get invalid username message"""
        return self.auth_messages.invalid_username_msg
    
    def get_account_locked_message(self) -> str:
        """Get account locked message"""
        return self.auth_messages.account_locked_msg
    
    def get_welcome_message(self) -> str:
        """Get welcome message"""
        return self.session_responses.welcome_msg
    
    def get_last_login_message(self, ip: str) -> str:
        """Get formatted last login message"""
        timestamp = datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Y %Z')
        return self.session_responses.last_login_format.format(timestamp=timestamp, ip=ip)
    
    def get_prompt(self, username: str = "admin", hostname: str = "production-server", 
                  path: str = "~", is_root: bool = False) -> str:
        """Get formatted command prompt"""
        if is_root:
            return self.session_responses.root_prompt
        else:
            return self.session_responses.prompt_style.format(
                username=username, hostname=hostname, path=path
            )
    
    def get_command_not_found_message(self, command: str) -> str:
        """Get command not found message"""
        return self.session_responses.command_not_found.format(command=command)
    
    def get_permission_denied_message(self) -> str:
        """Get permission denied message"""
        return self.session_responses.permission_denied
    
    def reload_config(self) -> None:
        """Reload configuration from file"""
        logger.info("Reloading banner matcher configuration")
        self.config = self._load_config()
        self.banner_config = self._parse_banner_config()
        self.auth_messages = self._parse_auth_messages()
        self.session_responses = self._parse_session_responses()
        logger.info("Configuration reloaded successfully")

# Global banner matcher instance
_banner_matcher = None

def get_banner_matcher(config_path: str = "honeypot/cowrie.cfg") -> BannerMatcher:
    """Get or create global banner matcher instance"""
    global _banner_matcher
    if _banner_matcher is None:
        _banner_matcher = BannerMatcher(config_path)
    return _banner_matcher

def apply_banner_matching() -> None:
    """Apply banner matching configuration"""
    matcher = get_banner_matcher()
    logger.info("Banner matching applied successfully")

def get_production_banner() -> str:
    """Get the production server banner"""
    matcher = get_banner_matcher()
    return matcher.get_banner()

def get_randomized_banner_delay(connection_id: Optional[str] = None) -> float:
    """Get randomized banner delay"""
    matcher = get_banner_matcher()
    return matcher.get_banner_delay(connection_id)

if __name__ == '__main__':
    # Test the banner matcher functionality
    logging.basicConfig(level=logging.INFO)
    
    print("Testing Banner Matcher Module")
    print("=" * 40)
    
    matcher = get_banner_matcher()
    
    print(f"Production Banner: {matcher.get_banner()}")
    print(f"Auth Failure Message: {matcher.get_auth_failure_message()}")
    print(f"Welcome Message: {matcher.get_welcome_message()}")
    print(f"Default Prompt: {matcher.get_prompt()}")
    print(f"Root Prompt: {matcher.get_prompt(is_root=True)}")
    print(f"Command Not Found: {matcher.get_command_not_found_message('invalid_cmd')}")
    print(f"Last Login: {matcher.get_last_login_message('192.168.1.100')}")
    
    # Test banner delay
    delays = [matcher.get_banner_delay(f"conn_{i}") for i in range(5)]
    print(f"Banner Delays: {[f'{d:.3f}s' for d in delays]}")
    
    print("\n✅ Banner matcher module test completed successfully!")

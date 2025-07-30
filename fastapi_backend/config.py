#!/usr/bin/env python3
"""
Digital Twin Honeynet - Configuration
Defines behavioral rules, system settings, and thresholds
"""

import os
from typing import List, Dict, Any

# Behavioral Analysis Rules
BEHAVIOR_RULES = {
    # Brute Force Detection
    'brute_force_threshold': 5,        # Number of failed attempts
    'brute_force_window': 60,          # Time window in seconds
    'brute_force_cooldown': 300,       # Cooldown period in seconds
    
    # Timing Analysis
    'legitimate_delay_min': 1.0,       # Minimum delay between attempts (seconds)
    'legitimate_delay_max': 5.0,       # Maximum delay between attempts (seconds)
    'suspicious_timing_threshold': 0.5, # Suspicious if faster than this
    
    # Suspicious Patterns
    'suspicious_patterns': [
        'admin', 'root', 'test', 'guest', 'user', 'ubuntu', 'centos',
        'debian', 'pi', 'raspberry', 'docker', 'jenkins', 'git'
    ],
    
    # Weak Passwords
    'weak_passwords': [
        'password', '123456', 'admin', 'root', 'test', 'guest',
        'ubuntu', 'centos', 'debian', 'raspberry', 'docker',
        'password123', 'admin123', 'root123', 'test123'
    ],
    
    # Network Whitelist
    'redirect_whitelist': [
        '192.168.1.0/24',    # Local network
        '10.0.0.0/8',        # Private network A
        '172.16.0.0/12'      # Private network B
    ],
    
    # Threat Scoring
    'threat_score_weights': {
        'failed_login': 10,
        'suspicious_username': 5,
        'weak_password': 3,
        'dangerous_command': 50,
        'file_download': 30,
        'multiple_sessions': 20,
        'timing_anomaly': 15
    },
    
    # Classification Thresholds
    'classification_thresholds': {
        'legitimate_max_score': 20,
        'suspicious_min_score': 21,
        'suspicious_max_score': 50,
        'malicious_min_score': 51
    }
}

# System Configuration
SYSTEM_CONFIG = {
    # Logging
    'log_level': 'INFO',
    'log_file': 'logs/honeynet.log',
    'max_log_size': 100 * 1024 * 1024,  # 100MB
    'log_retention_days': 30,
    
    # Monitoring
    'log_check_interval': 1.0,          # Seconds between log checks
    'stats_update_interval': 5.0,       # Seconds between stats updates
    'cleanup_interval': 3600,           # Seconds between cleanup runs
    
    # Dashboard
    'dashboard_refresh_interval': 5,    # Seconds
    'max_recent_events': 1000,
    'max_blocked_ips_display': 100,
    
    # Firewall
    'firewall_table': 'honeynet',
    'firewall_chain': 'blocked_ips',
    'firewall_set': 'blocked_ips',
    'max_blocked_ips': 1000,
    'block_timeout': 3600,              # Seconds (1 hour)
    
    # Honeypot
    'honeypot_port': 2222,
    'honeypot_log_path': 'honeypot/logs/cowrie.json',
    'honeypot_config_path': 'honeypot/cowrie.cfg',
    
    # Production
    'production_port': 22,
    'production_host': 'localhost',
    'haproxy_config_path': '/etc/haproxy/haproxy.cfg',
    
    # API
    'api_host': '0.0.0.0',
    'api_port': 8000,
    'api_debug': False,
    'api_workers': 4,
    
    # Security
    'max_requests_per_minute': 100,
    'session_timeout': 1800,            # Seconds (30 minutes)
    'enable_rate_limiting': True,
    'enable_cors': True,
    
    # Notifications
    'enable_email_alerts': False,
    'enable_sms_alerts': False,
    'alert_threshold': 'high',          # low, medium, high
    'notification_recipients': []
}

# HAProxy Configuration Template
HAPROXY_CONFIG_TEMPLATE = """
global
    daemon
    maxconn 4096
    log /dev/log local0
    log /dev/log local1 notice

defaults
    log global
    mode tcp
    option tcplog
    option dontlognull
    retries 3
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend honeynet_frontend
    bind *:22
    mode tcp
    default_backend honeypot_backend
    
    # ACL for whitelisted IPs
    acl whitelisted_ip src {whitelist_ips}
    
    # Use honeypot for non-whitelisted IPs
    use_backend honeypot_backend if !whitelisted_ip
    
    # Use production for whitelisted IPs
    use_backend production_backend if whitelisted_ip

backend honeypot_backend
    mode tcp
    server honeypot 127.0.0.1:2222 check

backend production_backend
    mode tcp
    server production {production_host}:{production_port} check
"""

# Cowrie Configuration Template
COWRIE_CONFIG_TEMPLATE = """
[output_jsonlog]
enabled = true
logfile = {log_path}

[output_logfiles]
enabled = true
logfile = honeypot/logs/cowrie.log

[ssh]
enabled = true
port = {port}
version = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

[shell]
enabled = true
honeypot = true

[logins]
enabled = true
users = admin:admin123, root:password, test:test123

[filesystem]
enabled = true
contents_path = honeypot/fs

[commands]
enabled = true
honeypot = true

[download]
enabled = true
download_path = honeypot/downloads

[output_mysql]
enabled = false

[output_elasticsearch]
enabled = false
"""

# Test Scenarios Configuration
TEST_SCENARIOS = {
    'tc1_legitimate': {
        'name': 'Legitimate Access',
        'description': 'Normal user access with valid credentials',
        'expected_result': 'redirect_to_production',
        'parameters': {
            'username': 'admin',
            'password': 'admin123',
            'delay': 2.0,
            'attempts': 1
        }
    },
    
    'tc2_boundary_value': {
        'name': 'Boundary Value Analysis',
        'description': 'Slight deviation from normal behavior',
        'expected_result': 'allow_but_log',
        'parameters': {
            'username': 'admin',
            'password': 'wrong_password',
            'delay': 1.5,
            'attempts': 4
        }
    },
    
    'tc3_timing_anomaly': {
        'name': 'Timing Anomaly',
        'description': 'Anomalous timing pattern',
        'expected_result': 'soft_alert',
        'parameters': {
            'username': 'test',
            'password': 'test123',
            'delay': 0.3,
            'attempts': 3
        }
    },
    
    'tc4_brute_force': {
        'name': 'Brute Force Attack',
        'description': 'Obvious brute force attempt',
        'expected_result': 'block_and_log',
        'parameters': {
            'username': 'root',
            'password': 'password',
            'delay': 0.1,
            'attempts': 10
        }
    }
}

# Dashboard Configuration
DASHBOARD_CONFIG = {
    'refresh_interval': 5000,  # milliseconds
    'chart_colors': {
        'legitimate': '#28a745',
        'suspicious': '#ffc107',
        'malicious': '#dc3545',
        'blocked': '#6c757d'
    },
    'alert_levels': {
        'low': {'color': '#28a745', 'icon': 'info'},
        'medium': {'color': '#ffc107', 'icon': 'warning'},
        'high': {'color': '#dc3545', 'icon': 'error'}
    },
    'widgets': [
        'system_status',
        'traffic_summary',
        'blocked_ips',
        'recent_events',
        'threat_analysis',
        'performance_metrics'
    ]
}

# Logging Configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'detailed': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'standard',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'detailed',
            'filename': 'logs/honeynet.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5
        },
        'security': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'WARNING',
            'formatter': 'detailed',
            'filename': 'logs/security.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True
        },
        'security': {
            'handlers': ['security'],
            'level': 'WARNING',
            'propagate': False
        }
    }
}

# Environment-specific configurations
def get_config_for_environment(env: str = None) -> Dict[str, Any]:
    """Get configuration for specific environment"""
    if not env:
        env = os.getenv('HONEYNET_ENV', 'development')
        
    configs = {
        'development': {
            'debug': True,
            'log_level': 'DEBUG',
            'api_debug': True,
            'max_blocked_ips': 100
        },
        'testing': {
            'debug': True,
            'log_level': 'INFO',
            'api_debug': False,
            'max_blocked_ips': 50
        },
        'production': {
            'debug': False,
            'log_level': 'WARNING',
            'api_debug': False,
            'max_blocked_ips': 1000,
            'enable_rate_limiting': True
        }
    }
    
    return configs.get(env, configs['development'])

# Update configuration based on environment
ENV_CONFIG = get_config_for_environment()
SYSTEM_CONFIG.update(ENV_CONFIG)

# Validation functions
def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_network_range(network: str) -> bool:
    """Validate network range format"""
    import ipaddress
    try:
        ipaddress.ip_network(network)
        return True
    except ValueError:
        return False

def validate_configuration() -> List[str]:
    """Validate configuration and return list of errors"""
    errors = []
    
    # Validate whitelist networks
    for network in BEHAVIOR_RULES['redirect_whitelist']:
        if not validate_network_range(network):
            errors.append(f"Invalid network range: {network}")
    
    # Validate thresholds
    if BEHAVIOR_RULES['brute_force_threshold'] <= 0:
        errors.append("Brute force threshold must be positive")
        
    if BEHAVIOR_RULES['brute_force_window'] <= 0:
        errors.append("Brute force window must be positive")
        
    if BEHAVIOR_RULES['legitimate_delay_min'] < 0:
        errors.append("Legitimate delay minimum cannot be negative")
        
    if BEHAVIOR_RULES['legitimate_delay_max'] <= BEHAVIOR_RULES['legitimate_delay_min']:
        errors.append("Legitimate delay maximum must be greater than minimum")
    
    # Validate system config
    if SYSTEM_CONFIG['api_port'] < 1 or SYSTEM_CONFIG['api_port'] > 65535:
        errors.append("Invalid API port number")
        
    if SYSTEM_CONFIG['max_blocked_ips'] <= 0:
        errors.append("Maximum blocked IPs must be positive")
    
    return errors

# Configuration validation on import
CONFIG_ERRORS = validate_configuration()
if CONFIG_ERRORS:
    import logging
    logger = logging.getLogger(__name__)
    for error in CONFIG_ERRORS:
        logger.error(f"Configuration error: {error}") 
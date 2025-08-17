# Digital Twin Honeynet for Adversarial Fingerprinting

A sophisticated deception-based cybersecurity system that uses honeypot technology to detect, analyze, and automatically respond to malicious actors through behavioral analysis and automated firewall enforcement.

## 🎯 Overview

This system implements a **Digital Twin** approach where all incoming traffic is initially routed to honeypots (SSH, HTTP, RDP, SMB). A background Python service analyzes behavior patterns and intelligently redirects legitimate traffic to production servers while keeping malicious actors trapped in the honeypot environment.

### Core Features

- **Multi-Protocol Honeypots**: SSH (Cowrie), HTTP, RDP, and SMB honeypots
- **Behavioral Analysis**: Rule-based classification of legitimate vs malicious traffic
- **Smart Redirection**: Legitimate traffic redirected to production via HAProxy
- **Automated Response**: Malicious IPs blocked via nftables/UFW
- **Real-time Dashboard**: FastAPI-based monitoring interface
- **Fingerprint Evasion**: Automatic testing and comparison of honeypot vs production fingerprints
- **Centralized Configuration**: Single config.yaml for all services
- **MongoDB Database**: Minimal schema for attack data storage

## 🚀 Quick Start

### Prerequisites

- Ubuntu 20.04+ or Debian 11+ (Linux host)
- Python 3.8+
- Root/sudo access
- Internet connection for package installation

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd digital-twin-honeynet
   ```

2. **Run automated installation**

   ```bash
   sudo ./install_native_services.sh
   ```

3. **Start all services**

   ```bash
   python3 controllers/honeynet_controller_native.py --action start
   ```

4. **Check service status**
   ```bash
   python3 controllers/honeynet_controller_native.py --action status
   ```

### Testing

**Run attack simulation for demo:**

```bash
python3 tests/simulate_attacker.py --target localhost
```

**View attack summary:**

```bash
python3 logs/log_parser.py
```

**Access dashboard:**

```bash
# Open browser to: http://localhost:8000
```

## 📚 Documentation

- **[Architecture Guide](architecture.md)** - Detailed technical architecture
- **[Setup Guide](setup.md)** - Complete installation and configuration instructions

## 🏗️ Repository Structure

```
digital-twin-honeynet/
├── controllers/              # Service management and controllers
│   ├── honeynet_controller.py
│   ├── honeynet_controller_native.py
│   └── setup_honeynet.sh
├── honeypots/                # Honeypot configurations and scripts
│   ├── http_honeypot.py
│   ├── rdp_honeypot.py
│   ├── smb_honeypot.py
│   ├── cowrie_integration_script.py
│   └── *.py                  # Honeypot implementations
├── router/                   # HAProxy configuration
│   └── haproxy.cfg
├── backend/                  # FastAPI app + MongoDB integration
│   ├── main.py
│   ├── models.py
│   ├── database.py
│   └── templates/
├── logs/                     # Log monitoring scripts
│   ├── cowrie_log_monitor.py
│   └── log_parser.py
├── utils/                    # Utility modules
│   ├── config_loader.py
│   └── network_router.py
├── tests/                    # Test files and attack simulation
│   ├── fingerprint_test.py
│   ├── simulate_attacker.py
│   └── *.py

├── config.yaml              # Central configuration
├── install_native_services.sh     # Installation script
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔧 Configuration

All settings are managed in `config.yaml`:

```yaml
# Protocol configurations
protocols:
  ssh:
    enabled: true
    port: 2222
    banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

  http:
    enabled: true
    port: 8080
    banner: "nginx/1.18.0 (Ubuntu)"

# Access control
access_control:
  whitelist:
    ips: ["127.0.0.1", "192.168.1.0/24"]
    user_agents: ["legitimate-bot", "monitoring-agent"]

  blacklist:
    ips: ["192.168.1.200"]
    user_agents: ["sqlmap", "nikto", "nmap"]
```

## 🌐 Network Ports

| Port | Service       | Description              |
| ---- | ------------- | ------------------------ |
| 80   | HAProxy       | Main entry point         |
| 443  | HAProxy       | HTTPS entry point        |
| 8080 | HTTP Honeypot | Direct honeypot access   |
| 8081 | Production    | Direct production access |
| 2222 | SSH Honeypot  | SSH honeypot (Cowrie)    |
| 3389 | RDP Honeypot  | RDP honeypot             |
| 445  | SMB Honeypot  | SMB honeypot             |
| 8000 | API Backend   | Management dashboard     |

## 🗄️ Database Schema

**MongoDB Collection: `attacks`**

```json
{
  "src_ip": "192.168.1.100",
  "dst_service": "ssh",
  "timestamp": "2024-01-01T12:00:00Z",
  "attack_type": "brute_force",
  "payload": "admin:password",
  "user_agent": "SSH-2.0-OpenSSH_8.2p1",
  "port": 2222
}
```

## 🧪 Testing & Demo

**Attack Simulation:**

```bash
# Run all attack types
python3 tests/simulate_attacker.py --target localhost

# Test specific attack type
python3 tests/simulate_attacker.py --attack-type http --http-type sql_injection
```

**Fingerprint Testing:**

```bash
# Basic fingerprint test
python3 tests/fingerprint_test.py

# Generate detailed report
python3 tests/fingerprint_test.py --output report.json
```

**Log Analysis:**

```bash
# View attack summary
python3 logs/log_parser.py

# Export to JSON
python3 logs/log_parser.py --output attacks.json
```

## 🔒 Security

- All services run on isolated network interfaces
- Firewall rules block unauthorized access
- Honeypot traffic is completely separated from production
- Services run under dedicated `honeynet` user
- Regular security updates are applied

## 🆘 Support

For issues and questions:

1. Check the [Setup Guide](setup.md) troubleshooting section
2. Review the logs: `/var/log/honeynet/`
3. Check service status: `python3 controllers/honeynet_controller_native.py --action status`
4. Open an issue on GitHub

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**⚠️ Warning**: This system is designed for research and educational purposes. Use in production environments at your own risk.

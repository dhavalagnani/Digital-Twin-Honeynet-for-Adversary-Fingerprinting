# Digital Twin Honeynet for Adversarial Fingerprinting

A sophisticated deception-based cybersecurity system that uses honeypot technology to detect, analyze, and automatically respond to malicious actors through behavioral analysis and automated firewall enforcement. This system runs natively on Linux VMs without containerization.

## 🎯 Project Overview

This system implements a **Digital Twin** approach where all incoming traffic is initially routed to honeypots (SSH, HTTP, RDP, SMB). A background Python service analyzes behavior patterns and intelligently redirects legitimate traffic to production servers while keeping malicious actors trapped in the honeypot environment.

### Core Features

- **Multi-Protocol Honeypots**: SSH (Cowrie), HTTP, RDP, and SMB honeypots
- **Behavioral Analysis**: Rule-based classification of legitimate vs malicious traffic
- **Smart Redirection**: Legitimate traffic redirected to production via HAProxy
- **Automated Response**: Malicious IPs blocked via nftables/UFW
- **Real-time Dashboard**: FastAPI-based monitoring interface
- **Fingerprint Evasion**: Automatic testing and comparison of honeypot vs production fingerprints
- **Centralized Configuration**: Single config.yaml for all services

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Attacker      │    │   Legitimate    │    │   Production    │
│   Traffic       │    │   User          │    │   Server        │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │      HAProxy Load         │
                    │      Balancer             │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   Multi-Protocol          │
                    │   Honeypots               │
                    │   (SSH, HTTP, RDP, SMB)   │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   Python Log Monitor     │
                    │   (Behavioral Analysis)  │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   Classification Engine   │
                    │  Legitimate | Malicious   │
                    └─────────────┬─────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
    ┌─────▼─────┐         ┌───────▼──────┐         ┌─────▼─────┐
    │ Production│         │   Firewall   │         │  Dashboard│
    │ Redirect  │         │   Block IP   │         │   Stats   │
    └───────────┘         └──────────────┘         └───────────┘
```

## 🛠️ Tech Stack

- **Honeypots**:
  - SSH: Cowrie honeypot with JSON logging
  - HTTP: nginx-based honeypot
  - RDP: Custom RDP honeypot
  - SMB: Custom SMB honeypot
- **Load Balancer**: HAProxy for traffic redirection
- **Backend**: Python FastAPI with PostgreSQL and Redis
- **Firewall**: nftables + UFW integration
- **Web Server**: nginx for HTTP honeypot and production server
- **Database**: PostgreSQL for data storage
- **Cache**: Redis for session management
- **System Management**: systemd services for native deployment

## 📦 Installation & Setup

### Prerequisites

- Ubuntu 20.04+ or Debian 11+ (Linux host)
- Python 3.8+
- Root/sudo access
- Internet connection for package installation

### Quick Start

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
   python controllers/honeynet_controller_native.py --action start
   ```

4. **Check service status**

   ```bash
   python honeynet_controller_native.py --action status
   ```

## 🔧 Service Configuration

### Service Locations

| Service             | Installation Path                     | Config Path                                           | Log Path                              |
| ------------------- | ------------------------------------- | ----------------------------------------------------- | ------------------------------------- |
| Cowrie SSH Honeypot | `/opt/honeynet/services/ssh-honeypot` | `/opt/honeynet/services/ssh-honeypot/cowrie.cfg`      | `/var/log/honeynet/cowrie.log`        |
| HTTP Honeypot       | nginx site                            | `/etc/nginx/sites-available/honeypot`                 | `/var/log/honeynet/http-honeypot.log` |
| RDP Honeypot        | `/opt/honeynet/services/rdp-honeypot` | `/opt/honeynet/services/rdp-honeypot/rdp_config.yaml` | `/var/log/honeynet/rdp-honeypot.log`  |
| SMB Honeypot        | `/opt/honeynet/services/smb-honeypot` | `/opt/honeynet/services/smb-honeypot/smb_config.yaml` | `/var/log/honeynet/smb-honeypot.log`  |
| Production Server   | nginx site                            | `/etc/nginx/sites-available/production`               | `/var/log/honeynet/production.log`    |
| API Backend         | `/opt/honeynet/services/api-backend`  | `/opt/honeynet/config/config.yaml`                    | `/var/log/honeynet/api.log`           |
| HAProxy             | system package                        | `/etc/haproxy/haproxy.cfg`                            | `/var/log/haproxy.log`                |
| PostgreSQL          | system package                        | `/etc/postgresql/*/main/postgresql.conf`              | `/var/log/postgresql/`                |
| Redis               | system package                        | `/etc/redis/redis.conf`                               | `/var/log/redis/`                     |

### Service Management

#### Using the Native Controller

```bash
# Start all services
python honeynet_controller_native.py --action start

# Stop all services
python honeynet_controller_native.py --action stop

# Restart all services
python honeynet_controller_native.py --action restart

# Check service status
python honeynet_controller_native.py --action status

# Validate service configuration
python honeynet_controller_native.py --action validate

# Configure services based on config.yaml
python honeynet_controller_native.py --action configure
```

#### Using systemd Directly

```bash
# Start individual services
sudo systemctl start cowrie
sudo systemctl start rdp-honeypot
sudo systemctl start smb-honeypot
sudo systemctl start honeynet-api
sudo systemctl start honeynet-monitor
sudo systemctl start haproxy
sudo systemctl start nginx

# Check service status
sudo systemctl status cowrie
sudo systemctl status rdp-honeypot
sudo systemctl status smb-honeypot

# Enable services to start on boot
sudo systemctl enable cowrie
sudo systemctl enable rdp-honeypot
sudo systemctl enable smb-honeypot
```

#### Using Helper Scripts

```bash
# Start all services
sudo /opt/honeynet/scripts/start_honeynet.sh

# Stop all services
sudo /opt/honeynet/scripts/stop_honeynet.sh

# Check status
/opt/honeynet/scripts/status_honeynet.sh
```

### Testing Services

```bash
# Test HTTP honeypot
curl http://localhost:8080

# Test production server
curl http://localhost:8081

# Test SSH honeypot
ssh -p 2222 honeynet@localhost

# Test RDP honeypot (requires RDP client)
# Connect to localhost:3389

# Test SMB honeypot (requires SMB client)
smbclient //localhost/honeypot -p 445

# Test API backend
curl http://localhost:8000/health
```

## 🌐 Network Configuration

### Port Mappings

| External Port | Internal Service  | Description                        |
| ------------- | ----------------- | ---------------------------------- |
| 80            | HAProxy           | Main entry point for HTTP traffic  |
| 443           | HAProxy           | HTTPS traffic (if configured)      |
| 8080          | HTTP Honeypot     | Direct access to HTTP honeypot     |
| 8081          | Production Server | Direct access to production server |
| 2222          | SSH Honeypot      | SSH honeypot (Cowrie)              |
| 3389          | RDP Honeypot      | RDP honeypot                       |
| 445           | SMB Honeypot      | SMB honeypot                       |
| 139           | SMB Honeypot      | SMB honeypot (NetBIOS)             |
| 8000          | API Backend       | FastAPI backend                    |
| 5432          | PostgreSQL        | Database (internal)                |
| 6379          | Redis             | Cache (internal)                   |

### Firewall Configuration

The installation script configures:

- **nftables**: Advanced packet filtering and NAT
- **UFW**: Uncomplicated firewall for basic rules
- **HAProxy**: Load balancing and traffic routing
- **Network isolation**: Honeynet traffic separated from production

### Routing Logic

1. **HAProxy** receives all incoming traffic on port 80
2. **Access Control**: Checks IP whitelist/blacklist and user agent patterns
3. **Attack Detection**: Identifies suspicious patterns (SQLi, XSS, etc.)
4. **Routing Decision**:
   - **Legitimate traffic** → Production server (port 8081)
   - **Suspicious traffic** → HTTP honeypot (port 8080)
   - **Blacklisted traffic** → Blocked or honeypot

## 📊 Monitoring & Logging

### Log Locations

- **Honeypot logs**: `/var/log/honeynet/`
- **System logs**: `/var/log/syslog`
- **HAProxy logs**: `/var/log/haproxy.log`
- **Database logs**: `/var/log/postgresql/`
- **Redis logs**: `/var/log/redis/`

### Monitoring Dashboard

Access the monitoring dashboard at: `http://localhost:8000`

Features:

- Real-time attack statistics
- Service health monitoring
- Log analysis and visualization
- Configuration management
- Fingerprint comparison results

### Log Analysis

```bash
# View honeypot logs
tail -f /var/log/honeynet/cowrie.log
tail -f /var/log/honeynet/http-honeypot.log
tail -f /var/log/honeynet/rdp-honeypot.log
tail -f /var/log/honeynet/smb-honeypot.log

# View system logs
journalctl -u cowrie -f
journalctl -u rdp-honeypot -f
journalctl -u smb-honeypot -f
```

## 🔍 Fingerprint Evasion Testing

### Running Fingerprint Tests

```bash
# Basic fingerprint test
python tests/fingerprint_test.py

# Test with specific targets
python tests/fingerprint_test.py --honeypot localhost --production localhost

# Generate detailed report
python tests/fingerprint_test.py --output report.json

# Demo mode (no external tools required)
python tests/test_fingerprint_evasion.py
```

### What Gets Tested

- **Nmap scans**: OS detection, service versions, open ports
- **p0f analysis**: Passive OS fingerprinting
- **TCP options**: Window size, MSS, TTL, flags
- **Service banners**: HTTP, SSH, RDP, SMB responses
- **Protocol handshakes**: Connection establishment patterns

### Similarity Scoring

The system calculates a weighted similarity score based on:

- OS fingerprint (30%)
- Service banners (25%)
- TCP options (20%)
- Port responses (15%)
- Protocol behavior (10%)

## 🔧 Configuration

### Central Configuration

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

# Network fingerprinting
network_fingerprinting:
  tcp_randomization:
    enabled: true
    ttl_variation: 5
    window_size_variation: 1000
```

### Service-Specific Configuration

Each service has its own configuration files:

- **Cowrie**: `/opt/honeynet/services/ssh-honeypot/cowrie.cfg`
- **HTTP Honeypot**: `/etc/nginx/sites-available/honeypot`
- **RDP Honeypot**: `/opt/honeynet/services/rdp-honeypot/rdp_config.yaml`
- **SMB Honeypot**: `/opt/honeynet/services/smb-honeypot/smb_config.yaml`
- **HAProxy**: `/etc/haproxy/haproxy.cfg`

## 🚨 Troubleshooting

### Common Issues

1. **Service won't start**

   ```bash
   # Check service status
   sudo systemctl status <service-name>

   # View logs
   sudo journalctl -u <service-name> -f

   # Check configuration
   python controllers/honeynet_controller_native.py --action validate
   ```

2. **Port conflicts**

   ```bash
   # Check what's using a port
   sudo netstat -tlnp | grep :<port>

   # Kill process using port
   sudo fuser -k <port>/tcp
   ```

3. **Permission issues**

   ```bash
   # Fix permissions
   sudo chown -R honeynet:honeynet /opt/honeynet
   sudo chmod -R 755 /opt/honeynet
   ```

4. **Database connection issues**

   ```bash
   # Check PostgreSQL status
   sudo systemctl status postgresql

   # Test connection
   sudo -u postgres psql -c "SELECT version();"
   ```

### Performance Tuning

1. **Increase log rotation**

   ```bash
   # Edit logrotate configuration
   sudo nano /etc/logrotate.d/honeynet
   ```

2. **Optimize database**

   ```bash
   # Tune PostgreSQL
   sudo nano /etc/postgresql/*/main/postgresql.conf
   ```

3. **Adjust firewall rules**
   ```bash
   # Review nftables rules
   sudo nft list ruleset
   ```

## 🔒 Security Considerations

### Network Security

- All services run on isolated network interfaces
- Firewall rules block unauthorized access
- Honeypot traffic is completely separated from production
- Regular security updates are applied

### Access Control

- Services run under dedicated `honeynet` user
- File permissions are restricted
- Database access is limited
- API endpoints are protected

### Monitoring

- All access attempts are logged
- Suspicious activity triggers alerts
- Regular security audits are performed
- Backup and recovery procedures are in place

## 📁 Repository Structure

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
│   ├── http_router.py
│   ├── cowrie_integration_script.py
│   ├── cowrie_patch.py
│   ├── *.yaml                # Protocol-specific configurations
│   └── *.py                  # Honeypot implementations
├── router/                   # HAProxy configuration
│   └── haproxy.cfg
├── backend/                  # FastAPI app + DB integration
│   ├── main.py
│   ├── config.py
│   └── templates/
├── logs/                     # Log monitoring scripts
│   └── cowrie_log_monitor.py
├── utils/                    # Utility modules
│   ├── config_loader.py
│   └── network_router.py
├── tests/                    # Test files
│   ├── fingerprint_test.py
│   └── *.py                  # Other test files
├── simulator/                # Attack simulation scripts
├── config.yaml              # Central configuration
├── install_native_services.sh     # Installation script
├── start_honeynet.py        # Startup script
├── requirements.txt         # Python dependencies
├── env.example              # Environment variables template
└── README.md               # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:

1. Check the troubleshooting section
2. Review the logs
3. Open an issue on GitHub
4. Contact the maintainers

---

**⚠️ Warning**: This system is designed for research and educational purposes. Use in production environments at your own risk.

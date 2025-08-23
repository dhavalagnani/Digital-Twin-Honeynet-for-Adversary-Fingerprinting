# Digital Twin Honeynet - Setup Guide

## Prerequisites

### System Requirements

- **Operating System**: Ubuntu 20.04+ or Debian 11+
- **Architecture**: x86_64
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Storage**: Minimum 20GB free space
- **Network**: At least 2 network interfaces (recommended)
- **Python**: 3.8 or higher
- **Access**: Root/sudo privileges

### Network Requirements

- **Public IP**: For external access (optional)
- **Domain Name**: For SSL certificates (optional)
- **Firewall Access**: Ports 22, 80, 443, 3389, 445
- **Bandwidth**: Minimum 10Mbps, Recommended 100Mbps+

## Installation Process

### Step 1: System Preparation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y curl wget git vim htop net-tools

# Install Python dependencies
sudo apt install -y python3 python3-pip python3-venv

# Install development tools
sudo apt install -y build-essential python3-dev
```

### Step 2: Clone Repository

```bash
# Clone the repository
git clone <repository-url>
cd digital-twin-honeynet

# Checkout the main branch (native installation)
git checkout main
```

### Step 3: Run Automated Installation

```bash
# Make installation script executable
chmod +x install_native_services.sh

# Run the installation script
sudo ./install_native_services.sh
```

The installation script will:

- Install all required packages (MongoDB, Redis, HAProxy, nginx, etc.)
- Create system users and directories
- Configure systemd services
- Set up firewall rules
- Configure network interfaces
- Install Python dependencies

### Step 4: Setup Comprehensive Logging System

```bash
# Install additional Python dependencies for logging
pip3 install watchdog==3.0.0 websockets==12.0

# Setup auditd for privilege escalation detection
sudo chmod +x logging/setup_auditd.sh
sudo ./logging/setup_auditd.sh
```

The auditd setup will:

- Install and configure auditd service
- Load comprehensive security monitoring rules
- Set up log rotation for audit logs
- Configure privilege escalation detection
- Enable file access monitoring
- Set up user management tracking

### Step 5: Verify Installation

```bash
# Check service status
python3 controllers/honeynet_controller_native.py --action status

# Test individual services
sudo systemctl status mongodb
sudo systemctl status redis-server
sudo systemctl status haproxy
sudo systemctl status nginx

# Verify auditd installation
sudo systemctl status auditd
sudo auditctl -l

# Check log forwarder dependencies
python3 -c "import watchdog, websockets; print('Logging dependencies installed successfully')"
```

## Configuration

### Step 1: Database Configuration

**MongoDB Setup**:

```bash
# Access MongoDB shell
sudo -u mongodb mongosh

# Create database and user
use honeynet
db.createUser({
  user: "honeynet_user",
  pwd: "secure_password",
  roles: ["readWrite"]
})

# Exit MongoDB shell
exit
```

**Redis Configuration**:

```bash
# Edit Redis configuration
sudo nano /etc/redis/redis.conf

# Add/modify these lines:
bind 127.0.0.1
requirepass your_redis_password
maxmemory 256mb
maxmemory-policy allkeys-lru
```

### Step 2: Network Configuration

**Configure Network Interfaces**:

```bash
# Edit network configuration
sudo nano /etc/netplan/01-netcfg.yaml

# Example configuration:
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
    eth1:
      addresses:
        - 172.20.0.1/16
      dhcp4: false
```

**Apply Network Configuration**:

```bash
sudo netplan apply
```

### Step 3: Firewall Configuration

**UFW Setup**:

```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow ssh

# Allow web traffic
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow honeypot ports
sudo ufw allow 8080/tcp
sudo ufw allow 2222/tcp
sudo ufw allow 3389/tcp
sudo ufw allow 445/tcp

# Check UFW status
sudo ufw status verbose
```

**nftables Configuration**:

```bash
# The installation script configures nftables automatically
# To view current rules:
sudo nft list ruleset

# To add custom rules:
sudo nft add rule ip filter input ip saddr 192.168.1.0/24 accept
```

### Step 4: Service Configuration

**HAProxy Configuration**:

```bash
# Edit HAProxy configuration
sudo nano /etc/haproxy/haproxy.cfg

# The installation script provides a basic configuration
# Customize based on your needs
```

**nginx Configuration**:

```bash
# Configure HTTP honeypot site
sudo nano /etc/nginx/sites-available/honeypot

# Configure production site
sudo nano /etc/nginx/sites-available/production

# Enable sites
sudo ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
sudo ln -s /etc/nginx/sites-available/production /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t
```

### Step 5: Enhanced System Startup

**Start Core Services**:

```bash
# Start all honeynet services
python3 controllers/honeynet_controller_native.py --action start

# Or start services individually
sudo systemctl start mongodb
sudo systemctl start redis-server
sudo systemctl start haproxy
sudo systemctl start nginx
```

**Start Enhanced Backend**:

```bash
# Navigate to backend directory
cd backend

# Start FastAPI backend with WebSocket support
python3 main.py

# Or using uvicorn directly
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Start Log Forwarder**:

```bash
# In a new terminal, start the log forwarder
python3 logging/log_forwarder.py

# For debug mode
python3 logging/log_forwarder.py --debug

# Check log forwarder status
ps aux | grep log_forwarder
```

**Verify Real-time Features**:

```bash
# Check WebSocket endpoint
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:8000/ws

# Check log forwarder API
curl http://localhost:8000/api/health

# Monitor real-time logs
tail -f /var/log/audit/audit.log
tail -f logs/honeynet.log
```

### Step 6: Honeypot Configuration

**SSH Honeypot (Cowrie)**:

```bash
# Edit Cowrie configuration
sudo nano /opt/honeynet/services/ssh-honeypot/cowrie.cfg

# Key configuration options:
[ssh]
enabled = true
port = 2222
banner = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

[output_jsonlog]
enabled = true
logfile = /var/log/honeynet/cowrie.json
```

**HTTP Honeypot**:

```bash
# Configure nginx site for HTTP honeypot
sudo nano /etc/nginx/sites-available/honeypot

# Example configuration:
server {
    listen 8080;
    server_name _;

    location / {
        return 200 "Welcome to our server!";
        add_header Content-Type text/plain;
    }

    access_log /var/log/honeynet/http-honeypot.log;
    error_log /var/log/honeynet/http-honeypot-error.log;
}
```

**RDP Honeypot**:

```bash
# Edit RDP honeypot configuration
sudo nano /opt/honeynet/services/rdp-honeypot/rdp_config.yaml

# Example configuration:
rdp:
  enabled: true
  port: 3389
  banner: "Microsoft Windows Server 2019"
  log_file: "/var/log/honeynet/rdp-honeypot.log"
```

**SMB Honeypot**:

```bash
# Edit SMB honeypot configuration
sudo nano /opt/honeynet/services/smb-honeypot/smb_config.yaml

# Example configuration:
smb:
  enabled: true
  port: 445
  banner: "Samba 4.9.5-Debian"
  log_file: "/var/log/honeynet/smb-honeypot.log"
```

## Starting Services

### Step 1: Start All Services

```bash
# Start all services using the controller
python3 controllers/honeynet_controller_native.py --action start

# Or start services individually
sudo systemctl start mongodb
sudo systemctl start redis-server
sudo systemctl start haproxy
sudo systemctl start nginx
sudo systemctl start cowrie
sudo systemctl start rdp-honeypot
sudo systemctl start smb-honeypot
sudo systemctl start honeynet-api
sudo systemctl start honeynet-monitor
```

### Step 2: Enable Services on Boot

```bash
# Enable services to start on boot
sudo systemctl enable mongodb
sudo systemctl enable redis-server
sudo systemctl enable haproxy
sudo systemctl enable nginx
sudo systemctl enable cowrie
sudo systemctl enable rdp-honeypot
sudo systemctl enable smb-honeypot
sudo systemctl enable honeynet-api
sudo systemctl enable honeynet-monitor
```

### Step 3: Verify Service Status

```bash
# Check all service status
python3 controllers/honeynet_controller_native.py --action status

# Check individual services
sudo systemctl status mongodb
sudo systemctl status redis-server
sudo systemctl status haproxy
sudo systemctl status nginx
sudo systemctl status cowrie
sudo systemctl status rdp-honeypot
sudo systemctl status smb-honeypot
sudo systemctl status honeynet-api
sudo systemctl status honeynet-monitor
```

## Testing the Installation

### Step 1: Test HTTP Services

```bash
# Test main entry point (HAProxy)
curl -I http://localhost:80

# Test HTTP honeypot directly
curl -I http://localhost:8080

# Test production server directly
curl -I http://localhost:8081

# Test API backend
curl -I http://localhost:8000/health
```

### Step 2: Test SSH Honeypot

```bash
# Test SSH honeypot
ssh -p 2222 honeynet@localhost

# Expected: Connection should be established and logged
```

### Step 3: Test RDP Honeypot

```bash
# Test RDP honeypot (requires RDP client)
# Connect to localhost:3389 using an RDP client
```

### Step 4: Test SMB Honeypot

```bash
# Test SMB honeypot
smbclient //localhost/honeypot -p 445

# Expected: Connection should be established and logged
```

### Step 5: Run Attack Simulation

```bash
# Run the attacker simulation script
python3 tests/simulate_attacker.py --target localhost

# This will test various attack patterns and verify logging
```

## Monitoring and Logs

### Step 1: Check Log Files

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

### Step 2: Access Enhanced Dashboard

```bash
# Open web browser and navigate to:
http://localhost:8000

# Enhanced features available:
# - Real-time WebSocket updates
# - Live SSH session monitoring
# - Dynamic threat level indicators
# - Real-time attack alerts
# - Interactive traffic flow visualization

# Default credentials (if configured):
# Username: admin
# Password: honeynet_password
```

### Step 3: Monitor Real-time Logs

```bash
# Monitor comprehensive logging system
tail -f /var/log/audit/audit.log          # Auditd logs (privilege escalation)
tail -f /var/log/honeynet/cowrie.json     # Cowrie SSH logs
tail -f /var/log/haproxy.log              # HAProxy access logs
tail -f /var/log/nftables.log             # Firewall logs

# Check log forwarder status
ps aux | grep log_forwarder

# Verify WebSocket connection
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:8000/ws
```

### Step 4: Check Database

```bash
# Access MongoDB
sudo -u mongodb mongosh honeynet

# View attack records
db.attacks.find().pretty()

# View recent attacks
db.attacks.find({timestamp: {$gte: new Date(Date.now() - 24*60*60*1000)}}).pretty()

# View normalized logs (if using log forwarder)
db.normalized_logs.find().sort({timestamp: -1}).limit(10).pretty()
```

## Troubleshooting

### Common Issues

**1. Service Won't Start**:

```bash
# Check service status
sudo systemctl status <service-name>

# View detailed logs
sudo journalctl -u <service-name> -f

# Check configuration
python3 controllers/honeynet_controller_native.py --action validate
```

**2. Port Conflicts**:

```bash
# Check what's using a port
sudo netstat -tlnp | grep :<port>

# Kill process using port
sudo fuser -k <port>/tcp
```

**3. Permission Issues**:

```bash
# Fix permissions
sudo chown -R honeynet:honeynet /opt/honeynet
sudo chmod -R 755 /opt/honeynet
```

**4. Database Connection Issues**:

```bash
# Check MongoDB status
sudo systemctl status mongodb

# Test connection
sudo -u mongodb mongosh -c "db.runCommand('ping')"
```

**5. Log Forwarder Issues**:

```bash
# Check log forwarder status
ps aux | grep log_forwarder

# Check log file permissions
ls -la /var/log/audit/audit.log
ls -la /var/log/honeynet/cowrie.json

# Restart log forwarder
pkill -f log_forwarder
python3 logging/log_forwarder.py --debug
```

**6. WebSocket Connection Issues**:

```bash
# Check WebSocket endpoint
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:8000/ws

# Check browser console for errors
# Verify no firewall blocking WebSocket connections

# Test WebSocket manually
python3 -c "
import websockets
import asyncio
async def test():
    try:
        async with websockets.connect('ws://localhost:8000/ws') as ws:
            print('WebSocket connection successful')
    except Exception as e:
        print(f'WebSocket error: {e}')
asyncio.run(test())
"
```

**7. Auditd Issues**:

```bash
# Check auditd status
sudo systemctl status auditd

# Reload audit rules
sudo auditctl -R /etc/audit/rules.d/honeynet.rules

# Verify audit rules are loaded
sudo auditctl -l

# Check audit log
sudo tail -f /var/log/audit/audit.log
```

## Enhanced Features

### Real-time Monitoring

The enhanced system provides comprehensive real-time monitoring capabilities:

**1. WebSocket Real-time Updates**:

- Instant event notifications
- Live SSH session tracking
- Dynamic threat level assessment
- Real-time attack alerts

**2. Comprehensive Logging**:

- Multi-source log collection (Cowrie, auditd, HAProxy, nftables)
- JSON normalization for unified processing
- Real-time log forwarding
- Threat scoring and pattern detection

**3. Privilege Escalation Detection**:

- Auditd rules for sudo/su monitoring
- File access pattern tracking
- User management monitoring
- System configuration change detection

**4. Interactive Dashboard**:

- Real-time metrics and statistics
- Live session monitoring
- Interactive traffic flow visualization
- Dynamic threat level indicators

### Log Schema

All logs are normalized into a unified JSON schema:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "source": "cowrie_ssh|auditd|haproxy|nftables",
  "actor": {
    "ip": "192.168.1.100",
    "username": "attacker",
    "session": "session_id"
  },
  "action": "ssh_login|command_execution|privilege_escalation",
  "result": "success|failed|blocked|allowed",
  "threat_score": 75,
  "raw_data": {...},
  "normalized": true
}
```

### Performance Tuning

**1. Increase Log Rotation**:

```bash
# Edit logrotate configuration
sudo nano /etc/logrotate.d/honeynet
```

**2. Optimize MongoDB**:

```bash
# Edit MongoDB configuration
sudo nano /etc/mongod.conf
```

**3. Adjust Firewall Rules**:

```bash
# Review nftables rules
sudo nft list ruleset
```

## Security Hardening

### Step 1: Update Passwords

```bash
# Change default passwords
sudo passwd honeynet
sudo -u mongodb mongosh -c "db.changeUserPassword('honeynet_user', 'new_secure_password')"
```

### Step 2: Configure SSL/TLS

```bash
# Generate SSL certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/honeynet.key \
  -out /etc/ssl/certs/honeynet.crt

# Configure HAProxy for SSL
sudo nano /etc/haproxy/haproxy.cfg
```

### Step 3: Restrict Access

```bash
# Configure firewall rules
sudo ufw deny from 192.168.1.200
sudo ufw allow from 192.168.1.0/24 to any port 22
```

## Backup and Recovery

### Step 1: Backup Configuration

```bash
# Create backup directory
sudo mkdir -p /opt/backups/honeynet

# Backup configuration files
sudo tar -czf /opt/backups/honeynet/config-$(date +%Y%m%d).tar.gz \
  /opt/honeynet/config \
  /etc/haproxy \
  /etc/nginx/sites-available \
  /opt/honeynet/services/*/config
```

### Step 2: Backup Database

```bash
# Backup MongoDB
sudo -u mongodb mongodump --db honeynet --out /opt/backups/honeynet/mongodb-$(date +%Y%m%d)

# Backup Redis (if needed)
sudo cp /var/lib/redis/dump.rdb /opt/backups/honeynet/redis-$(date +%Y%m%d).rdb
```

### Step 3: Restore Procedures

```bash
# Restore MongoDB
sudo -u mongodb mongorestore --db honeynet /opt/backups/honeynet/mongodb-YYYYMMDD/honeynet

# Restore configuration
sudo tar -xzf /opt/backups/honeynet/config-YYYYMMDD.tar.gz -C /
```

## Next Steps

After successful installation:

1. **Configure Monitoring**: Set up email alerts and dashboard notifications
2. **Customize Honeypots**: Modify banners and responses to match your environment
3. **Add Custom Rules**: Create specific detection rules for your use case
4. **Integration**: Connect with external SIEM or monitoring systems
5. **Documentation**: Document your specific configuration and procedures

For additional support, refer to the architecture documentation and troubleshooting guides.

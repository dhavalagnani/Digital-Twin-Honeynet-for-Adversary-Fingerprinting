#!/bin/bash
# Digital Twin Honeynet - Native Service Installation Script
# Installs all required services natively on Ubuntu/Debian systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    error "Cannot detect OS"
fi

log "Detected OS: $OS $VER"

# Update system
log "Updating system packages..."
apt update && apt upgrade -y

# Install base dependencies
log "Installing base dependencies..."
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    unzip \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    supervisor \
    systemd \
    ufw \
    iptables \
    nftables

# Create honeynet user and directories
log "Creating honeynet user and directories..."
useradd -m -s /bin/bash honeynet || true
usermod -aG sudo honeynet

# Create directory structure
mkdir -p /opt/honeynet/{services,logs,config,scripts}
mkdir -p /opt/honeynet/services/{http-honeypot,ssh-honeypot,rdp-honeypot,smb-honeypot,production-server,api-backend}
mkdir -p /opt/honeynet/logs/{http,ssh,rdp,smb,api,monitor}
mkdir -p /etc/honeynet
mkdir -p /var/log/honeynet

# Set permissions
chown -R honeynet:honeynet /opt/honeynet
chmod -R 755 /opt/honeynet

# Install HAProxy
log "Installing HAProxy..."
apt install -y haproxy

# Install nginx for HTTP honeypot and production server
log "Installing nginx..."
apt install -y nginx

# Install PostgreSQL
log "Installing PostgreSQL..."
apt install -y postgresql postgresql-contrib

# Install Redis
log "Installing Redis..."
apt install -y redis-server

# Install Cowrie SSH honeypot
log "Installing Cowrie SSH honeypot..."
cd /opt/honeynet/services
git clone https://github.com/cowrie/cowrie.git ssh-honeypot
cd ssh-honeypot

# Create Python virtual environment for Cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Install RDP honeypot dependencies
log "Installing RDP honeypot dependencies..."
apt install -y \
    python3-rdpy \
    python3-impacket \
    freerdp2-x11

# Install SMB honeypot dependencies
log "Installing SMB honeypot dependencies..."
apt install -y \
    samba \
    python3-impacket

# Install FastAPI and dependencies
log "Installing FastAPI and dependencies..."
pip3 install fastapi uvicorn sqlalchemy psycopg2-binary redis

# Install fingerprinting tools
log "Installing fingerprinting tools..."
apt install -y nmap

# Try to install p0f (may not be available in all repos)
if apt search p0f | grep -q p0f; then
    apt install -y p0f
else
    warn "p0f not available in package repository, will need manual installation"
fi

# Configure PostgreSQL
log "Configuring PostgreSQL..."
sudo -u postgres createuser --createdb --createrole honeynet || true
sudo -u postgres createdb honeynet_db || true
sudo -u postgres psql -c "ALTER USER honeynet WITH PASSWORD 'honeynet_password';"

# Configure Redis
log "Configuring Redis..."
sed -i 's/bind 127.0.0.1/bind 127.0.0.1 172.20.0.0\/16/' /etc/redis/redis.conf
systemctl enable redis-server
systemctl restart redis-server

# Configure nftables
log "Configuring nftables..."
cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow established connections
        ct state established,related accept
        
        # Allow loopback
        iif lo accept
        
        # Allow SSH
        tcp dport 22 accept
        
        # Allow honeynet services
        tcp dport { 80, 443, 8080, 2222, 3389, 445, 139, 8000 } accept
        
        # Allow management ports
        tcp dport { 8081, 8082 } accept
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        # Allow established connections
        ct state established,related accept
        
        # Allow honeynet traffic
        iifname eth0 oifname honeynet0 accept
        iifname honeynet0 oifname eth0 accept
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table inet nat {
    chain prerouting {
        type nat hook prerouting priority 0; policy accept;
        
        # Redirect HTTP traffic to honeypot
        tcp dport 80 dnat to 172.20.0.10:8080
        
        # Redirect SSH traffic to honeypot
        tcp dport 22 dnat to 172.20.0.10:2222
        
        # Redirect RDP traffic to honeypot
        tcp dport 3389 dnat to 172.20.0.10:3389
        
        # Redirect SMB traffic to honeypot
        tcp dport { 445, 139 } dnat to 172.20.0.10:445
    }
    
    chain postrouting {
        type nat hook postrouting priority 0; policy accept;
        
        # Masquerade honeynet traffic
        oifname eth0 masquerade
    }
}
EOF

# Enable nftables
systemctl enable nftables
systemctl start nftables

# Configure HAProxy
log "Configuring HAProxy..."
cat > /etc/haproxy/haproxy.cfg << 'EOF'
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000

frontend http_front
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/honeynet.pem
    mode http
    
    # ACLs for routing decisions
    acl is_whitelisted src -f /etc/haproxy/whitelist.txt
    acl is_blacklisted src -f /etc/haproxy/blacklist.txt
    acl is_attack req.hdr(User-Agent) -m sub sqlmap
    acl is_attack req.hdr(User-Agent) -m sub nikto
    acl is_attack req.hdr(User-Agent) -m sub nmap
    
    # Route to production if whitelisted
    use_backend production if is_whitelisted
    
    # Route to honeypot if blacklisted or attack detected
    use_backend honeypot if is_blacklisted is_attack
    
    # Default to production
    default_backend production

backend production
    mode http
    server prod1 127.0.0.1:8081 check

backend honeypot
    mode http
    server honeypot1 127.0.0.1:8080 check
EOF

# Create SSL certificate for HAProxy
log "Creating SSL certificate for HAProxy..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/honeynet.key \
    -out /etc/ssl/certs/honeynet.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=honeynet.local"

cat /etc/ssl/certs/honeynet.crt /etc/ssl/private/honeynet.key > /etc/ssl/certs/honeynet.pem
chmod 600 /etc/ssl/certs/honeynet.pem

# Create whitelist and blacklist files
touch /etc/haproxy/whitelist.txt
touch /etc/haproxy/blacklist.txt

# Enable HAProxy
systemctl enable haproxy
systemctl restart haproxy

# Configure nginx for HTTP honeypot
log "Configuring nginx for HTTP honeypot..."
cat > /etc/nginx/sites-available/honeypot << 'EOF'
server {
    listen 8080;
    server_name _;
    
    access_log /var/log/honeynet/http-honeypot.log;
    error_log /var/log/honeynet/http-honeypot-error.log;
    
    location / {
        return 200 "Welcome to our server!";
        add_header Server "nginx/1.18.0 (Ubuntu)";
    }
    
    location /admin {
        return 403 "Access Denied";
    }
    
    location /phpmyadmin {
        return 404 "Not Found";
    }
}
EOF

# Configure nginx for production server
cat > /etc/nginx/sites-available/production << 'EOF'
server {
    listen 8081;
    server_name _;
    
    access_log /var/log/honeynet/production.log;
    error_log /var/log/honeynet/production-error.log;
    
    location / {
        return 200 "Welcome to our production server!";
        add_header Server "nginx/1.18.0 (Ubuntu)";
    }
}
EOF

# Enable nginx sites
ln -sf /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
ln -sf /etc/nginx/sites-available/production /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Restart nginx
systemctl enable nginx
systemctl restart nginx

# Create systemd service files
log "Creating systemd service files..."

# Cowrie SSH honeypot service
cat > /etc/systemd/system/cowrie.service << 'EOF'
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=simple
User=honeynet
Group=honeynet
WorkingDirectory=/opt/honeynet/services/ssh-honeypot
Environment=PATH=/opt/honeynet/services/ssh-honeypot/cowrie-env/bin
ExecStart=/opt/honeynet/services/ssh-honeypot/cowrie-env/bin/twistd -n -l /var/log/honeynet/cowrie.log cowrie
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# RDP honeypot service
cat > /etc/systemd/system/rdp-honeypot.service << 'EOF'
[Unit]
Description=RDP Honeypot Service
After=network.target

[Service]
Type=simple
User=honeynet
Group=honeynet
WorkingDirectory=/opt/honeynet/services/rdp-honeypot
ExecStart=/usr/bin/python3 /opt/honeynet/services/rdp-honeypot/rdp_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# SMB honeypot service
cat > /etc/systemd/system/smb-honeypot.service << 'EOF'
[Unit]
Description=SMB Honeypot Service
After=network.target

[Service]
Type=simple
User=honeynet
Group=honeynet
WorkingDirectory=/opt/honeynet/services/smb-honeypot
ExecStart=/usr/bin/python3 /opt/honeynet/services/smb-honeypot/smb_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# FastAPI backend service
cat > /etc/systemd/system/honeynet-api.service << 'EOF'
[Unit]
Description=Honeynet API Backend
After=network.target postgresql.service redis-server.service

[Service]
Type=simple
User=honeynet
Group=honeynet
WorkingDirectory=/opt/honeynet/services/api-backend
Environment=PATH=/opt/honeynet/venv/bin
ExecStart=/opt/honeynet/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Log monitor service
cat > /etc/systemd/system/honeynet-monitor.service << 'EOF'
[Unit]
Description=Honeynet Log Monitor
After=network.target

[Service]
Type=simple
User=honeynet
Group=honeynet
WorkingDirectory=/opt/honeynet/services/log-monitor
ExecStart=/usr/bin/python3 /opt/honeynet/services/log-monitor/monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Create Python virtual environment for API
log "Creating Python virtual environment for API..."
cd /opt/honeynet
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn sqlalchemy psycopg2-binary redis

# Set up log rotation
log "Setting up log rotation..."
cat > /etc/logrotate.d/honeynet << 'EOF'
/var/log/honeynet/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 honeynet honeynet
    postrotate
        systemctl reload honeynet-monitor
    endscript
}
EOF

# Configure firewall
log "Configuring firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8080/tcp
ufw allow 8081/tcp
ufw allow 2222/tcp
ufw allow 3389/tcp
ufw allow 445/tcp
ufw allow 139/tcp
ufw allow 8000/tcp

# Create startup script
log "Creating startup script..."
cat > /opt/honeynet/scripts/start_honeynet.sh << 'EOF'
#!/bin/bash
# Start all honeynet services

set -e

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting Honeynet services..."

# Start database and cache
systemctl start postgresql
systemctl start redis-server

# Start honeypot services
systemctl start cowrie
systemctl start rdp-honeypot
systemctl start smb-honeypot

# Start API and monitoring
systemctl start honeynet-api
systemctl start honeynet-monitor

# Start web servers
systemctl start nginx

# Start load balancer
systemctl start haproxy

log "Honeynet services started successfully"
EOF

chmod +x /opt/honeynet/scripts/start_honeynet.sh

# Create stop script
cat > /opt/honeynet/scripts/stop_honeynet.sh << 'EOF'
#!/bin/bash
# Stop all honeynet services

set -e

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "Stopping Honeynet services..."

# Stop services in reverse order
systemctl stop haproxy
systemctl stop nginx
systemctl stop honeynet-monitor
systemctl stop honeynet-api
systemctl stop smb-honeypot
systemctl stop rdp-honeypot
systemctl stop cowrie
systemctl stop redis-server
systemctl stop postgresql

log "Honeynet services stopped successfully"
EOF

chmod +x /opt/honeynet/scripts/stop_honeynet.sh

# Create status script
cat > /opt/honeynet/scripts/status_honeynet.sh << 'EOF'
#!/bin/bash
# Check status of all honeynet services

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "Honeynet Service Status:"
echo "========================"

services=(
    "postgresql:PostgreSQL Database"
    "redis-server:Redis Cache"
    "cowrie:Cowrie SSH Honeypot"
    "rdp-honeypot:RDP Honeypot"
    "smb-honeypot:SMB Honeypot"
    "honeynet-api:API Backend"
    "honeynet-monitor:Log Monitor"
    "nginx:Web Server"
    "haproxy:Load Balancer"
)

for service in "${services[@]}"; do
    IFS=':' read -r service_name display_name <<< "$service"
    if systemctl is-active --quiet "$service_name"; then
        echo "✓ $display_name: RUNNING"
    else
        echo "✗ $display_name: STOPPED"
    fi
done

echo "========================"
EOF

chmod +x /opt/honeynet/scripts/status_honeynet.sh

# Set final permissions
chown -R honeynet:honeynet /opt/honeynet
chmod -R 755 /opt/honeynet/scripts

log "Native service installation completed successfully!"
log ""
log "Next steps:"
log "1. Copy your config.yaml to /opt/honeynet/config/"
log "2. Copy your honeynet_controller.py to /opt/honeynet/scripts/"
log "3. Run: /opt/honeynet/scripts/start_honeynet.sh"
log "4. Check status: /opt/honeynet/scripts/status_honeynet.sh"
log ""
log "Services will be available on:"
log "- HTTP Honeypot: http://localhost:8080"
log "- Production Server: http://localhost:8081"
log "- API Backend: http://localhost:8000"
log "- SSH Honeypot: localhost:2222"
log "- RDP Honeypot: localhost:3389"
log "- SMB Honeypot: localhost:445"

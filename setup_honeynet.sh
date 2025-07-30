#!/bin/bash
# Digital Twin Honeynet - Complete Setup Script
# Installs and configures the entire honeynet system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HONEYNET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$HONEYNET_DIR/setup.log"
BACKUP_DIR="$HONEYNET_DIR/backups"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        error "Cannot detect OS"
        exit 1
    fi
    
    log "Detected OS: $OS $VER"
}

# Update system packages
update_system() {
    log "Updating system packages..."
    
    case $OS in
        *"Ubuntu"*|*"Debian"*)
            apt update && apt upgrade -y
            ;;
        *"CentOS"*|*"Red Hat"*)
            yum update -y
            ;;
        *"Arch"*)
            pacman -Syu --noconfirm
            ;;
        *)
            warn "Unknown OS, skipping system update"
            ;;
    esac
}

# Install dependencies
install_dependencies() {
    log "Installing system dependencies..."
    
    case $OS in
        *"Ubuntu"*|*"Debian"*)
            apt install -y python3 python3-pip python3-venv git curl wget
            apt install -y nftables ipset haproxy
            apt install -y build-essential libssl-dev libffi-dev
            apt install -y virtualbox virtualbox-ext-pack
            ;;
        *"CentOS"*|*"Red Hat"*)
            yum install -y python3 python3-pip git curl wget
            yum install -y nftables ipset haproxy
            yum install -y gcc openssl-devel libffi-devel
            yum install -y VirtualBox-6.1
            ;;
        *"Arch"*)
            pacman -S --noconfirm python python-pip git curl wget
            pacman -S --noconfirm nftables ipset haproxy
            pacman -S --noconfirm base-devel openssl libffi
            pacman -S --noconfirm virtualbox
            ;;
        *)
            error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    
    mkdir -p "$HONEYNET_DIR"/{logs,honeypot/logs,honeypot/downloads,firewall,backups}
    mkdir -p "$HONEYNET_DIR"/fastapi_backend/{templates,static}
    mkdir -p "$HONEYNET_DIR"/simulator
    mkdir -p "$HONEYNET_DIR"/utils
    
    # Set permissions
    chmod 755 "$HONEYNET_DIR"
    chmod 644 "$HONEYNET_DIR"/logs
    chmod 755 "$HONEYNET_DIR"/honeypot
    
    log "Directory structure created"
}

# Setup Python virtual environment
setup_python_env() {
    log "Setting up Python virtual environment..."
    
    cd "$HONEYNET_DIR"
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install Python dependencies
    pip install -r requirements.txt
    
    log "Python environment setup completed"
}

# Configure nftables
configure_nftables() {
    log "Configuring nftables..."
    
    # Create nftables configuration
    cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f

# Digital Twin Honeynet - nftables configuration

# Flush existing rules
flush ruleset

# Define honeynet table
table ip honeynet {
    # Chain for blocked IP addresses
    chain blocked_ips {
        type filter hook input priority 0; policy accept;
        
        # Default policy - return (allow traffic)
        counter return
        
        # Rules will be dynamically added here by the honeynet system
    }
    
    # Chain for logging suspicious activity
    chain log_suspicious {
        type filter hook input priority 10; policy accept;
        
        # Log all incoming connections for analysis
        counter log prefix "honeynet-suspicious: "
        counter return
    }
}

# Include honeynet table in main filter
table ip filter {
    chain input {
        type filter hook input priority 0; policy accept;
        
        # Jump to honeynet blocked_ips chain
        jump honeynet-blocked_ips
        
        # Jump to honeynet logging chain
        jump honeynet-log_suspicious
    }
}
EOF
    
    # Enable and start nftables
    systemctl enable nftables
    systemctl start nftables
    
    # Load configuration
    nft -f /etc/nftables.conf
    
    log "nftables configured and started"
}

# Configure HAProxy
configure_haproxy() {
    log "Configuring HAProxy..."
    
    # Copy HAProxy configuration
    cp "$HONEYNET_DIR/utils/haproxy.cfg" /etc/haproxy/haproxy.cfg
    
    # Create SSL certificate for HTTPS (self-signed)
    mkdir -p /etc/ssl/certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/honeynet.key \
        -out /etc/ssl/certs/honeynet.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=honeynet.local"
    
    # Combine certificate and key
    cat /etc/ssl/certs/honeynet.crt /etc/ssl/private/honeynet.key > /etc/ssl/certs/honeynet.pem
    chmod 644 /etc/ssl/certs/honeynet.pem
    
    # Enable and start HAProxy
    systemctl enable haproxy
    systemctl start haproxy
    
    log "HAProxy configured and started"
}

# Setup Cowrie honeypot
setup_cowrie() {
    log "Setting up Cowrie honeypot..."
    
    cd "$HONEYNET_DIR"
    
    # Clone Cowrie repository
    if [[ ! -d "cowrie" ]]; then
        git clone https://github.com/cowrie/cowrie.git
    fi
    
    cd cowrie
    
    # Create virtual environment for Cowrie
    python3 -m venv cowrie-env
    source cowrie-env/bin/activate
    
    # Install Cowrie dependencies
    pip install -r requirements.txt
    
    # Copy configuration
    cp "$HONEYNET_DIR/honeypot/cowrie.cfg" etc/cowrie.cfg
    
    # Create necessary directories
    mkdir -p log var/lib/cowrie
    
    # Set permissions
    chown -R $SUDO_USER:$SUDO_USER .
    
    log "Cowrie honeypot setup completed"
}

# Create systemd services
create_services() {
    log "Creating systemd services..."
    
    # Honeynet API service
    cat > /etc/systemd/system/honeynet-api.service << EOF
[Unit]
Description=Digital Twin Honeynet API
After=network.target

[Service]
Type=simple
User=$SUDO_USER
WorkingDirectory=$HONEYNET_DIR
Environment=PATH=$HONEYNET_DIR/venv/bin
ExecStart=$HONEYNET_DIR/venv/bin/python fastapi_backend/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Honeynet monitor service
    cat > /etc/systemd/system/honeynet-monitor.service << EOF
[Unit]
Description=Digital Twin Honeynet Log Monitor
After=network.target honeynet-api.service

[Service]
Type=simple
User=$SUDO_USER
WorkingDirectory=$HONEYNET_DIR
Environment=PATH=$HONEYNET_DIR/venv/bin
ExecStart=$HONEYNET_DIR/venv/bin/python fastapi_backend/log_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Cowrie honeypot service
    cat > /etc/systemd/system/cowrie.service << EOF
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=simple
User=$SUDO_USER
WorkingDirectory=$HONEYNET_DIR/cowrie
Environment=PATH=$HONEYNET_DIR/cowrie/cowrie-env/bin
ExecStart=$HONEYNET_DIR/cowrie/cowrie-env/bin/python bin/cowrie start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable services
    systemctl enable honeynet-api
    systemctl enable honeynet-monitor
    systemctl enable cowrie
    
    log "Systemd services created and enabled"
}

# Create firewall rules
create_firewall_rules() {
    log "Creating firewall rules..."
    
    # Create honeynet table and chain
    nft add table ip honeynet
    nft add chain ip honeynet blocked_ips { type filter hook input priority 0 \; policy accept \; }
    nft add rule ip honeynet blocked_ips counter return
    
    # Add rule to main filter table
    nft add rule ip filter input jump honeynet-blocked_ips
    
    # Allow SSH on port 22 (HAProxy)
    nft add rule ip filter input tcp dport 22 accept
    
    # Allow API on port 8000
    nft add rule ip filter input tcp dport 8000 accept
    
    # Allow HAProxy stats on port 8404
    nft add rule ip filter input tcp dport 8404 accept
    
    # Allow Cowrie on port 2222
    nft add rule ip filter input tcp dport 2222 accept
    
    log "Firewall rules created"
}

# Create test data
create_test_data() {
    log "Creating test data..."
    
    cd "$HONEYNET_DIR"
    
    # Create sample log entries
    cat > honeypot/logs/sample_cowrie.json << EOF
{"eventid": "cowrie.login.failed", "timestamp": "2024-01-15T10:00:00", "src_ip": "192.168.1.100", "username": "admin", "password": "password", "session": "test_001", "message": "Sample failed login"}
{"eventid": "cowrie.login.success", "timestamp": "2024-01-15T10:01:00", "src_ip": "192.168.1.101", "username": "admin", "password": "admin123", "session": "test_002", "message": "Sample successful login"}
{"eventid": "cowrie.session.connect", "timestamp": "2024-01-15T10:02:00", "src_ip": "10.0.0.50", "src_port": 12345, "dst_port": 22, "session": "test_003", "message": "Sample connection"}
EOF
    
    # Create sample configuration files
    cat > honeypot/cowrie.cfg << EOF
[output_jsonlog]
enabled = true
logfile = logs/cowrie.json

[ssh]
enabled = true
port = 2222
version = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

[shell]
enabled = true
honeypot = true

[logins]
enabled = true
users = admin:admin123, root:password, test:test123
EOF
    
    log "Test data created"
}

# Setup logging
setup_logging() {
    log "Setting up logging..."
    
    # Create logrotate configuration
    cat > /etc/logrotate.d/honeynet << EOF
$HONEYNET_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $SUDO_USER $SUDO_USER
    postrotate
        systemctl reload honeynet-api
    endscript
}
EOF
    
    # Create rsyslog configuration
    cat > /etc/rsyslog.d/honeynet.conf << EOF
# Honeynet logging
:programname, contains, "honeynet" /var/log/honeynet.log
:programname, contains, "cowrie" /var/log/cowrie.log
EOF
    
    # Restart rsyslog
    systemctl restart rsyslog
    
    log "Logging configured"
}

# Create startup script
create_startup_script() {
    log "Creating startup script..."
    
    cat > "$HONEYNET_DIR/start_honeynet.sh" << EOF
#!/bin/bash
# Digital Twin Honeynet - Startup Script

set -e

HONEYNET_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"

echo "Starting Digital Twin Honeynet..."

# Start services
systemctl start honeynet-api
systemctl start honeynet-monitor
systemctl start cowrie

echo "Honeynet services started"
echo "Dashboard available at: http://localhost:8000"
echo "HAProxy stats at: http://localhost:8404/stats"
EOF
    
    chmod +x "$HONEYNET_DIR/start_honeynet.sh"
    
    # Create stop script
    cat > "$HONEYNET_DIR/stop_honeynet.sh" << EOF
#!/bin/bash
# Digital Twin Honeynet - Stop Script

set -e

echo "Stopping Digital Twin Honeynet..."

# Stop services
systemctl stop honeynet-api
systemctl stop honeynet-monitor
systemctl stop cowrie

echo "Honeynet services stopped"
EOF
    
    chmod +x "$HONEYNET_DIR/stop_honeynet.sh"
    
    log "Startup scripts created"
}

# Run tests
run_tests() {
    log "Running system tests..."
    
    cd "$HONEYNET_DIR"
    
    # Test Python environment
    source venv/bin/activate
    python -c "import fastapi, uvicorn, jinja2; print('Python dependencies: OK')"
    
    # Test nftables
    if nft list tables >/dev/null 2>&1; then
        log "nftables: OK"
    else
        warn "nftables: FAILED"
    fi
    
    # Test HAProxy
    if systemctl is-active haproxy >/dev/null 2>&1; then
        log "HAProxy: OK"
    else
        warn "HAProxy: FAILED"
    fi
    
    # Test API connectivity
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        log "API connectivity: OK"
    else
        warn "API connectivity: FAILED (service not started yet)"
    fi
    
    log "System tests completed"
}

# Show final instructions
show_instructions() {
    echo ""
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Setup Completed Successfully!${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    echo "Digital Twin Honeynet has been installed and configured."
    echo ""
    echo "Next steps:"
    echo "1. Start the honeynet system:"
    echo "   sudo $HONEYNET_DIR/start_honeynet.sh"
    echo ""
    echo "2. Access the dashboard:"
    echo "   http://localhost:8000"
    echo ""
    echo "3. View HAProxy statistics:"
    echo "   http://localhost:8404/stats"
    echo "   Username: admin"
    echo "   Password: secure_password_2024"
    echo ""
    echo "4. Run attack simulations:"
    echo "   cd $HONEYNET_DIR"
    echo "   source venv/bin/activate"
    echo "   python simulator/simulate_attacker1.py  # Legitimate access"
    echo "   python simulator/simulate_attacker2.py  # Boundary value analysis"
    echo "   python simulator/simulate_attacker3.py  # Timing anomalies"
    echo "   python simulator/simulate_attacker4.py  # Brute force attacks"
    echo ""
    echo "5. Stop the honeynet system:"
    echo "   sudo $HONEYNET_DIR/stop_honeynet.sh"
    echo ""
    echo "Log files:"
    echo "  - System logs: $HONEYNET_DIR/logs/"
    echo "  - Honeypot logs: $HONEYNET_DIR/honeypot/logs/"
    echo "  - Setup log: $LOG_FILE"
    echo ""
    echo -e "${YELLOW}Important:${NC}"
    echo "  - This system is for educational and testing purposes only"
    echo "  - Do not use in production without proper security review"
    echo "  - Keep the system isolated from production networks"
    echo ""
}

# Main function
main() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Digital Twin Honeynet Setup${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    # Initialize log file
    echo "Digital Twin Honeynet Setup Log - $(date)" > "$LOG_FILE"
    
    # Check prerequisites
    check_root
    detect_os
    
    # Execute setup steps
    update_system
    install_dependencies
    create_directories
    setup_python_env
    configure_nftables
    configure_haproxy
    setup_cowrie
    create_services
    create_firewall_rules
    create_test_data
    setup_logging
    create_startup_script
    run_tests
    
    # Show instructions
    show_instructions
    
    log "Setup completed successfully!"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  -h, --help     Show this help message"
        echo "  --test-only    Run tests only"
        echo "  --clean        Clean installation (remove existing setup)"
        echo ""
        exit 0
        ;;
    --test-only)
        run_tests
        exit 0
        ;;
    --clean)
        echo "Cleaning existing installation..."
        systemctl stop honeynet-api honeynet-monitor cowrie 2>/dev/null || true
        systemctl disable honeynet-api honeynet-monitor cowrie 2>/dev/null || true
        rm -f /etc/systemd/system/honeynet-*.service
        rm -f /etc/systemd/system/cowrie.service
        systemctl daemon-reload
        echo "Cleanup completed"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        error "Unknown option: $1"
        exit 1
        ;;
esac 
#!/bin/bash
# Digital Twin Honeynet - MAC/IP Spoofing Utility
# Sets MAC and IP addresses to mimic production systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INTERFACE="eth0"
PRODUCTION_MAC="00:15:5d:01:ca:05"
PRODUCTION_IP="192.168.1.100"
PRODUCTION_GATEWAY="192.168.1.1"
PRODUCTION_NETMASK="255.255.255.0"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Check if interface exists
check_interface() {
    if ! ip link show $INTERFACE >/dev/null 2>&1; then
        error "Interface $INTERFACE does not exist"
        exit 1
    fi
}

# Get current network configuration
get_current_config() {
    log "Current network configuration:"
    echo "Interface: $INTERFACE"
    echo "Current IP: $(ip addr show $INTERFACE | grep 'inet ' | awk '{print $2}' | head -1 || echo 'Not set')"
    echo "Current MAC: $(ip link show $INTERFACE | grep 'link/ether' | awk '{print $2}' || echo 'Not set')"
    echo ""
}

# Backup current configuration
backup_config() {
    log "Backing up current network configuration..."
    
    BACKUP_FILE="/tmp/network_backup_$(date +%Y%m%d_%H%M%S).sh"
    
    cat > $BACKUP_FILE << EOF
#!/bin/bash
# Network configuration backup - $(date)
# Restore with: sudo bash $BACKUP_FILE

# Restore IP configuration
ip addr add $(ip addr show $INTERFACE | grep 'inet ' | awk '{print $2}' | head -1) dev $INTERFACE 2>/dev/null || true

# Restore MAC address
ip link set $INTERFACE address $(ip link show $INTERFACE | grep 'link/ether' | awk '{print $2}') 2>/dev/null || true

# Restore routing
ip route add default via $(ip route | grep default | awk '{print $3}') dev $INTERFACE 2>/dev/null || true

echo "Network configuration restored"
EOF
    
    chmod +x $BACKUP_FILE
    log "Backup saved to: $BACKUP_FILE"
}

# Set MAC address
set_mac_address() {
    log "Setting MAC address to production value: $PRODUCTION_MAC"
    
    # Bring interface down
    ip link set $INTERFACE down
    
    # Set MAC address
    ip link set $INTERFACE address $PRODUCTION_MAC
    
    # Bring interface up
    ip link set $INTERFACE up
    
    # Verify MAC address
    CURRENT_MAC=$(ip link show $INTERFACE | grep 'link/ether' | awk '{print $2}')
    if [[ "$CURRENT_MAC" == "$PRODUCTION_MAC" ]]; then
        log "MAC address set successfully"
    else
        error "Failed to set MAC address. Current: $CURRENT_MAC, Expected: $PRODUCTION_MAC"
        return 1
    fi
}

# Set IP address
set_ip_address() {
    log "Setting IP address to production value: $PRODUCTION_IP/$PRODUCTION_NETMASK"
    
    # Remove existing IP addresses
    ip addr flush dev $INTERFACE
    
    # Add production IP
    ip addr add $PRODUCTION_IP/$PRODUCTION_NETMASK dev $INTERFACE
    
    # Set default gateway
    ip route add default via $PRODUCTION_GATEWAY dev $INTERFACE
    
    # Verify IP address
    CURRENT_IP=$(ip addr show $INTERFACE | grep 'inet ' | awk '{print $2}' | head -1)
    if [[ "$CURRENT_IP" == "$PRODUCTION_IP/24" ]]; then
        log "IP address set successfully"
    else
        error "Failed to set IP address. Current: $CURRENT_IP, Expected: $PRODUCTION_IP/24"
        return 1
    fi
}

# Test network connectivity
test_connectivity() {
    log "Testing network connectivity..."
    
    # Test gateway connectivity
    if ping -c 3 -W 5 $PRODUCTION_GATEWAY >/dev/null 2>&1; then
        log "Gateway connectivity: OK"
    else
        warn "Gateway connectivity: FAILED"
    fi
    
    # Test DNS resolution
    if nslookup google.com >/dev/null 2>&1; then
        log "DNS resolution: OK"
    else
        warn "DNS resolution: FAILED"
    fi
    
    # Test internet connectivity
    if ping -c 3 -W 5 8.8.8.8 >/dev/null 2>&1; then
        log "Internet connectivity: OK"
    else
        warn "Internet connectivity: FAILED"
    fi
}

# Configure DNS
configure_dns() {
    log "Configuring DNS servers..."
    
    # Backup current DNS configuration
    if [[ -f /etc/resolv.conf ]]; then
        cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S)
    fi
    
    # Set DNS servers
    cat > /etc/resolv.conf << EOF
# DNS configuration for honeynet
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
EOF
    
    log "DNS configuration updated"
}

# Configure hostname
configure_hostname() {
    log "Configuring hostname to mimic production..."
    
    # Set hostname
    hostnamectl set-hostname production-server
    
    # Update /etc/hosts
    cat > /etc/hosts << EOF
127.0.0.1 localhost
$PRODUCTION_IP production-server
$PRODUCTION_IP honeynet.local
EOF
    
    log "Hostname configured as: production-server"
}

# Configure system services
configure_services() {
    log "Configuring system services..."
    
    # Enable SSH service
    systemctl enable ssh >/dev/null 2>&1 || systemctl enable sshd >/dev/null 2>&1 || true
    
    # Start common services
    systemctl start ssh >/dev/null 2>&1 || systemctl start sshd >/dev/null 2>&1 || true
    
    log "System services configured"
}

# Create production-like environment
create_production_env() {
    log "Creating production-like environment..."
    
    # Create common directories
    mkdir -p /var/www/html
    mkdir -p /var/log/apache2
    mkdir -p /var/log/nginx
    mkdir -p /opt/backup
    mkdir -p /home/admin
    
    # Create fake production files
    cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Production Server</title>
</head>
<body>
    <h1>Welcome to Production Server</h1>
    <p>This is a production environment.</p>
</body>
</html>
EOF
    
    # Create fake log files
    echo "$(date): Production server started" > /var/log/production.log
    echo "$(date): System running normally" >> /var/log/production.log
    
    log "Production environment created"
}

# Main function
main() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Digital Twin Honeynet Setup${NC}"
    echo -e "${BLUE}  MAC/IP Spoofing Utility${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    # Check prerequisites
    check_root
    check_interface
    
    # Show current configuration
    get_current_config
    
    # Confirm action
    echo -e "${YELLOW}This script will:${NC}"
    echo "1. Backup current network configuration"
    echo "2. Set MAC address to: $PRODUCTION_MAC"
    echo "3. Set IP address to: $PRODUCTION_IP/$PRODUCTION_NETMASK"
    echo "4. Configure hostname as: production-server"
    echo "5. Create production-like environment"
    echo ""
    
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Operation cancelled"
        exit 0
    fi
    
    # Execute configuration
    backup_config
    set_mac_address
    set_ip_address
    configure_dns
    configure_hostname
    configure_services
    create_production_env
    
    # Test connectivity
    test_connectivity
    
    # Show final configuration
    echo ""
    log "Final network configuration:"
    echo "Interface: $INTERFACE"
    echo "MAC Address: $(ip link show $INTERFACE | grep 'link/ether' | awk '{print $2}')"
    echo "IP Address: $(ip addr show $INTERFACE | grep 'inet ' | awk '{print $2}' | head -1)"
    echo "Gateway: $(ip route | grep default | awk '{print $3}')"
    echo "Hostname: $(hostname)"
    
    echo ""
    log "MAC/IP spoofing completed successfully!"
    log "System now mimics production environment"
    echo ""
    warn "Remember to restore original configuration when done testing"
    echo "Backup file: /tmp/network_backup_*.sh"
}

# Restore function
restore() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Network Configuration Restore${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    check_root
    
    # Find latest backup file
    BACKUP_FILE=$(ls -t /tmp/network_backup_*.sh 2>/dev/null | head -1)
    
    if [[ -z "$BACKUP_FILE" ]]; then
        error "No backup file found"
        exit 1
    fi
    
    echo "Found backup file: $BACKUP_FILE"
    echo ""
    
    read -p "Do you want to restore from this backup? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Restore cancelled"
        exit 0
    fi
    
    log "Restoring network configuration..."
    bash "$BACKUP_FILE"
    
    log "Network configuration restored"
}

# Help function
show_help() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -r, --restore  Restore network configuration from backup"
    echo "  -i, --interface INTERFACE  Specify network interface (default: eth0)"
    echo "  -m, --mac MAC  Specify MAC address"
    echo "  -p, --ip IP    Specify IP address"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run with default settings"
    echo "  $0 --restore         # Restore from backup"
    echo "  $0 -i eth1 -m 00:11:22:33:44:55 -p 192.168.1.200"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -r|--restore)
            restore
            exit 0
            ;;
        -i|--interface)
            INTERFACE="$2"
            shift 2
            ;;
        -m|--mac)
            PRODUCTION_MAC="$2"
            shift 2
            ;;
        -p|--ip)
            PRODUCTION_IP="$2"
            shift 2
            ;;
        *)
            error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Run main function
main "$@" 
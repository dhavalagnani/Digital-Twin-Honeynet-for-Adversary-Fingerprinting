#!/bin/bash
# Digital Twin Honeynet - Auditd Setup Script
# Configures auditd for comprehensive privilege escalation logging

set -e

echo "🔧 Setting up auditd for Digital Twin Honeynet..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (use sudo)"
   exit 1
fi

# Install auditd if not present
if ! command -v auditd &> /dev/null; then
    echo "📦 Installing auditd..."
    apt-get update
    apt-get install -y auditd audispd-plugins
fi

# Backup existing audit rules
if [ -f /etc/audit/rules.d/audit.rules ]; then
    echo "💾 Backing up existing audit rules..."
    cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.backup.$(date +%Y%m%d_%H%M%S)
fi

# Install honeynet audit rules
echo "📋 Installing honeynet audit rules..."
cp logging/auditd_rules.conf /etc/audit/rules.d/honeynet.rules

# Configure auditd
echo "⚙️ Configuring auditd..."
cat > /etc/audit/auditd.conf << 'EOF'
# Digital Twin Honeynet - Auditd Configuration

# Log file location
log_file = /var/log/audit/audit.log

# Maximum log file size (MB)
max_log_file = 100

# Number of log files to keep
num_logs = 5

# Maximum log file size action
max_log_file_action = ROTATE

# Space left action
space_left = 100
space_left_action = SYSLOG

# Admin space left action
admin_space_left = 50
admin_space_left_action = SUSPEND

# Disk full action
disk_full_action = SUSPEND

# Disk error action
disk_error_action = SUSPEND

# Audit failure action
audit_failure = 2

# Flush interval
flush = INCREMENTAL_ASYNC

# Frequency
freq = 50

# Disable auditd when audit log is full
dispatcher = /sbin/audispd
name_format = NONE

# Maximum number of audit rules
max_rules = 1000

# Buffer size
buffer_size = 8192

# Failure mode
failure_mode = 2

# Rate limiting
rate_limit = 0

# Network listener
tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1

# Local events
local_events = yes
write_logs = yes
log_group = root
EOF

# Start and enable auditd
echo "🚀 Starting auditd service..."
systemctl enable auditd
systemctl start auditd

# Verify auditd is running
if systemctl is-active --quiet auditd; then
    echo "✅ Auditd is running successfully"
else
    echo "❌ Failed to start auditd"
    exit 1
fi

# Load audit rules
echo "📋 Loading audit rules..."
auditctl -R /etc/audit/rules.d/honeynet.rules

# Verify rules are loaded
echo "🔍 Verifying audit rules..."
auditctl -l

# Test auditd functionality
echo "🧪 Testing auditd functionality..."
echo "Running test command: sudo ls /root"
sudo ls /root > /dev/null 2>&1 || true

# Check if audit log is being written
sleep 2
if [ -s /var/log/audit/audit.log ]; then
    echo "✅ Auditd is logging events successfully"
    echo "📊 Recent audit events:"
    tail -5 /var/log/audit/audit.log
else
    echo "⚠️ No audit events found - this might be normal if no privileged commands were run"
fi

# Set up log rotation for audit logs
echo "🔄 Setting up log rotation..."
cat > /etc/logrotate.d/audit << 'EOF'
/var/log/audit/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    postrotate
        /sbin/service auditd restart > /dev/null 2>&1 || true
    endscript
}
EOF

echo "🎉 Auditd setup completed successfully!"
echo ""
echo "📋 Summary:"
echo "  - Auditd service: $(systemctl is-active auditd)"
echo "  - Audit rules loaded: $(auditctl -l | wc -l) rules"
echo "  - Log file: /var/log/audit/audit.log"
echo "  - Log rotation: /etc/logrotate.d/audit"
echo ""
echo "🔍 Monitor audit logs with:"
echo "  tail -f /var/log/audit/audit.log"
echo ""
echo "📊 View audit rules with:"
echo "  auditctl -l"

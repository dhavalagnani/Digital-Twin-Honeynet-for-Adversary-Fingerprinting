# Digital Twin Honeynet - Comprehensive Logging System

This directory contains the enhanced logging and monitoring components for the Digital Twin Honeynet system, providing comprehensive security event collection, normalization, and real-time dashboard updates.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Sources   │    │  Log Forwarder  │    │  FastAPI Backend│
│                 │    │                 │    │                 │
│ • Cowrie SSH    │───▶│ • Normalization │───▶│ • WebSocket     │
│ • Auditd        │    │ • Real-time     │    │ • Dashboard     │
│ • HAProxy       │    │ • Queue-based   │    │ • Alerts        │
│ • nftables      │    │ • File watching │    │ • Analytics     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📁 Components

### 1. Auditd Rules (`auditd_rules.conf`)

Comprehensive auditd ruleset for privilege escalation detection:

- **EXECVE monitoring**: All command executions
- **Privilege escalation**: sudo, su, passwd usage
- **File access**: Sensitive file modifications
- **User management**: User creation/deletion
- **Network activity**: Connection monitoring
- **System changes**: Configuration modifications

### 2. Log Forwarder (`log_forwarder.py`)

Real-time log collection and normalization system:

- **Multi-source monitoring**: Cowrie, auditd, HAProxy, nftables
- **JSON normalization**: Unified schema across all sources
- **Real-time processing**: File watching with inotify
- **Threat scoring**: Automatic threat level calculation
- **Queue-based forwarding**: Reliable delivery to backend

### 3. Enhanced Dashboard

WebSocket-enabled real-time dashboard with:

- **Live updates**: Instant event notifications
- **Active session monitoring**: Real-time SSH session tracking
- **Attack alerts**: High-threat event notifications
- **Threat level indicators**: Dynamic threat assessment
- **Interactive visualizations**: Real-time charts and metrics

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Setup Auditd

```bash
sudo chmod +x logging/setup_auditd.sh
sudo ./logging/setup_auditd.sh
```

### 3. Start the Backend

```bash
cd backend
python main.py
```

### 4. Start the Log Forwarder

```bash
python logging/log_forwarder.py
```

### 5. Access the Dashboard

Open your browser to: `http://localhost:8000/`

## 📊 Log Schema

All logs are normalized into a unified JSON schema:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "source": "cowrie_ssh|auditd|haproxy|nftables",
  "actor": {
    "ip": "192.168.1.100",
    "username": "attacker",
    "session": "session_id",
    "uid": "1000"
  },
  "action": "ssh_login|command_execution|privilege_escalation",
  "result": "success|failed|blocked|allowed",
  "threat_score": 75,
  "raw_data": {...},
  "event_type": "cowrie.login.success",
  "normalized": true
}
```

## 🔍 Threat Scoring

The system automatically calculates threat scores:

| Event Type           | Base Score | Additional Factors            |
| -------------------- | ---------- | ----------------------------- |
| Failed login         | 10         | +5 per attempt                |
| Command execution    | 5          | +30 for dangerous commands    |
| Privilege escalation | 20         | +20 for sudo/su               |
| File download        | 30         | +10 for executable files      |
| Port scanning        | 40         | +20 for multiple ports        |
| Network attack       | 50         | +30 for known attack patterns |

## 🎯 Real-time Features

### WebSocket Events

- `log_update`: New log entry received
- `attack_alert`: High-threat event detected
- `session_update`: SSH session status change
- `threat_update`: Threat level change

### Dashboard Components

- **Real-time alerts**: Instant attack notifications
- **Active sessions**: Live SSH session monitoring
- **Threat level**: Dynamic threat assessment
- **Event timeline**: Chronological event display
- **Metrics**: Real-time statistics

## 🔧 Configuration

### Log Forwarder Options

```bash
python logging/log_forwarder.py --api-url http://localhost:8000 --debug
```

### Auditd Configuration

- **Log file**: `/var/log/audit/audit.log`
- **Max size**: 100MB per file
- **Rotation**: 5 files kept
- **Rules**: 1000+ monitoring rules

### HAProxy Logging

Ensure HAProxy is configured to log to `/var/log/haproxy.log`:

```haproxy
global
    log /dev/log local0
    log /dev/log local1 notice
```

## 📈 Monitoring

### View Real-time Logs

```bash
# Auditd logs
tail -f /var/log/audit/audit.log

# Cowrie logs
tail -f honeypot/logs/cowrie.json

# HAProxy logs
tail -f /var/log/haproxy.log
```

### Check System Status

```bash
# Auditd status
sudo systemctl status auditd
sudo auditctl -l

# Log forwarder status
ps aux | grep log_forwarder

# WebSocket connections
curl http://localhost:8000/api/status
```

## 🛡️ Security Features

### Privilege Escalation Detection

- **sudo usage**: All sudo commands logged
- **su attempts**: User switching monitored
- **passwd changes**: Password modification tracking
- **file permissions**: chmod/chown monitoring
- **process creation**: execve syscall tracking

### Attack Pattern Recognition

- **Brute force**: Multiple failed login attempts
- **Command injection**: Suspicious command patterns
- **File operations**: Unusual file access patterns
- **Network scanning**: Port scanning detection
- **Data exfiltration**: Large data transfer monitoring

### Real-time Response

- **Instant alerts**: WebSocket notifications
- **Threat scoring**: Automatic risk assessment
- **Session tracking**: Live SSH session monitoring
- **IP reputation**: Dynamic IP scoring
- **Blocking**: Automatic malicious IP blocking

## 🔄 Integration

### With Existing Components

- **Cowrie SSH**: Enhanced command logging
- **HAProxy**: Traffic routing analysis
- **nftables**: Firewall rule monitoring
- **FastAPI Backend**: Centralized processing

### External Systems

- **SIEM Integration**: Standard JSON output
- **Log Aggregation**: Compatible with ELK stack
- **Alert Systems**: Webhook support
- **Monitoring**: Prometheus metrics

## 🚨 Troubleshooting

### Common Issues

**Auditd not logging:**

```bash
sudo systemctl restart auditd
sudo auditctl -R /etc/audit/rules.d/honeynet.rules
```

**Log forwarder not connecting:**

```bash
# Check API backend is running
curl http://localhost:8000/api/health

# Check log file permissions
ls -la /var/log/audit/audit.log
```

**WebSocket not working:**

```bash
# Check browser console for errors
# Verify WebSocket endpoint
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:8000/ws
```

### Debug Mode

```bash
# Enable debug logging
python logging/log_forwarder.py --debug

# Check detailed logs
tail -f logs/honeynet.log
```

## 📚 API Reference

### Log Forwarder API

- `POST /api/logs`: Receive normalized logs
- `GET /api/status`: System status
- `GET /api/stats`: Statistics
- `WebSocket /ws`: Real-time updates

### Dashboard API

- `GET /`: Main dashboard
- `GET /api/health`: Health check
- `GET /api/logs`: Recent logs
- `GET /api/blocked`: Blocked IPs

## 🤝 Contributing

1. Follow the existing code structure
2. Add comprehensive logging for new features
3. Update threat scoring algorithms
4. Test with real attack scenarios
5. Document new log sources

## 📄 License

This logging system is part of the Digital Twin Honeynet project and follows the same licensing terms.

# Digital Twin Honeynet - Architecture Documentation

## System Overview

The Digital Twin Honeynet is a sophisticated deception-based cybersecurity system that implements a "digital twin" approach to network security. All incoming traffic is initially routed to honeypots, where behavioral analysis determines whether traffic should be redirected to production servers or kept in the honeypot environment.

## Core Architecture Components

### 1. Traffic Routing Layer (HAProxy)

**Purpose**: Intelligent traffic distribution based on access control lists and attack patterns.

**Components**:

- **HAProxy Load Balancer**: Routes traffic on ports 80, 443, 22, 3389, 445
- **Access Control Lists**: IP whitelist/blacklist management
- **Attack Pattern Detection**: User agent and payload analysis
- **Health Checks**: Service availability monitoring

**Configuration**: `/etc/haproxy/haproxy.cfg`

### 2. Multi-Protocol Honeypot Layer

**SSH Honeypot (Cowrie)**:

- **Port**: 2222
- **Purpose**: SSH attack detection and logging
- **Features**: JSON logging, command execution tracking
- **Location**: `/opt/honeynet/services/ssh-honeypot/`

**HTTP Honeypot (nginx-based)**:

- **Port**: 8080
- **Purpose**: Web application attack detection
- **Features**: Custom error pages, attack pattern logging
- **Location**: nginx site configuration

**RDP Honeypot**:

- **Port**: 3389
- **Purpose**: Remote desktop attack detection
- **Features**: Connection logging, authentication attempts
- **Location**: `/opt/honeynet/services/rdp-honeypot/`

**SMB Honeypot**:

- **Port**: 445, 139
- **Purpose**: File sharing attack detection
- **Features**: Share enumeration, authentication logging
- **Location**: `/opt/honeynet/services/smb-honeypot/`

### 3. Behavioral Analysis Engine

**Log Monitor Service**:

- **Purpose**: Real-time log analysis and pattern recognition
- **Input**: Honeypot logs, system logs, HAProxy logs
- **Output**: Attack classifications, IP reputation scores
- **Location**: `/opt/honeynet/services/log-monitor/`

**Classification Rules**:

- **Legitimate Traffic**: Known good IPs, normal user agents
- **Suspicious Traffic**: Unknown patterns, scanning behavior
- **Malicious Traffic**: Attack signatures, blacklisted IPs

### 4. Production Environment

**Production Server**:

- **Port**: 8081
- **Purpose**: Legitimate application hosting
- **Features**: Isolated from honeypot traffic
- **Location**: nginx site configuration

**API Backend**:

- **Port**: 8000
- **Purpose**: System monitoring and management
- **Features**: Dashboard, configuration management
- **Location**: `/opt/honeynet/services/api-backend/`

### 5. Data Storage Layer

**MongoDB Database**:

- **Purpose**: Attack data storage and analysis
- **Schema**: Minimal with attacks, src_ip, dst_service, timestamp
- **Location**: Local MongoDB instance
- **Collections**: attacks, configurations, statistics

**Redis Cache**:

- **Purpose**: Session management and temporary data
- **Features**: IP reputation caching, rate limiting
- **Location**: Local Redis instance

## Network Architecture

### Port Mappings

| External Port | Internal Service | Protocol | Purpose                  |
| ------------- | ---------------- | -------- | ------------------------ |
| 80            | HAProxy          | HTTP     | Main entry point         |
| 443           | HAProxy          | HTTPS    | Secure entry point       |
| 22            | HAProxy          | SSH      | SSH routing              |
| 3389          | HAProxy          | RDP      | RDP routing              |
| 445           | HAProxy          | SMB      | SMB routing              |
| 8080          | HTTP Honeypot    | HTTP     | Direct honeypot access   |
| 8081          | Production       | HTTP     | Direct production access |
| 2222          | SSH Honeypot     | SSH      | Direct SSH honeypot      |
| 8000          | API Backend      | HTTP     | Management interface     |

### Network Isolation

**Honeynet Network**: `172.20.0.0/16`

- Isolated from production traffic
- Dedicated interfaces for honeypot services
- Controlled access for monitoring

**Production Network**: `192.168.1.0/24`

- Legitimate user traffic
- Isolated from honeypot environment
- Direct access to production services

## Security Architecture

### Access Control

**Whitelist Management**:

- Trusted IP ranges
- Known good user agents
- Legitimate monitoring tools

**Blacklist Management**:

- Known malicious IPs
- Attack tool user agents
- Suspicious behavior patterns

### Firewall Configuration

**nftables Rules**:

- Advanced packet filtering
- NAT for network isolation
- Rate limiting per IP

**UFW Integration**:

- Basic firewall rules
- Service-specific access control
- Logging and monitoring

### Monitoring and Alerting

**Real-time Monitoring**:

- Service health checks
- Attack pattern detection
- Performance metrics

**Alerting System**:

- Email notifications
- Dashboard alerts
- Log-based triggers

## Service Dependencies

### Startup Order

1. **Database Services**: MongoDB, Redis
2. **Core Services**: HAProxy, nginx
3. **Honeypot Services**: SSH, HTTP, RDP, SMB
4. **Analysis Services**: Log monitor, API backend
5. **Monitoring**: Dashboard, health checks

### Service Management

**systemd Units**:

- `cowrie.service`: SSH honeypot
- `rdp-honeypot.service`: RDP honeypot
- `smb-honeypot.service`: SMB honeypot
- `honeynet-api.service`: API backend
- `honeynet-monitor.service`: Log monitor

**Controller Scripts**:

- `honeynet_controller_native.py`: Main controller
- `install_native_services.sh`: Installation script
- Helper scripts for service management

## Performance Considerations

### Resource Allocation

**CPU**: Distributed across services
**Memory**: Optimized for log processing
**Storage**: Log rotation and archiving
**Network**: Bandwidth monitoring

### Scalability

**Horizontal Scaling**: Multiple honeypot instances
**Load Balancing**: HAProxy clustering
**Database**: MongoDB replication
**Caching**: Redis clustering

## Integration Points

### External Systems

**SIEM Integration**: Log forwarding to external SIEM
**Firewall Integration**: Dynamic rule updates
**DNS Integration**: Blackhole DNS for malicious domains
**Email Integration**: Alert notifications

### APIs and Interfaces

**REST API**: Configuration management
**Web Dashboard**: Real-time monitoring
**CLI Tools**: Service management
**Log APIs**: External log consumers

## Deployment Architecture

### Single Host Deployment

All services run on a single Linux host with:

- Network isolation via VLANs
- Service separation via systemd
- Resource limits and monitoring

### Multi-Host Deployment

Distributed deployment with:

- Dedicated honeypot hosts
- Centralized management
- Load balancer clustering
- Database replication

## Security Considerations

### Network Security

- Complete traffic isolation
- Encrypted communications
- Regular security updates
- Intrusion detection integration

### Access Security

- Dedicated service accounts
- Minimal privilege principle
- Regular access reviews
- Audit logging

### Data Security

- Encrypted data storage
- Secure log transmission
- Data retention policies
- Backup and recovery procedures

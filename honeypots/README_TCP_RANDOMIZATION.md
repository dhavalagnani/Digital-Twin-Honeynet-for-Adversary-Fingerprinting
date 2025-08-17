# TCP/IP Stack Behavior Randomization for Digital Twin Honeynet

This module implements configurable TCP/IP stack behavior randomization to reduce fingerprinting risk between the honeypot and real production servers.

## Overview

The TCP/IP stack randomization system provides:

- **Configurable timing jitter** (±20-50ms) for TCP handshake responses
- **Network parameter variations** in window size, TTL, and MSS values
- **Production server fingerprinting** to match real server behavior
- **Easy integration** with Cowrie SSH honeypot
- **Comprehensive testing** and validation

## Architecture

The implementation consists of three main components:

1. **TCP Randomizer** (`tcp_randomizer.py`) - Core randomization logic
2. **Network Layer** (`network_layer.py`) - Socket wrappers and network management
3. **Cowrie Integration** (`cowrie_integration.py`) - Integration hooks for Cowrie

## Configuration

All parameters are configurable via YAML configuration file (`tcp_config.yaml`):

```yaml
# Enable/disable TCP/IP stack randomization
enabled: true

# Timing configuration for response delays
timing:
  base_response_delay: 0.05 # 50ms base delay
  jitter_range: [0.02, 0.05] # ±20-50ms jitter
  min_delay: 0.01 # 10ms minimum
  max_delay: 0.15 # 150ms maximum

# Network parameter variations
network_params:
  window_size:
    base: 65535 # Base window size
    variation: 0.1 # ±10% variation
    min: 4096 # Minimum window size
    max: 131072 # Maximum window size

  ttl:
    base: 64 # Base TTL value
    variation: 0.15 # ±15% variation
    min: 32 # Minimum TTL
    max: 128 # Maximum TTL

  mss:
    base: 1460 # Base MSS value
    variation: 0.05 # ±5% variation
    min: 536 # Minimum MSS
    max: 1460 # Maximum MSS

# Production server fingerprint (used when randomization is disabled)
production_fingerprint:
  window_size: 65535 # Production window size
  ttl: 64 # Production TTL
  mss: 1460 # Production MSS
  response_delay: 0.03 # Production response delay (30ms)
```

## Usage

### Basic Usage

```python
from honeypot.tcp_randomizer import get_tcp_randomizer, apply_tcp_randomization

# Get randomizer instance
randomizer = get_tcp_randomizer()

# Apply randomized delay
apply_tcp_randomization()

# Get randomized network parameters
params = randomizer.get_randomized_params()
print(f"Window Size: {params.window_size}")
print(f"TTL: {params.ttl}")
print(f"MSS: {params.mss}")
print(f"Response Delay: {params.response_delay}")
```

### Network Layer Integration

```python
from honeypot.network_layer import create_randomized_socket, get_network_manager

# Create randomized TCP socket
with create_randomized_socket() as sock:
    sock.bind(('0.0.0.0', 2222))
    sock.listen(5)

    # Accept connections with randomization
    client_sock, client_addr = sock.accept()

    # Send data with randomized timing
    client_sock.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")

# Get network manager for statistics
manager = get_network_manager()
stats = manager.get_connection_stats()
print(f"Active connections: {stats['total_connections']}")
```

### Cowrie Integration

```python
from honeypot.cowrie_integration import get_cowrie_integration, apply_cowrie_patches

# Get integration instance
integration = get_cowrie_integration()

# Apply patches to Cowrie's socket handling
apply_cowrie_patches()

# Get integration hooks
hooks = integration.create_ssh_server_hooks()

# Use hooks in Cowrie SSH server
def handle_connection(client_address, connection_id):
    hooks['connection_hook'](client_address, connection_id)
    # ... rest of connection handling

def handle_authentication(username, password, success, connection_id):
    hooks['authentication_hook'](username, password, success, connection_id)
    # ... rest of authentication handling
```

## Integration with Cowrie

### Method 1: Automatic Patching

```python
# In Cowrie's main server file (e.g., bin/cowrie)
from honeypot.cowrie_integration import apply_cowrie_patches

# Apply patches before starting the server
apply_cowrie_patches()

# Start Cowrie server
# ... existing Cowrie startup code
```

### Method 2: Manual Integration

```python
# In Cowrie's SSH server class
from honeypot.cowrie_integration import get_cowrie_integration

class CowrieSSHServer:
    def __init__(self):
        self.integration = get_cowrie_integration()
        self.hooks = self.integration.create_ssh_server_hooks()

    def handle_connection(self, client_address, connection_id):
        # Apply connection randomization
        self.hooks['connection_hook'](client_address, connection_id)

        # ... existing connection handling code

    def handle_authentication(self, username, password, success, connection_id):
        # Apply authentication randomization
        self.hooks['authentication_hook'](username, password, success, connection_id)

        # ... existing authentication handling code
```

### Method 3: Using Generated Patch

The integration module can generate a patch file for Cowrie:

```python
from honeypot.cowrie_integration import get_cowrie_integration

integration = get_cowrie_integration()
integration.generate_cowrie_patch("cowrie_patch.py")
```

Then in Cowrie's main file:

```python
# Import and apply the generated patch
from cowrie_patch import apply_patches

# Apply patches to SSH server class
apply_patches(CowrieSSHServer)
```

## Testing

### Run All Tests

```bash
python run_tests.py
```

### Run Specific Tests

```bash
# Unit tests only
python -m unittest tests.test_tcp_randomizer -v

# Test individual modules
python honeypot/tcp_randomizer.py
python honeypot/network_layer.py
python honeypot/cowrie_integration.py
```

### Test Configuration

```python
from honeypot.tcp_randomizer import TCPStackRandomizer

# Test with custom config
randomizer = TCPStackRandomizer("custom_config.yaml")

# Test randomization
for i in range(10):
    params = randomizer.get_randomized_params()
    print(f"Test {i+1}: Window={params.window_size}, TTL={params.ttl}, MSS={params.mss}")
```

## Monitoring and Statistics

### Connection Statistics

```python
from honeypot.network_layer import get_network_manager

manager = get_network_manager()
stats = manager.get_connection_stats()

print(f"Total connections: {stats['total_connections']}")
print(f"Randomizer enabled: {stats['randomizer_enabled']}")

for conn_id, conn_data in stats['connections'].items():
    print(f"Connection {conn_id}:")
    print(f"  Parameters: {conn_data['params']}")
    print(f"  Duration: {conn_data['duration']:.2f}s")
```

### Integration Status

```python
from honeypot.cowrie_integration import get_cowrie_integration

integration = get_cowrie_integration()
status = integration.get_integration_status()

print(f"Randomizer enabled: {status['randomizer_enabled']}")
print(f"Network manager active: {status['network_manager_active']}")
print(f"Patched modules: {status['patched_modules']}")
```

## Performance Considerations

### Timing Impact

- **Base delay**: 50ms (configurable)
- **Jitter range**: ±20-50ms (configurable)
- **Total impact**: 10-150ms per operation (configurable)

### Resource Usage

- **Memory**: Minimal overhead (~1MB for manager)
- **CPU**: Negligible impact
- **Network**: No additional bandwidth usage

### Optimization Tips

1. **Adjust timing parameters** based on your requirements
2. **Disable randomization** for high-performance scenarios
3. **Use production fingerprint** for exact server matching
4. **Monitor connection statistics** to optimize parameters

## Security Considerations

### Fingerprinting Protection

- **Timing variations** prevent timing-based fingerprinting
- **Parameter randomization** prevents static fingerprinting
- **Configurable ranges** allow fine-tuning of protection level

### Production Matching

- **Production fingerprint** ensures honeypot matches real server
- **Configurable parameters** allow easy updates
- **Disable option** for emergency situations

## Troubleshooting

### Common Issues

1. **Configuration not loaded**

   - Check file path and permissions
   - Verify YAML syntax
   - Check log messages

2. **Randomization not working**

   - Verify `enabled: true` in config
   - Check log level for debug messages
   - Test with unit tests

3. **Integration issues**
   - Ensure patches are applied before server start
   - Check for import errors
   - Verify Python path includes honeypot directory

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# This will show detailed randomization information
from honeypot.tcp_randomizer import get_tcp_randomizer
randomizer = get_tcp_randomizer()
```

### Log Files

Check the following log files for issues:

- `logs/cowrie.log` - Cowrie application logs
- `logs/tcp_randomizer.log` - Randomization module logs (if configured)

## API Reference

### TCPStackRandomizer

```python
class TCPStackRandomizer:
    def __init__(self, config_path: str = "honeypot/tcp_config.yaml")
    def get_randomized_delay(self) -> float
    def get_randomized_window_size(self) -> int
    def get_randomized_ttl(self) -> int
    def get_randomized_mss(self) -> int
    def get_randomized_params(self) -> NetworkParams
    def apply_delay(self) -> None
    def enable(self) -> None
    def disable(self) -> None
    def reload_config(self) -> None
```

### NetworkLayerManager

```python
class NetworkLayerManager:
    def __init__(self, config_path: str = "honeypot/tcp_config.yaml")
    def create_socket(self, family, type, proto, fileno) -> RandomizedTCPSocket
    def apply_connection_randomization(self, sock, connection_id) -> None
    def get_connection_stats(self) -> dict
    def remove_connection(self, connection_id) -> None
    def enable_randomization(self) -> None
    def disable_randomization(self) -> None
    def reload_config(self) -> None
```

### CowrieIntegration

```python
class CowrieIntegration:
    def __init__(self, config_path: str = "honeypot/tcp_config.yaml")
    def patch_cowrie_socket(self) -> bool
    def unpatch_cowrie_socket(self) -> bool
    def create_ssh_server_hooks(self) -> Dict[str, Any]
    def generate_cowrie_patch(self, output_path: str) -> bool
    def get_integration_status(self) -> Dict[str, Any]
    def enable_integration(self) -> bool
    def disable_integration(self) -> bool
    def reload_configuration(self) -> bool
```

## Contributing

When contributing to the TCP/IP stack randomization:

1. **Follow existing code style** and patterns
2. **Add unit tests** for new functionality
3. **Update documentation** for new features
4. **Test integration** with Cowrie
5. **Validate configuration** changes

## License

This module is part of the Digital Twin Honeynet project and follows the same license terms.

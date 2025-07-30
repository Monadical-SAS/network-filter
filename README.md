# network-filter

A lightweight Docker container that provides network filtering capabilities using iptables and dnsmasq. It restricts outbound network access to an allowlist of domains, making it useful for creating secure network environments where containers should only communicate with specific external services.

## How it works

The network-filter uses a combination of:
- **iptables**: Drops all outbound traffic by default, then allows only specific IP addresses resolved from allowed domains
- **dnsmasq**: Acts as a local DNS server that only resolves allowed domains
- **Dynamic IP resolution**: Periodically refreshes IP addresses for allowed domains to handle DNS changes

The filter operates at the network level, meaning any container that shares its network namespace will inherit these restrictions.

## Usage

### Basic usage

```bash
docker run --cap-add NET_ADMIN \
  -e ALLOWED_DOMAINS="github.com,api.github.com" \
  monadicalsas/network-filter
```

### Docker Compose

To restrict a container's network access, use Docker's `network_mode` to share the network-filter's network namespace.

This ensures the container can only access domains specified in `ALLOWED_DOMAINS`.

```yaml
services:
  network-filter:
    image: monadicalsas/network-filter:latest
    cap_add:
      - NET_ADMIN
    environment:
      - ALLOWED_DOMAINS=github.com,api.github.com

  my-app:
    image: my-app:latest
    network_mode: "service:network-filter"
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `ALLOWED_DOMAINS` | Comma-separated list of allowed domains with optional port specifications | (none - required) |
| `DNS_SERVERS` | Comma-separated list of upstream DNS servers | `8.8.8.8,8.8.4.4` |
| `REFRESH_INTERVAL` | How often to refresh domain IP addresses (seconds) | `300` |
| `RUN_SELFTEST` | Run connectivity tests on startup | `false` |

### Domain and port specification

You can specify which ports are allowed for each domain:

- `domain.com` - allows ports 80 and 443 (default)
- `domain.com:443` - allows only port 443
- `domain.com:22:80:443` - allows ports 22, 80, and 443

Examples:
```bash
# Default ports (80, 443)
ALLOWED_DOMAINS=github.com,api.github.com

# HTTPS only for github.com
ALLOWED_DOMAINS=github.com:443,api.github.com

# Multiple ports including SSH
ALLOWED_DOMAINS=github.com:22:443,api.github.com
```

## Network rules

The filter allows:
- All loopback traffic
- Established connections
- Local network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- DNS queries to configured DNS servers
- TCP connections to resolved IPs of allowed domains on specified ports

All other outbound traffic is dropped.

## Testing

Enable self-test on startup to verify the configuration:

```bash
docker run --cap-add NET_ADMIN \
  -e ALLOWED_DOMAINS="github.com" \
  -e RUN_SELFTEST=true \
  monadicalsas/network-filter
```

Or run the self-test manually:
```bash
docker exec <container-id> /network-filter.sh selftest
```

### Example: Testing with ping

Test that allowed domains work while others are blocked:

```bash
# Start the network filter container
docker run -d --name net-filter --cap-add NET_ADMIN -e ALLOWED_DOMAINS="github.com" monadicalsas/network-filter

# This will work - github.com is in the allowed list
docker run --rm --network "container:net-filter" alpine ping -c 3 github.com

# This will fail - google.com is not in the allowed list
docker run --rm --network "container:net-filter" alpine ping -c 3 google.com
```

## Limitations

- Only supports IPv4 addresses
- Requires periodic refresh to handle DNS changes
- All containers sharing the network namespace share the same restrictions

## Q&A

### Why is NET_ADMIN capability required?

The `NET_ADMIN` capability is required to configure iptables rules within the container. This capability only affects the container's network namespace and does not grant any privileges to modify the host's network configuration. The container's iptables rules are isolated and cannot impact the host system's networking.

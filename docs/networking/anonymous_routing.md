# Anonymous Routing in Obscura

This document provides information about anonymous routing options in the Obscura blockchain, including Tor and I2P support.

## Overview

Obscura supports routing connections through anonymous networks to enhance user privacy and protect against network surveillance. By leveraging established anonymity networks like Tor and I2P, Obscura provides users with options to conceal their network identity and protect against traffic analysis attacks.

## Tor Support

### What is Tor?

Tor (The Onion Router) is an anonymity network that enables anonymous communication by directing internet traffic through a worldwide network of relays to conceal a user's location and usage. Tor uses a technique called onion routing, where messages are encapsulated in multiple layers of encryption.

### Tor Integration in Obscura

Obscura integrates with Tor through the following features:

- **Tor Proxy Service**: Manages connections to the Tor network
- **Onion Address Handling**: Parses and validates .onion addresses
- **Transparent Routing**: Automatically routes .onion addresses through Tor
- **Feature Negotiation**: Negotiates Tor support during peer handshakes
- **Address Mapping**: Maps onion addresses to internal socket representations

## I2P Support

### What is I2P?

I2P (Invisible Internet Project) is a network layer that provides anonymous and private communication. Unlike Tor, which is primarily designed for accessing the regular internet anonymously, I2P is a self-contained network with its own DNS-like system and services. I2P uses a technique called garlic routing, which is similar to onion routing but with some key differences.

### I2P Integration in Obscura

Obscura integrates with I2P through the following features:

- **I2P Proxy Service**: Manages connections to the I2P network
- **Destination Handling**: Parses and validates .i2p addresses
- **Transparent Routing**: Automatically routes .i2p addresses through I2P
- **Feature Negotiation**: Negotiates I2P support during peer handshakes
- **Address Mapping**: Maps I2P destinations to internal socket representations
- **Inbound Connections**: Accepts inbound connections through I2P tunnels

## Comparison: Tor vs. I2P

| Feature | Tor | I2P |
|---------|-----|-----|
| Routing Technique | Onion Routing | Garlic Routing |
| Primary Design | Accessing regular internet anonymously | Self-contained anonymous network |
| Connection Type | Primarily outbound | Both inbound and outbound |
| Tunnel Direction | Unidirectional | Unidirectional |
| Directory Services | Centralized | Distributed |
| Exit Nodes | Yes | No (by default) |
| Resistance to Correlation Attacks | Moderate | Strong (due to tunnel rotation) |
| Implementation in Obscura | `tor_proxy.rs` | `i2p_proxy.rs` |

## Configuration

### Enabling Anonymous Routing

To enable anonymous routing in Obscura, use the following feature flags:

```bash
# Enable Tor support
cargo build --features "use-tor"

# Enable I2P support
cargo build --features "use-i2p"

# Enable both Tor and I2P support
cargo build --features "use-tor use-i2p"
```

### Configuration Options

In your Obscura configuration file, you can specify the following options:

```toml
[network.privacy]
# Enable or disable Tor support
use_tor = true
# Tor proxy host
tor_proxy_host = "127.0.0.1"
# Tor proxy port
tor_proxy_port = 9050
# Enable or disable I2P support
use_i2p = true
# I2P proxy host
i2p_proxy_host = "127.0.0.1"
# I2P proxy port
i2p_proxy_port = 7656
# I2P proxy authentication (optional)
i2p_proxy_auth = "username:password"
```

## Best Practices

For optimal privacy when using anonymous routing in Obscura:

1. **Run your own Tor/I2P node** rather than relying on public nodes
2. **Enable traffic obfuscation features** to complement anonymous routing
3. **Use protocol morphing** to make your traffic pattern less recognizable
4. **Rotate connections periodically** to prevent long-term correlation
5. **Consider network diversity** when connecting to peers

## Implementation Details

For developers interested in the implementation details, the anonymous routing features are implemented in:

- `src/networking/tor_proxy.rs`: Tor proxy service implementation
- `src/networking/i2p_proxy.rs`: I2P proxy service implementation
- `src/networking/p2p.rs`: Integration with the P2P networking layer

## Related Documentation

- [Connection Management](connection_management.md): Information about connection management in Obscura
- [P2P Protocol](p2p_protocol.md): Information about Obscura's peer-to-peer protocol
- [Privacy Features](../privacy_features.md): Overview of privacy features in Obscura 
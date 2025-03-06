# DNS-over-HTTPS in Obscura

Obscura implements DNS-over-HTTPS (DoH) for seed node discovery to enhance privacy and security while preventing DNS leakage. This document explains how the feature works, its configuration options, and its integration with the peer discovery process.

## Overview

DNS-over-HTTPS encrypts DNS queries using the HTTPS protocol, preventing ISPs and network observers from monitoring or tampering with DNS lookups. For Obscura, this is particularly important for seed node discovery, as DNS queries for seed nodes could reveal that a user is connecting to the Obscura network.

## Key Benefits

- **Privacy Protection**: Prevents ISPs and network observers from seeing which seed nodes you're connecting to
- **DNS Hijacking Prevention**: Mitigates attacks where DNS responses are manipulated to direct users to malicious nodes
- **Censorship Resistance**: Helps bypass DNS-based censorship of the Obscura network
- **Reliability**: Multiple providers and fallback mechanisms ensure seed node discovery works even if one DoH provider is blocked

## How It Works

1. **Initialization**: During node startup, the DoH service is initialized with default or custom configuration
2. **Seed Node Discovery**: Instead of using traditional DNS resolution, seed node hostnames are resolved through DoH
3. **Periodic Refresh**: Seed nodes are periodically refreshed using DoH to ensure the node stays connected to the network
4. **Fallback Mechanism**: If DoH resolution fails, the system falls back to hardcoded bootstrap nodes

## Features

### Multiple Providers

The Obscura DoH implementation supports multiple DNS-over-HTTPS providers:

- Cloudflare (`https://cloudflare-dns.com/dns-query`)
- Google (`https://dns.google/resolve`)
- Quad9 (`https://dns.quad9.net/dns-query`)
- Custom providers (user-configured)

### Privacy Enhancements

Several privacy-enhancing techniques are implemented:

- **Provider Rotation**: DoH providers are automatically rotated on a configurable interval
- **Provider Randomization**: Providers can be randomly selected for each resolution to enhance privacy
- **Result Verification**: Results from multiple providers can be compared to detect manipulation
- **Request Caching**: Successful resolutions are cached to reduce the number of DoH requests

### Configuration Options

The DoH service can be customized through the following configuration options:

```rust
pub struct DoHConfig {
    // Enable or disable DNS-over-HTTPS
    pub enabled: bool,
    
    // Primary DNS-over-HTTPS provider
    pub primary_provider: DoHProvider,
    
    // Fallback DNS-over-HTTPS provider
    pub fallback_provider: DoHProvider,
    
    // Custom DNS-over-HTTPS URL
    pub custom_url: String,
    
    // Request format (JSON or DNS wire format)
    pub format: DoHFormat,
    
    // Request timeout in seconds
    pub timeout_secs: u64,
    
    // Cache TTL for successful resolutions
    pub cache_ttl_secs: u64,
    
    // Randomize resolver selection for enhanced privacy
    pub randomize_resolver: bool,
    
    // Use multiple resolvers and compare results for security
    pub verify_with_multiple_resolvers: bool,
    
    // Automatically rotate resolvers
    pub rotate_resolvers: bool,
    
    // Time interval between resolver rotations
    pub rotation_interval_secs: u64,
}
```

## Integration with Peer Discovery

The DoH service is integrated with Obscura's peer discovery process:

1. **Initial Bootstrap**: During node initialization, seed node hostnames are resolved using DoH
2. **Bootstrap Refresh**: When the discovery service determines that bootstrapping is needed, seed nodes are refreshed using DoH
3. **Connection Attempts**: Resolved seed node addresses are added to the discovery service and connection attempts are made

## Command-Line Options

The following command-line options are available for configuring DNS-over-HTTPS:

- `--use-doh`: Enable or disable DNS-over-HTTPS (default: enabled)
- `--doh-provider`: Set the primary DoH provider (options: cloudflare, google, quad9, custom)
- `--doh-fallback-provider`: Set the fallback DoH provider
- `--doh-custom-url`: Set a custom DoH provider URL
- `--doh-randomize`: Enable or disable resolver randomization
- `--doh-verify`: Enable or disable result verification with multiple resolvers
- `--doh-rotate`: Enable or disable resolver rotation
- `--doh-rotate-interval`: Set the interval (in seconds) for resolver rotation

## Implementation Details

The DNS-over-HTTPS functionality is implemented in the following files:

- `src/networking/dns_over_https.rs`: Primary implementation of the DoH service
- `src/networking/mod.rs`: Integration with the Node structure and peer discovery

## Error Handling

The DoH implementation includes robust error handling:

- **Request Failures**: If a request to the primary DoH provider fails, the fallback provider is used
- **Resolution Failures**: If a hostname cannot be resolved, a warning is logged and the system falls back to hardcoded bootstrap nodes
- **Timeout Handling**: Requests that take too long automatically time out to prevent blocking the application

## Future Enhancements

Potential future enhancements to the DNS-over-HTTPS implementation include:

- **DNS Wire Format Support**: Add support for the DNS wire format (RFC 8484) for increased compatibility
- **DNS-over-TLS Support**: Add support for DNS-over-TLS as an alternative to DNS-over-HTTPS
- **Bloom Filter Integration**: Integrate with Bloom filters to further enhance privacy of DNS lookups
- **ESNI Support**: Add support for Encrypted Server Name Indication for enhanced privacy

## Security Considerations

When using DNS-over-HTTPS, consider the following security aspects:

- **Provider Trust**: Your DNS queries are visible to the DoH provider you choose
- **HTTPS Security**: The security of DoH depends on the security of HTTPS itself
- **Correlation Risk**: Using the same DoH provider for all queries may allow correlation attacks
- **Fingerprinting Risk**: DoH usage can create a unique browser fingerprint 
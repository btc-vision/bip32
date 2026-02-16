# @btc-vision/bip32 Documentation

A BIP32 hierarchical deterministic (HD) wallet library for Bitcoin with quantum-resistant ML-DSA support.

## Table of Contents

### Getting Started

- [Overview](./getting-started/overview.md) - What this library does and why
- [Installation](./getting-started/installation.md) - Setup and requirements
- [Quick Start](./getting-started/quick-start.md) - Get up and running in minutes

### BIP32 (Classical)

- [Factory & Key Creation](./bip32/factory.md) - Creating keys from seeds, Base58, and raw keys
- [Key Derivation](./bip32/key-derivation.md) - Child key derivation and BIP32 paths
- [Serialization](./bip32/serialization.md) - Base58 and WIF encoding
- [Signing & Verification](./bip32/signing.md) - ECDSA and Schnorr signatures
- [Key Tweaking](./bip32/tweaking.md) - Taproot-compatible key tweaking

### Quantum-Resistant (ML-DSA)

- [Overview](./quantum/overview.md) - Post-quantum cryptography with ML-DSA
- [Security Levels](./quantum/security-levels.md) - ML-DSA-44, ML-DSA-65, ML-DSA-87
- [Factory & Key Creation](./quantum/factory.md) - Creating quantum keys
- [Key Derivation](./quantum/key-derivation.md) - Quantum hierarchical derivation

### Configuration

- [Networks](./networks/network-configuration.md) - Bitcoin, Testnet, and Regtest
- [Derivation Paths](./derivation-paths/derivation-paths.md) - BIP44/49/84/86/360 paths

### API Reference

- [BIP32 API](./api-reference/bip32-api.md) - Complete classical BIP32 reference
- [Quantum API](./api-reference/quantum-api.md) - Complete quantum BIP32 reference
- [Types & Interfaces](./api-reference/types-interfaces.md) - All exported types

---

[Next: Overview →](./getting-started/overview.md)

# Quantum API Reference

Complete reference for the quantum-resistant BIP32 API.

---

## QuantumBIP32Factory

A singleton object implementing `QuantumBIP32API`.

```typescript
import { QuantumBIP32Factory } from '@btc-vision/bip32';
```

---

## QuantumBIP32API

| Method | Signature |
|--------|-----------|
| `fromSeed` | `(seed: Uint8Array, network?: Network, securityLevel?: MLDSASecurityLevel) => QuantumBIP32Interface` |
| `fromBase58` | `(inString: string) => QuantumBIP32Interface` |
| `fromPublicKey` | `(publicKey: Uint8Array, chainCode: Uint8Array, network?: Network, securityLevel?: MLDSASecurityLevel) => QuantumBIP32Interface` |
| `fromPrivateKey` | `(privateKey: Uint8Array, chainCode: Uint8Array, network?: Network, securityLevel?: MLDSASecurityLevel) => QuantumBIP32Interface` |
| `fromKeyPair` | `(privateKey: Uint8Array, publicKey: Uint8Array, chainCode: Uint8Array, network?: Network, securityLevel?: MLDSASecurityLevel) => QuantumBIP32Interface` |
| `fromPrecomputed` | `(privateKey: Uint8Array \| undefined, publicKey: Uint8Array, chainCode: Uint8Array, depth: number, index: number, parentFingerprint: number, network?: Network, securityLevel?: MLDSASecurityLevel) => QuantumBIP32Interface` |

---

## QuantumBIP32Interface

Extends `QuantumSigner`.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `publicKey` | `Uint8Array` | ML-DSA public key |
| `privateKey` | `Uint8Array \| undefined` | ML-DSA private key |
| `chainCode` | `Uint8Array` | 32-byte chain code |
| `network` | `Network` | Network configuration |
| `depth` | `number` | Derivation depth |
| `index` | `number` | Child index |
| `parentFingerprint` | `number` | Parent key fingerprint |
| `identifier` | `Uint8Array` | hash160(publicKey) |
| `fingerprint` | `Uint8Array` | First 4 bytes of identifier |
| `securityLevel` | `MLDSASecurityLevel` | ML-DSA security level |

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `derive` | `(index: number) => QuantumBIP32Interface` | Derive child key (requires private key) |
| `deriveHardened` | `(index: number) => QuantumBIP32Interface` | Derive hardened child |
| `derivePath` | `(path: string) => QuantumBIP32Interface` | Derive along BIP32 path |
| `isNeutered` | `() => boolean` | True if public-only |
| `neutered` | `() => QuantumBIP32Interface` | Return public-only copy |
| `toBase58` | `() => string` | Serialize to Base58Check |
| `sign` | `(hash: Uint8Array) => Uint8Array` | ML-DSA sign (with extra entropy) |
| `verify` | `(hash: Uint8Array, signature: Uint8Array) => boolean` | ML-DSA verify |

---

## QuantumSigner

Base interface for quantum signing operations.

| Member | Type | Description |
|--------|------|-------------|
| `publicKey` | `Uint8Array` | ML-DSA public key |
| `privateKey` | `Uint8Array \| undefined` | ML-DSA private key |
| `sign` | `(hash: Uint8Array) => Uint8Array` | Sign a message hash |
| `verify` | `(hash: Uint8Array, signature: Uint8Array) => boolean` | Verify a signature |

---

## MLDSAKeyPair

```typescript
interface MLDSAKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}
```

---

## MLDSASecurityLevel

```typescript
enum MLDSASecurityLevel {
  LEVEL2 = 44,  // ML-DSA-44 (128-bit classical security)
  LEVEL3 = 65,  // ML-DSA-65 (192-bit classical security)
  LEVEL5 = 87,  // ML-DSA-87 (256-bit classical security)
}
```

---

## MLDSAConfig

```typescript
interface MLDSAConfig {
  level: MLDSASecurityLevel;
  privateKeySize: number;
  publicKeySize: number;
  signatureSize: number;
  algorithm: typeof ml_dsa44 | typeof ml_dsa65 | typeof ml_dsa87;
  network: Network;
}
```

---

## getMLDSAConfig

```typescript
function getMLDSAConfig(
  level: MLDSASecurityLevel,
  network: Network,
): MLDSAConfig
```

Returns the full ML-DSA configuration for a given security level and network.

---

## DEFAULT_SECURITY_LEVEL

```typescript
const DEFAULT_SECURITY_LEVEL: MLDSASecurityLevel = MLDSASecurityLevel.LEVEL2;
```

---

[← Previous: BIP32 API Reference](./bip32-api.md) | [Next: Types & Interfaces →](./types-interfaces.md)

# Quantum Factory & Key Creation

`QuantumBIP32Factory` is a singleton object providing all quantum key creation methods. Unlike classical `BIP32Factory`, it does not require an ECC library.

```typescript
import { QuantumBIP32Factory } from '@btc-vision/bip32';
```

---

## fromSeed

Create a quantum master key from a seed.

```typescript
fromSeed(
  seed: Uint8Array,
  network?: Network,
  securityLevel?: MLDSASecurityLevel,
): QuantumBIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `seed` | `Uint8Array` | — | Seed bytes (16–64 bytes) |
| `network` | `Network` | `BITCOIN` | Network configuration |
| `securityLevel` | `MLDSASecurityLevel` | `LEVEL2` | ML-DSA security level |

```typescript
const seed = Buffer.from(
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  'hex',
);
const master = QuantumBIP32Factory.fromSeed(seed);
```

The seed is processed through HMAC-SHA512 with key `"Bitcoin seed"`. The first 32 bytes feed into ML-DSA key generation; the last 32 bytes become the chain code.

---

## fromBase58

Deserialize a quantum key from Base58Check. Network and security level are detected automatically from the version bytes and key size.

```typescript
fromBase58(inString: string): QuantumBIP32Interface
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `inString` | `string` | Base58Check-encoded quantum extended key |

```typescript
const restored = QuantumBIP32Factory.fromBase58(master.toBase58());
```

The security level is inferred from the key data size in the decoded buffer.

---

## fromPrivateKey

Create a quantum key from a raw ML-DSA private key and chain code. The public key is derived from the private key.

```typescript
fromPrivateKey(
  privateKey: Uint8Array,
  chainCode: Uint8Array,
  network?: Network,
  securityLevel?: MLDSASecurityLevel,
): QuantumBIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `privateKey` | `Uint8Array` | — | ML-DSA private key |
| `chainCode` | `Uint8Array` | — | 32-byte chain code |
| `network` | `Network` | `BITCOIN` | Network configuration |
| `securityLevel` | `MLDSASecurityLevel` | `LEVEL2` | ML-DSA security level |

**Validation:**
- Private key must match the expected size for the security level
- Chain code must be 32 bytes

---

## fromPublicKey

Create a neutered (public-only) quantum key.

```typescript
fromPublicKey(
  publicKey: Uint8Array,
  chainCode: Uint8Array,
  network?: Network,
  securityLevel?: MLDSASecurityLevel,
): QuantumBIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `publicKey` | `Uint8Array` | — | ML-DSA public key |
| `chainCode` | `Uint8Array` | — | 32-byte chain code |
| `network` | `Network` | `BITCOIN` | Network configuration |
| `securityLevel` | `MLDSASecurityLevel` | `LEVEL2` | ML-DSA security level |

Neutered quantum keys can verify signatures but **cannot derive child keys** (unlike classical BIP32).

---

## fromKeyPair

Create a quantum key from both private and public keys, skipping the expensive public key derivation.

```typescript
fromKeyPair(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  chainCode: Uint8Array,
  network?: Network,
  securityLevel?: MLDSASecurityLevel,
): QuantumBIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `privateKey` | `Uint8Array` | — | ML-DSA private key |
| `publicKey` | `Uint8Array` | — | ML-DSA public key |
| `chainCode` | `Uint8Array` | — | 32-byte chain code |
| `network` | `Network` | `BITCOIN` | Network configuration |
| `securityLevel` | `MLDSASecurityLevel` | `LEVEL2` | ML-DSA security level |

Use this for faster imports when both keys are available (e.g., from backup). The caller is responsible for ensuring the keys are a valid pair — **no verification is performed**.

---

## fromPrecomputed

Restore a quantum BIP32 node from precomputed values without validation.

```typescript
fromPrecomputed(
  privateKey: Uint8Array | undefined,
  publicKey: Uint8Array,
  chainCode: Uint8Array,
  depth: number,
  index: number,
  parentFingerprint: number,
  network?: Network,
  securityLevel?: MLDSASecurityLevel,
): QuantumBIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `privateKey` | `Uint8Array \| undefined` | — | ML-DSA private key or undefined |
| `publicKey` | `Uint8Array` | — | ML-DSA public key |
| `chainCode` | `Uint8Array` | — | 32-byte chain code |
| `depth` | `number` | — | Derivation depth |
| `index` | `number` | — | Child index |
| `parentFingerprint` | `number` | — | Parent key fingerprint |
| `network` | `Network` | `BITCOIN` | Network configuration |
| `securityLevel` | `MLDSASecurityLevel` | `LEVEL2` | ML-DSA security level |

Use this when restoring from cache/backup where all values are already known. **No validation is performed.**

---

[← Previous: Security Levels](./security-levels.md) | [Next: Quantum Key Derivation →](./key-derivation.md)

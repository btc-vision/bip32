# Types & Interfaces

All types exported from `@btc-vision/bip32`.

---

## Network Types

### Network

Defined in `@btc-vision/ecpair`. Import directly from that package:

```typescript
import type { Network } from '@btc-vision/ecpair';
```

```typescript
interface Network {
  messagePrefix: string | Uint8Array;
  bech32: string;
  pubKeyHash: number;
  scriptHash: number;
  wif: number;
  bip32: Bip32Versions;
}
```

### Bip32 (Bip32Versions)

```typescript
interface Bip32Versions {
  public: number;
  private: number;
}
```

---

## Derivation Path Types

### DerivationPath

```typescript
enum DerivationPath {
  BIP44 = "m/44'/0'/0'/0/0",
  BIP49 = "m/49'/0'/0'/0/0",
  BIP84 = "m/84'/0'/0'/0/0",
  BIP86 = "m/86'/0'/0'/0/0",
  BIP360 = "m/360'/0'/0'/0/0",
}
```

### QuantumDerivationPath

```typescript
enum QuantumDerivationPath {
  STANDARD = "m/360'/0'/0'/0/0",
  CHANGE = "m/360'/0'/0'/1/0",
  ACCOUNT_0_ADDRESS_0 = "m/360'/0'/0'/0/0",
  ACCOUNT_0_ADDRESS_1 = "m/360'/0'/0'/0/1",
  ACCOUNT_1_ADDRESS_0 = "m/360'/1'/0'/0/0",
}
```

---

## Signer Types

From `@btc-vision/ecpair`:

### UniversalSigner

```typescript
interface UniversalSigner {
  publicKey: PublicKey;
  xOnlyPublicKey: XOnlyPublicKey;
  privateKey?: PrivateKey;
  compressed: boolean;
  capabilities: number;
  hasCapability(cap: SignerCapability): boolean;
  sign(hash: MessageHash, lowR?: boolean): Signature;
  signSchnorr(hash: MessageHash): SchnorrSignature;
  verify(hash: MessageHash, signature: Signature): boolean;
  verifySchnorr(hash: MessageHash, signature: SchnorrSignature): boolean;
  tweak(t: Bytes32): UniversalSigner;
  toWIF(): string;
}
```

---

## Branded Types

From `@btc-vision/ecpair` — these are `Uint8Array` at runtime with branded type tags:

| Type | Runtime | Description |
|------|---------|-------------|
| `PublicKey` | `Uint8Array` | 33-byte compressed public key |
| `XOnlyPublicKey` | `Uint8Array` | 32-byte x-only public key |
| `PrivateKey` | `Uint8Array` | 32-byte private key |
| `MessageHash` | `Uint8Array` | 32-byte message hash |
| `Signature` | `Uint8Array` | ECDSA signature |
| `SchnorrSignature` | `Uint8Array` | Schnorr signature |
| `Bytes32` | `Uint8Array` | 32-byte buffer |

---

## Constants

### Network Constants

| Constant | Type | Description |
|----------|------|-------------|
| `BITCOIN` | `Network` | Bitcoin mainnet |
| `TESTNET` | `Network` | Bitcoin testnet |
| `REGTEST` | `Network` | Bitcoin regtest |

### Quantum Constants

| Constant | Type | Description |
|----------|------|-------------|
| `DEFAULT_SECURITY_LEVEL` | `MLDSASecurityLevel` | `LEVEL2` (ML-DSA-44) |

---

[← Previous: Quantum API Reference](./quantum-api.md) | [Back to Index](../README.md)

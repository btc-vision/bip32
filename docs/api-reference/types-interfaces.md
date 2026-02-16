# Types & Interfaces

All types exported from `@btc-vision/bip32`.

---

## Network Types

### Network

Re-exported from `@btc-vision/ecpair`.

```typescript
interface Network {
  messagePrefix: string | Uint8Array;
  bech32: string;
  bech32Opnet?: string;
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

### DerivationPathType

```typescript
type DerivationPathType = DerivationPath | string;
```

### QuantumDerivationPathType

```typescript
type QuantumDerivationPathType = QuantumDerivationPath | string;
```

---

## Signer Types

Re-exported from `@btc-vision/ecpair`:

### BIP32Signer

```typescript
type BIP32Signer = UniversalSigner;
```

Type alias for `UniversalSigner` from `@btc-vision/ecpair`. Used for backward compatibility.

### UniversalSigner

From `@btc-vision/ecpair`:

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

## Buffer Type

```typescript
type Uint8ArrayOrBuffer = Uint8Array | Buffer;
```

Convenience type for accepting either `Uint8Array` or Node.js `Buffer`.

---

## Validation Functions

### validateBip32Path

```typescript
function validateBip32Path(path: string): void
```

Throws `TypeError` if `path` is not a valid BIP32 derivation path matching `^(m\/)?(\d+'?\/)*\d+'?$`.

### validateBuffer256Bit

```typescript
function validateBuffer256Bit(buf: Uint8Array): void
```

Throws `TypeError` if `buf` is not a `Uint8Array` of length 32.

### validateBuffer33Bytes

```typescript
function validateBuffer33Bytes(buf: Uint8Array): void
```

Throws `TypeError` if `buf` is not a `Uint8Array` of length 33.

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

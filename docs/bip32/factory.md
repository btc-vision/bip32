# Factory & Key Creation

The `BIP32Factory` function creates a BIP32 API bound to a specific secp256k1 ECC library. All key creation methods are accessed through the returned factory object.

## Creating the Factory

```typescript
import { createNobleBackend } from '@btc-vision/ecpair';
import { BIP32Factory } from '@btc-vision/bip32';

const bip32 = BIP32Factory(createNobleBackend());
```

The factory accepts either a `TinySecp256k1Interface` or a `CryptoBackend` from `@btc-vision/ecpair` (e.g. `createNobleBackend()` or `createLegacyBackend(ecc)`). The ECC library is validated on first use — if it fails validation, an error is thrown immediately.

---

## fromSeed

Create a master key from a seed (typically derived from a BIP39 mnemonic).

```typescript
fromSeed(seed: Uint8Array, network?: Network): BIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `seed` | `Uint8Array` | — | Seed bytes (16–64 bytes) |
| `network` | `Network` | `BITCOIN` | Network configuration |

```typescript
const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const master = bip32.fromSeed(seed);
```

The seed is processed through HMAC-SHA512 with the key `"Bitcoin seed"` to produce a 32-byte private key and a 32-byte chain code, per the BIP32 specification.

**Validation:**
- Seed must be a `Uint8Array`
- Minimum 16 bytes (128 bits)
- Maximum 64 bytes (512 bits)

---

## fromBase58

Deserialize a key from a Base58Check-encoded extended key string (xprv/xpub).

```typescript
fromBase58(inString: string, network?: Network): BIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `inString` | `string` | — | Base58Check-encoded extended key |
| `network` | `Network` | `BITCOIN` | Network configuration |

```typescript
const xprv = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi';
const node = bip32.fromBase58(xprv);

const xpub = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
const pubNode = bip32.fromBase58(xpub);
```

**Validation:**
- Buffer must decode to exactly 78 bytes
- Version bytes must match the network
- Depth 0 keys must have zero parent fingerprint and index

---

## fromPrivateKey

Create a key from a raw private key and chain code.

```typescript
fromPrivateKey(
  privateKey: Uint8Array,
  chainCode: Uint8Array,
  network?: Network,
): BIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `privateKey` | `Uint8Array` | — | 32-byte private key |
| `chainCode` | `Uint8Array` | — | 32-byte chain code |
| `network` | `Network` | `BITCOIN` | Network configuration |

```typescript
const privateKey = Buffer.alloc(32, 0x01);
const chainCode = Buffer.alloc(32, 0x02);
const node = bip32.fromPrivateKey(privateKey, chainCode);
```

**Validation:**
- Private key must be 32 bytes
- Chain code must be 32 bytes
- Private key must be in range [1, n)

---

## fromPublicKey

Create a neutered (public-only) key from a compressed public key and chain code.

```typescript
fromPublicKey(
  publicKey: Uint8Array,
  chainCode: Uint8Array,
  network?: Network,
): BIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `publicKey` | `Uint8Array` | — | 33-byte compressed public key |
| `chainCode` | `Uint8Array` | — | 32-byte chain code |
| `network` | `Network` | `BITCOIN` | Network configuration |

```typescript
const pubKey = Buffer.from('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2', 'hex');
const chainCode = Buffer.from('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508', 'hex');
const node = bip32.fromPublicKey(pubKey, chainCode);
```

**Validation:**
- Public key must be 33 bytes (compressed SEC format)
- Chain code must be 32 bytes
- Public key must be a valid point on the curve

---

## fromPrecomputed

Restore a BIP32 node from precomputed values without validation. Use this when restoring from cache or backup where all values are already known.

```typescript
fromPrecomputed(
  privateKey: Uint8Array | undefined,
  publicKey: Uint8Array,
  chainCode: Uint8Array,
  depth: number,
  index: number,
  parentFingerprint: number,
  network?: Network,
): BIP32Interface
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `privateKey` | `Uint8Array \| undefined` | — | 32-byte private key or undefined for neutered |
| `publicKey` | `Uint8Array` | — | 33-byte compressed public key |
| `chainCode` | `Uint8Array` | — | 32-byte chain code |
| `depth` | `number` | — | Derivation depth |
| `index` | `number` | — | Child index |
| `parentFingerprint` | `number` | — | Parent key fingerprint |
| `network` | `Network` | `BITCOIN` | Network configuration |

```typescript
const node = bip32.fromPrecomputed(
  privateKey,
  publicKey,
  chainCode,
  2,          // depth
  0x80000000, // index (hardened 0)
  0x3442193e, // parent fingerprint
);
```

**No validation is performed.** The caller must ensure all values are correct.

---

[← Previous: Quick Start](../getting-started/quick-start.md) | [Next: Key Derivation →](./key-derivation.md)

# Networks

The library ships three pre-configured Bitcoin network constants. Networks define version bytes for key serialization, WIF encoding, and address generation.

## Built-in Networks

### BITCOIN (Mainnet)

```typescript
import { BITCOIN } from '@btc-vision/bip32';
```

| Property | Value |
|----------|-------|
| `messagePrefix` | `'\x18Bitcoin Signed Message:\n'` |
| `bech32` | `'bc'` |
| `pubKeyHash` | `0x00` |
| `scriptHash` | `0x05` |
| `wif` | `0x80` |
| `bip32.public` | `0x0488b21e` |
| `bip32.private` | `0x0488ade4` |

### TESTNET

```typescript
import { TESTNET } from '@btc-vision/bip32';
```

| Property | Value |
|----------|-------|
| `messagePrefix` | `'\x18Bitcoin Signed Message:\n'` |
| `bech32` | `'tb'` |
| `pubKeyHash` | `0x6f` |
| `scriptHash` | `0xc4` |
| `wif` | `0xef` |
| `bip32.public` | `0x043587cf` |
| `bip32.private` | `0x04358394` |

### REGTEST

```typescript
import { REGTEST } from '@btc-vision/bip32';
```

| Property | Value |
|----------|-------|
| `messagePrefix` | `'\x18Bitcoin Signed Message:\n'` |
| `bech32` | `'bcrt'` |
| `pubKeyHash` | `0x6f` |
| `scriptHash` | `0xc4` |
| `wif` | `0xef` |
| `bip32.public` | `0x043587cf` |
| `bip32.private` | `0x04358394` |

## Using a Custom Network

Pass any object conforming to the `Network` type from `@btc-vision/ecpair`:

```typescript
import { BIP32Factory } from '@btc-vision/bip32';
import type { Network } from '@btc-vision/bip32';

const LITECOIN: Network = {
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bech32: 'ltc',
  pubKeyHash: 0x30,
  scriptHash: 0x32,
  wif: 0xb0,
  bip32: {
    public: 0x019da462,
    private: 0x019d9cfe,
  },
};

const bip32 = BIP32Factory(ecc);
const master = bip32.fromSeed(seed, LITECOIN);
const wif = master.toWIF(); // Litecoin WIF format
```

## Network Type

The `Network` type is re-exported from `@btc-vision/ecpair`:

```typescript
interface Network {
  messagePrefix: string | Uint8Array;
  bech32: string;
  bech32Opnet?: string;
  pubKeyHash: number;
  scriptHash: number;
  wif: number;
  bip32: {
    public: number;
    private: number;
  };
}
```

---

[← Previous: Quantum Key Derivation](../quantum/key-derivation.md) | [Next: Derivation Paths →](../derivation-paths/derivation-paths.md)

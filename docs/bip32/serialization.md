# Serialization

BIP32 keys can be serialized to Base58Check-encoded strings (xprv/xpub) and WIF format.

---

## toBase58

Serialize a key to a Base58Check-encoded extended key string.

```typescript
toBase58(): string
```

Private keys serialize as `xprv...` and public (neutered) keys as `xpub...`. The prefix depends on the network.

```typescript
const master = bip32.fromSeed(seed);

// Extended private key
const xprv = master.toBase58();
// "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

// Extended public key
const xpub = master.neutered().toBase58();
// "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
```

### Base58 Encoding Structure

The serialized format is exactly 78 bytes before Base58Check encoding:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 bytes | Version bytes |
| 4 | 1 byte | Depth |
| 5 | 4 bytes | Parent fingerprint |
| 9 | 4 bytes | Child index |
| 13 | 32 bytes | Chain code |
| 45 | 33 bytes | Key data (0x00 + private key, or compressed public key) |

### Version Bytes by Network

| Network | Private | Public |
|---------|---------|--------|
| Bitcoin | `0x0488ade4` (xprv) | `0x0488b21e` (xpub) |
| Testnet | `0x04358394` (tprv) | `0x043587cf` (tpub) |
| Regtest | `0x04358394` (tprv) | `0x043587cf` (tpub) |

---

## toWIF

Serialize a private key to Wallet Import Format.

```typescript
toWIF(): string
```

```typescript
const master = bip32.fromSeed(seed);
const wif = master.toWIF();
// "L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW"
```

WIF encoding includes the network version byte and a compression flag. Only available on keys with a private key — throws `TypeError` on neutered keys.

---

## Neutering

Create a public-only copy of a key, stripping the private key.

```typescript
isNeutered(): boolean
neutered(): BIP32Interface
```

```typescript
const master = bip32.fromSeed(seed);

console.log(master.isNeutered());           // false
console.log(master.privateKey !== undefined); // true

const pub = master.neutered();
console.log(pub.isNeutered());              // true
console.log(pub.privateKey);                // undefined

// Neutered keys can still derive normal children
const child = pub.derive(0);
```

A neutered key retains `publicKey`, `chainCode`, `depth`, `index`, and `parentFingerprint`. It can derive normal (non-hardened) children but cannot sign or derive hardened children.

---

[← Previous: Key Derivation](./key-derivation.md) | [Next: Signing & Verification →](./signing.md)

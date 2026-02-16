# Signing & Verification

BIP32 keys implement the `UniversalSigner` interface from `@btc-vision/ecpair`, supporting both ECDSA and Schnorr signature schemes.

---

## ECDSA Signing

```typescript
sign(hash: MessageHash, lowR?: boolean): Signature
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hash` | `MessageHash` | — | 32-byte message hash to sign |
| `lowR` | `boolean` | `this.lowR` | Produce low-R signatures |

```typescript
const hash = Buffer.alloc(32, 0x01);
const signature = node.sign(hash);
```

### Low-R Signatures

Low-R signatures have a first byte <= 0x7f, producing shorter DER encodings. Enable by default on a key or per-call:

```typescript
// Enable globally on this key
node.lowR = true;
const sig = node.sign(hash);

// Or per-call
const sig2 = node.sign(hash, true);
```

When enabled, the signer retries with incrementing extra entropy until a low-R signature is produced.

---

## ECDSA Verification

```typescript
verify(hash: MessageHash, signature: Signature): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | `MessageHash` | 32-byte message hash |
| `signature` | `Signature` | Signature to verify |

```typescript
const valid = node.verify(hash, signature);
```

---

## Schnorr Signing

```typescript
signSchnorr(hash: MessageHash): SchnorrSignature
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | `MessageHash` | 32-byte message hash |

```typescript
const sig = node.signSchnorr(hash);
```

Requires the ECC library to support `signSchnorr`. Throws if the library does not implement it or if the key has no private key.

---

## Schnorr Verification

```typescript
verifySchnorr(hash: MessageHash, signature: SchnorrSignature): boolean
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | `MessageHash` | 32-byte message hash |
| `signature` | `SchnorrSignature` | Schnorr signature to verify |

```typescript
const valid = node.verifySchnorr(hash, sig);
```

---

## Capabilities

Each key reports its signing capabilities via a bitmask:

```typescript
const caps = node.capabilities;

node.hasCapability(SignerCapability.EcdsaSign);      // true if private key present
node.hasCapability(SignerCapability.EcdsaVerify);     // always true
node.hasCapability(SignerCapability.SchnorrSign);     // true if ecc supports it + private key
node.hasCapability(SignerCapability.SchnorrVerify);   // true if ecc supports it
node.hasCapability(SignerCapability.HdDerivation);    // always true for BIP32 nodes
node.hasCapability(SignerCapability.PrivateKeyExport); // true if private key present
node.hasCapability(SignerCapability.PublicKeyTweak);  // always true
```

---

## Key Properties

```typescript
node.publicKey;      // Uint8Array — 33-byte compressed public key
node.xOnlyPublicKey; // Uint8Array — 32-byte x-only public key (for Taproot)
node.privateKey;     // Uint8Array | undefined — 32-byte private key
node.compressed;     // true (always compressed)
```

---

[← Previous: Serialization](./serialization.md) | [Next: Key Tweaking →](./tweaking.md)

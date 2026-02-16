# Key Tweaking

Key tweaking is used for Taproot (BIP86/BIP341) to create tweaked keys from internal keys. BIP32 keys support tweaking through the `UniversalSigner` interface.

---

## tweak

Apply a tweak to the key, returning a new signer with the tweaked key pair.

```typescript
tweak(t: Bytes32): UniversalSigner
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `t` | `Bytes32` | 32-byte tweak value |

### Tweaking with Private Key

When the key has a private key, the tweaked private key is computed as:

```
tweakedPrivateKey = privateKey + t  (mod n)
```

If the public key has an odd Y coordinate, the private key is negated first (per BIP340).

```typescript
const tweak = Buffer.alloc(32, 0x01);
const tweaked = node.tweak(tweak);

// tweaked is a new UniversalSigner with tweaked keys
const sig = tweaked.sign(hash);
```

### Tweaking with Public Key Only

When the key is neutered (no private key), the tweaked public key is computed using `xOnlyPointAddTweak`:

```typescript
const neutered = node.neutered();
const tweaked = neutered.tweak(tweak);

// Can only verify, not sign
const valid = tweaked.verify(hash, signature);
```

Requires the ECC library to implement `xOnlyPointAddTweak`. Throws if not supported.

---

[← Previous: Signing & Verification](./signing.md) | [Next: Quantum Overview →](../quantum/overview.md)

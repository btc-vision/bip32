# BIP32 API Reference

Complete reference for the classical BIP32 API.

---

## BIP32Factory

```typescript
function BIP32Factory(ecc: TinySecp256k1Interface | CryptoBackend): BIP32API
```

Creates a BIP32 HD wallet factory bound to a secp256k1 ECC library. The library is validated on first call.

---

## BIP32API

The object returned by `BIP32Factory`.

| Method | Signature |
|--------|-----------|
| `fromSeed` | `(seed: Uint8Array, network?: Network) => BIP32Interface` |
| `fromBase58` | `(inString: string, network?: Network) => BIP32Interface` |
| `fromPublicKey` | `(publicKey: Uint8Array, chainCode: Uint8Array, network?: Network) => BIP32Interface` |
| `fromPrivateKey` | `(privateKey: Uint8Array, chainCode: Uint8Array, network?: Network) => BIP32Interface` |
| `fromPrecomputed` | `(privateKey: Uint8Array \| undefined, publicKey: Uint8Array, chainCode: Uint8Array, depth: number, index: number, parentFingerprint: number, network?: Network) => BIP32Interface` |

---

## BIP32Interface

Extends `UniversalSigner` from `@btc-vision/ecpair`.

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `publicKey` | `PublicKey` | 33-byte compressed public key |
| `xOnlyPublicKey` | `XOnlyPublicKey` | 32-byte x-only public key |
| `privateKey` | `PrivateKey \| undefined` | 32-byte private key |
| `compressed` | `boolean` | Always `true` |
| `chainCode` | `Uint8Array` | 32-byte chain code |
| `network` | `Network` | Network configuration |
| `depth` | `number` | Derivation depth (0 for master) |
| `index` | `number` | Child index |
| `parentFingerprint` | `number` | Parent key fingerprint |
| `identifier` | `Uint8Array` | hash160(publicKey) |
| `fingerprint` | `Uint8Array` | First 4 bytes of identifier |
| `lowR` | `boolean` | Low-R signing mode (default `false`) |
| `capabilities` | `number` | Bitmask of `SignerCapability` flags |

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `derive` | `(index: number) => BIP32Interface` | Derive child key by index |
| `deriveHardened` | `(index: number) => BIP32Interface` | Derive hardened child (index + 0x80000000) |
| `derivePath` | `(path: string) => BIP32Interface` | Derive along BIP32 path |
| `isNeutered` | `() => boolean` | True if public-only |
| `neutered` | `() => BIP32Interface` | Return public-only copy |
| `toBase58` | `() => string` | Serialize to xprv/xpub |
| `toWIF` | `() => string` | Serialize private key to WIF |
| `sign` | `(hash: MessageHash, lowR?: boolean) => Signature` | ECDSA sign |
| `signSchnorr` | `(hash: MessageHash) => SchnorrSignature` | Schnorr sign |
| `verify` | `(hash: MessageHash, signature: Signature) => boolean` | ECDSA verify |
| `verifySchnorr` | `(hash: MessageHash, signature: SchnorrSignature) => boolean` | Schnorr verify |
| `tweak` | `(t: Bytes32) => UniversalSigner` | Taproot key tweak |
| `hasCapability` | `(cap: SignerCapability) => boolean` | Check capability |

---

## TinySecp256k1Interface

Extends `EcpairTinySecp256k1Interface` from `@btc-vision/ecpair`.

| Method | Signature | Description |
|--------|-----------|-------------|
| `isPoint` | `(p: Uint8Array) => boolean` | Validate a public key |
| `isPrivate` | `(d: Uint8Array) => boolean` | Validate a private key |
| `pointFromScalar` | `(d: Uint8Array, compressed?: boolean) => Uint8Array \| null` | Derive public key |
| `pointAddScalar` | `(p: Uint8Array, tweak: Uint8Array, compressed?: boolean) => Uint8Array \| null` | Add tweak to point |
| `privateAdd` | `(d: Uint8Array, tweak: Uint8Array) => Uint8Array \| null` | Add tweak to private key |
| `privateNegate` | `(d: Uint8Array) => Uint8Array` | Negate private key |
| `sign` | `(h: Uint8Array, d: Uint8Array, e?: Uint8Array) => Uint8Array` | ECDSA sign |
| `verify` | `(h: Uint8Array, Q: Uint8Array, signature: Uint8Array) => boolean` | ECDSA verify |
| `signSchnorr` | `(h: Uint8Array, d: Uint8Array) => Uint8Array` | Schnorr sign (optional) |
| `verifySchnorr` | `(h: Uint8Array, Q: Uint8Array, signature: Uint8Array) => boolean` | Schnorr verify (optional) |
| `xOnlyPointAddTweak` | `(p: Uint8Array, tweak: Uint8Array) => XOnlyPointAddTweakResult \| null` | X-only tweak (optional) |

---

[← Previous: Derivation Paths](../derivation-paths/derivation-paths.md) | [Next: Quantum API Reference →](./quantum-api.md)

# Quick Start

## Classical BIP32

```typescript
import { createNobleBackend } from '@btc-vision/ecpair';
import { BIP32Factory, BITCOIN } from '@btc-vision/bip32';

// 1. Create the factory
const bip32 = BIP32Factory(createNobleBackend());

// 2. Generate a master key from a seed
const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const master = bip32.fromSeed(seed);

// 3. Derive child keys using a BIP44 path
const child = master.derivePath("m/44'/0'/0'/0/0");

// 4. Access key material
console.log('Public key:', Buffer.from(child.publicKey).toString('hex'));
console.log('Private key:', Buffer.from(child.privateKey).toString('hex'));
console.log('WIF:', child.toWIF());
console.log('Base58:', child.toBase58());

// 5. Sign a message
const hash = new Uint8Array(32).fill(0x01);
const signature = child.sign(hash);
const valid = child.verify(hash, signature);
console.log('Signature valid:', valid);
```

## Quantum BIP32

```typescript
import {
  QuantumBIP32Factory,
  MLDSASecurityLevel,
} from '@btc-vision/bip32';

// 1. Generate a master key from a seed
const seed = Buffer.from(
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  'hex',
);
const master = QuantumBIP32Factory.fromSeed(seed);

// 2. Derive child keys
const child = master.derivePath("m/360'/0'/0'/0/0");

// 3. Sign and verify
const hash = new Uint8Array(32).fill(0x01);
const signature = child.sign(hash);
const valid = child.verify(hash, signature);
console.log('Quantum signature valid:', valid);

// 4. Use a higher security level
const masterL5 = QuantumBIP32Factory.fromSeed(
  seed,
  undefined,
  MLDSASecurityLevel.LEVEL5,
);
```

## Derivation Path Helpers

```typescript
import { getBitcoinPath, getQuantumPath } from '@btc-vision/bip32';

// Standard Bitcoin paths
const legacy = getBitcoinPath(44);      // m/44'/0'/0'/0/0
const segwit = getBitcoinPath(84);      // m/84'/0'/0'/0/0
const taproot = getBitcoinPath(86);     // m/86'/0'/0'/0/0
const taproot2 = getBitcoinPath(86, 1); // m/86'/0'/1'/0/0 (account 1)

// Quantum paths (4-component: purpose/account/change/addressIndex)
const quantum = getQuantumPath();                // m/360'/0'/0'/0
const quantumChange = getQuantumPath(0, 0, true); // m/360'/0'/1'/0
```

---

[← Previous: Installation](./installation.md) | [Next: Factory & Key Creation →](../bip32/factory.md)

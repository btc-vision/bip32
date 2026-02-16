# Installation

## Requirements

- **Node.js** >= 24.0.0
- **TypeScript** >= 5.9 (if using TypeScript)

## Install

```bash
npm install @btc-vision/bip32
```

## ECC Library (Classical BIP32 only)

Classical BIP32 requires a secp256k1 ECC library. You can use either:

### Option A: Noble Backend (Recommended)

Pure JavaScript via `@noble/curves` — no native dependencies.

```bash
npm install @btc-vision/ecpair
```

```typescript
import { createNobleBackend } from '@btc-vision/ecpair';
import { BIP32Factory } from '@btc-vision/bip32';

const backend = createNobleBackend();
const bip32 = BIP32Factory(backend);
```

### Option B: Legacy Backend (tiny-secp256k1)

Wraps the native `tiny-secp256k1` library.

```bash
npm install @btc-vision/ecpair tiny-secp256k1
```

```typescript
import { createLegacyBackend } from '@btc-vision/ecpair';
import type { TinySecp256k1Interface } from '@btc-vision/ecpair';
import * as tinysecp from 'tiny-secp256k1';
import { BIP32Factory } from '@btc-vision/bip32';

const backend = createLegacyBackend(tinysecp as unknown as TinySecp256k1Interface);
const bip32 = BIP32Factory(backend);
```

## Quantum BIP32

No ECC library is needed for quantum keys — ML-DSA is built in:

```typescript
import { QuantumBIP32Factory } from '@btc-vision/bip32';

// Ready to use directly
const master = QuantumBIP32Factory.fromSeed(seed);
```

## Module Formats

The package ships dual ESM/CJS builds:

```typescript
// ESM (recommended)
import { BIP32Factory } from '@btc-vision/bip32';

// CJS
const { BIP32Factory } = require('@btc-vision/bip32');
```

---

[← Previous: Overview](./overview.md) | [Next: Quick Start →](./quick-start.md)

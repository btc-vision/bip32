# Derivation Paths

The library provides enums and helper functions for standard BIP derivation paths.

## Standard Bitcoin Paths

```typescript
import { DerivationPath } from '@btc-vision/bip32';
```

| Enum Value | Path | Address Type |
|------------|------|-------------|
| `DerivationPath.BIP44` | `m/44'/0'/0'/0/0` | Legacy P2PKH (1...) |
| `DerivationPath.BIP49` | `m/49'/0'/0'/0/0` | SegWit P2SH-P2WPKH (3...) |
| `DerivationPath.BIP84` | `m/84'/0'/0'/0/0` | Native SegWit P2WPKH (bc1q...) |
| `DerivationPath.BIP86` | `m/86'/0'/0'/0/0` | Taproot P2TR (bc1p...) |
| `DerivationPath.BIP360` | `m/360'/0'/0'/0/0` | Post-Quantum |

```typescript
const child = master.derivePath(DerivationPath.BIP84);
```

---

## Quantum Paths

```typescript
import { QuantumDerivationPath } from '@btc-vision/bip32';
```

| Enum Value | Path |
|------------|------|
| `QuantumDerivationPath.STANDARD` | `m/360'/0'/0'/0/0` |
| `QuantumDerivationPath.CHANGE` | `m/360'/0'/0'/1/0` |
| `QuantumDerivationPath.ACCOUNT_0_ADDRESS_0` | `m/360'/0'/0'/0/0` |
| `QuantumDerivationPath.ACCOUNT_0_ADDRESS_1` | `m/360'/0'/0'/0/1` |
| `QuantumDerivationPath.ACCOUNT_1_ADDRESS_0` | `m/360'/1'/0'/0/0` |

```typescript
const qChild = quantumMaster.derivePath(QuantumDerivationPath.STANDARD);
```

---

## Path Generators

### getBitcoinPath

Generate a standard Bitcoin derivation path with custom account and address indices.

```typescript
getBitcoinPath(
  bipType: 44 | 49 | 84 | 86,
  account?: number,
  addressIndex?: number,
  isChange?: boolean,
): string
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `bipType` | `44 \| 49 \| 84 \| 86` | — | BIP standard number |
| `account` | `number` | `0` | Account index (hardened) |
| `addressIndex` | `number` | `0` | Address index |
| `isChange` | `boolean` | `false` | Change address (1) or receive (0) |

```typescript
import { getBitcoinPath } from '@btc-vision/bip32';

getBitcoinPath(84);              // "m/84'/0'/0'/0/0"
getBitcoinPath(84, 1);           // "m/84'/0'/1'/0/0"
getBitcoinPath(84, 0, 5);        // "m/84'/0'/0'/0/5"
getBitcoinPath(84, 0, 0, true);  // "m/84'/0'/0'/1/0"
```

### getQuantumPath

Generate a quantum (BIP360) derivation path. Returns a 4-component path: `m/360'/{account}'/{change}'/{addressIndex}`.

```typescript
getQuantumPath(
  account?: number,
  addressIndex?: number,
  isChange?: boolean,
): string
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `account` | `number` | `0` | Account index (hardened) |
| `addressIndex` | `number` | `0` | Address index |
| `isChange` | `boolean` | `false` | Change address (1) or receive (0) |

```typescript
import { getQuantumPath } from '@btc-vision/bip32';

getQuantumPath();               // "m/360'/0'/0'/0"
getQuantumPath(1);              // "m/360'/1'/0'/0"
getQuantumPath(0, 3);           // "m/360'/0'/0'/3"
getQuantumPath(0, 0, true);     // "m/360'/0'/1'/0"
```

---

[← Previous: Networks](../networks/network-configuration.md) | [Next: BIP32 API Reference →](../api-reference/bip32-api.md)

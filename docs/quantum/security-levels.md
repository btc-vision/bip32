# Security Levels

ML-DSA offers three security levels with different key/signature sizes and security strengths.

## Levels

| Level | Enum | Classical Security | Quantum Security | Algorithm |
|-------|------|-------------------|-----------------|-----------|
| **LEVEL2** | `MLDSASecurityLevel.LEVEL2` (44) | 128-bit | Category 2 | ML-DSA-44 |
| **LEVEL3** | `MLDSASecurityLevel.LEVEL3` (65) | 192-bit | Category 3 | ML-DSA-65 |
| **LEVEL5** | `MLDSASecurityLevel.LEVEL5` (87) | 256-bit | Category 5 | ML-DSA-87 |

## Key and Signature Sizes

| Level | Private Key | Public Key | Signature |
|-------|-------------|------------|-----------|
| ML-DSA-44 | 2,560 bytes | 1,312 bytes | 2,420 bytes |
| ML-DSA-65 | 4,032 bytes | 1,952 bytes | 3,309 bytes |
| ML-DSA-87 | 4,896 bytes | 2,592 bytes | 4,627 bytes |

## Choosing a Level

**LEVEL2 (ML-DSA-44)** is the default. It offers sufficient post-quantum security with the smallest key sizes. Use higher levels only when your threat model requires it.

```typescript
import {
  QuantumBIP32Factory,
  MLDSASecurityLevel,
} from '@btc-vision/bip32';

// Default: LEVEL2
const master2 = QuantumBIP32Factory.fromSeed(seed);

// LEVEL3: Balanced security/size
const master3 = QuantumBIP32Factory.fromSeed(
  seed,
  undefined,
  MLDSASecurityLevel.LEVEL3,
);

// LEVEL5: Maximum security
const master5 = QuantumBIP32Factory.fromSeed(
  seed,
  undefined,
  MLDSASecurityLevel.LEVEL5,
);
```

## Configuration

Use `getMLDSAConfig` to get the full configuration for a security level:

```typescript
import { getMLDSAConfig, MLDSASecurityLevel, BITCOIN } from '@btc-vision/bip32';

const config = getMLDSAConfig(MLDSASecurityLevel.LEVEL2, BITCOIN);

console.log(config.privateKeySize);  // 2560
console.log(config.publicKeySize);   // 1312
console.log(config.signatureSize);   // 2420
console.log(config.level);           // 44
```

---

[← Previous: Quantum Overview](./overview.md) | [Next: Quantum Factory →](./factory.md)

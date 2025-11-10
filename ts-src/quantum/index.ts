/**
 * Quantum-resistant BIP32 implementation using ML-DSA-87
 *
 * This module provides hierarchical deterministic key derivation using
 * ML-DSA-87 (FIPS 204) for post-quantum security.
 *
 * Key features:
 * - Uses BIP32 path derivation (e.g., m/360'/0'/0'/0/0)
 * - ML-DSA-87 provides Level 5 security (256-bit classical security)
 * - Compatible with standard BIP32 mnemonic seeds
 * - Private keys: 4896 bytes
 * - Public keys: 2592 bytes
 *
 * Usage:
 * ```typescript
 * import { QuantumBIP32Factory } from '@btc-vision/bip32/quantum';
 *
 * const seed = ...; // Your BIP39 seed
 * const master = QuantumBIP32Factory.fromSeed(seed);
 * const child = master.derivePath("m/360'/0'/0'/0/0");
 *
 * const signature = child.sign(messageHash);
 * const isValid = child.verify(messageHash, signature);
 * ```
 */

export { QuantumBIP32Factory } from './mldsa87.js';
export {
  QuantumBIP32Interface,
  QuantumBIP32API,
  QuantumSigner,
  MLDSA87KeyPair,
} from './types.js';
